package pgproxy

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const backendHandshakeTimeout = 10 * time.Second

func dialBackendAuth(target spi.BackendTarget) (net.Conn, []pgproto3.ParameterStatus, pgproto3.BackendKeyData, byte, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(target.Host, strconv.Itoa(target.Port)), backendHandshakeTimeout)
	if err != nil {
		return nil, nil, pgproto3.BackendKeyData{}, 0, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = conn.Close()
		}
	}()
	if err := conn.SetDeadline(time.Now().Add(backendHandshakeTimeout)); err != nil {
		return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("set backend auth deadline: %w", err)
	}

	wireConn := &switchConn{Conn: conn, strictReads: true}
	frontend := pgproto3.NewFrontend(wireConn, wireConn)
	frontend.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters: map[string]string{
			"user":            target.User,
			"database":        target.Db,
			"client_encoding": "UTF8",
		},
	})
	if err := frontend.Flush(); err != nil {
		return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("write backend startup: %w", err)
	}

	var scram *scramClient
	scramFinalSent := false
	scramVerified := false
	authenticated := false
	for !authenticated {
		message, err := frontend.Receive()
		if err != nil {
			return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("read backend auth response: %w", err)
		}
		switch message := message.(type) {
		case *pgproto3.AuthenticationOk:
			if scram != nil && !scramVerified {
				return nil, nil, pgproto3.BackendKeyData{}, 0, errors.New("backend accepted auth without completing the SCRAM exchange")
			}
			authenticated = true

		case *pgproto3.AuthenticationCleartextPassword:
			frontend.Send(&pgproto3.PasswordMessage{Password: target.Password})
			if err := frontend.Flush(); err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("write backend cleartext password: %w", err)
			}

		case *pgproto3.AuthenticationMD5Password:
			frontend.Send(&pgproto3.PasswordMessage{Password: md5Password(target.User, target.Password, message.Salt)})
			if err := frontend.Flush(); err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("write backend md5 password: %w", err)
			}

		case *pgproto3.AuthenticationSASL:
			if scram != nil || !containsString(message.AuthMechanisms, "SCRAM-SHA-256") {
				return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("backend offered no usable SCRAM-SHA-256 mechanism: %v", message.AuthMechanisms)
			}
			scram, err = newScramClient(target.Password)
			if err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("create SCRAM client: %w", err)
			}
			frontend.Send(&pgproto3.SASLInitialResponse{
				AuthMechanism: "SCRAM-SHA-256",
				Data:          scram.clientFirstMessage(),
			})
			if err := frontend.Flush(); err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("write backend SCRAM initial response: %w", err)
			}

		case *pgproto3.AuthenticationSASLContinue:
			if scram == nil || scramFinalSent {
				return nil, nil, pgproto3.BackendKeyData{}, 0, errors.New("unexpected SASLContinue from backend")
			}
			if err := scram.recvServerFirstMessage(message.Data); err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("SCRAM exchange failed: %w", err)
			}
			final, err := scram.clientFinalMessage()
			if err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("SCRAM exchange failed: %w", err)
			}
			scramFinalSent = true
			frontend.Send(&pgproto3.SASLResponse{Data: final})
			if err := frontend.Flush(); err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("write backend SCRAM final response: %w", err)
			}

		case *pgproto3.AuthenticationSASLFinal:
			if scram == nil || !scramFinalSent || scramVerified {
				return nil, nil, pgproto3.BackendKeyData{}, 0, errors.New("unexpected SASLFinal from backend")
			}
			if err := scram.verifyServerFinal(message.Data); err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, err
			}
			scramVerified = true

		case *pgproto3.ErrorResponse:
			return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("backend auth failed: %s", message.Message)

		case *pgproto3.NoticeResponse:
			// Notices during service-account authentication have no authenticated frontend recipient.

		default:
			return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("unexpected backend auth message %T", message)
		}
	}

	var parameters []pgproto3.ParameterStatus
	var keyData pgproto3.BackendKeyData
	for {
		message, err := frontend.Receive()
		if err != nil {
			return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("read backend startup response: %w", err)
		}
		switch message := message.(type) {
		case *pgproto3.ParameterStatus:
			parameters = append(parameters, pgproto3.ParameterStatus{Name: message.Name, Value: message.Value})
		case *pgproto3.BackendKeyData:
			keyData = pgproto3.BackendKeyData{ProcessID: message.ProcessID, SecretKey: message.SecretKey}
		case *pgproto3.ReadyForQuery:
			if err := validateStartupParameters(parameters); err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, err
			}
			if err := conn.SetDeadline(time.Time{}); err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("clear backend auth deadline: %w", err)
			}
			keep = true
			return conn, parameters, keyData, message.TxStatus, nil
		case *pgproto3.ErrorResponse:
			return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("backend startup failed: %s", message.Message)
		case *pgproto3.NoticeResponse:
			// Ignore pre-ready notices; client authentication has not completed yet.
		default:
			return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("unexpected backend startup message %T", message)
		}
	}
}

func validateStartupParameters(parameters []pgproto3.ParameterStatus) error {
	sawEncoding := false
	sawStdStrings := false
	for _, parameter := range parameters {
		switch parameter.Name {
		case "client_encoding":
			sawEncoding = true
			if !strings.EqualFold(parameter.Value, "UTF8") {
				return fmt.Errorf("unsafe backend startup client_encoding %q: %w", parameter.Value, errClientEncoding)
			}
		case "standard_conforming_strings":
			sawStdStrings = true
			if !strings.EqualFold(parameter.Value, "on") {
				return fmt.Errorf("unsafe backend startup standard_conforming_strings %q: %w", parameter.Value, errStdConformingStrings)
			}
		}
	}
	if !sawEncoding {
		return fmt.Errorf("backend did not report client_encoding at startup: %w", errClientEncoding)
	}
	if !sawStdStrings {
		return fmt.Errorf("backend did not report standard_conforming_strings at startup: %w", errStdConformingStrings)
	}
	return nil
}

func md5Password(user, password string, salt [4]byte) string {
	first := md5.Sum([]byte(password + user))
	firstHex := hex.EncodeToString(first[:])
	secondInput := append([]byte(firstHex), salt[:]...)
	second := md5.Sum(secondInput)
	return "md5" + hex.EncodeToString(second[:])
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (c *sessionCore) probeNamespace() ([]string, error) {
	rows, err := c.runProbe(c.db.NamespaceProbeSQL(), 1, false)
	if err != nil {
		return nil, fmt.Errorf("backend namespace probe: %w", err)
	}
	return namespaceFromRows(rows)
}

func namespaceFromRows(rows [][]*string) ([]string, error) {
	schemas := make([]string, 0, len(rows))
	for _, row := range rows {
		if len(row) != 1 || row[0] == nil {
			return nil, errors.New("namespace probe returned a malformed row")
		}
		schemas = append(schemas, *row[0])
	}
	return schemas, nil
}

func (c *sessionCore) probeTempColumns() ([]engine.TempColumn, error) {
	rows, err := c.runProbe(c.db.TempColumnsProbeSQL(), 5, false)
	if err != nil {
		return nil, fmt.Errorf("backend temp-column probe: %w", err)
	}
	return tempColumnsFromRows(rows)
}

func tempColumnsFromRows(rows [][]*string) ([]engine.TempColumn, error) {
	columns := make([]engine.TempColumn, 0, len(rows))
	for _, row := range rows {
		if len(row) != 5 || row[0] == nil || row[1] == nil || row[2] == nil || row[3] == nil || row[4] == nil {
			return nil, errors.New("temp-column probe returned a malformed row")
		}
		ordinal, err := strconv.Atoi(*row[4])
		if err != nil {
			return nil, fmt.Errorf("temp-column probe returned invalid ordinal %q", *row[4])
		}
		columns = append(columns, engine.TempColumn{
			Schema:  *row[0],
			Table:   *row[1],
			Column:  *row[2],
			SqlType: *row[3],
			Ordinal: ordinal,
		})
	}
	return columns, nil
}

func (c *sessionCore) runProbe(sql string, expectedColumns int, quiet bool) ([][]*string, error) {
	c.backend.Send(&pgproto3.Query{String: sql})
	return c.collectProbe(expectedColumns, quiet)
}

func (c *sessionCore) collectProbe(expectedColumns int, quiet bool) ([][]*string, error) {
	if err := c.backend.Flush(); err != nil {
		return nil, err
	}
	result := engine.StatementResult{Rows: make([][]*string, 0)}
	collector := rowsCollector{expected: expectedColumns, result: &result}
	emit := collector.emit
	if !quiet && c.forward != nil {
		emit = func(message pgproto3.BackendMessage) error {
			switch message.(type) {
			case *pgproto3.ParameterStatus, *pgproto3.NoticeResponse, *pgproto3.NotificationResponse:
				c.forward(message)
			case *pgproto3.ReadyForQuery:
				if c.flushForward != nil {
					return c.flushForward()
				}
			}
			return collector.emit(message)
		}
	}
	backendErr, streamErr := c.streamResult(nil, streamOpts{soft: true}, emit)
	if err := firstErr(streamErr, collector.failed, backendErr); err != nil {
		return nil, err
	}
	return result.Rows, nil
}

func (c *sessionCore) authzInput(sql, token, clientAddr string, connectionID []byte, runCommands func([]*pb.Refetch) error) engine.AuthzInput {
	if c.pendingDirty && c.lastTxStatus != 'E' {
		c.qe.MarkNamespaceDirty()
		c.pendingDirty = false
	}
	return engine.AuthzInput{
		SQL:          sql,
		Token:        token,
		ClientAddr:   clientAddr,
		ConnectionID: connectionID,
		RunCommands:  runCommands,
		ProbeNamespace: func() (engine.NamespaceProbe, error) {
			// Postgres never reports MySQLAnsiQuotes: it has no ANSI_QUOTES mode, and its string-lexing
			// divergence (standard_conforming_strings) fails the connection closed at the relay instead.
			if c.lastTxStatus == 'E' {
				return engine.NamespaceProbe{Namespace: c.namespaceOverlay}, nil
			}
			namespace, err := c.probeNamespace()
			if err == nil {
				c.namespaceOverlay = namespace
			}
			return engine.NamespaceProbe{Namespace: namespace}, err
		},
		ProbeTempColumns: func() ([]engine.TempColumn, error) {
			if c.lastTxStatus == 'E' {
				return c.tempOverlay, nil
			}
			temps, err := c.probeTempColumns()
			if err == nil {
				c.tempOverlay = temps
			}
			return temps, err
		},
	}
}

func (s *Server) refetcher(sess *session, extended bool) *engine.Refetcher {
	probe := func(sql string, expectedColumns int) ([][]*string, error) {
		return sess.sessionCore.runProbe(sql, expectedColumns, false)
	}
	if extended {
		probe = func(sql string, expectedColumns int) ([][]*string, error) {
			return s.runExtendedProbe(sess, sql, expectedColumns)
		}
	}
	return engine.NewRefetcher(s.db, sess.connectionID, sess.backendGen, probe, s.client.PushSchemaFragment, sess.inTransaction)
}

func (s *Server) quietRefetcher(sess *session) *engine.Refetcher {
	return engine.NewRefetcher(s.db, sess.connectionID, sess.backendGen, func(sql string, expectedColumns int) ([][]*string, error) {
		return sess.sessionCore.runProbe(sql, expectedColumns, true)
	}, s.client.PushSchemaFragment, sess.inTransaction)
}

func (s *Server) forwardCancelRequest(message *pgproto3.CancelRequest) {
	if err := sendCancelRequest(s.backend.Host, s.backend.Port, message.ProcessID, message.SecretKey); err != nil {
		slog.Warn("postgres CancelRequest forward failed", "host", s.backend.Host, "port", s.backend.Port, "error", err)
	}
}

func sendCancelRequest(host string, port int, processID, secretKey uint32) error {
	request := &pgproto3.CancelRequest{ProcessID: processID, SecretKey: secretKey}
	encoded, err := request.Encode(nil)
	if err != nil {
		return fmt.Errorf("encode CancelRequest: %w", err)
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), backendHandshakeTimeout)
	if err != nil {
		return fmt.Errorf("dial backend for cancel: %w", err)
	}
	defer conn.Close()
	if err := conn.SetWriteDeadline(time.Now().Add(socketWriteTimeout)); err != nil {
		return fmt.Errorf("set cancel write deadline: %w", err)
	}
	if _, err := conn.Write(encoded); err != nil {
		return fmt.Errorf("write CancelRequest: %w", err)
	}
	return nil
}
