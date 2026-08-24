package pgproxy

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
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
	"github.com/ridi-oss/proxy-monster/goproxy/wire"
)

const targetDbHandshakeTimeout = 10 * time.Second

// dialTargetDbAuth honors ctx for the whole handshake: DialContext aborts the connect, and while the
// (deadline-bounded) auth exchange runs, an AfterFunc closes the conn on cancel so a blocked read unwinds at
// once. On the run path ctx is the target-DB open context, so a run the control-plane already closed does not
// finish a target-DB handshake nobody is waiting for; the wire path passes a background ctx (never cancelled).
func dialTargetDbAuth(ctx context.Context, target spi.TargetDb) (net.Conn, []pgproto3.ParameterStatus, pgproto3.BackendKeyData, byte, error) {
	dialer := net.Dialer{Timeout: targetDbHandshakeTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
	if err != nil {
		return nil, nil, pgproto3.BackendKeyData{}, 0, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = conn.Close()
		}
	}()
	defer context.AfterFunc(ctx, func() { _ = conn.Close() })()
	if err := conn.SetDeadline(time.Now().Add(targetDbHandshakeTimeout)); err != nil {
		return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("set target-DB auth deadline: %w", err)
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
		return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("write target-DB startup: %w", err)
	}

	var scram *scramClient
	scramFinalSent := false
	scramVerified := false
	authenticated := false
	for !authenticated {
		message, err := frontend.Receive()
		if err != nil {
			return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("read target-DB auth response: %w", err)
		}
		switch message := message.(type) {
		case *pgproto3.AuthenticationOk:
			if scram != nil && !scramVerified {
				return nil, nil, pgproto3.BackendKeyData{}, 0, errors.New("target DB accepted auth without completing the SCRAM exchange")
			}
			authenticated = true

		case *pgproto3.AuthenticationCleartextPassword:
			frontend.Send(&pgproto3.PasswordMessage{Password: target.Password})
			if err := frontend.Flush(); err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("write target DB cleartext password: %w", err)
			}

		case *pgproto3.AuthenticationMD5Password:
			frontend.Send(&pgproto3.PasswordMessage{Password: md5Password(target.User, target.Password, message.Salt)})
			if err := frontend.Flush(); err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("write target DB md5 password: %w", err)
			}

		case *pgproto3.AuthenticationSASL:
			if scram != nil || !containsString(message.AuthMechanisms, "SCRAM-SHA-256") {
				return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("target DB offered no usable SCRAM-SHA-256 mechanism: %v", message.AuthMechanisms)
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
				return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("write target DB SCRAM initial response: %w", err)
			}

		case *pgproto3.AuthenticationSASLContinue:
			if scram == nil || scramFinalSent {
				return nil, nil, pgproto3.BackendKeyData{}, 0, errors.New("unexpected SASLContinue from target DB")
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
				return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("write target DB SCRAM final response: %w", err)
			}

		case *pgproto3.AuthenticationSASLFinal:
			if scram == nil || !scramFinalSent || scramVerified {
				return nil, nil, pgproto3.BackendKeyData{}, 0, errors.New("unexpected SASLFinal from target DB")
			}
			if err := scram.verifyServerFinal(message.Data); err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, err
			}
			scramVerified = true

		case *pgproto3.ErrorResponse:
			return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("target-DB auth failed: %s", message.Message)

		case *pgproto3.NoticeResponse:
			// Notices during service-account authentication have no authenticated frontend recipient.

		default:
			return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("unexpected target-DB auth message %T", message)
		}
	}

	var parameters []pgproto3.ParameterStatus
	var keyData pgproto3.BackendKeyData
	for {
		message, err := frontend.Receive()
		if err != nil {
			return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("read target-DB startup response: %w", err)
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
				return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("clear target-DB auth deadline: %w", err)
			}
			keep = true
			return conn, parameters, keyData, message.TxStatus, nil
		case *pgproto3.ErrorResponse:
			return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("target-DB startup failed: %s", message.Message)
		case *pgproto3.NoticeResponse:
			// Ignore pre-ready notices; client authentication has not completed yet.
		default:
			return nil, nil, pgproto3.BackendKeyData{}, 0, fmt.Errorf("unexpected target-DB startup message %T", message)
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
				return fmt.Errorf("unsafe target-DB startup client_encoding %q: %w", parameter.Value, errClientEncoding)
			}
		case "standard_conforming_strings":
			sawStdStrings = true
			if !strings.EqualFold(parameter.Value, "on") {
				return fmt.Errorf("unsafe target-DB startup standard_conforming_strings %q: %w", parameter.Value, errStdConformingStrings)
			}
		}
	}
	if !sawEncoding {
		return fmt.Errorf("target DB did not report client_encoding at startup: %w", errClientEncoding)
	}
	if !sawStdStrings {
		return fmt.Errorf("target DB did not report standard_conforming_strings at startup: %w", errStdConformingStrings)
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

func (c *sessionCore) probeNamespace() (engine.NamespaceProbe, error) {
	rows, err := c.runProbe(c.db.NamespaceProbeSQL(), 1, false)
	if err != nil {
		return engine.NamespaceProbe{}, fmt.Errorf("target-DB namespace probe: %w", err)
	}
	return namespaceProbeFromRows(rows)
}

type postgresNamespaceObservation struct {
	SearchPath          []string `json:"search_path"`
	ShadowedFunctions   []string `json:"shadowed_functions"`
	PgCatalogXIDVisible *bool    `json:"pg_catalog_xid_visible"`
}

func namespaceProbeFromRows(rows [][]*string) (engine.NamespaceProbe, error) {
	if len(rows) != 1 || len(rows[0]) != 1 || rows[0][0] == nil {
		return engine.NamespaceProbe{}, errors.New("namespace probe returned a malformed result")
	}
	var observed postgresNamespaceObservation
	if err := json.Unmarshal([]byte(*rows[0][0]), &observed); err != nil {
		return engine.NamespaceProbe{}, fmt.Errorf("namespace probe returned invalid JSON: %w", err)
	}
	seen := make(map[string]bool, len(observed.ShadowedFunctions))
	for _, name := range observed.ShadowedFunctions {
		if name == "" || name != strings.ToLower(name) || seen[name] {
			return engine.NamespaceProbe{}, fmt.Errorf("namespace probe returned invalid shadowed function %q", name)
		}
		seen[name] = true
	}
	return engine.NamespaceProbe{
		Namespace:                         observed.SearchPath,
		PostgresShadowedFunctions:         observed.ShadowedFunctions,
		PostgresFunctionShadowingObserved: true,
		PostgresSystemXIDVisible:          observed.PgCatalogXIDVisible != nil && *observed.PgCatalogXIDVisible,
		PostgresTypeVisibilityObserved:    observed.PgCatalogXIDVisible != nil,
	}, nil
}

func (c *sessionCore) probeTempColumns() ([]engine.TempColumn, error) {
	rows, err := c.runProbe(c.db.TempColumnsProbeSQL(), 5, false)
	if err != nil {
		return nil, fmt.Errorf("target DB temp-column probe: %w", err)
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
	c.targetDb.Send(&pgproto3.Query{String: sql})
	return c.collectProbe(expectedColumns, quiet)
}

func (c *sessionCore) collectProbe(expectedColumns int, quiet bool) ([][]*string, error) {
	if err := c.targetDb.Flush(); err != nil {
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
	targetDbErr, streamErr := c.streamResult(nil, streamOpts{soft: true}, emit)
	if err := firstErr(streamErr, collector.failed, targetDbErr); err != nil {
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
				return engine.NamespaceProbe{
					Namespace:                         append([]string{}, c.namespaceOverlay...),
					PostgresShadowedFunctions:         append([]string{}, c.shadowedFunctions...),
					PostgresFunctionShadowingObserved: c.functionShadowingObserved,
					PostgresSystemXIDVisible:          c.postgresSystemXIDVisible,
					PostgresTypeVisibilityObserved:    c.typeVisibilityObserved,
				}, nil
			}
			probe, err := c.probeNamespace()
			if err == nil {
				c.namespaceOverlay = append([]string{}, probe.Namespace...)
				c.shadowedFunctions = append([]string{}, probe.PostgresShadowedFunctions...)
				c.functionShadowingObserved = probe.PostgresFunctionShadowingObserved
				c.postgresSystemXIDVisible = probe.PostgresSystemXIDVisible
				c.typeVisibilityObserved = probe.PostgresTypeVisibilityObserved
			}
			return probe, err
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
	return engine.NewRefetcher(s.db, sess.connectionID, sess.backendGen, probe, s.client.PushSchemaFragment)
}

func (s *Server) quietRefetcher(sess *session) *engine.Refetcher {
	return engine.NewRefetcher(s.db, sess.connectionID, sess.backendGen, func(sql string, expectedColumns int) ([][]*string, error) {
		return sess.sessionCore.runProbe(sql, expectedColumns, true)
	}, s.client.PushSchemaFragment)
}

func (s *Server) forwardCancelRequest(message *pgproto3.CancelRequest) {
	if err := sendCancelRequest(s.targetDb.Host, s.targetDb.Port, message.ProcessID, message.SecretKey); err != nil {
		slog.Warn("postgres CancelRequest forward failed", "host", s.targetDb.Host, "port", s.targetDb.Port, "error", err)
	}
}

func sendCancelRequest(host string, port int, processID uint32, secretKey []byte) error {
	request := &pgproto3.CancelRequest{ProcessID: processID, SecretKey: secretKey}
	encoded, err := request.Encode(nil)
	if err != nil {
		return fmt.Errorf("encode CancelRequest: %w", err)
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), targetDbHandshakeTimeout)
	if err != nil {
		return fmt.Errorf("dial target DB for cancel: %w", err)
	}
	defer conn.Close()
	if err := conn.SetWriteDeadline(time.Now().Add(wire.SocketWriteTimeout)); err != nil {
		return fmt.Errorf("set cancel write deadline: %w", err)
	}
	if _, err := conn.Write(encoded); err != nil {
		return fmt.Errorf("write CancelRequest: %w", err)
	}
	return nil
}
