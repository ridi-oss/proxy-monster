package postgres

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/spi"

	"github.com/jackc/pgx/v5/pgproto3"
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/wire"
)

const targetDbHandshakeTimeout = 10 * time.Second

// dialTargetDbAuth honors ctx for the whole handshake: DialContext aborts the connect, and while the
// (deadline-bounded) auth exchange runs, an AfterFunc closes the conn on cancel so a blocked read unwinds at
// once. On the run path ctx is the target-DB open context, so a run the control-plane already closed does not
// finish a target-DB handshake nobody is waiting for; the wire path passes a background ctx (never cancelled).
func dialTargetDbAuth(ctx context.Context, config spi.TargetConfig) (net.Conn, []pgproto3.ParameterStatus, pgproto3.BackendKeyData, byte, string, error) {
	return dialTargetDbAuthParams(ctx, config, nil)
}

// dialTargetDbAuthParams adds extra startup parameters; the server applies them as session settings.
func dialTargetDbAuthParams(ctx context.Context, config spi.TargetConfig, extra map[string]string) (net.Conn, []pgproto3.ParameterStatus, pgproto3.BackendKeyData, byte, string, error) {
	dialer := net.Dialer{Timeout: targetDbHandshakeTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(config.Host, strconv.Itoa(config.Port)))
	if err != nil {
		return nil, nil, pgproto3.BackendKeyData{}, 0, "", err
	}
	keep := false
	defer func() {
		if !keep {
			_ = conn.Close()
		}
	}()
	socket := conn
	defer context.AfterFunc(ctx, func() { _ = socket.Close() })()
	if err := conn.SetDeadline(time.Now().Add(targetDbHandshakeTimeout)); err != nil {
		return nil, nil, pgproto3.BackendKeyData{}, 0, "", fmt.Errorf("set target-DB auth deadline: %w", err)
	}
	secured, err := startTargetDbTLS(ctx, conn, config.TLS)
	if err != nil {
		return nil, nil, pgproto3.BackendKeyData{}, 0, "", err
	}
	conn = secured

	wireConn := &switchConn{Conn: conn, strictReads: true}
	frontend := pgproto3.NewFrontend(wireConn, wireConn)
	startup := map[string]string{
		"user":            config.User,
		"database":        config.Db,
		"client_encoding": "UTF8",
	}
	for key, value := range extra {
		startup[key] = value
	}
	frontend.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      startup,
	})
	if err := frontend.Flush(); err != nil {
		return nil, nil, pgproto3.BackendKeyData{}, 0, "", fmt.Errorf("write target-DB startup: %w", err)
	}

	var scram *scramClient
	scramFinalSent := false
	scramVerified := false
	authenticated := false
	for !authenticated {
		message, err := frontend.Receive()
		if err != nil {
			return nil, nil, pgproto3.BackendKeyData{}, 0, "", fmt.Errorf("read target-DB auth response: %w", err)
		}
		switch message := message.(type) {
		case *pgproto3.AuthenticationOk:
			if scram != nil && !scramVerified {
				return nil, nil, pgproto3.BackendKeyData{}, 0, "", errors.New("target DB accepted auth without completing the SCRAM exchange")
			}
			authenticated = true

		case *pgproto3.AuthenticationCleartextPassword:
			frontend.Send(&pgproto3.PasswordMessage{Password: config.Password})
			if err := frontend.Flush(); err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, "", fmt.Errorf("write target DB cleartext password: %w", err)
			}

		case *pgproto3.AuthenticationMD5Password:
			frontend.Send(&pgproto3.PasswordMessage{Password: md5Password(config.User, config.Password, message.Salt)})
			if err := frontend.Flush(); err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, "", fmt.Errorf("write target DB md5 password: %w", err)
			}

		case *pgproto3.AuthenticationSASL:
			if scram != nil || !containsString(message.AuthMechanisms, "SCRAM-SHA-256") {
				return nil, nil, pgproto3.BackendKeyData{}, 0, "", fmt.Errorf("target DB offered no usable SCRAM-SHA-256 mechanism: %v", message.AuthMechanisms)
			}
			scram, err = newScramClient(config.Password)
			if err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, "", fmt.Errorf("create SCRAM client: %w", err)
			}
			frontend.Send(&pgproto3.SASLInitialResponse{
				AuthMechanism: "SCRAM-SHA-256",
				Data:          scram.clientFirstMessage(),
			})
			if err := frontend.Flush(); err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, "", fmt.Errorf("write target DB SCRAM initial response: %w", err)
			}

		case *pgproto3.AuthenticationSASLContinue:
			if scram == nil || scramFinalSent {
				return nil, nil, pgproto3.BackendKeyData{}, 0, "", errors.New("unexpected SASLContinue from target DB")
			}
			if err := scram.recvServerFirstMessage(message.Data); err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, "", fmt.Errorf("SCRAM exchange failed: %w", err)
			}
			final, err := scram.clientFinalMessage()
			if err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, "", fmt.Errorf("SCRAM exchange failed: %w", err)
			}
			scramFinalSent = true
			frontend.Send(&pgproto3.SASLResponse{Data: final})
			if err := frontend.Flush(); err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, "", fmt.Errorf("write target DB SCRAM final response: %w", err)
			}

		case *pgproto3.AuthenticationSASLFinal:
			if scram == nil || !scramFinalSent || scramVerified {
				return nil, nil, pgproto3.BackendKeyData{}, 0, "", errors.New("unexpected SASLFinal from target DB")
			}
			if err := scram.verifyServerFinal(message.Data); err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, "", err
			}
			scramVerified = true

		case *pgproto3.ErrorResponse:
			return nil, nil, pgproto3.BackendKeyData{}, 0, "", fmt.Errorf("target-DB auth failed: %s", message.Message)

		case *pgproto3.NoticeResponse:
			// Notices during service-account authentication have no authenticated frontend recipient.

		default:
			return nil, nil, pgproto3.BackendKeyData{}, 0, "", fmt.Errorf("unexpected target-DB auth message %T", message)
		}
	}

	var parameters []pgproto3.ParameterStatus
	var keyData pgproto3.BackendKeyData
	for {
		message, err := frontend.Receive()
		if err != nil {
			return nil, nil, pgproto3.BackendKeyData{}, 0, "", fmt.Errorf("read target-DB startup response: %w", err)
		}
		switch message := message.(type) {
		case *pgproto3.ParameterStatus:
			parameters = append(parameters, pgproto3.ParameterStatus{Name: message.Name, Value: message.Value})
		case *pgproto3.BackendKeyData:
			keyData = pgproto3.BackendKeyData{ProcessID: message.ProcessID, SecretKey: message.SecretKey}
		case *pgproto3.ReadyForQuery:
			if err := validateStartupParameters(parameters); err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, "", err
			}
			c := connection{targetDb: frontend, lastTxStatus: message.TxStatus}
			catalog, err := c.probeCurrentCatalog()
			if err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, "", err
			}
			if err := conn.SetDeadline(time.Time{}); err != nil {
				return nil, nil, pgproto3.BackendKeyData{}, 0, "", fmt.Errorf("clear target-DB auth deadline: %w", err)
			}
			keep = true
			return conn, parameters, keyData, c.lastTxStatus, catalog, nil
		case *pgproto3.ErrorResponse:
			return nil, nil, pgproto3.BackendKeyData{}, 0, "", fmt.Errorf("target-DB startup failed: %s", message.Message)
		case *pgproto3.NoticeResponse:
			// Ignore pre-ready notices; client authentication has not completed yet.
		default:
			return nil, nil, pgproto3.BackendKeyData{}, 0, "", fmt.Errorf("unexpected target-DB startup message %T", message)
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

// probeCurrentCatalog runs once at connect; a Postgres session cannot change its database afterwards.
func (c *connection) probeCurrentCatalog() (string, error) {
	rows, err := c.runProbe("SELECT pg_catalog.current_database()", 1)
	if err != nil {
		return "", fmt.Errorf("target-DB catalog probe: %w", err)
	}
	if len(rows) != 1 || len(rows[0]) != 1 || rows[0][0] == nil || *rows[0][0] == "" {
		return "", errors.New("target-DB catalog probe returned no current database")
	}
	return *rows[0][0], nil
}

func (c *connection) probeSession() (spi.SessionSnapshot, error) {
	rows, err := c.runProbe(namespaceProbeSQL, 1)
	if err != nil {
		return spi.SessionSnapshot{}, fmt.Errorf("target-DB namespace probe: %w", err)
	}
	snapshot, err := snapshotFromRows(rows)
	snapshot.CurrentCatalog = c.currentCatalog
	return snapshot, err
}

type postgresNamespaceObservation struct {
	SearchPath          []string `json:"search_path"`
	ShadowedFunctions   []string `json:"shadowed_functions"`
	PgCatalogXIDVisible *bool    `json:"pg_catalog_xid_visible"`
}

func snapshotFromRows(rows [][]*string) (spi.SessionSnapshot, error) {
	if len(rows) != 1 || len(rows[0]) != 1 || rows[0][0] == nil {
		return spi.SessionSnapshot{}, errors.New("namespace probe returned a malformed result")
	}
	var observed postgresNamespaceObservation
	decoder := json.NewDecoder(strings.NewReader(*rows[0][0]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&observed); err != nil {
		return spi.SessionSnapshot{}, fmt.Errorf("namespace probe returned invalid JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return spi.SessionSnapshot{}, errors.New("namespace probe returned trailing JSON")
	}
	seen := make(map[string]bool, len(observed.ShadowedFunctions))
	for _, name := range observed.ShadowedFunctions {
		if name == "" || name != strings.ToLower(name) || seen[name] {
			return spi.SessionSnapshot{}, fmt.Errorf("namespace probe returned invalid shadowed function %q", name)
		}
		seen[name] = true
	}
	return spi.SessionSnapshot{
		Namespace: observed.SearchPath,
		SessionObservation: &enginepb.SessionObservation{Engine: &enginepb.SessionObservation_Postgres{Postgres: &enginepb.PostgresSession{
			ShadowedFunctions:         observed.ShadowedFunctions,
			FunctionShadowingObserved: observed.ShadowedFunctions != nil,
			SystemXidVisible:          observed.PgCatalogXIDVisible,
		}}},
	}, nil
}

func (c *connection) probeTempColumns() ([]spi.TempColumn, error) {
	rows, err := c.runProbe(tempColumnsProbeSQL, 6)
	if err != nil {
		return nil, fmt.Errorf("target DB temp-column probe: %w", err)
	}
	return tempColumnsFromRows(rows)
}

func tempColumnsFromRows(rows [][]*string) ([]spi.TempColumn, error) {
	columns := make([]spi.TempColumn, 0, len(rows))
	for _, row := range rows {
		if len(row) != 6 || row[0] == nil || row[1] == nil || row[2] == nil || row[3] == nil || row[4] == nil || row[5] == nil {
			return nil, errors.New("temp-column probe returned a malformed row")
		}
		ordinal, err := strconv.Atoi(*row[4])
		if err != nil {
			return nil, fmt.Errorf("temp-column probe returned invalid ordinal %q", *row[4])
		}
		columns = append(columns, spi.TempColumn{
			Catalog: *row[5],
			Schema:  *row[0],
			Table:   *row[1],
			Column:  *row[2],
			SqlType: *row[3],
			Ordinal: ordinal,
		})
	}
	return columns, nil
}

func (c *connection) runProbe(sql string, expectedColumns int) ([][]*string, error) {
	c.targetDb.Send(&pgproto3.Query{String: sql})
	return c.collectProbe(expectedColumns)
}

func (c *connection) collectProbe(expectedColumns int) ([][]*string, error) {
	if err := c.targetDb.Flush(); err != nil {
		return nil, err
	}
	result := spi.StatementResult{Rows: make([][]*string, 0)}
	collector := rowsCollector{expected: expectedColumns, result: &result}
	emit := collector.emit
	if c.forward != nil {
		emit = func(message pgproto3.BackendMessage, rowBytes int64) error {
			switch message.(type) {
			case *pgproto3.ParameterStatus, *pgproto3.NoticeResponse, *pgproto3.NotificationResponse:
				c.forward(message)
			case *pgproto3.ReadyForQuery:
				if c.flushForward != nil {
					return c.flushForward()
				}
			}
			return collector.emit(message, rowBytes)
		}
	}
	targetDbErr, streamErr := c.streamResult(nil, streamOpts{soft: true}, emit)
	if err := firstErr(streamErr, collector.failed, targetDbErr); err != nil {
		return nil, err
	}
	return result.Rows, nil
}

func (c *connection) authzInput(sql string, commandRunner spi.ProxyCommandRunner) spi.AuthzInput {
	// In an aborted transaction the probe below returns the session's last snapshot instead of querying.
	if c.pendingDirty {
		c.authz.MarkNamespaceDirty()
		c.pendingDirty = false
	}
	return spi.AuthzInput{
		SQL:      sql,
		Commands: commandRunner,
		ProbeSession: func() (spi.SessionSnapshot, error) {
			// Postgres never reports MysqlAnsiQuotes: it has no ANSI_QUOTES mode, and its string-lexing
			// divergence (standard_conforming_strings) fails the connection closed at the relay instead.
			if c.lastTxStatus == 'E' {
				return c.authz.Snapshot(), nil
			}
			return c.probeSession()
		},
		ProbeTempColumns: func() ([]spi.TempColumn, error) {
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

func (s *Server) forwardCancelRequest(message *pgproto3.CancelRequest) {
	if err := sendCancelRequest(s.target.config, message.ProcessID, message.SecretKey); err != nil {
		slog.Warn("postgres CancelRequest forward failed", "host", s.target.config.Host, "port", s.target.config.Port, "error", err)
	}
}

// startTargetDbTLS runs the SSLRequest exchange and returns the TLS-wrapped conn; a nil config leaves conn as is.
func startTargetDbTLS(ctx context.Context, conn net.Conn, config *tls.Config) (net.Conn, error) {
	if config == nil {
		return conn, nil
	}
	request, err := (&pgproto3.SSLRequest{}).Encode(nil)
	if err != nil {
		return nil, fmt.Errorf("encode SSLRequest: %w", err)
	}
	if _, err := conn.Write(request); err != nil {
		return nil, fmt.Errorf("write target-DB SSLRequest: %w", err)
	}
	// Exactly one byte: anything past it belongs to the TLS handshake.
	answer := make([]byte, 1)
	if _, err := io.ReadFull(conn, answer); err != nil {
		return nil, fmt.Errorf("read target-DB SSLRequest answer: %w", err)
	}
	if answer[0] != 'S' {
		return nil, fmt.Errorf("target DB refused TLS (SSLRequest answered %q)", answer[0])
	}
	tlsConn := tls.Client(conn, config)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("target-DB TLS handshake: %w", err)
	}
	return tlsConn, nil
}

func sendCancelRequest(config spi.TargetConfig, processID uint32, secretKey []byte) error {
	request := &pgproto3.CancelRequest{ProcessID: processID, SecretKey: secretKey}
	encoded, err := request.Encode(nil)
	if err != nil {
		return fmt.Errorf("encode CancelRequest: %w", err)
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(config.Host, strconv.Itoa(config.Port)), targetDbHandshakeTimeout)
	if err != nil {
		return fmt.Errorf("dial target DB for cancel: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(targetDbHandshakeTimeout)); err != nil {
		return fmt.Errorf("set cancel handshake deadline: %w", err)
	}
	secured, err := startTargetDbTLS(context.Background(), conn, config.TLS)
	if err != nil {
		return err
	}
	conn = secured
	if err := conn.SetWriteDeadline(time.Now().Add(wire.SocketWriteTimeout)); err != nil {
		return fmt.Errorf("set cancel write deadline: %w", err)
	}
	if _, err := conn.Write(encoded); err != nil {
		return fmt.Errorf("write CancelRequest: %w", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(targetDbHandshakeTimeout)); err != nil {
		return err
	}
	// Wait for the cancel connection to close before the held session can start another query.
	_, err = io.Copy(io.Discard, conn)
	return err
}
