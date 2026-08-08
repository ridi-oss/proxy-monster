package pgproxy

import (
	"crypto/tls"
	"log/slog"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
)

const (
	frontendHandshakeTimeout = 10 * time.Second
	maxFrontendAuthBody      = 8192
	maxFrontendFrameBody     = 16 << 20
)

type sessionCore struct {
	backend          *pgproto3.Frontend
	qe               *engine.QueryEngine
	db               engine.Db
	lastTxStatus     byte
	pendingDirty     bool
	namespaceOverlay []string
	tempOverlay      []engine.TempColumn
	forward          func(pgproto3.BackendMessage)
	flushForward     func() error
}

type session struct {
	sessionCore
	client       *pgproto3.Backend
	clientConn   net.Conn
	backendConn  net.Conn
	token        string
	clientAddr   string
	connectionID []byte
	backendGen   uint64
	statements   map[string]preparedStatement
	portals      map[string]boundPortal
	skipToSync   bool
}

func (s *Server) handleConn(rawClientConn net.Conn) {
	defer rawClientConn.Close()

	var tlsConfig *tls.Config
	if s.tlsProvider != nil {
		var err error
		tlsConfig, err = s.tlsProvider()
		if err != nil {
			return
		}
	}

	clientConn := rawClientConn
	tlsActive := false
	clientIO := &switchConn{Conn: rawClientConn, strictReads: true}
	client := pgproto3.NewBackend(clientIO, clientIO)
	if err := clientConn.SetReadDeadline(time.Now().Add(frontendHandshakeTimeout)); err != nil {
		return
	}

	for {
		message, err := client.ReceiveStartupMessage()
		if err != nil {
			return
		}
		switch message := message.(type) {
		case *pgproto3.SSLRequest:
			if tlsConfig == nil {
				if _, err := clientConn.Write([]byte{'N'}); err != nil {
					return
				}
				if err := clientConn.SetReadDeadline(time.Now().Add(frontendHandshakeTimeout)); err != nil {
					return
				}
				continue
			}
			if tlsActive {
				return
			}
			if _, err := clientConn.Write([]byte{'S'}); err != nil {
				return
			}
			if err := clientConn.SetDeadline(time.Now().Add(frontendHandshakeTimeout)); err != nil {
				return
			}
			tlsConn := tls.Server(clientConn, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			if err := tlsConn.SetWriteDeadline(time.Time{}); err != nil {
				return
			}
			clientConn = tlsConn
			tlsActive = true
			clientIO.Conn = tlsConn
			if err := clientConn.SetReadDeadline(time.Now().Add(frontendHandshakeTimeout)); err != nil {
				return
			}
			continue
		case *pgproto3.GSSEncRequest:
			if _, err := clientConn.Write([]byte{'N'}); err != nil {
				return
			}
			if err := clientConn.SetReadDeadline(time.Now().Add(frontendHandshakeTimeout)); err != nil {
				return
			}
			continue
		case *pgproto3.CancelRequest:
			s.forwardCancelRequest(message)
			return
		case *pgproto3.StartupMessage:
			if tlsConfig != nil && !tlsActive {
				_ = sendError(client, "FATAL", "28000", "proxy-monster: TLS required — reconnect with sslmode=verify-full", false, 0)
				return
			}
			if _, replication := message.Parameters["replication"]; replication {
				_ = sendError(client, "FATAL", "0A000", "proxy-monster: replication protocol is not supported", false, 0)
				return
			}
			goto startupComplete
		default:
			return
		}
	}

startupComplete:
	client.Send(&pgproto3.AuthenticationCleartextPassword{})
	if err := client.Flush(); err != nil {
		return
	}
	if err := client.SetAuthType(pgproto3.AuthTypeCleartextPassword); err != nil {
		return
	}
	client.SetMaxBodyLen(maxFrontendAuthBody)
	if err := clientConn.SetReadDeadline(time.Now().Add(frontendHandshakeTimeout)); err != nil {
		return
	}
	message, err := client.Receive()
	if err != nil {
		return
	}
	password, ok := message.(*pgproto3.PasswordMessage)
	if !ok {
		_ = sendError(client, "FATAL", "08P01", "proxy-monster: expected password message", false, 0)
		return
	}
	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		return
	}

	identity, err := s.client.ValidateToken(password.Password, rawClientConn.RemoteAddr().String())
	if err != nil {
		_ = sendError(client, "FATAL", "28000", "proxy-monster: invalid or expired token", false, 0)
		return
	}
	defer func() { _ = s.client.CloseConnection(identity.ConnectionID) }()
	slog.Info("authenticated postgres client", "client", rawClientConn.RemoteAddr().String(), "principal", identity.Principal, "roles", identity.Roles)

	backendConn, parameters, keyData, txStatus, err := dialBackendAuth(s.backend)
	if err != nil {
		slog.Warn("postgres backend unavailable", "host", s.backend.Host, "port", s.backend.Port, "error", err)
		_ = sendError(client, "FATAL", "08004", "proxy-monster: backend unavailable", false, 0)
		return
	}
	defer backendConn.Close()

	client.SetMaxBodyLen(maxFrontendFrameBody)
	clientIO.Conn = withDrainAwareIODeadlines(clientConn, frontendCommandIdleTimeout, socketWriteTimeout, &s.draining)
	clientIO.strictReads = false
	backendConn = withIODeadlines(backendConn, backendResponseIdleTimeout, socketWriteTimeout)
	backend := pgproto3.NewFrontend(backendConn, backendConn)

	backendGen := backendGeneration.Add(1)
	if backendGen == 0 || backendGen > maxBackendGeneration {
		_ = sendError(client, "FATAL", "08004", "proxy-monster: backend generation unavailable", false, 0)
		return
	}
	sess := &session{
		sessionCore: sessionCore{
			backend:      backend,
			qe:           engine.NewQueryEngine(s.db, s.client),
			db:           s.db,
			lastTxStatus: txStatus,
			forward:      client.Send,
			flushForward: client.Flush,
		},
		client:       client,
		clientConn:   clientIO,
		backendConn:  backendConn,
		token:        password.Password,
		clientAddr:   rawClientConn.RemoteAddr().String(),
		connectionID: append([]byte(nil), identity.ConnectionID...),
		backendGen:   backendGen,
		statements:   make(map[string]preparedStatement),
		portals:      make(map[string]boundPortal),
	}
	if err := s.quietRefetcher(sess).RunAll(identity.OnOpen); err != nil {
		slog.Warn("postgres on-open catalog fetch failed", "error", err)
		_ = sendError(client, "FATAL", "08004", "proxy-monster: connection catalog unavailable", false, 0)
		return
	}

	client.Send(&pgproto3.AuthenticationOk{})
	for i := range parameters {
		parameter := parameters[i]
		client.Send(&parameter)
	}
	client.Send(&keyData)
	client.Send(&pgproto3.ReadyForQuery{TxStatus: txStatus})
	if err := client.Flush(); err != nil {
		return
	}

	for {
		message, err := client.Receive()
		if err != nil {
			// The single drain point. A drain forces the client read deadline, so a handler waiting here for the
			// next message unblocks and sends the FATAL shutdown notice, and its pool reconnects onto the
			// replacement task. Checking only here (not before the read) lets a Sync already decoded above the
			// socket after a completed Execute be answered with ReadyForQuery first; a Sync still in the kernel
			// read buffer is preempted by the forced deadline, so the completed Execute is rolled back on close
			// and the client reconnects and retries it (the pipelined-drain limitation in KNOWN_LIMITATIONS).
			// A plain idle-timeout or client disconnect stays a silent close.
			if s.draining.Load() {
				_ = sendShutdownNotice(client)
			}
			return
		}
		if sess.skipToSync {
			switch message.(type) {
			case *pgproto3.Sync:
				if err := s.handleSync(sess); err != nil {
					return
				}
			case *pgproto3.Terminate:
				return
			}
			continue
		}

		switch message := message.(type) {
		case *pgproto3.Query:
			if err := s.handleQuery(sess, message.String); err != nil {
				return
			}
		case *pgproto3.Parse:
			if err := s.handleParse(sess, message); err != nil {
				return
			}
		case *pgproto3.Bind:
			if err := s.handleBind(sess, message); err != nil {
				return
			}
		case *pgproto3.Describe:
			if err := s.handleDescribe(sess, message); err != nil {
				return
			}
		case *pgproto3.Execute:
			if err := s.handleExecute(sess, message); err != nil {
				return
			}
		case *pgproto3.Close:
			if err := s.handleClose(sess, message); err != nil {
				return
			}
		case *pgproto3.Flush:
			if err := s.handleFlush(sess); err != nil {
				return
			}
		case *pgproto3.Sync:
			if err := s.handleSync(sess); err != nil {
				return
			}
		case *pgproto3.FunctionCall:
			if err := sendError(client, "ERROR", "0A000", "proxy-monster: function call protocol is not supported", true, sess.lastTxStatus); err != nil {
				return
			}
		case *pgproto3.Terminate:
			return
		case *pgproto3.CopyData, *pgproto3.CopyDone, *pgproto3.CopyFail, *pgproto3.GSSResponse:
			_ = sendError(client, "ERROR", "08P01", "proxy-monster: protocol desynchronization", false, 0)
			return
		default:
			_ = sendError(client, "ERROR", "08P01", "proxy-monster: protocol desynchronization", false, 0)
			return
		}
	}
}

// sendShutdownNotice tells an idle client the proxy is going away, so its pool reconnects onto the
// replacement task instead of seeing a bare TCP reset. FATAL 57P01 (admin_shutdown) is what PostgreSQL
// itself sends on shutdown, so a driver already treats it as a reconnect signal. Best-effort: the
// connection closes regardless.
func sendShutdownNotice(client *pgproto3.Backend) error {
	return sendError(client, "FATAL", "57P01", "proxy-monster: server shutting down", false, 0)
}

func sendError(client *pgproto3.Backend, severity, code, message string, ready bool, txStatus byte) error {
	client.Send(&pgproto3.ErrorResponse{
		Severity:            severity,
		SeverityUnlocalized: severity,
		Code:                code,
		Message:             message,
	})
	if ready {
		client.Send(&pgproto3.ReadyForQuery{TxStatus: txStatus})
	}
	return client.Flush()
}
