package mysqlproxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

const (
	frontendServerVersion      = "8.0.40-proxy-monster"
	frontendHandshakeTimeout   = 15 * time.Second
	maxFrontendHandshakePacket = 64 << 10
	maxFrontendTokenPacket     = 64 << 10
)

// handleConn performs the frontend clear-password token handshake, authenticates the service-account
// backend, then runs one blocking command at a time.
func (s *Server) handleConn(clientConn net.Conn) {
	defer clientConn.Close()

	var tlsConfig *tls.Config
	if s.tlsProvider != nil {
		var err error
		tlsConfig, err = s.tlsProvider()
		if err != nil {
			return
		}
	}

	scramble, err := mysqlwire.Scramble()
	if err != nil {
		return
	}
	connID := s.connID.Add(1)
	// true: this handler relays a handshake-supplied database to the backend as COM_INIT_DB below, so
	// it is safe (and, for a real client's self-consistency, necessary) to advertise CapConnectWithDB.
	greeting := mysqlwire.ServerGreeting(connID, scramble, frontendServerVersion, true)
	if tlsConfig != nil {
		greeting = mysqlwire.ServerGreetingSSL(connID, scramble, frontendServerVersion, true)
	}
	if err := mysqlwire.WritePacket(clientConn, 0, greeting); err != nil {
		return
	}

	if err := clientConn.SetReadDeadline(time.Now().Add(frontendHandshakeTimeout)); err != nil {
		return
	}
	handshakeSeq, handshakePayload, err := mysqlwire.ReadPacketLimited(clientConn, maxFrontendHandshakePacket)
	if err != nil {
		return
	}
	if tlsConfig != nil {
		if !mysqlwire.LooksLikeSSLRequest(handshakePayload) {
			_ = mysqlwire.WritePacket(clientConn, handshakeSeq+1, mysqlwire.ErrPacketState(
				1045,
				"28000",
				"proxy-monster: TLS required — reconnect with ssl-mode=VERIFY_IDENTITY",
			))
			return
		}
		if err := clientConn.SetDeadline(time.Now().Add(frontendHandshakeTimeout)); err != nil {
			return
		}
		tlsConn := tls.Server(clientConn, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		clientConn = tlsConn
		if err := clientConn.SetWriteDeadline(time.Time{}); err != nil {
			return
		}
		if err := clientConn.SetReadDeadline(time.Now().Add(frontendHandshakeTimeout)); err != nil {
			return
		}
		handshakeSeq, handshakePayload, err = mysqlwire.ReadPacketLimited(clientConn, maxFrontendHandshakePacket)
		if err != nil {
			return
		}
	} else if mysqlwire.LooksLikeSSLRequest(handshakePayload) {
		_ = mysqlwire.WritePacket(clientConn, handshakeSeq+1, mysqlwire.ErrPacketState(
			1045,
			"28000",
			"proxy-monster: TLS not enabled on this proxy",
		))
		return
	}
	// true: this greeting advertises CapConnectWithDB (above), so a database field here is genuine —
	// not a stale bit from a client whose server never offered the capability.
	handshake, err := mysqlwire.ParseHandshakeResponse(handshakePayload, true)
	if err != nil {
		return
	}
	clientCaps := handshake.Capabilities
	deprecateEOF := clientCaps&mysqlwire.CapDeprecateEOF != 0
	if err := mysqlwire.WritePacket(clientConn, handshakeSeq+1, mysqlwire.AuthSwitchClearPassword()); err != nil {
		return
	}

	if err := clientConn.SetReadDeadline(time.Now().Add(frontendHandshakeTimeout)); err != nil {
		return
	}
	tokenSeq, tokenPayload, err := mysqlwire.ReadPacketLimited(clientConn, maxFrontendTokenPacket)
	if err != nil {
		return
	}
	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		return
	}
	clientConn = withIODeadlines(clientConn, frontendCommandIdleTimeout, socketWriteTimeout)
	token := mysqlwire.ParseClearPassword(tokenPayload)
	identity, err := s.client.ValidateToken(token)
	if err != nil {
		_ = mysqlwire.WritePacket(clientConn, tokenSeq+1, mysqlwire.ErrPacketState(
			1045,
			"28000",
			"proxy-monster: invalid or expired token",
		))
		return
	}
	defer func() {
		if err := s.client.CloseConnection(identity.ConnectionID); err != nil {
			slog.Warn("failed to close mysql control-plane connection", "error", err)
		}
	}()
	slog.Info("authenticated mysql client", "client", clientConn.RemoteAddr().String(), "principal", identity.Principal, "roles", identity.Roles)

	backendConn, err := dialBackendAuth(s.backend, deprecateEOF)
	if err != nil {
		slog.Warn("mysql backend unavailable", "host", s.backend.Host, "port", s.backend.Port, "error", err)
		_ = mysqlwire.WritePacket(clientConn, tokenSeq+1, mysqlwire.ErrPacketState(
			1045,
			"08004",
			"proxy-monster: backend unavailable",
		))
		return
	}
	backendConn = withIODeadlines(backendConn, backendResponseIdleTimeout, socketWriteTimeout)
	defer backendConn.Close()

	qe := engine.NewQueryEngine(s.db, s.client)
	preparedStmts := make(map[uint32]preparedStmt)
	clientAddr := clientConn.RemoteAddr().String()
	if handshake.Database != "" {
		// The client selected a database at connect time. Switching the current database is not a gated
		// action, so relay it mechanically to the backend as COM_INIT_DB rather than synthesizing and
		// authorizing a USE — the control plane enforces subsequent queries under the new namespace. The
		// backend's response is consumed here (the client is still awaiting the single auth result): only a
		// failure is surfaced to the client, and the auth OK written below stands in for success.
		payload := append([]byte{mysqlwire.ComInitDB}, handshake.Database...)
		result, err := executeSingleResponse(backendConn, 0, payload)
		if err != nil {
			_ = mysqlwire.WritePacket(clientConn, tokenSeq+1, mysqlwire.ErrPacketState(
				1045,
				"08004",
				"proxy-monster: backend unavailable",
			))
			return
		}
		if !result.ok {
			_ = mysqlwire.WritePacket(clientConn, tokenSeq+1, result.payload)
			return
		}
		// The current database changed; the next query re-probes the namespace.
		qe.MarkNamespaceDirty()
	}

	generation := backendGeneration.Add(1)
	if generation == 0 || generation > maxBackendGeneration {
		return
	}
	refetcher := engine.NewRefetcher(s.db, identity.ConnectionID, generation, func(sql string, expectedColumns int) ([][]*string, error) {
		return runInternalQuery(backendConn, deprecateEOF, sql, expectedColumns)
	}, s.client.PushSchemaFragment)
	if err := refetcher.RunAll(identity.OnOpen); err != nil {
		slog.Warn("mysql catalog initialization failed", "error", err)
		_ = mysqlwire.WritePacket(clientConn, tokenSeq+1, mysqlwire.ErrPacketState(
			1105,
			"HY000",
			"proxy-monster: catalog initialization failed",
		))
		return
	}

	if err := mysqlwire.WritePacket(clientConn, tokenSeq+1, mysqlwire.OKPacket()); err != nil {
		return
	}
	for {
		// A physical payload of exactly MaxPacketPayload always has a continuation. Reject it from the
		// header before allocating or reading its body: this broker cannot safely authorize a prefix or
		// infer arbitrary command framing while a continuation remains pending.
		seq, payload, err := mysqlwire.ReadPacketLimited(clientConn, maxPacketPayload-1)
		if errors.Is(err, mysqlwire.ErrPacketTooLarge) {
			_ = mysqlwire.WritePacket(clientConn, seq+1, mysqlwire.ErrPacketState(
				1235,
				"42000",
				"proxy-monster: multi-packet commands not yet supported by proxy-monster (go)",
			))
			return
		}
		if err != nil || len(payload) == 0 {
			return
		}
		cmd := payload[0]
		switch cmd {
		case mysqlwire.ComQuit:
			_ = mysqlwire.WritePacket(backendConn, seq, payload)
			return

		case mysqlwire.ComQuery:
			sql := string(payload[1:])
			start := time.Now()
			var relayStats engine.RelayStats
			relayStatus := engine.StatusError
			decision, denied, serveErr := engine.ServeStatement(qe, engine.AuthzInput{
				SQL:            sql,
				Token:          token,
				ClientAddr:     clientAddr,
				ConnectionID:   identity.ConnectionID,
				ProbeNamespace: func() (engine.NamespaceProbe, error) { return probeNamespaceObservation(backendConn, deprecateEOF) },
				RunCommands:    refetcher.RunAll,
			}, refetcher, nil, func(toSend string, masks []*pb.ColumnMask) (bool, error) {
				queryPayload := mysqlwire.ComQueryPayload(toSend)
				if len(queryPayload) >= maxPacketPayload {
					if err := mysqlwire.WritePacket(clientConn, seq+1, mysqlwire.ErrPacketState(
						1105,
						"HY000",
						"proxy-monster: expanded query exceeds max packet size",
					)); err != nil {
						return false, err
					}
					return false, nil
				}
				if err := mysqlwire.WritePacket(backendConn, 0, queryPayload); err != nil {
					return false, err
				}
				clean, stats, err := relayQueryResponseTracked(clientConn, backendConn, deprecateEOF, masks, errRedactor(qe))
				relayStats = stats
				relayStatus = engine.RelayStatus(clean, err)
				if err != nil {
					return false, err
				}
				qe.MarkNamespaceDirty()
				return clean, nil
			})
			// Post-relay, best-effort completion: only a relayed (Proceed) statement reports. A DENY relayed
			// nothing, and EmitCompletion additionally no-ops for a decision with no audit id.
			if !denied {
				engine.EmitCompletion(s.client, decision, relayStats, relayStatus, start)
			}
			if serveErr != nil {
				var fail engine.FailError
				if errors.As(serveErr, &fail) {
					_ = mysqlwire.WritePacket(clientConn, seq+1, mysqlwire.ErrPacketState(1105, "HY000", "proxy-monster: "+fail.Message))
				}
				return
			}
			if denied {
				reason := "policy"
				if decision != nil && decision.DenyReason != "" {
					reason = decision.DenyReason
				}
				if err := mysqlwire.WritePacket(clientConn, seq+1, mysqlwire.ErrPacketState(1142, "42000", "proxy-monster denied: "+reason)); err != nil {
					return
				}
			}

		case mysqlwire.ComInitDB:
			// Switching the current database is not a gated action. Relay COM_INIT_DB mechanically to the
			// backend and forward its OK/ERR verbatim; the control plane enforces subsequent queries under
			// the new namespace via Decide. The database changed, so re-probe the namespace on the next query.
			if _, err := relaySingleResponse(clientConn, backendConn, seq, payload, errRedactor(qe)); err != nil {
				return
			}
			qe.MarkNamespaceDirty()

		case mysqlwire.ComPing:
			if _, err := relaySingleResponse(clientConn, backendConn, seq, payload, errRedactor(qe)); err != nil {
				return
			}

		case mysqlwire.ComStmtPrepare:
			qe.MarkNamespaceDirty()
			sql := string(payload[1:])
			var frozen []string
			var frozenAnsiQuotes bool
			proceed, allowed, err := s.authorize(qe, clientConn, seq, sql, token, clientAddr, identity.ConnectionID, refetcher.RunAll, func() (engine.NamespaceProbe, error) {
				obs, err := probeNamespaceObservation(backendConn, deprecateEOF)
				if err == nil {
					frozen = append([]string{}, obs.Namespace...)
					frozenAnsiQuotes = obs.MySQLAnsiQuotes
				}
				return obs, err
			})
			if err != nil {
				return
			}
			if !allowed {
				continue
			}
			toSend := payload
			sentSQL := sql
			if proceed.RewrittenSQL != nil {
				sentSQL = *proceed.RewrittenSQL
				toSend = mysqlwire.ComStmtPreparePayload(sentSQL)
				if len(toSend) >= maxPacketPayload {
					if err := mysqlwire.WritePacket(clientConn, seq+1, mysqlwire.ErrPacketState(
						1105,
						"HY000",
						"proxy-monster: expanded query exceeds max packet size",
					)); err != nil {
						return
					}
					continue
				}
			}
			if proceed.Decision == nil {
				_ = mysqlwire.WritePacket(clientConn, seq+1, mysqlwire.ErrPacketState(
					1105,
					"HY000",
					"proxy-monster: control plane returned no decision",
				))
				return
			}
			if frozen == nil {
				if err := mysqlwire.WritePacket(clientConn, seq+1, mysqlwire.ErrPacketState(
					1105,
					"HY000",
					"proxy-monster: prepare-time namespace unavailable",
				)); err != nil {
					return
				}
				continue
			}
			// After-statement commands from PREPARE are deliberately ignored: PREPARE executes no statement effect,
			// and EXECUTE obtains its own fresh verdict whose commands govern the actual execution.
			if err := mysqlwire.WritePacket(backendConn, 0, toSend); err != nil {
				return
			}
			stmtID, prepared, err := relayStmtPrepareResponse(clientConn, backendConn, deprecateEOF, errRedactor(qe))
			if err != nil {
				return
			}
			if prepared {
				preparedStmts[stmtID] = preparedStmt{sql: sentSQL, namespace: frozen, ansiQuotes: frozenAnsiQuotes}
			}
			qe.MarkNamespaceDirty()

		case mysqlwire.ComStmtExecute:
			id, parseErr := mysqlwire.StmtID(payload)
			var ps preparedStmt
			var known bool
			if parseErr == nil {
				ps, known = preparedStmts[id]
			}
			if parseErr != nil || !known || len(payload) < 10 {
				if err := writeUnknownPreparedStatement(clientConn, seq+1, id); err != nil {
					return
				}
				continue
			}
			if payload[5]&0x07 != 0 {
				if err := mysqlwire.WritePacket(clientConn, seq+1, mysqlwire.ErrPacketState(
					1235,
					"42000",
					"proxy-monster: prepared-statement cursors are not supported",
				)); err != nil {
					return
				}
				continue
			}

			// MySQL executes the statement in its prepare-time database. Re-decide against that frozen
			// namespace rather than live session state, then dirty the engine cache immediately so it cannot
			// leak into the next statement's decision.
			qe.MarkNamespaceDirty()
			proceed, allowed, err := s.authorize(qe, clientConn, seq, ps.sql, token, clientAddr, identity.ConnectionID, refetcher.RunAll, func() (engine.NamespaceProbe, error) {
				return engine.NamespaceProbe{Namespace: ps.namespace, MySQLAnsiQuotes: ps.ansiQuotes}, nil
			})
			qe.MarkNamespaceDirty()
			if err != nil {
				return
			}
			if !allowed {
				continue
			}
			if proceed.Decision == nil {
				if err := mysqlwire.WritePacket(clientConn, seq+1, mysqlwire.ErrPacketState(
					1105,
					"HY000",
					"proxy-monster: control plane returned no decision",
				)); err != nil {
					return
				}
				continue
			}
			if proceed.Decision.Action == "MASK" && !proceed.Decision.UnmaskablePermitted {
				if err := mysqlwire.WritePacket(clientConn, seq+1, mysqlwire.ErrPacketState(
					1235,
					"42000",
					"proxy-monster: this result cannot be masked on the binary protocol",
				)); err != nil {
					return
				}
				continue
			}

			// The fresh verdict authorized exactly the SQL already prepared on the backend under exactly its
			// frozen namespace. EXECUTE is forwarded verbatim; a fresh rewrite and masks cannot be applied to
			// the binary path and are deliberately ignored.
			start := time.Now()
			if err := mysqlwire.WritePacket(backendConn, 0, payload); err != nil {
				return
			}
			ok, stats, err := relayQueryResponseTracked(clientConn, backendConn, deprecateEOF, nil, errRedactor(qe))
			// Post-relay, best-effort completion for this binary-protocol EXECUTE (no-op if unaudited).
			engine.EmitCompletion(s.client, proceed.Decision, stats, engine.RelayStatus(ok, err), start)
			if err != nil {
				return
			}
			if ok && proceed.Decision != nil && len(proceed.Decision.AfterStatement) > 0 {
				if err := refetcher.RunAll(proceed.Decision.AfterStatement); err != nil {
					return
				}
			}

		case mysqlwire.ComStmtClose:
			id, err := mysqlwire.StmtID(payload)
			if err != nil {
				continue
			}
			if _, ok := preparedStmts[id]; !ok {
				continue
			}
			delete(preparedStmts, id)
			if err := mysqlwire.WritePacket(backendConn, seq, payload); err != nil {
				return
			}

		case mysqlwire.ComStmtSendLongData:
			id, err := mysqlwire.StmtID(payload)
			if _, ok := preparedStmts[id]; err != nil || !ok {
				continue
			}
			if err := mysqlwire.WritePacket(backendConn, seq, payload); err != nil {
				return
			}

		case mysqlwire.ComStmtReset:
			id, err := mysqlwire.StmtID(payload)
			if _, ok := preparedStmts[id]; err != nil || !ok {
				if err := writeUnknownPreparedStatement(clientConn, seq+1, id); err != nil {
					return
				}
				continue
			}
			if _, err := relaySingleResponse(clientConn, backendConn, seq, payload, errRedactor(qe)); err != nil {
				return
			}

		case mysqlwire.ComFieldList:
			// COM_FIELD_LIST is a deprecated command with no SQL text the control plane can decide on.
			// The broker must not synthesize an equivalent SHOW COLUMNS on its behalf, so it is refused
			// fail-closed.
			if err := mysqlwire.WritePacket(clientConn, seq+1, mysqlwire.ErrPacketState(
				1235,
				"42000",
				"proxy-monster: COM_FIELD_LIST is not supported by proxy-monster (go)",
			)); err != nil {
				return
			}

		default:
			message := fmt.Sprintf("proxy-monster: command %d not supported (use text queries)", cmd)
			if err := mysqlwire.WritePacket(clientConn, seq+1, mysqlwire.ErrPacketState(1047, "08S01", message)); err != nil {
				return
			}
		}
	}
}

func (s *Server) authorize(
	qe *engine.QueryEngine,
	clientConn net.Conn,
	seq byte,
	sql, token, clientAddr string,
	connectionID []byte,
	runCommands func([]*pb.Refetch) error,
	probeNamespace func() (engine.NamespaceProbe, error),
) (engine.Proceed, bool, error) {
	verdict := qe.Authorize(engine.AuthzInput{
		SQL:            sql,
		Token:          token,
		ClientAddr:     clientAddr,
		ConnectionID:   connectionID,
		ProbeNamespace: probeNamespace,
		RunCommands:    runCommands,
	})
	switch v := verdict.(type) {
	case engine.Fail:
		if err := mysqlwire.WritePacket(clientConn, seq+1, mysqlwire.ErrPacketState(
			1105,
			"HY000",
			"proxy-monster: "+v.Message,
		)); err != nil {
			return engine.Proceed{}, false, err
		}
		return engine.Proceed{}, false, errors.New("mysqlproxy: authorization failed mechanically")
	case engine.Deny:
		reason := "policy"
		if v.Decision != nil && v.Decision.DenyReason != "" {
			reason = v.Decision.DenyReason
		}
		err := mysqlwire.WritePacket(clientConn, seq+1, mysqlwire.ErrPacketState(
			1142,
			"42000",
			"proxy-monster denied: "+reason,
		))
		return engine.Proceed{}, false, err
	case engine.Proceed:
		return v, true, nil
	default:
		return engine.Proceed{}, false, errors.New("mysqlproxy: engine returned an unknown verdict")
	}
}

type singleResponse struct {
	seq     byte
	payload []byte
	ok      bool
	schema  *string
}

func executeSingleResponse(backend net.Conn, seq byte, payload []byte) (singleResponse, error) {
	if err := mysqlwire.WritePacket(backend, seq, payload); err != nil {
		return singleResponse{}, err
	}
	responseSeq, response, err := mysqlwire.ReadPacket(backend)
	if err != nil {
		return singleResponse{}, err
	}
	if len(response) == 0 {
		return singleResponse{}, errors.New("mysqlproxy: empty single-packet backend response")
	}
	result := singleResponse{seq: responseSeq, payload: response}
	switch response[0] {
	case 0x00:
		result.payload, _, result.schema, _, err = normalizeBackendOK(response)
		if err != nil {
			return singleResponse{}, err
		}
		result.ok = true
	case 0xff:
		// Preserve the backend ERR packet for the frontend.
	default:
		return singleResponse{}, fmt.Errorf("mysqlproxy: unexpected single-packet backend response 0x%02x", response[0])
	}
	return result, nil
}

// relaySingleResponse forwards a command and exactly one backend packet, translating a session-tracked OK
// into the frontend's non-tracking packet shape.
func relaySingleResponse(client, backend net.Conn, seq byte, payload []byte, redactErr func([]byte) []byte) (singleResponse, error) {
	result, err := executeSingleResponse(backend, seq, payload)
	if err != nil {
		return singleResponse{}, err
	}
	// A single-response backend ERR (COM_INIT_DB / COM_PING / COM_STMT_RESET) is a mandated redaction site
	// (fail-closed): strip it on a redacted decision before forwarding. See docs/diagnostic-redaction.md.
	if !result.ok && redactErr != nil && len(result.payload) > 0 && result.payload[0] == 0xff {
		result.payload = redactErr(result.payload)
	}
	if err := mysqlwire.WritePacket(client, result.seq, result.payload); err != nil {
		return singleResponse{}, err
	}
	return result, nil
}

func mysqlNamespace(schema string) []string {
	if schema == "" {
		return []string{}
	}
	return []string{schema}
}
