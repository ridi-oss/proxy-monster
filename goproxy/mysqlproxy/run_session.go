package mysqlproxy

import (
	"context"
	"errors"
	"math"
	"net"
	"strconv"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/wire"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

type RunSession struct {
	conn         net.Conn
	connID       uint32
	target       spi.TargetDb
	token        string
	connectionID []byte
	qe           *engine.QueryEngine
	ref          *engine.Refetcher
	guard        engine.ExecGuard
}

func NewRunSession(ctx context.Context, target spi.TargetDb, db engine.Db, client spi.SessionClient, token string, connectionID []byte, guard engine.ExecGuard, readTimeout time.Duration) (*RunSession, error) {
	conn, connID, err := dialTargetDbAuthID(ctx, target, true)
	if err != nil {
		return nil, err
	}
	conn = wire.WithTargetDbReadTimeout(conn, readTimeout)
	generation, ok := wire.NextBackendGeneration()
	if !ok {
		_ = conn.Close()
		return nil, errors.New("run backend generation out of range")
	}
	s := &RunSession{
		conn:         conn,
		connID:       connID,
		target:       target,
		token:        token,
		connectionID: append([]byte(nil), connectionID...),
		qe:           engine.NewQueryEngine(db, client),
		guard:        guard,
	}
	s.ref = engine.NewRefetcher(db, s.connectionID, generation, func(sql string, expectedColumns int) ([][]*string, error) {
		return runInternalQuery(s.conn, true, sql, expectedColumns)
	}, client.PushSchemaFragment)
	return s, nil
}

// OnOpen runs the on-open catalog fetch over the target DB conn. A cancel of ctx (the control-plane closed the
// run, or the proxy is draining, during the target-DB open) closes the conn, which unwinds an in-flight fetch read
// at once instead of holding the target DB until readTimeout.
func (s *RunSession) OnOpen(ctx context.Context, cmds []*pb.Refetch) error {
	defer context.AfterFunc(ctx, func() { _ = s.conn.Close() })()
	return s.ref.RunAll(cmds)
}

func (s *RunSession) ServeStatement(sql string, maxRows int) (result engine.StatementResult, err error) {
	result.Decision, result.Denied, err = engine.ServeStatement(s.qe, engine.AuthzInput{
		SQL:            sql,
		Token:          s.token,
		ConnectionID:   s.connectionID,
		ProbeNamespace: func() (engine.NamespaceProbe, error) { return probeNamespaceObservation(s.conn, true) },
		RunCommands:    s.ref.RunAll,
	}, s.ref, s.guard, func(toSend string, masks []*pb.ColumnMask) (clean bool, runErr error) {
		payload := mysqlwire.ComQueryPayload(toSend)
		if len(payload) >= mysqlwire.MaxPacketPayload {
			return false, errors.New("query exceeds the maximum MySQL packet payload")
		}
		capped := maxRows > 0
		if capped {
			if maxRows == math.MaxInt {
				return false, errors.New("max rows exceeds MySQL SQL_SELECT_LIMIT range")
			}
			if err := execTargetDbSet(s.conn, "SET SQL_SELECT_LIMIT = "+strconv.Itoa(maxRows+1)); err != nil {
				return false, err
			}
		}
		reset := func() error {
			if !capped {
				return nil
			}
			return execTargetDbSet(s.conn, "SET SQL_SELECT_LIMIT = DEFAULT")
		}

		if err := mysqlwire.WritePacket(s.conn, 0, payload); err != nil {
			_ = reset()
			return false, err
		}
		collect := textResultCollector{maxRows: maxRows, masks: masks, result: &result}
		h := collect.hooks()
		h.OnSysVars = checkSysVarInvariants
		h.RedactErr = errRedactor(s.qe)
		clean, relayErr := relayResultSet(s.conn, true, h)
		s.qe.MarkNamespaceDirty()
		resetErr := reset()
		if relayErr != nil {
			return false, relayErr
		}
		if collect.targetDbErr != nil {
			// The target DB's own ERR for THIS executed statement (already run through RedactErr). Tag its
			// provenance so the control-plane may surface it; an internal probe/refetch ERR never reaches here.
			return false, engine.TargetDbError{Err: collect.targetDbErr}
		}
		if resetErr != nil {
			return false, resetErr
		}
		return clean, nil
	})
	return result, err
}

func (s *RunSession) Cancel() error {
	conn, _, err := dialTargetDbAuthID(context.Background(), s.target, true)
	if err != nil {
		_ = s.conn.Close()
		return err
	}
	conn = wire.WithIODeadlines(conn, 5*time.Second, 5*time.Second)
	defer conn.Close()
	if err := execTargetDbSet(conn, "KILL QUERY "+strconv.FormatUint(uint64(s.connID), 10)); err != nil {
		_ = s.conn.Close()
		return err
	}
	return nil
}

func (s *RunSession) Close() error { return s.conn.Close() }
