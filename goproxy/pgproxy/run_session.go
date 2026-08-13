package pgproxy

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/wire"
)

type RunSession struct {
	sessionCore
	conn         net.Conn
	keyData      pgproto3.BackendKeyData
	target       spi.TargetDb
	token        string
	connectionID []byte
	ref          *engine.Refetcher
	guard        engine.ExecGuard
	poisoned     bool
}

func NewRunSession(ctx context.Context, target spi.TargetDb, db engine.Db, client spi.SessionClient, token string, connectionID []byte, guard engine.ExecGuard, readTimeout time.Duration) (*RunSession, error) {
	conn, _, keyData, txStatus, err := dialTargetDbAuth(ctx, target)
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
		sessionCore: sessionCore{
			targetDb:     pgproto3.NewFrontend(conn, conn),
			qe:           engine.NewQueryEngine(db, client),
			db:           db,
			lastTxStatus: txStatus,
		},
		conn:         conn,
		keyData:      keyData,
		target:       target,
		token:        token,
		connectionID: append([]byte(nil), connectionID...),
		guard:        guard,
	}
	s.ref = engine.NewRefetcher(db, s.connectionID, generation, func(sql string, expectedColumns int) ([][]*string, error) {
		return s.runProbe(sql, expectedColumns, true)
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
	if s.poisoned {
		return result, errors.New("run session is unusable after a prior protocol error")
	}
	result.Decision, result.Denied, err = engine.ServeStatement(s.qe,
		s.authzInput(sql, s.token, "", s.connectionID, s.ref.RunAll), s.ref, s.guard,
		func(toSend string, masks []*pb.ColumnMask) (bool, error) {
			max, runErr := executeMaxRows(maxRows)
			if runErr != nil {
				return false, runErr
			}
			for _, message := range []pgproto3.FrontendMessage{
				&pgproto3.Parse{Name: "", Query: toSend}, &pgproto3.Bind{}, &pgproto3.Describe{ObjectType: 'P'},
				&pgproto3.Execute{MaxRows: max}, &pgproto3.Close{ObjectType: 'P'}, &pgproto3.Sync{},
			} {
				s.targetDb.Send(message)
			}
			if runErr = s.targetDb.Flush(); runErr != nil {
				return false, runErr
			}
			collector := rowsCollector{maxRows: maxRows, result: &result}
			targetDbErr, runErr := s.streamResult(masks, streamOpts{extended: true}, collector.emit)
			runErr = firstErr(runErr, collector.failed)
			s.poisoned = runErr != nil
			s.pendingDirty = true
			return targetDbErr == nil, firstErr(targetDbErr, runErr)
		})
	return result, err
}

func (s *RunSession) Cancel() error {
	if s.keyData.ProcessID == 0 {
		_ = s.conn.Close()
		return errors.New("cannot cancel: target DB did not provide a cancellation key")
	}
	if err := sendCancelRequest(s.target.Host, s.target.Port, s.keyData.ProcessID, s.keyData.SecretKey); err != nil {
		_ = s.conn.Close()
		return err
	}
	return nil
}
func (s *RunSession) Close() error { return s.conn.Close() }
