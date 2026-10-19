package postgres

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"

	"github.com/jackc/pgx/v5/pgproto3"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/wire"
)

type RunSession struct {
	sessionCore
	conn     net.Conn
	keyData  pgproto3.BackendKeyData
	config   spi.TargetConfig
	ref      *sqldb.Refetcher
	guard    spi.ExecGuard
	poisoned bool
}

func NewRunSession(ctx context.Context, config spi.TargetConfig, db relay.Db, authz *spi.Authorizer, guard spi.ExecGuard, readTimeout time.Duration, defaultSchema string) (*RunSession, error) {
	var extra map[string]string
	if defaultSchema != "" {
		extra = map[string]string{"search_path": `"` + strings.ReplaceAll(defaultSchema, `"`, `""`) + `"`}
	}
	conn, _, keyData, txStatus, catalog, err := dialTargetDbAuthParams(ctx, config, extra)
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
			currentCatalog: catalog,
			targetDb:       pgproto3.NewFrontend(conn, conn),
			authz:          authz,
			db:             db,
			lastTxStatus:   txStatus,
		},
		conn:    conn,
		keyData: keyData,
		config:  config,
		guard:   guard,
	}
	s.ref = sqldb.NewRefetcher(db, authz.ConnectionID(), generation, func(sql string, expectedColumns int) ([][]*string, error) {
		return s.runProbe(sql, expectedColumns, true)
	}, authz.Client().PushSchemaFragment)
	s.ref.Catalog = catalog
	return s, nil
}

// OnOpen runs the on-open catalog fetch over the target DB conn. A cancel of ctx (the control-plane closed the
// run, or the proxy is draining, during the target-DB open) closes the conn, which unwinds an in-flight fetch read
// at once instead of holding the target DB until readTimeout.
func (s *RunSession) OnOpen(ctx context.Context, cmds []*pb.ProxyCommand) error {
	defer context.AfterFunc(ctx, func() { _ = s.conn.Close() })()
	return s.ref.RunAll(cmds, nil)
}

func (s *RunSession) ServeStatement(sql string, maxRows int) (result spi.StatementResult, err error) {
	if s.poisoned {
		return result, errors.New("run session is unusable after a prior protocol error")
	}
	result.Decision, result.Denied, err = relay.ServeStatement(s.authz,
		s.authzInput(sql, s.ref.RunAll), s.ref, s.guard,
		func(toSend string, masks []*pb.ColumnMask, dec *spi.Decision) (bool, error) {
			pageRows := dec.PageRows(maxRows)
			max, runErr := executeMaxRows(pageRows)
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
			collector := rowsCollector{
				budget: relay.RowBudget{MaxRows: pageRows, MaxBytes: dec.MaxBytes},
				result: &result,
			}
			targetDbErr, runErr := s.streamResult(masks, streamOpts{extended: true}, collector.emit)
			runErr = firstErr(runErr, collector.failed)
			s.poisoned = runErr != nil
			s.pendingDirty = true
			if targetDbErr != nil {
				// Promote the statement's OWN target-DB ERR to relay.TargetDbError (raw + redacted forms), the
				// only provenance the control-plane may surface — and re-gate per viewer. A probe/refetch ERR
				// reaches ServeStatement as a plain error, never a *pgTargetDbErr, so it stays generic.
				var pgErr *pgTargetDbErr
				if errors.As(targetDbErr, &pgErr) {
					return false, relay.TargetDbError{Message: pgErr.message, Redacted: pgErr.redacted}
				}
				return false, targetDbErr
			}
			result.TruncatedByCap = collector.budget.CapTruncated(dec, maxRows)
			return true, runErr
		})
	return result, err
}

func (s *RunSession) Namespace() (string, []string, error) {
	if s.poisoned {
		return "", nil, errors.New("run session is unusable after a prior protocol error")
	}
	// An aborted transaction runs no queries; authorization uses the same last snapshot there.
	if s.lastTxStatus == 'E' {
		return s.session.CurrentCatalog, append([]string(nil), s.session.Namespace...), nil
	}
	session, err := s.probeSession()
	return session.CurrentCatalog, session.Namespace, err
}

func (s *RunSession) Cancel() error {
	if s.keyData.ProcessID == 0 {
		_ = s.conn.Close()
		return errors.New("cannot cancel: target DB did not provide a cancellation key")
	}
	if err := sendCancelRequest(s.config, s.keyData.ProcessID, s.keyData.SecretKey); err != nil {
		_ = s.conn.Close()
		return err
	}
	return nil
}
func (s *RunSession) Close() error { return s.conn.Close() }
