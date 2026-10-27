package postgres

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"

	"github.com/jackc/pgx/v5/pgproto3"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/wire"
)

// connection is goproxy's connection to the target, for a wire client or an editor session.
type connection struct {
	target         *target
	session        *engines.Session
	targetDbConn   net.Conn
	targetDb       *pgproto3.Frontend
	keyData        pgproto3.BackendKeyData
	generation     uint64
	currentCatalog string
	authz          *spi.Authorizer
	commandRunner  *sqldb.ProxyCommandRunner
	guard          spi.ExecGuard
	lastTxStatus   byte
	pendingDirty   bool
	poisoned       bool
	tempOverlay    []spi.TempColumn
	// forward and flushForward relay what the target reports to a wire client; an editor session has none.
	forward      func(pgproto3.BackendMessage)
	flushForward func() error
}

func (t *target) OpenConnection(ctx context.Context, authz *spi.Authorizer, guard spi.ExecGuard, readTimeout time.Duration, defaultSchema string) (spi.Connection, error) {
	var extra map[string]string
	if defaultSchema != "" {
		extra = map[string]string{"search_path": `"` + strings.ReplaceAll(defaultSchema, `"`, `""`) + `"`}
	}
	conn, _, keyData, txStatus, catalog, err := dialTargetDbAuthParams(ctx, t.config, extra)
	if err != nil {
		return nil, err
	}
	conn = wire.WithTargetDbReadTimeout(conn, readTimeout)
	generation, ok := wire.NextBackendGeneration()
	if !ok {
		_ = conn.Close()
		return nil, errors.New("backend generation out of range")
	}
	c := &connection{
		target:         t,
		targetDbConn:   conn,
		targetDb:       pgproto3.NewFrontend(conn, conn),
		keyData:        keyData,
		generation:     generation,
		currentCatalog: catalog,
		authz:          authz,
		guard:          guard,
		lastTxStatus:   txStatus,
	}
	if c.session, err = c.newSession(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	c.commandRunner = c.newCommandRunner(c.runProbe)
	return c, nil
}

// OnOpen runs the on-open catalog fetch over the target DB conn. A cancel of ctx (the control-plane closed the
// run, or the proxy is draining, during the target-DB open) closes the conn, which unwinds an in-flight fetch read
// at once instead of holding the target DB until readTimeout.
func (c *connection) OnOpen(ctx context.Context, cmds []*pb.ProxyCommand) error {
	defer context.AfterFunc(ctx, func() { _ = c.targetDbConn.Close() })()
	return c.commandRunner.RunAll(cmds, nil)
}

func (c *connection) ServeStatement(sql string, maxRows int) (result spi.StatementResult, err error) {
	if c.poisoned {
		return result, errors.New("connection is unusable after a prior protocol error")
	}
	result.Decision, result.Denied, err = relay.ServeStatement(c.authz,
		c.authzInput(sql, c.commandRunner), c.commandRunner, c.guard,
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
				c.targetDb.Send(message)
			}
			if runErr = c.targetDb.Flush(); runErr != nil {
				return false, runErr
			}
			collector := rowsCollector{
				budget: relay.RowBudget{MaxRows: pageRows, MaxBytes: dec.MaxBytes},
				result: &result,
			}
			targetDbErr, runErr := c.streamResult(masks, streamOpts{extended: true}, collector.emit)
			runErr = firstErr(runErr, collector.failed)
			c.poisoned = runErr != nil
			c.pendingDirty = true
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

func (c *connection) Namespace() (string, []string, error) {
	if c.poisoned {
		return "", nil, errors.New("connection is unusable after a prior protocol error")
	}
	// An aborted transaction runs no queries; authorization uses the same last snapshot there.
	if c.lastTxStatus == 'E' {
		snapshot := c.authz.Snapshot()
		return snapshot.CurrentCatalog, snapshot.Namespace, nil
	}
	snapshot, err := c.probeSession()
	return snapshot.CurrentCatalog, snapshot.Namespace, err
}

func (c *connection) Cancel() error {
	if c.keyData.ProcessID == 0 {
		_ = c.targetDbConn.Close()
		return errors.New("cannot cancel: target DB did not provide a cancellation key")
	}
	if err := sendCancelRequest(c.target.config, c.keyData.ProcessID, c.keyData.SecretKey); err != nil {
		_ = c.targetDbConn.Close()
		return err
	}
	return nil
}
func (c *connection) Close() error { return c.targetDbConn.Close() }

// newSession runs once at connect; the connection keeps its engine session for its lifetime.
func (c *connection) newSession() (*engines.Session, error) {
	return sqldb.NewSession(Queries, c.runProbe)
}

func (c *connection) newCommandRunner(probe func(sql string, expectedColumns int) ([][]*string, error)) *sqldb.ProxyCommandRunner {
	commandRunner := sqldb.NewProxyCommandRunner(Queries, c.session, c.authz.ConnectionID(), c.generation, probe, c.authz.Client().PushSchemaFragment)
	commandRunner.Catalog = c.currentCatalog
	return commandRunner
}
