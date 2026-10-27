package mysql

import (
	"context"
	"errors"
	"math"
	"net"
	"strconv"
	"time"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/wire"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

// connection is goproxy's connection to the target, for a wire client or an editor session.
type connection struct {
	targetDbConn net.Conn
	session      *engines.Session
	// targetConnectionID is the target's id for this connection, which KILL QUERY names.
	targetConnectionID uint32
	config             spi.TargetConfig
	authz              *spi.Authorizer
	commandRunner      *sqldb.ProxyCommandRunner
	guard              spi.ExecGuard
	// deprecateEOF is the result framing the connection negotiated: the wire client's choice, always on for an editor session.
	deprecateEOF bool
}

// newConnection is the connection on targetDbConn, which greeting opened.
func newConnection(targetDbConn net.Conn, greeting mysqlwire.Greeting, config spi.TargetConfig, authz *spi.Authorizer, guard spi.ExecGuard, deprecateEOF bool) (*connection, error) {
	generation, ok := wire.NextBackendGeneration()
	if !ok {
		return nil, errors.New("backend generation out of range")
	}
	c := &connection{
		targetDbConn:       targetDbConn,
		targetConnectionID: greeting.ConnectionID,
		config:             config,
		authz:              authz,
		guard:              guard,
		deprecateEOF:       deprecateEOF,
	}
	probe := func(sql string, expectedColumns int) ([][]*string, error) {
		return runInternalQuery(c.targetDbConn, c.deprecateEOF, sql, expectedColumns)
	}
	var err error
	if c.session, err = sqldb.NewSession(Queries, probe); err != nil {
		return nil, err
	}
	c.commandRunner = sqldb.NewProxyCommandRunner(Queries, c.session, authz.ConnectionID(), generation, probe, authz.Client().PushSchemaFragment)
	c.commandRunner.Catalog = engines.MySQL.CatalogName("").String()
	return c, nil
}

func (c *connection) probeSession() (spi.SessionSnapshot, error) {
	return probeSession(c.targetDbConn, c.deprecateEOF, c.session)
}

func (c *connection) checkTargetError(sql string) (*spi.TargetError, error) {
	return checkTargetError(c.targetDbConn, c.deprecateEOF, sql)
}

func (t *target) OpenConnection(ctx context.Context, authz *spi.Authorizer, guard spi.ExecGuard, readTimeout time.Duration, defaultSchema string) (spi.Connection, error) {
	config := t.config
	if defaultSchema != "" {
		config.Db = defaultSchema
	}
	conn, greeting, err := dialTargetDbAuthID(ctx, config, true)
	if err != nil {
		return nil, err
	}
	conn = wire.WithTargetDbReadTimeout(conn, readTimeout)
	c, err := newConnection(conn, greeting, config, authz, guard, true)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
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
	result.Decision, result.Denied, err = relay.ServeStatement(c.authz, spi.AuthzInput{
		SQL:          sql,
		ProbeSession: c.probeSession,
		Commands:     c.commandRunner,
	}, c.commandRunner, c.guard, func(toSend string, masks []*pb.ColumnMask, dec *spi.Decision) (clean bool, runErr error) {
		payload := mysqlwire.ComQueryPayload(toSend)
		if len(payload) >= mysqlwire.MaxPacketPayload {
			return false, errors.New("query exceeds the maximum MySQL packet payload")
		}
		pageRows := dec.PageRows(maxRows)
		limited := pageRows > 0
		if limited {
			if pageRows == math.MaxInt {
				return false, errors.New("max rows exceeds MySQL SQL_SELECT_LIMIT range")
			}
			if err := execTargetDbSet(c.targetDbConn, "SET SQL_SELECT_LIMIT = "+strconv.Itoa(pageRows+1)); err != nil {
				return false, err
			}
		}
		reset := func() error {
			if !limited {
				return nil
			}
			return execTargetDbSet(c.targetDbConn, "SET SQL_SELECT_LIMIT = DEFAULT")
		}

		if err := mysqlwire.WritePacket(c.targetDbConn, 0, payload); err != nil {
			_ = reset()
			return false, err
		}
		collect := textResultCollector{
			budget: relay.RowBudget{MaxRows: pageRows, MaxBytes: dec.MaxBytes},
			masks:  masks,
			result: &result,
		}
		h := collect.hooks()
		h.OnSysVars = checkSysVarInvariants
		// An editor-session result is stored and re-gated per viewer at view time, so — unlike the wire path — redaction
		// is NOT decided here; the editor session captures BOTH forms of a target-DB ERR. The hook keeps the raw packet
		// for the full-reader view and hands the collector the redacted form for the masked view.
		var rawErrPacket []byte
		h.RedactErr = func(raw []byte) []byte {
			rawErrPacket = append([]byte(nil), raw...)
			return sanitizeErrPacket(raw)
		}
		clean, _, relayErr := relayResultSet(c.targetDbConn, c.deprecateEOF, h)
		c.authz.MarkNamespaceDirty()
		resetErr := reset()
		if relayErr != nil {
			return false, relayErr
		}
		if collect.targetDbErr != nil {
			// The target DB's own ERR for THIS executed statement — raw for a full-reader view, the redacted form
			// for a masked view. An internal probe/refetch ERR never reaches here.
			raw := collect.targetDbErr.Error()
			redacted := collect.targetDbErr.Error()
			if len(rawErrPacket) > 0 {
				raw = mysqlwire.ErrString(rawErrPacket)
				redacted = redactedErrString(rawErrPacket)
			}
			return false, relay.TargetDbError{Message: raw, Redacted: redacted}
		}
		if resetErr != nil {
			return false, resetErr
		}
		result.TruncatedByCap = collect.budget.CapTruncated(dec, maxRows)
		return clean, nil
	})
	return result, err
}

func (c *connection) Namespace() (string, []string, error) {
	snapshot, err := c.probeSession()
	return snapshot.CurrentCatalog, snapshot.Namespace, err
}

func (c *connection) Cancel() error {
	if err := cancelTargetDbQuery(c.config, c.targetConnectionID); err != nil {
		_ = c.targetDbConn.Close()
		return err
	}
	return nil
}

func (c *connection) Close() error { return c.targetDbConn.Close() }
