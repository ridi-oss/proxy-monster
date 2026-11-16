package httpdb

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

var ErrCanceled = errors.New("query was canceled")

// Decider decides a submission through the control plane.
type Decider interface {
	Authorize(authz *spi.Authorizer, commands *relay.ProxyCommandRunner, submission Submission) spi.Verdict
	NewProxyCommandRunner(*spi.Authorizer) (*relay.ProxyCommandRunner, error)
}

// Executor runs console editor and workflow statements on one HTTP-API target as the proxy's own client.
type Executor interface {
	Decider
	// Namespace is the configured catalog and schema every statement runs in.
	Namespace() (catalog, schema string)
	// Session is the SQL context Decide sees for a statement capped at maxRows.
	Session(maxRows int) *enginepb.SessionObservation
	// Submit starts query and returns as soon as the target names its job.
	Submit(ctx context.Context, query string, parameters []string, maxRows int) (Job, error)
}

// Job is one submitted statement.
type Job interface {
	// Await returns once the statement is complete.
	Await(ctx context.Context) error
	// Read pages the result within budget, masking inline.
	Read(ctx context.Context, budget *relay.RowBudget, masks []*pb.ColumnMask) (columns []string, rows [][]*string, affected int, err error)
	Cancel(ctx context.Context) error
}

// connection serves the console editor and workflows; the control plane stores the rows, so nothing is cached.
type connection struct {
	name     string
	executor Executor
	authz    *spi.Authorizer
	commands *relay.ProxyCommandRunner
	guard    spi.ExecGuard
	mu       sync.Mutex
	job      Job
	running  bool
	canceled bool
	closed   bool
	cancel   context.CancelFunc
}

// OpenConnection opens an editor session; every statement names the configured schema, so it opens nowhere else.
func OpenConnection(name string, executor Executor, authz *spi.Authorizer, guard spi.ExecGuard, defaultSchema string) (spi.Connection, error) {
	if _, schema := executor.Namespace(); defaultSchema != "" && defaultSchema != schema {
		return nil, fmt.Errorf("%s editor session cannot open in %q: the target is configured for %q", name, defaultSchema, schema)
	}
	commands, err := executor.NewProxyCommandRunner(authz)
	if err != nil {
		return nil, err
	}
	return &connection{name: name, executor: executor, authz: authz, commands: commands, guard: guard}, nil
}

func (c *connection) OnOpen(ctx context.Context, commands []*pb.ProxyCommand) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.commands.RunAll(commands, nil)
}

func (c *connection) Namespace() (string, []string, error) {
	catalog, schema := c.executor.Namespace()
	return catalog, []string{schema}, nil
}

func (c *connection) ServeStatement(sql string, maxRows int) (result spi.StatementResult, err error) {
	c.mu.Lock()
	c.running, c.canceled = true, false
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.running, c.canceled = false, false
		c.mu.Unlock()
	}()
	verdict := c.executor.Authorize(c.authz, c.commands, Submission{Query: sql, Session: c.executor.Session(maxRows)})
	var proceed spi.Proceed
	switch v := verdict.(type) {
	case spi.Fail:
		return result, relay.FailError{Message: v.Message}
	case spi.Deny:
		result.Decision, result.Denied = v.Decision, true
		return result, nil
	case spi.Proceed:
		proceed = v
		result.Decision = v.Decision
	default:
		return result, relay.FailError{Message: fmt.Sprintf("unexpected authorization verdict %T", verdict)}
	}
	query, parameters := SubmittedQuery(sql, nil, proceed.Decision)
	budget := &relay.RowBudget{MaxRows: proceed.Decision.PageRows(maxRows), MaxBytes: proceed.Decision.MaxBytes}
	exec := func() error {
		columns, rows, affected, execErr := c.execute(query, parameters, budget, proceed.Masks, proceed.Decision.AfterStatement)
		if execErr != nil {
			return execErr
		}
		result.Columns, result.Rows, result.RowsAffected = columns, rows, affected
		result.TruncatedByCap = budget.CapTruncated(proceed.Decision, maxRows)
		return nil
	}
	if c.guard != nil {
		err = c.guard(exec)
	} else {
		err = exec()
	}
	return result, err
}

func (c *connection) execute(query string, parameters []string, budget *relay.RowBudget, masks []*pb.ColumnMask, afterStatement []*pb.ProxyCommand) ([]string, [][]*string, int, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, nil, 0, fmt.Errorf("%s: connection is closed", c.name)
	}
	if c.canceled {
		c.mu.Unlock()
		return nil, nil, 0, c.canceledError()
	}
	c.cancel = cancel
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.cancel, c.job = nil, nil
		c.mu.Unlock()
	}()
	job, err := c.executor.Submit(ctx, query, parameters, budget.MaxRows)
	if err != nil {
		return nil, nil, 0, c.failure(ctx, err)
	}
	c.mu.Lock()
	c.job = job
	canceled := c.canceled
	c.mu.Unlock()
	if canceled {
		_ = cancelJob(job)
		return nil, nil, 0, c.canceledError()
	}
	if err := job.Await(ctx); err != nil {
		return nil, nil, 0, c.failure(ctx, err)
	}
	if err := c.commands.RunAll(afterStatement, nil); err != nil {
		return nil, nil, 0, err
	}
	columns, rows, affected, err := job.Read(ctx, budget, masks)
	if err != nil {
		return nil, nil, 0, c.failure(ctx, err)
	}
	return columns, rows, affected, nil
}

func (c *connection) canceledError() error { return fmt.Errorf("%s: %w", c.name, ErrCanceled) }

func (c *connection) failure(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return c.canceledError()
	}
	return err
}

// Cancel never aborts a Submit, which would leave the job running unseen; execute cancels the job once named.
func (c *connection) Cancel() error {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return nil
	}
	c.canceled = true
	job, cancel := c.job, c.cancel
	c.mu.Unlock()
	if job == nil {
		return nil
	}
	cancel()
	return cancelJob(job)
}

func cancelJob(job Job) error {
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	return job.Cancel(ctx)
}

func (c *connection) Close() error {
	c.mu.Lock()
	c.closed = true
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

var _ spi.Connection = (*connection)(nil)
