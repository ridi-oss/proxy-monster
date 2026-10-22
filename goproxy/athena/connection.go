package athena

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsa "github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/athena/types"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const (
	pollInterval   = 500 * time.Millisecond
	resultPageSize = 1000
)

// connection serves the console editor: the proxy is the Athena client, so it submits, polls, reads, masks,
// and cancels through the SDK with its own credentials. No enforcement context is cached: the control plane
// stores the rows it receives.
type connection struct {
	target        *target
	authz         *spi.Authorizer
	commandRunner *proxyCommandRunner
	guard         spi.ExecGuard
	timeout       time.Duration
	mu            sync.Mutex
	current       string
	closed        bool
	cancel        context.CancelFunc
}

func (t *target) OpenConnection(_ context.Context, authz *spi.Authorizer, guard spi.ExecGuard, readTimeout time.Duration, defaultSchema string) (spi.Connection, error) {
	// Every Athena query names the configured database, so a run cannot open anywhere else.
	if defaultSchema != "" && defaultSchema != t.databaseIdentity() {
		return nil, fmt.Errorf("athena run cannot open in database %q: the target is configured for %q", defaultSchema, t.config.database)
	}
	commandRunner, err := t.newProxyCommandRunner(authz)
	if err != nil {
		return nil, err
	}
	return &connection{target: t, authz: authz, commandRunner: commandRunner, guard: guard, timeout: readTimeout}, nil
}

func (c *connection) OnOpen(ctx context.Context, commands []*pb.ProxyCommand) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.commandRunner.RunAll(commands, nil)
}

// Namespace is the configured catalog and database in canonical spelling; nothing on the session changes them.
func (c *connection) Namespace() (string, []string, error) {
	return c.target.catalogIdentity(), []string{c.target.databaseIdentity()}, nil
}

func (c *connection) ServeStatement(sql string, maxRows int) (result spi.StatementResult, err error) {
	verdict := c.target.authorize(c.authz, c.commandRunner, sql, nil, maxRows)
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
		return result, verdictError(verdict)
	}
	query, parameters := submittedQuery(sql, nil, proceed.Decision)
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
	ctx, cancel := withDeadline(context.Background(), 0)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		cancel()
		return nil, nil, 0, errors.New("athena: connection is closed")
	}
	c.cancel = cancel
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.cancel = nil
		c.current = ""
		c.mu.Unlock()
		cancel()
	}()
	input := &awsa.StartQueryExecutionInput{
		QueryString: aws.String(query), WorkGroup: aws.String(c.target.config.workgroup),
		QueryExecutionContext: &types.QueryExecutionContext{Catalog: aws.String(c.target.config.catalog), Database: aws.String(c.target.config.database)},
	}
	if len(parameters) > 0 {
		input.ExecutionParameters = parameters
	}
	started, err := c.target.api.StartQueryExecution(ctx, input)
	if err != nil {
		return nil, nil, 0, describeFailure(err.Error())
	}
	id := aws.ToString(started.QueryExecutionId)
	if id == "" {
		return nil, nil, 0, errors.New("athena: StartQueryExecution returned no execution id")
	}
	c.mu.Lock()
	c.current = id
	c.mu.Unlock()
	execution, err := c.target.awaitExecution(ctx, id)
	if err != nil {
		return nil, nil, 0, err
	}
	if err := c.commandRunner.RunAll(afterStatement, nil); err != nil {
		return nil, nil, 0, err
	}
	// Athena prefixes DML (SELECT) results with a header row of column names; DDL and utility results have none.
	return c.read(ctx, id, budget, masks, execution.StatementType == types.StatementTypeDml)
}

// awaitExecution polls Athena until the execution is terminal; the SDK client returns the state, Athena owns it.
func (t *target) awaitExecution(ctx context.Context, id string) (*types.QueryExecution, error) {
	for {
		output, err := t.api.GetQueryExecution(ctx, &awsa.GetQueryExecutionInput{QueryExecutionId: aws.String(id)})
		if err != nil {
			if ctx.Err() != nil {
				return nil, errRunCanceled
			}
			return nil, describeFailure(err.Error())
		}
		execution := output.QueryExecution
		if execution == nil || execution.Status == nil {
			return nil, errors.New("athena: GetQueryExecution returned no status")
		}
		switch execution.Status.State {
		case types.QueryExecutionStateSucceeded:
			return execution, nil
		case types.QueryExecutionStateFailed:
			reason := aws.ToString(execution.Status.StateChangeReason)
			if execution.Status.AthenaError != nil && aws.ToString(execution.Status.AthenaError.ErrorMessage) != "" {
				reason = aws.ToString(execution.Status.AthenaError.ErrorMessage)
			}
			return nil, describeFailure(reason)
		case types.QueryExecutionStateCancelled:
			return nil, errRunCanceled
		}
		select {
		case <-ctx.Done():
			return nil, errRunCanceled
		case <-time.After(pollInterval):
		}
	}
}

// read pages the managed result set within budget, drops Athena's header row on a DML first page, and masks
// inline.
func (c *connection) read(ctx context.Context, id string, budget *relay.RowBudget, masks []*pb.ColumnMask, headerRow bool) ([]string, [][]*string, int, error) {
	var columns []string
	var masker *relay.RowMasker
	rows := [][]*string{}
	affected := 0
	var next *string
	first := true
	for !budget.Overflowed {
		page, err := c.target.api.GetQueryResults(ctx, &awsa.GetQueryResultsInput{QueryExecutionId: aws.String(id), NextToken: next, MaxResults: aws.Int32(resultPageSize)})
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, 0, errRunCanceled
			}
			return nil, nil, 0, describeFailure(err.Error())
		}
		if page.UpdateCount != nil {
			affected = int(*page.UpdateCount)
		}
		if page.ResultSet == nil || page.ResultSet.ResultSetMetadata == nil {
			return nil, nil, 0, ErrResultShape
		}
		var pageColumns []string
		for _, info := range page.ResultSet.ResultSetMetadata.ColumnInfo {
			pageColumns = append(pageColumns, aws.ToString(info.Name))
		}
		if columns == nil {
			columns = pageColumns
			if len(masks) > 0 {
				masker = relay.NewRowMasker(masks, len(columns))
				if masker == nil {
					return nil, nil, 0, relay.ErrMaskUnbound
				}
			}
		} else if !slices.Equal(columns, pageColumns) {
			return nil, nil, 0, ErrResultShape
		}
		for i, row := range page.ResultSet.Rows {
			if len(row.Data) != len(columns) {
				return nil, nil, 0, ErrResultShape
			}
			if first && i == 0 && headerRow {
				continue
			}
			values := make([]*string, len(row.Data))
			var rowBytes int64
			for j, datum := range row.Data {
				values[j] = datum.VarCharValue
				rowBytes += int64(len(aws.ToString(datum.VarCharValue)))
			}
			if masker != nil {
				values = masker.Apply(values)
			}
			if !budget.Admit(len(rows), rowBytes) {
				break
			}
			rows = append(rows, values)
		}
		first = false
		next = page.NextToken
		if next == nil {
			break
		}
	}
	if columns == nil {
		columns = []string{}
	}
	return columns, rows, affected, nil
}

func (c *connection) Cancel() error {
	c.mu.Lock()
	id, cancel := c.current, c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if id == "" {
		return nil
	}
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	_, err := c.target.api.StopQueryExecution(ctx, &awsa.StopQueryExecutionInput{QueryExecutionId: aws.String(id)})
	return err
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
