package athena

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsa "github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/athena/types"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const (
	pollInterval   = 500 * time.Millisecond
	resultPageSize = 1000
)

// runSession serves the console editor: the proxy is the Athena client, so it submits, polls, reads, masks,
// and cancels through the SDK with its own credentials. No enforcement context is cached: the control plane
// stores the rows it receives.
type runSession struct {
	target  *target
	session *enforcementSession
	guard   engine.ExecGuard
	timeout time.Duration
	mu      sync.Mutex
	current string
	closed  bool
	cancel  context.CancelFunc
}

func (t *target) NewRunSession(_ context.Context, options spi.RunSessionOptions) (spi.TargetDbSession, error) {
	session, err := t.newEnforcementSession(options.Client, options.Token, options.ConnectionID)
	if err != nil {
		return nil, err
	}
	return &runSession{target: t, session: session, guard: options.Guard, timeout: options.ReadTimeout}, nil
}

func (s *runSession) OnOpen(ctx context.Context, commands []*pb.Refetch) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.session.onOpen(commands)
}

func (s *runSession) ServeStatement(sql string, maxRows int) (result engine.StatementResult, err error) {
	verdict := s.session.authorize(sql, "", nil, maxRows)
	var proceed engine.Proceed
	switch v := verdict.(type) {
	case engine.Fail:
		return result, engine.FailError{Message: v.Message}
	case engine.Deny:
		result.Decision, result.Denied = v.Decision, true
		return result, nil
	case engine.Proceed:
		proceed = v
		result.Decision = v.Decision
	default:
		return result, verdictError(verdict)
	}
	query, parameters := submittedQuery(sql, nil, proceed.Decision)
	if proceed.RewrittenSQL != nil && proceed.Decision.AthenaSubmission == nil {
		query = *proceed.RewrittenSQL
	}
	exec := func() error {
		columns, rows, affected, execErr := s.execute(query, parameters, maxRows, proceed.Masks, proceed.Decision.AfterStatement)
		if execErr != nil {
			return execErr
		}
		result.Columns, result.Rows, result.RowsAffected = columns, rows, affected
		return nil
	}
	if s.guard != nil {
		err = s.guard(exec)
	} else {
		err = exec()
	}
	return result, err
}

func (s *runSession) execute(query string, parameters []string, maxRows int, masks []*pb.ColumnMask, afterStatement []*pb.Refetch) ([]string, [][]*string, int, error) {
	ctx, cancel := withDeadline(context.Background(), 0)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		cancel()
		return nil, nil, 0, errors.New("athena: run session is closed")
	}
	s.cancel = cancel
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.cancel = nil
		s.current = ""
		s.mu.Unlock()
		cancel()
	}()
	input := &awsa.StartQueryExecutionInput{
		QueryString: aws.String(query), WorkGroup: aws.String(s.target.config.workgroup),
		QueryExecutionContext: &types.QueryExecutionContext{Catalog: aws.String(s.target.config.catalog), Database: aws.String(s.target.config.database)},
	}
	if len(parameters) > 0 {
		input.ExecutionParameters = parameters
	}
	started, err := s.target.api.StartQueryExecution(ctx, input)
	if err != nil {
		return nil, nil, 0, describeFailure(err.Error())
	}
	id := aws.ToString(started.QueryExecutionId)
	if id == "" {
		return nil, nil, 0, errors.New("athena: StartQueryExecution returned no execution id")
	}
	s.mu.Lock()
	s.current = id
	s.mu.Unlock()
	execution, err := s.target.awaitExecution(ctx, id)
	if err != nil {
		return nil, nil, 0, err
	}
	if err := s.session.refetcher.RunAll(afterStatement); err != nil {
		return nil, nil, 0, err
	}
	// Athena prefixes DML (SELECT) results with a header row of column names; DDL and utility results have none.
	return s.read(ctx, id, maxRows, masks, execution.StatementType == types.StatementTypeDml)
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

// read pages the managed result set, drops Athena's header row on a non-DML first page, and masks inline.
func (s *runSession) read(ctx context.Context, id string, maxRows int, masks []*pb.ColumnMask, headerRow bool) ([]string, [][]*string, int, error) {
	var columns []string
	var masker *engine.RowMasker
	rows := [][]*string{}
	affected := 0
	var next *string
	first := true
	for {
		if maxRows > 0 && len(rows) >= maxRows {
			break
		}
		page, err := s.target.api.GetQueryResults(ctx, &awsa.GetQueryResultsInput{QueryExecutionId: aws.String(id), NextToken: next, MaxResults: aws.Int32(resultPageSize)})
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
				masker = engine.NewRowMasker(masks, len(columns))
				if masker == nil {
					return nil, nil, 0, engine.ErrMaskUnbound
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
			for j, datum := range row.Data {
				values[j] = datum.VarCharValue
			}
			if masker != nil {
				values = masker.Apply(values)
			}
			rows = append(rows, values)
			if maxRows > 0 && len(rows) >= maxRows {
				break
			}
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

func (s *runSession) Cancel() error {
	s.mu.Lock()
	id, cancel := s.current, s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if id == "" {
		return nil
	}
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	_, err := s.target.api.StopQueryExecution(ctx, &awsa.StopQueryExecutionInput{QueryExecutionId: aws.String(id)})
	return err
}

func (s *runSession) Close() error {
	s.mu.Lock()
	s.closed = true
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

var _ spi.TargetDbSession = (*runSession)(nil)
