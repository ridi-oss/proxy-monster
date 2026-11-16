package athena

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsa "github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/athena/types"
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/httpdb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const (
	pollInterval   = 500 * time.Millisecond
	resultPageSize = 1000
)

func (t *target) OpenConnection(_ context.Context, authz *spi.Authorizer, guard spi.ExecGuard, _ time.Duration, defaultSchema string) (spi.Connection, error) {
	return httpdb.OpenConnection("athena", engine{t}, authz, guard, defaultSchema)
}

func (e engine) Namespace() (string, string) {
	return e.target.catalogIdentity(), e.target.databaseIdentity()
}

func (e engine) Session(maxRows int) *enginepb.SessionObservation {
	return e.target.session(nil, maxRows)
}

func (e engine) Submit(ctx context.Context, query string, parameters []string, _ int) (httpdb.Job, error) {
	t := e.target
	input := &awsa.StartQueryExecutionInput{
		QueryString: aws.String(query), WorkGroup: aws.String(t.settings.workgroup),
		QueryExecutionContext: &types.QueryExecutionContext{Catalog: aws.String(t.settings.catalog), Database: aws.String(t.settings.database)},
	}
	if len(parameters) > 0 {
		input.ExecutionParameters = parameters
	}
	started, err := t.api.StartQueryExecution(ctx, input)
	if err != nil {
		return nil, describeFailure(err.Error())
	}
	id := aws.ToString(started.QueryExecutionId)
	if id == "" {
		return nil, errors.New("athena: StartQueryExecution returned no execution id")
	}
	return &execution{target: t, id: id}, nil
}

type execution struct {
	target *target
	id     string
	// headerRow: Athena prefixes DML (SELECT) results with a header row of column names, DDL results not.
	headerRow bool
}

func (x *execution) Await(ctx context.Context) error {
	done, err := x.target.awaitExecution(ctx, x.id)
	if err != nil {
		return err
	}
	x.headerRow = done.StatementType == types.StatementTypeDml
	return nil
}

func (x *execution) Cancel(ctx context.Context) error {
	_, err := x.target.api.StopQueryExecution(ctx, &awsa.StopQueryExecutionInput{QueryExecutionId: aws.String(x.id)})
	return err
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

// Read pages the managed result set within budget, drops Athena's header row on a DML first page, and masks
// inline.
func (x *execution) Read(ctx context.Context, budget *relay.RowBudget, masks []*pb.ColumnMask) ([]string, [][]*string, int, error) {
	var columns []string
	var masker *relay.RowMasker
	rows := [][]*string{}
	affected := 0
	var next *string
	first := true
	for !budget.Overflowed {
		page, err := x.target.api.GetQueryResults(ctx, &awsa.GetQueryResultsInput{QueryExecutionId: aws.String(x.id), NextToken: next, MaxResults: aws.Int32(resultPageSize)})
		if err != nil {
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
			if first && i == 0 && x.headerRow {
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

var _ httpdb.Executor = engine{}
