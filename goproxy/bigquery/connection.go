package bigquery

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/httpdb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const (
	resultPageSize = 1000
	// editorSubmitWait keeps jobs.query short so the job reference, which a cancel needs, arrives early.
	editorSubmitWait = 1000
)

func (t *target) OpenConnection(_ context.Context, authz *spi.Authorizer, guard spi.ExecGuard, _ time.Duration, defaultSchema string) (spi.Connection, error) {
	return httpdb.OpenConnection("bigquery", engine{t}, authz, guard, defaultSchema)
}

func (e engine) Namespace() (string, string) { return e.target.catalogIdentity(), e.target.dataset }

func (e engine) Session(maxRows int) *enginepb.SessionObservation {
	return &enginepb.SessionObservation{Engine: &enginepb.SessionObservation_Bigquery{Bigquery: &enginepb.BigQuerySqlContext{
		Project: e.target.project, Httpdb: &enginepb.HttpDbSqlContext{MaxRows: uint32(max(maxRows, 0))},
	}}}
}

func (e engine) Submit(ctx context.Context, query string, _ []string, maxRows int) (httpdb.Job, error) {
	pageSize := resultPageSize
	if maxRows > 0 && maxRows < pageSize {
		pageSize = maxRows + 1
	}
	t := e.target
	page, raw, err := t.startQuery(ctx, queryRequest{Query: query, TimeoutMs: editorSubmitWait, MaxResults: pageSize, DefaultDataset: &datasetReference{ProjectID: t.project, DatasetID: t.dataset}})
	if err != nil {
		return nil, upstreamFailure(err)
	}
	if page.JobReference == nil {
		return nil, errors.New("bigquery: jobs.query returned no job reference")
	}
	return &job{target: t, pageSize: pageSize, page: page, raw: raw}, nil
}

// job is one editor query job; page and raw hold the result page read last.
type job struct {
	target   *target
	pageSize int
	page     *queryPage
	raw      []byte
}

func (j *job) Await(ctx context.Context) error {
	for !j.page.JobComplete {
		if err := j.next(ctx, ""); err != nil {
			return err
		}
	}
	return nil
}

func (j *job) next(ctx context.Context, pageToken string) error {
	page, raw, err := j.target.resultPage(ctx, j.page.JobReference, pageToken, j.pageSize)
	if err != nil {
		return upstreamFailure(err)
	}
	j.page, j.raw = page, raw
	return nil
}

func (j *job) Read(ctx context.Context, budget *relay.RowBudget, masks []*pb.ColumnMask) ([]string, [][]*string, int, error) {
	affected, _ := strconv.Atoi(j.page.NumDMLAffectedRows)
	var verdict *pb.Verdict
	if len(masks) > 0 {
		verdict = &pb.Verdict{Decision: pb.EnfAction_MASK, Masks: masks}
	}
	var columns []string
	rows := [][]*string{}
	seen := map[string]bool{}
	for {
		pageColumns, values, err := pageValues(j.raw, verdict)
		if err != nil {
			return nil, nil, 0, err
		}
		if columns == nil {
			columns = pageColumns
		} else if !slices.Equal(columns, pageColumns) {
			return nil, nil, 0, httpdb.ErrResultShape
		}
		for _, row := range values {
			var rowBytes int64
			for _, value := range row {
				if value != nil {
					rowBytes += int64(len(*value))
				}
			}
			if !budget.Admit(len(rows), rowBytes) {
				break
			}
			rows = append(rows, row)
		}
		token := j.page.PageToken
		if budget.Overflowed || token == "" {
			break
		}
		if seen[token] {
			return nil, nil, 0, errors.New("bigquery: repeated result page token")
		}
		seen[token] = true
		if err := j.next(ctx, token); err != nil {
			return nil, nil, 0, err
		}
	}
	return columns, rows, affected, nil
}

func (j *job) Cancel(ctx context.Context) error {
	ref := j.page.JobReference
	return j.target.call(ctx, http.MethodPost, projectPath(ref.ProjectID)+"/jobs/"+url.PathEscape(ref.JobID)+"/cancel", url.Values{"location": {ref.Location}}, nil, nil)
}

// pageValues masks a result page as the forwarder masks it, then reads its column names and cells.
func pageValues(raw []byte, verdict *pb.Verdict) ([]string, [][]*string, error) {
	if verdict != nil {
		masked, _, err := maskPage(raw, verdict, nil, nil)
		if err != nil {
			return nil, nil, err
		}
		raw = masked
	}
	page, _, err := decodePage(raw)
	if err != nil {
		return nil, nil, err
	}
	columns := []string{}
	if page.Schema != nil {
		for _, field := range page.Schema.Fields {
			columns = append(columns, field.Name)
		}
	}
	values, err := page.values()
	return columns, values, err
}

// upstreamFailure reports an upstream error as a target error whose message may echo stored values.
func upstreamFailure(err error) error {
	var upstream *apiError
	if errors.As(err, &upstream) {
		message := upstream.message
		if message == "" {
			message = "query job failed"
		}
		return relay.TargetDbError{Message: message, Redacted: relay.RedactedDiagnosticMessage}
	}
	return err
}

var _ httpdb.Executor = engine{}
