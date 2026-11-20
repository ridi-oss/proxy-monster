package bigquery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	"github.com/ridi-oss/proxy-monster/goproxy/httpdb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/wire"
)

const (
	defaultRequestLimit  = 2 << 20
	defaultResponseLimit = 16 << 20
	pollInterval         = 500 * time.Millisecond
	// BigQuery keeps a query's results in its anonymous table for about 24 hours.
	contextLifetime = 24 * time.Hour
	// contextFormat names the enforcement-context file format, so a file from another engine or version is refused.
	contextFormat = "bigquery-enforcement-context-v1"
)

// TokenSource returns an OAuth access token for the upstream BigQuery credential.
type TokenSource func(context.Context) (string, error)

// target is one BigQuery datasource: jobs run in project at location, unqualified tables resolve in dataset,
// and every upstream call carries a token from token.
type target struct {
	settings
	token       TokenSource
	transport   http.RoundTripper
	inspector   relay.Inspector
	binding     []byte
	contexts    *httpdb.EnforcementContextCache
	generations wire.BackendGenerations
	// storage reaches the Storage Read API; storageConn is its connection.
	storage      storagepb.BigQueryReadClient
	storageConn  io.Closer
	destinations destinations
}

func newTarget(cfg settings, token TokenSource, principal string, transport http.RoundTripper) (*target, error) {
	contexts, err := httpdb.OpenContextCache(cfg.contextPath, contextFormat, 10000)
	if err != nil {
		return nil, err
	}
	t := &target{settings: cfg, token: token, transport: transport, binding: targetBinding(cfg, principal), contexts: contexts}
	t.inspector = t
	return t, nil
}

func (t *target) TargetInfo() string {
	u, _ := url.Parse(t.endpoint)
	return fmt.Sprintf("%s project %s, location %s", u.Host, t.project, t.location)
}

// ConnectionInfo publishes the HTTPS endpoint and the scope; the Google credentials never leave the proxy.
func (t *target) ConnectionInfo() *pb.ConnectionInfo {
	endpoint := ""
	if t.advertise != "" {
		endpoint = "https://" + t.advertise
	}
	return &pb.ConnectionInfo{Endpoint: endpoint, Properties: map[string]string{"project": t.project, "location": t.location, "dataset": t.dataset}}
}

func (t *target) Close() error {
	if transport, ok := t.transport.(interface{ CloseIdleConnections() }); ok {
		transport.CloseIdleConnections()
	}
	var failures []error
	if t.storageConn != nil {
		failures = append(failures, t.storageConn.Close())
	}
	if t.contexts != nil {
		failures = append(failures, t.contexts.Close())
	}
	return errors.Join(failures...)
}

func (t *target) sign(ctx context.Context, request *http.Request, _ []byte) error {
	if t.token == nil {
		return httpdb.ErrUnsigned
	}
	token, err := t.token(ctx)
	if err != nil {
		return fmt.Errorf("bigquery: access token: %w", err)
	}
	if token == "" {
		return httpdb.ErrUnsigned
	}
	request.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func (t *target) catalogIdentity() string { return engines.BigQuery.CatalogName(t.project).String() }

func (t *target) newProxyCommandRunner(authz *spi.Authorizer) (*relay.ProxyCommandRunner, error) {
	if t.inspector == nil {
		return nil, errors.New("bigquery: no catalog inspector")
	}
	generation, ok := t.generations.Next()
	if !ok {
		return nil, errors.New("bigquery: backend generation out of range")
	}
	return &relay.ProxyCommandRunner{
		Catalog: t.catalogIdentity(), ConnectionID: authz.ConnectionID(), BackendGeneration: generation,
		Inspector: t.inspector, Push: authz.Client().PushSchemaFragment,
	}, nil
}

// apiError is a BigQuery error response; its message may echo stored values.
type apiError struct {
	status  int
	message string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("bigquery: upstream returned %d: %s", e.status, e.message)
}

// call sends the proxy's own request to path under /bigquery/v2/ and decodes a 200 response into out.
func (t *target) call(ctx context.Context, method, path string, query url.Values, in, out any) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	address := t.endpoint + apiPrefix + path
	if len(query) > 0 {
		address += "?" + query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, method, address, body)
	if err != nil {
		return err
	}
	request.Header.Set("Accept-Encoding", "identity")
	if in != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if err := t.sign(ctx, request, nil); err != nil {
		return err
	}
	client := &http.Client{Transport: t.transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, defaultResponseLimit+1))
	if err != nil {
		return err
	}
	if len(data) > defaultResponseLimit {
		return httpdb.ErrResultShape
	}
	if response.StatusCode != http.StatusOK {
		var failure struct {
			Error struct{ Message string } `json:"error"`
		}
		_ = json.Unmarshal(data, &failure)
		return &apiError{status: response.StatusCode, message: failure.Error.Message}
	}
	if out != nil && json.Unmarshal(data, out) != nil {
		return httpdb.ErrResultShape
	}
	return nil
}

func projectPath(project string) string { return "projects/" + url.PathEscape(project) }

// jobResource is a job's reference and the result table its query wrote.
type jobResource struct {
	JobReference  *jobReference `json:"jobReference"`
	Configuration struct {
		Query struct {
			DestinationTable *struct {
				ProjectID string `json:"projectId"`
				DatasetID string `json:"datasetId"`
				TableID   string `json:"tableId"`
			} `json:"destinationTable"`
		} `json:"query"`
	} `json:"configuration"`
}

// destination is the job's result table as the Storage API names it, or "" for none.
func (j *jobResource) destination() string {
	table := j.Configuration.Query.DestinationTable
	if table == nil {
		return ""
	}
	name := "projects/" + table.ProjectID + "/datasets/" + table.DatasetID + "/tables/" + table.TableID
	if _, _, _, ok := tableName(name); !ok {
		return ""
	}
	return name
}

// jobStatus is the part of a jobs.get response the proxy reads.
type jobStatus struct {
	jobResource
	Statistics struct {
		CreationTime string `json:"creationTime"`
		Query        struct {
			StatementType string `json:"statementType"`
		} `json:"query"`
	} `json:"statistics"`
	Status struct {
		State       string `json:"state"`
		ErrorResult *struct {
			Message string `json:"message"`
		} `json:"errorResult"`
	} `json:"status"`
}

// getJob reads a job by its resource id, "<project>/<location>/<jobId>".
func (t *target) getJob(ctx context.Context, id string) (*jobStatus, error) {
	parts := strings.SplitN(id, "/", 3)
	if len(parts) != 3 {
		return nil, errors.New("bigquery: malformed job id")
	}
	var job jobStatus
	if err := t.call(ctx, http.MethodGet, projectPath(parts[0])+"/jobs/"+url.PathEscape(parts[2]), url.Values{"location": {parts[1]}}, nil, &job); err != nil {
		return nil, err
	}
	return &job, nil
}

func (t *target) submittedAfter(ctx context.Context, id string, instant time.Time) (bool, error) {
	job, err := t.getJob(ctx, id)
	if err != nil {
		return false, err
	}
	millis, err := strconv.ParseInt(job.Statistics.CreationTime, 10, 64)
	if err != nil {
		return false, nil
	}
	return !time.UnixMilli(millis).Before(instant), nil
}

func (t *target) awaitExecution(ctx context.Context, id string) error {
	for {
		job, err := t.getJob(ctx, id)
		if err != nil {
			return err
		}
		if job.Status.State == "DONE" {
			if job.Status.ErrorResult != nil {
				return relay.TargetDbError{Message: job.Status.ErrorResult.Message, Redacted: relay.RedactedDiagnosticMessage}
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}
