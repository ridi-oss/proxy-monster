package bigquery

import (
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

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	"github.com/ridi-oss/proxy-monster/goproxy/httpdb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/wire"
)

const (
	defaultEndpoint      = "https://bigquery.googleapis.com"
	defaultRequestLimit  = 2 << 20
	defaultResponseLimit = 16 << 20
	pollInterval         = 500 * time.Millisecond
	// BigQuery keeps a query's results in its anonymous table for about 24 hours.
	contextLifetime = 24 * time.Hour
)

// TokenSource returns an OAuth access token for the upstream BigQuery credential.
type TokenSource func(context.Context) (string, error)

// target is one BigQuery datasource: jobs run in project at location, unqualified tables resolve in dataset,
// and every upstream call carries a token from token.
type target struct {
	project, location, dataset string
	endpoint                   string
	token                      TokenSource
	transport                  http.RoundTripper
	inspector                  relay.Inspector
	binding                    []byte
	contexts                   *httpdb.EnforcementContextCache
	generations                wire.BackendGenerations
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

// jobStatus is the part of a jobs.get response the proxy reads.
type jobStatus struct {
	Statistics struct {
		CreationTime string `json:"creationTime"`
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
	address := t.endpoint + "/bigquery/v2/projects/" + url.PathEscape(parts[0]) + "/jobs/" + url.PathEscape(parts[2]) + "?location=" + url.QueryEscape(parts[1])
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept-Encoding", "identity")
	if err := t.sign(ctx, request, nil); err != nil {
		return nil, err
	}
	client := &http.Client{Transport: t.transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, defaultResponseLimit))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bigquery: jobs.get returned %d", response.StatusCode)
	}
	var job jobStatus
	if err := json.Unmarshal(body, &job); err != nil {
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
