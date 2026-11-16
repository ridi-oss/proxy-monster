package bigquery

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/httpdb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// newServer serves the BigQuery REST API under /bigquery/v2/; uploads and tabledata are refused.
func newServer(t *target, listen spi.Listen, client spi.ControlPlane, tlsProvider func() (*tls.Config, error)) *httpdb.Server {
	return &httpdb.Server{
		Engine: engine{t}, Name: "bigquery", Listen: listen, Client: client, TLSProvider: tlsProvider,
		Contexts: t.contexts, TargetBinding: t.binding, ContextLifetime: contextLifetime,
		Forward:       httpdb.ForwardOptions{Endpoint: t.endpoint, KeepPath: true, MaxBodyBytes: defaultRequestLimit, Sign: t.sign, Transport: t.transport},
		ResponseLimit: defaultResponseLimit, DiagnosticKeys: diagnosticKeys,
	}
}

type engine struct{ target *target }

func (engine) Operation(r *http.Request) (httpdb.Operation, error) {
	dropFieldMask(r)
	c, err := match(r)
	if err != nil {
		return httpdb.Operation{}, err
	}
	return httpdb.Operation{Name: c.route.name, Kind: c.route.kind, InlineResult: c.route.name == "jobs.query"}, nil
}

// References names the job a call addresses; a getQueryResults page without pageToken or startIndex is the first.
func (e engine) References(r *http.Request, _ []byte) ([]string, bool, error) {
	c, err := match(r)
	if err != nil {
		return nil, false, err
	}
	if c.vars["j"] == "" {
		return nil, false, nil
	}
	first := c.query.Get("pageToken") == "" && (c.query.Get("startIndex") == "" || c.query.Get("startIndex") == "0")
	return []string{c.jobID(e.target.location)}, first, nil
}

func (e engine) SetTarget(d *pb.HttpDbRequest) {
	t := e.target
	d.Target = &pb.HttpDbRequest_Bigquery{Bigquery: &enginepb.BigQueryTarget{Project: t.project, Location: t.location, DefaultDataset: t.dataset, Endpoint: t.endpoint}}
}

// queryFields is what a jobs.query body, or a jobs.insert body's configuration.query, says about its SQL.
type queryFields struct {
	Query          *string `json:"query"`
	UseLegacySQL   *bool   `json:"useLegacySql"`
	DefaultDataset *struct {
		ProjectID string `json:"projectId"`
		DatasetID string `json:"datasetId"`
	} `json:"defaultDataset"`
	QueryParameters []queryParameter `json:"queryParameters"`
	ParameterMode   string           `json:"parameterMode"`
	RequestID       string           `json:"requestId"`
}

// isJob tells a jobs.insert body (a Job with configuration.query) from a jobs.query body.
func isJob(envelope *httpdb.Envelope) bool { return envelope.Field("configuration") != nil }

func (e engine) ReadSubmission(body []byte) (httpdb.Submission, error) {
	envelope, err := httpdb.DecodeEnvelope(body)
	if err != nil {
		return httpdb.Submission{}, err
	}
	var fields queryFields
	job := isJob(envelope)
	if job {
		var insert struct {
			Configuration struct {
				Query *queryFields `json:"query"`
			} `json:"configuration"`
		}
		if err := json.Unmarshal(body, &insert); err != nil || insert.Configuration.Query == nil {
			return httpdb.Submission{}, errors.New("bigquery: only query jobs are supported")
		}
		fields = *insert.Configuration.Query
	} else if err := json.Unmarshal(body, &fields); err != nil {
		return httpdb.Submission{}, err
	}
	if fields.Query == nil {
		return httpdb.Submission{}, errors.New("bigquery: query is required")
	}
	if fields.UseLegacySQL == nil || *fields.UseLegacySQL {
		return httpdb.Submission{}, httpdb.ErrUnauthorized
	}
	parameters, err := sqlParameters(fields.ParameterMode, fields.QueryParameters)
	if err != nil {
		return httpdb.Submission{}, err
	}
	sqlContext := &enginepb.BigQuerySqlContext{Project: e.target.project, Httpdb: &enginepb.HttpDbSqlContext{Parameters: parameters}}
	if d := fields.DefaultDataset; d != nil {
		sqlContext.DefaultDatasetProjectId, sqlContext.DefaultDatasetId = d.ProjectID, d.DatasetID
	}
	// A jobs.insert retry is idempotent by its jobId, so only jobs.query has a token.
	if job {
		fields.RequestID = ""
	}
	return httpdb.Submission{
		Query: *fields.Query, Token: fields.RequestID,
		Session: &enginepb.SessionObservation{Engine: &enginepb.SessionObservation_Bigquery{Bigquery: sqlContext}},
	}, nil
}

// WriteSubmission sends the admitted SQL with its parameters bound, in the target's location and default
// dataset; jobs.query must create a job, since only a job can own the result.
func (e engine) WriteSubmission(body []byte, admitted httpdb.Submission) ([]byte, error) {
	if len(admitted.Parameters) > 0 {
		return nil, errors.New("bigquery: admitted query parameters cannot be sent")
	}
	envelope, err := httpdb.DecodeEnvelope(body)
	if err != nil {
		return nil, err
	}
	t := e.target
	if !isJob(envelope) {
		if envelope, err = t.pinQuery(envelope, admitted); err != nil {
			return nil, err
		}
		if envelope, err = envelope.WithField("location", t.location); err != nil {
			return nil, err
		}
		if envelope, err = envelope.WithField("jobCreationMode", "JOB_CREATION_REQUIRED"); err != nil {
			return nil, err
		}
		if admitted.Token != "" {
			if envelope, err = envelope.WithField("requestId", requestID(admitted.Token)); err != nil {
				return nil, err
			}
		}
		return envelope.Bytes(), nil
	}
	err = edit(envelope, "configuration", func(config *httpdb.Envelope) (*httpdb.Envelope, error) {
		err := edit(config, "query", func(query *httpdb.Envelope) (*httpdb.Envelope, error) { return t.pinQuery(query, admitted) })
		return config, err
	})
	if err != nil {
		return nil, err
	}
	reference := map[string]any{}
	if raw := envelope.Field("jobReference"); raw != nil {
		if err := json.Unmarshal(raw, &reference); err != nil {
			return nil, err
		}
	}
	reference["projectId"], reference["location"] = t.project, t.location
	if envelope, err = envelope.WithField("jobReference", reference); err != nil {
		return nil, err
	}
	return envelope.Bytes(), nil
}

// edit replaces envelope's object field name with what change makes of it, in place.
func edit(envelope *httpdb.Envelope, name string, change func(*httpdb.Envelope) (*httpdb.Envelope, error)) error {
	inner, err := httpdb.DecodeEnvelope(envelope.Field(name))
	if err != nil {
		return err
	}
	if inner, err = change(inner); err != nil {
		return err
	}
	edited, err := envelope.WithField(name, json.RawMessage(inner.Bytes()))
	if err != nil {
		return err
	}
	*envelope = *edited
	return nil
}

// pinQuery puts the admitted SQL in place of the client's, drops the parameters it binds, and names the
// default dataset the analyzer resolved against.
func (t *target) pinQuery(query *httpdb.Envelope, admitted httpdb.Submission) (*httpdb.Envelope, error) {
	query, err := query.WithField("query", admitted.Query)
	if err != nil {
		return nil, err
	}
	if query, err = query.WithoutField("queryParameters"); err != nil {
		return nil, err
	}
	if query, err = query.WithoutField("parameterMode"); err != nil {
		return nil, err
	}
	project, dataset := t.project, t.dataset
	if sqlContext := admitted.Session.GetBigquery(); sqlContext.GetDefaultDatasetId() != "" {
		dataset = sqlContext.GetDefaultDatasetId()
		if p := sqlContext.GetDefaultDatasetProjectId(); p != "" {
			project = p
		}
	}
	if dataset == "" {
		return query.WithoutField("defaultDataset")
	}
	return query.WithField("defaultDataset", map[string]string{"projectId": project, "datasetId": dataset})
}

// requestID shapes a namespaced token as a UUID, since BigQuery takes at most 36 characters.
func requestID(token string) string {
	return token[0:8] + "-" + token[8:12] + "-" + token[12:16] + "-" + token[16:20] + "-" + token[20:32]
}

// jobReference is a job's {projectId, location, jobId}, as its resource id.
type jobReference struct {
	ProjectID string `json:"projectId"`
	Location  string `json:"location"`
	JobID     string `json:"jobId"`
}

func (r *jobReference) id() (string, error) {
	if r == nil || r.ProjectID == "" || r.Location == "" || r.JobID == "" || strings.Contains(r.ProjectID+r.Location+r.JobID, "/") {
		return "", httpdb.ErrResultShape
	}
	return r.ProjectID + "/" + strings.ToLower(r.Location) + "/" + r.JobID, nil
}

// referencedJobs reads the jobs a response names: its own jobReference, a cancel response's job, or a
// listing's jobs.
func referencedJobs(body []byte) ([]string, error) {
	if len(body) == 0 {
		return nil, nil
	}
	var response struct {
		JobReference *jobReference `json:"jobReference"`
		Job          *struct {
			JobReference *jobReference `json:"jobReference"`
		} `json:"job"`
		Jobs []struct {
			JobReference *jobReference `json:"jobReference"`
		} `json:"jobs"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, httpdb.ErrResultShape
	}
	references := []*jobReference{}
	if response.JobReference != nil {
		references = append(references, response.JobReference)
	}
	if response.Job != nil {
		references = append(references, response.Job.JobReference)
	}
	for _, job := range response.Jobs {
		references = append(references, job.JobReference)
	}
	ids := make([]string, 0, len(references))
	for _, reference := range references {
		id, err := reference.id()
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (engine) CreatedResource(body []byte) (string, error) {
	ids, err := referencedJobs(body)
	if err != nil || len(ids) != 1 {
		return "", httpdb.ErrResultShape
	}
	return ids[0], nil
}

func (engine) Observe(body []byte) ([]*pb.HttpDbObservation, error) {
	ids, err := referencedJobs(body)
	if err != nil {
		return nil, err
	}
	observations := make([]*pb.HttpDbObservation, 0, len(ids))
	for _, id := range ids {
		observations = append(observations, &pb.HttpDbObservation{Source: pb.HttpDbObservationSource_HTTP_DB_OBSERVATION_SOURCE_UPSTREAM_RESPONSE, Kind: "job", Id: id})
	}
	return observations, nil
}

// FilterListing keeps the owned jobs of a jobs.list page, their diagnostics redacted; nextPageToken passes.
func (engine) FilterListing(body []byte, owned map[string]bool) ([]byte, error) {
	envelope, err := httpdb.DecodeEnvelope(body)
	if err != nil {
		return nil, httpdb.ErrResultShape
	}
	if envelope.Field("jobs") == nil {
		return body, nil
	}
	var jobs []json.RawMessage
	if err := json.Unmarshal(envelope.Field("jobs"), &jobs); err != nil {
		return nil, httpdb.ErrResultShape
	}
	kept := make([]json.RawMessage, 0, len(owned))
	for _, job := range jobs {
		var entry struct {
			JobReference *jobReference `json:"jobReference"`
		}
		if err := json.Unmarshal(job, &entry); err != nil {
			return nil, httpdb.ErrResultShape
		}
		id, err := entry.JobReference.id()
		if err != nil {
			return nil, err
		}
		if owned[id] {
			kept = append(kept, job)
		}
	}
	filtered, err := envelope.WithField("jobs", kept)
	if err != nil {
		return nil, httpdb.ErrResultShape
	}
	return httpdb.RedactDiagnostics(filtered.Bytes(), diagnosticKeys)
}

func (engine) MaskResult(body []byte, verdict *pb.Verdict, expectedWidth *int32, metadataDigest []byte, _ bool) ([]byte, []byte, error) {
	return maskPage(body, verdict, expectedWidth, metadataDigest)
}

func (e engine) Authorize(authz *spi.Authorizer, commands *relay.ProxyCommandRunner, submission httpdb.Submission) spi.Verdict {
	t := e.target
	// The snapshot carries this request's parameters and default dataset, so a cached one would be stale.
	authz.MarkNamespaceDirty()
	return authz.Authorize(spi.AuthzInput{
		SQL: submission.Query,
		ProbeSession: func() (spi.SessionSnapshot, error) {
			if submission.Session.GetBigquery() == nil {
				return spi.SessionSnapshot{}, errors.New("bigquery: submission has no SQL context")
			}
			return spi.SessionSnapshot{CurrentCatalog: t.catalogIdentity(), Namespace: []string{t.dataset}, SessionObservation: submission.Session}, nil
		},
		Commands: commands,
	})
}

func (e engine) NewProxyCommandRunner(authz *spi.Authorizer) (*relay.ProxyCommandRunner, error) {
	return e.target.newProxyCommandRunner(authz)
}

func (e engine) SubmittedAfter(ctx context.Context, id string, instant time.Time) (bool, error) {
	return e.target.submittedAfter(ctx, id, instant)
}

func (e engine) AwaitExecution(ctx context.Context, id string) error {
	return e.target.awaitExecution(ctx, id)
}

// googleStatus is the canonical status Google APIs pair with an HTTP status.
func googleStatus(code int) string {
	switch code {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge:
		return "INVALID_ARGUMENT"
	case http.StatusForbidden:
		return "PERMISSION_DENIED"
	case http.StatusConflict:
		return "ABORTED"
	default:
		return "UNAVAILABLE"
	}
}

func writeGoogleError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": message, "status": googleStatus(code)}})
}

func (engine) WriteError(w http.ResponseWriter, status int, code string) {
	writeGoogleError(w, status, code)
}

// WriteDenied reports a SQL deny as BigQuery reports an invalid query, so clients surface the reason instead
// of retrying.
func (engine) WriteDenied(w http.ResponseWriter, reason string) {
	writeGoogleError(w, http.StatusBadRequest, "proxy-monster denied this statement: "+reason)
}
