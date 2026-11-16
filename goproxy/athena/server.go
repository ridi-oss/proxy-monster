package athena

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

var (
	ErrUnauthorized = httpdb.ErrUnauthorized
	ErrUnsigned     = httpdb.ErrUnsigned
)

// newServer serves the Athena JSON 1.1 API; streaming and S3 result paths are refused.
func newServer(t *target, listen spi.Listen, client spi.ControlPlane, tlsProvider func() (*tls.Config, error)) *httpdb.Server {
	return &httpdb.Server{
		Engine: engine{t}, Name: "athena", Listen: listen, Client: client, TLSProvider: tlsProvider,
		Contexts: t.contexts, TargetBinding: t.binding, ContextLifetime: contextLifetime,
		Forward:       httpdb.ForwardOptions{Endpoint: t.endpoint, MaxBodyBytes: defaultRequestLimit, Sign: t.sign, Transport: t.transport},
		ResponseLimit: defaultResponseLimit, DiagnosticKeys: diagnosticKeys,
	}
}

type engine struct{ target *target }

func (engine) Operation(request *http.Request) (httpdb.Operation, error) {
	if request.Method != http.MethodPost || request.URL.Path != "/" || request.URL.RawQuery != "" {
		return httpdb.Operation{}, httpdb.ErrUnsupportedTransport
	}
	if len(request.Header.Values("X-Amz-Target")) > 1 {
		return httpdb.Operation{}, errors.New("athena: multiple operation headers")
	}
	name, valid := strings.CutPrefix(request.Header.Get("X-Amz-Target"), "AmazonAthena.")
	if !valid || name == "" {
		return httpdb.Operation{}, errors.New("athena: invalid operation")
	}
	kind := httpdb.KindMetadata
	switch name {
	case "StartQueryExecution":
		kind = httpdb.KindSubmission
	case "GetQueryResults":
		kind = httpdb.KindResultPage
	case "ListQueryExecutions":
		kind = httpdb.KindListing
	case "GetQueryResultsStream":
		kind = httpdb.KindRefused
	}
	return httpdb.Operation{Name: name, Kind: kind}, nil
}

func (engine) References(_ *http.Request, body []byte) ([]string, bool, error) {
	envelope, err := httpdb.DecodeEnvelope(body)
	if err != nil {
		return nil, false, err
	}
	var ids []string
	if raw := envelope.Field("QueryExecutionId"); raw != nil {
		var id string
		if err := json.Unmarshal(raw, &id); err != nil {
			return nil, false, errors.New("athena: QueryExecutionId must be a string")
		}
		ids = append(ids, id)
	}
	if raw := envelope.Field("QueryExecutionIds"); raw != nil {
		var batch []string
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, false, errors.New("athena: QueryExecutionIds must be strings")
		}
		ids = append(ids, batch...)
	}
	return ids, envelope.Field("NextToken") == nil, nil
}

func (e engine) SetTarget(d *pb.HttpDbRequest) {
	t := e.target
	d.Target = &pb.HttpDbRequest_Athena{Athena: &enginepb.AthenaTarget{Region: t.settings.region, DefaultWorkgroup: t.settings.workgroup, DefaultCatalog: t.settings.catalog, DefaultDatabase: t.settings.database, Endpoint: t.endpoint}}
}

func (e engine) ReadSubmission(body []byte) (httpdb.Submission, error) {
	envelope, err := httpdb.DecodeEnvelope(body)
	if err != nil {
		return httpdb.Submission{}, err
	}
	scope, err := readSubmission(envelope, e.target.settings)
	if err != nil {
		return httpdb.Submission{}, err
	}
	return httpdb.Submission{Query: scope.query, Parameters: scope.parameters, Token: scope.token}, nil
}

func (e engine) WriteSubmission(body []byte, admitted httpdb.Submission) ([]byte, error) {
	envelope, err := httpdb.DecodeEnvelope(body)
	if err != nil {
		return nil, err
	}
	if envelope, err = applySubmission(envelope, admitted.Query, admitted.Parameters); err != nil {
		return nil, err
	}
	if envelope, err = pinScope(envelope, e.target.settings); err != nil {
		return nil, err
	}
	if admitted.Token != "" {
		if envelope, err = envelope.WithField("ClientRequestToken", admitted.Token); err != nil {
			return nil, err
		}
	}
	return envelope.Bytes(), nil
}

func (engine) CreatedResource(body []byte) (string, error) { return executionID(body) }

// Observe reports AWS-returned execution identities so the control plane can bind them to cached contexts.
func (engine) Observe(body []byte) ([]*pb.HttpDbObservation, error) {
	envelope, err := httpdb.DecodeEnvelope(body)
	if err != nil {
		return nil, ErrResultShape
	}
	var observations []*pb.HttpDbObservation
	add := func(id string) {
		observations = append(observations, &pb.HttpDbObservation{Source: pb.HttpDbObservationSource_HTTP_DB_OBSERVATION_SOURCE_UPSTREAM_RESPONSE, Kind: "query-execution", Id: id})
	}
	observe := func(raw json.RawMessage) error {
		if raw == nil {
			return nil
		}
		execution, err := httpdb.DecodeEnvelope(raw)
		if err != nil {
			return ErrResultShape
		}
		if execution.Field("QueryExecutionId") == nil {
			return nil
		}
		var id string
		if err := json.Unmarshal(execution.Field("QueryExecutionId"), &id); err != nil || id == "" {
			return ErrResultShape
		}
		add(id)
		return nil
	}
	if err := observe(envelope.Field("QueryExecution")); err != nil {
		return nil, err
	}
	if raw := envelope.Field("QueryExecutions"); raw != nil {
		var executions []json.RawMessage
		if err := json.Unmarshal(raw, &executions); err != nil {
			return nil, ErrResultShape
		}
		for _, execution := range executions {
			if err := observe(execution); err != nil {
				return nil, err
			}
		}
	}
	if raw := envelope.Field("QueryExecutionIds"); raw != nil {
		var ids []string
		if err := json.Unmarshal(raw, &ids); err != nil {
			return nil, ErrResultShape
		}
		for _, id := range ids {
			add(id)
		}
	}
	return observations, nil
}

// FilterListing keeps only the owned executions in a listing, in AWS order; the page token passes through
// so the client keeps paging.
func (engine) FilterListing(body []byte, owned map[string]bool) ([]byte, error) {
	envelope, err := httpdb.DecodeEnvelope(body)
	if err != nil {
		return nil, ErrResultShape
	}
	var ids []string
	if raw := envelope.Field("QueryExecutionIds"); raw != nil {
		if err := json.Unmarshal(raw, &ids); err != nil {
			return nil, ErrResultShape
		}
	}
	kept := make([]string, 0, len(owned))
	for _, id := range ids {
		if owned[id] {
			kept = append(kept, id)
		}
	}
	filtered, err := envelope.WithField("QueryExecutionIds", kept)
	if err != nil {
		return nil, ErrResultShape
	}
	return filtered.Bytes(), nil
}

func (engine) MaskResult(body []byte, verdict *pb.Verdict, expectedWidth *int32, metadataDigest []byte, firstPage bool) ([]byte, []byte, error) {
	envelope, err := httpdb.DecodeEnvelope(body)
	if err != nil || envelope.Field("ResultSet") == nil {
		return nil, nil, ErrResultShape
	}
	if verdict.Decision == pb.EnfAction_ALLOW {
		return body, nil, nil
	}
	return MaskResultPage(body, verdict.Masks, expectedWidth, metadataDigest, firstPage)
}

func (e engine) Authorize(authz *spi.Authorizer, commands *relay.ProxyCommandRunner, query string, parameters []string) spi.Verdict {
	return e.target.authorize(authz, commands, query, parameters, 0)
}

func (e engine) NewProxyCommandRunner(authz *spi.Authorizer) (*relay.ProxyCommandRunner, error) {
	return e.target.newProxyCommandRunner(authz)
}

func (e engine) SubmittedAfter(ctx context.Context, id string, instant time.Time) (bool, error) {
	return e.target.submittedAfter(ctx, id, instant)
}

func (e engine) AwaitExecution(ctx context.Context, id string) error {
	_, err := e.target.awaitExecution(ctx, id)
	return err
}

func (engine) WriteError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": "AccessDeniedException", "Message": code})
}

// WriteDenied renders a SQL deny the way Athena reports a rejected statement, so clients surface the reason
// instead of retrying.
func (engine) WriteDenied(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": "InvalidRequestException", "AthenaErrorCode": "PROXY_MONSTER_DENIED", "Message": "proxy-monster denied this statement: " + reason})
}
