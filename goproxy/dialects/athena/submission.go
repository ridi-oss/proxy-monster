package athena

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Athena keeps managed results for 24 hours; the enforcement context lives exactly that long.
const contextLifetime = 24 * time.Hour

// submissionScope reads the fields of a StartQueryExecution body that the analysis depends on.
type submissionScope struct {
	query      string
	parameters []string
	workgroup  string
	database   string
	token      string
}

func readSubmission(envelope *Envelope, defaults targetConfig) (*submissionScope, error) {
	query, present, err := envelope.QueryString()
	if err != nil || !present {
		return nil, errors.New("athena: QueryString is required")
	}
	parameters, _, err := envelope.ExecutionParameters()
	if err != nil {
		return nil, err
	}
	if envelope.Field("ResultReuseConfiguration") != nil {
		return nil, ErrUnauthorized
	}
	scope := &submissionScope{query: query, parameters: parameters, workgroup: defaults.workgroup, database: defaults.database}
	if raw := envelope.Field("WorkGroup"); raw != nil {
		if err := json.Unmarshal(raw, &scope.workgroup); err != nil {
			return nil, errors.New("athena: WorkGroup must be a string")
		}
	}
	if raw := envelope.Field("ClientRequestToken"); raw != nil {
		if err := json.Unmarshal(raw, &scope.token); err != nil {
			return nil, errors.New("athena: ClientRequestToken must be a string")
		}
	}
	if raw := envelope.Field("QueryExecutionContext"); raw != nil {
		var context struct {
			Database *string `json:"Database"`
			Catalog  *string `json:"Catalog"`
		}
		if err := json.Unmarshal(raw, &context); err != nil {
			return nil, errors.New("athena: QueryExecutionContext must be an object")
		}
		if context.Database != nil && *context.Database != "" {
			scope.database = *context.Database
		}
	}
	return scope, nil
}

// applySubmission replaces the query string and execution parameters with the admitted submission.
func applySubmission(envelope *Envelope, submission *enginepb.AthenaSubmission) (*Envelope, error) {
	replaced, err := envelope.WithQueryString(submission.GetQueryString())
	if err != nil {
		return nil, err
	}
	if len(submission.GetExecutionParameters()) == 0 {
		return replaced.WithoutField("ExecutionParameters")
	}
	return replaced.WithField("ExecutionParameters", submission.GetExecutionParameters())
}

// pinScope forwards the submission in exactly the scope it was admitted for; AWS would otherwise fill an
// omitted workgroup or database with its own defaults.
func pinScope(envelope *Envelope, cfg targetConfig) (*Envelope, error) {
	pinned, err := envelope.WithField("WorkGroup", cfg.workgroup)
	if err != nil {
		return nil, err
	}
	return pinned.WithField("QueryExecutionContext", map[string]string{"Catalog": cfg.catalog, "Database": cfg.database})
}

// requestBinding fingerprints the upstream submission's fields so a stable-token retry can be matched to the
// context it was admitted under; field order and whitespace do not change the submission.
func requestBinding(body []byte) []byte {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var fields map[string]any
	canonical := body
	if decoder.Decode(&fields) == nil {
		if encoded, err := json.Marshal(fields); err == nil {
			canonical = encoded
		}
	}
	hash := sha256.Sum256(canonical)
	return hash[:]
}

// namespacedToken maps a client idempotency token to one stable upstream token per (datasource, principal),
// so one principal's retry can never return another principal's execution.
func namespacedToken(datasource, principal, token string) string {
	hash := sha256.Sum256([]byte(datasource + "\x00" + principal + "\x00" + token))
	return hex.EncodeToString(hash[:])
}

// newCachedContext freezes an ALLOW/MASK decision for a returned execution id.
func newCachedContext(resourceID, owner string, targetBinding []byte, decision *engine.Decision, expectedWidth *uint32, binding []byte, now time.Time) (*enginepb.AthenaCachedContext, error) {
	action := engine.ParseEnfActionName(decision.Action)
	if action != pb.EnfAction_ALLOW && action != pb.EnfAction_MASK {
		return nil, ErrUnauthorized
	}
	if action == pb.EnfAction_ALLOW && len(decision.Masks) > 0 {
		return nil, ErrUnauthorized
	}
	trimmed := &pb.Verdict{Decision: action, Masks: decision.Masks, UnmaskablePermitted: decision.UnmaskablePermitted, SanitizeDiagnostics: decision.SanitizeDiagnostics, DecisionId: decision.DecisionID}
	instructions, err := proto.MarshalOptions{Deterministic: true}.Marshal(trimmed)
	if err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	record := &enginepb.AthenaCachedContext{
		Version: 1, ContextId: hex.EncodeToString(nonce[:]), ResourceId: resourceID, Owner: owner,
		TargetBinding: bytes.Clone(targetBinding), ExpiresAt: timestamppb.New(now.Add(contextLifetime)),
		ExpectedWidth: expectedWidth, RequestBinding: bytes.Clone(binding), EnforcementInstructions: instructions,
	}
	if _, err := decodeContextRecord(record); err != nil {
		return nil, err
	}
	return record, nil
}

func decodeContextRecord(record *enginepb.AthenaCachedContext) (*enginepb.AthenaCachedContext, error) {
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(record)
	if err != nil {
		return nil, err
	}
	return decodeContext(data)
}

// cachedVerdict decodes the trimmed enforcement instructions a cached context carries.
func cachedVerdict(record *enginepb.AthenaCachedContext) (*pb.Verdict, error) {
	var verdict pb.Verdict
	if err := proto.Unmarshal(record.GetEnforcementInstructions(), &verdict); err != nil {
		return nil, ErrContextCorrupt
	}
	return &verdict, nil
}

// executionID reads the QueryExecutionId AWS returned; a client-supplied id never reaches here.
func executionID(body []byte) (string, error) {
	envelope, err := DecodeEnvelope(body)
	if err != nil {
		return "", err
	}
	raw := envelope.Field("QueryExecutionId")
	if raw == nil {
		return "", errors.New("athena: response carries no QueryExecutionId")
	}
	var id string
	if err := json.Unmarshal(raw, &id); err != nil || strings.TrimSpace(id) == "" || len(id) > 256 {
		return "", errors.New("athena: QueryExecutionId is malformed")
	}
	return id, nil
}
