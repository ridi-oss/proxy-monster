package httpdb

import (
	"bytes"
	"context"
	"net/http"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// ResultRead is a result the control plane admitted a caller to read: who the caller is, and the context
// the result's execution was admitted under.
type ResultRead struct {
	Principal string
	Context   *enginepb.HttpDbCachedContext
	Verdict   *pb.Verdict
}

// AuthorizeResultRead authorizes a result read that does not go through the REST surface, such as a gRPC
// read of the same rows, exactly as the result-page call r would be: both phases, with observed as what
// the target reports for it.
func (s *Server) AuthorizeResultRead(ctx context.Context, token, clientAddr string, r *http.Request, observed *pb.HttpDbObservation) (ResultRead, error) {
	if s.Client == nil || token == "" {
		return ResultRead{}, ErrUnauthorized
	}
	operation, err := s.Engine.Operation(r)
	if err != nil || operation.Kind != KindResultPage {
		return ResultRead{}, ErrUnauthorized
	}
	c := &call{server: s, request: r, token: token, clientAddr: clientAddr, operation: operation, contexts: map[string]*enginepb.HttpDbCachedContext{}}
	ids, _, err := s.Engine.References(r, nil)
	if err != nil {
		return ResultRead{}, err
	}
	if len(ids) != 1 || observed == nil || observed.Id != ids[0] {
		return ResultRead{}, ErrOriginalContextUnavailable
	}
	if err := c.attachContext(ids[0]); err != nil {
		return ResultRead{}, err
	}
	result, instructions, err := s.authorize(ctx, token, clientAddr, c.describe(enginepb.HttpDbAuthorizationPhase_HTTP_DB_AUTHORIZATION_PHASE_REQUEST, nil))
	if err != nil {
		return ResultRead{}, err
	}
	if result.Principal == "" || instructions.Action != enginepb.HttpDbInstruction_HTTP_DB_INSTRUCTION_FORWARD_REQUEST {
		return ResultRead{}, ErrUnauthorized
	}
	c.principal = result.Principal
	result, instructions, err = s.authorize(ctx, token, clientAddr, c.describe(enginepb.HttpDbAuthorizationPhase_HTTP_DB_AUTHORIZATION_PHASE_RESPONSE, []*pb.HttpDbObservation{observed}))
	if err != nil {
		return ResultRead{}, err
	}
	if result.Principal != c.principal || instructions.Action != enginepb.HttpDbInstruction_HTTP_DB_INSTRUCTION_APPLY_ORIGINAL_CONTEXT || len(instructions.Contexts) != 1 {
		return ResultRead{}, ErrUnauthorized
	}
	ref := instructions.Contexts[0]
	record, found := c.contexts[ref.GetResourceId()]
	if !found || ref.GetResourceId() != ids[0] || record.ContextId != ref.GetContextId() || record.Owner != c.principal || !bytes.Equal(record.TargetBinding, s.TargetBinding) {
		return ResultRead{}, ErrOriginalContextUnavailable
	}
	verdict, err := ContextVerdict(record)
	if err != nil {
		return ResultRead{}, err
	}
	return ResultRead{Principal: c.principal, Context: record, Verdict: verdict}, nil
}
