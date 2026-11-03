package workload

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	bridgepb "github.com/ridi-oss/proxy-monster/cpgo/gobridge/pb"
)

type BridgeService struct {
	bridgepb.UnimplementedWorkloadBindingsServer
	issuers []Issuer
	pool    atomic.Pointer[pgxpool.Pool]
}

func NewBridgeService(issuers []Issuer) *BridgeService { return &BridgeService{issuers: issuers} }

func (s *BridgeService) Ready(pool *pgxpool.Pool) { s.pool.Store(pool) }

func (s *BridgeService) db() (*pgxpool.Pool, error) {
	if p := s.pool.Load(); p != nil {
		return p, nil
	}
	return nil, grpcstatus.Error(codes.Unavailable, "control-plane store not open yet")
}

func (s *BridgeService) ListBindings(ctx context.Context, _ *bridgepb.ListBindingsRequest) (*bridgepb.ListBindingsResponse, error) {
	pool, err := s.db()
	if err != nil {
		return nil, err
	}
	all, err := listBindings(ctx, pool)
	if err != nil {
		return nil, bridgeError(err)
	}
	out := &bridgepb.ListBindingsResponse{}
	for _, b := range all {
		out.Bindings = append(out.Bindings, toPB(b))
	}
	return out, nil
}

func (s *BridgeService) CreateBinding(ctx context.Context, in *bridgepb.WriteBindingRequest) (*bridgepb.WorkloadBinding, error) {
	return s.write(ctx, in, func(ctx context.Context, tx pgx.Tx, actor audit.Actor, v validBinding) (*Binding, error) {
		return createBinding(ctx, tx, actor, v)
	})
}

func (s *BridgeService) UpdateBinding(ctx context.Context, in *bridgepb.WriteBindingRequest) (*bridgepb.WorkloadBinding, error) {
	return s.write(ctx, in, func(ctx context.Context, tx pgx.Tx, actor audit.Actor, v validBinding) (*Binding, error) {
		id, err := bindingID(ctx, tx, v.name)
		if err != nil {
			return nil, err
		}
		return updateBinding(ctx, tx, actor, id, v)
	})
}

func (s *BridgeService) DeleteBinding(ctx context.Context, in *bridgepb.DeleteBindingRequest) (*bridgepb.DeleteBindingResponse, error) {
	pool, err := s.db()
	if err != nil {
		return nil, err
	}
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		id, err := bindingID(ctx, tx, in.GetName())
		if err != nil {
			return err
		}
		return deleteBinding(ctx, tx, caller(in.GetCaller()), id)
	})
	if err != nil {
		return nil, bridgeError(err)
	}
	return &bridgepb.DeleteBindingResponse{}, nil
}

type writeFunc func(context.Context, pgx.Tx, audit.Actor, validBinding) (*Binding, error)

func (s *BridgeService) write(ctx context.Context, in *bridgepb.WriteBindingRequest, f writeFunc) (*bridgepb.WorkloadBinding, error) {
	pool, err := s.db()
	if err != nil {
		return nil, err
	}
	v, err := fromPB(in.GetBinding()).validate(s.issuers)
	if err != nil {
		return nil, bridgeError(err)
	}
	var out *Binding
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		out, err = f(ctx, tx, caller(in.GetCaller()), v)
		return err
	})
	if err != nil {
		return nil, bridgeError(err)
	}
	return toPB(*out), nil
}

func caller(c *bridgepb.BindingCaller) audit.Actor {
	return audit.Actor{Principal: c.GetPrincipal(), ClientAddr: c.GetClientAddr(), Channel: "mcp"}
}

func fromPB(in *bridgepb.WorkloadBindingInput) bindingInput {
	name, issuer, subject := in.GetName(), in.GetIssuer(), in.GetSubject()
	out := bindingInput{Name: &name, Issuer: &issuer, Subject: &subject, Description: in.Description, Principal: in.Principal,
		Purposes: in.GetPurposes(), MCPScopes: in.GetMcpScopes(), TTLSeconds: in.TtlSeconds, Enabled: in.Enabled}
	if len(in.GetConditions()) > 0 {
		out.Conditions = map[string]json.RawMessage{}
		for k, v := range in.GetConditions() {
			raw, _ := json.Marshal(append([]string{}, v.GetValues()...))
			out.Conditions[k] = raw
		}
	}
	return out
}

func toPB(b Binding) *bridgepb.WorkloadBinding {
	out := &bridgepb.WorkloadBinding{Id: b.ID, Name: b.Name, Description: b.Description, Issuer: b.Issuer, Subject: b.Subject,
		Conditions: map[string]*bridgepb.ConditionValues{}, Principal: b.Principal, Purposes: b.Purposes, McpScopes: b.MCPScopes,
		TtlSeconds: b.TTLSeconds, Enabled: b.Enabled, CreatedAt: b.CreatedAt, UpdatedAt: b.UpdatedAt}
	for k, v := range b.Conditions {
		out.Conditions[k] = &bridgepb.ConditionValues{Values: v}
	}
	return out
}

func bridgeError(err error) error {
	var me *api.ManagementError
	if !errors.As(err, &me) {
		return grpcstatus.Error(codes.Internal, err.Error())
	}
	detail := &bridgepb.WorkloadBindingError{Code: me.Error()}
	for _, kv := range me.Params {
		detail.Params = append(detail.Params, &bridgepb.BindingErrorParam{Key: kv[0], Value: kv[1]})
	}
	st, derr := grpcstatus.New(codes.FailedPrecondition, me.Error()).WithDetails(detail)
	if derr != nil {
		return grpcstatus.Error(codes.Internal, me.Error())
	}
	return st.Err()
}
