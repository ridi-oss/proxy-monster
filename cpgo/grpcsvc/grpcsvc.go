// Package grpcsvc serves the ControlPlane RPCs Go owns. Every other method keeps falling through to the
// Kotlin control plane, because the service registered here lists only these.
package grpcsvc

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/ridi-oss/proxy-monster/auditmon/canon"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/authz"
	pb "github.com/ridi-oss/proxy-monster/cpgo/internal/pb"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

// owned is every ControlPlane method this package serves.
var owned = []string{"ReportCompletion", "AuthorizeRequest"}

type service struct {
	pb.UnimplementedControlPlaneServer
	pool  *pgxpool.Pool
	authz *authz.Engine
}

// Register adds Go's ControlPlane methods to s; engine decides their Cedar questions.
func Register(s *grpc.Server, pool *pgxpool.Pool, engine *authz.Engine) {
	desc := pb.ControlPlane_ServiceDesc
	desc.Methods = slices.DeleteFunc(slices.Clone(desc.Methods), func(m grpc.MethodDesc) bool { return !slices.Contains(owned, m.MethodName) })
	desc.Streams = nil
	s.RegisterService(&desc, &service{pool: pool, authz: engine})
}

// SecretToken is SecretTokenInterceptor: with a secret set, a call without a matching x-pm-secret-token
// is UNAUTHENTICATED. It guards only Go's methods; forwarded calls are checked by Kotlin.
func SecretToken(expected string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if expected != "" {
			md, _ := metadata.FromIncomingContext(ctx)
			presented := md.Get("x-pm-secret-token")
			if len(presented) == 0 || subtle.ConstantTimeCompare([]byte(presented[0]), []byte(expected)) != 1 {
				return nil, status.Error(codes.Unauthenticated, "missing or invalid x-pm-secret-token")
			}
		}
		return handler(ctx, req)
	}
}

var completionStatuses = []string{"ok", "error", "canceled"}

// ReportCompletion records the proxy's outcome for a decision and settles the wire task it opened, if any.
func (s *service) ReportCompletion(ctx context.Context, r *pb.CompletionReport) (*emptypb.Empty, error) {
	if r.GetDecisionId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "decision_id must reference a recorded decision")
	}
	if !slices.Contains(completionStatuses, r.GetStatus()) {
		return nil, status.Error(codes.InvalidArgument, "status must be one of ok|error|canceled")
	}
	row, err := db.New(s.pool).DecisionEvent(ctx, r.GetDecisionId())
	ev := canon.AuditEvent{Principal: row.Principal, Datasource: row.Datasource, Statement: row.Statement, Decision: row.Decision, Channel: row.Channel}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, status.Errorf(codes.NotFound, "unknown decision_id %d", r.GetDecisionId())
	}
	if err != nil {
		return nil, err
	}
	decisionID, rows, bytes, outcome := r.GetDecisionId(), r.GetRowsReturned(), r.GetBytesReturned(), r.GetStatus()
	ev.Kind, ev.Roles, ev.DecisionID, ev.RowsReturned, ev.BytesReturned = "completion", []string{}, &decisionID, &rows, &bytes
	ev.Outcome, ev.LatencyMs = &outcome, r.GetDurationMs()
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := audit.Insert(ctx, tx, ev); err != nil {
			return err
		}
		q := db.New(tx)
		task, err := q.WireTaskOfDecision(ctx, &decisionID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		now := time.Now()
		claimed, err := q.ClaimWireTask(ctx, db.ClaimWireTaskParams{ExecutingAt: &now, ID: task})
		if err != nil || claimed == 0 {
			return err
		}
		var settled int64
		if outcome == "ok" {
			settled, err = q.SettleWireTaskExecuted(ctx, db.SettleWireTaskExecutedParams{ExecutedAt: &now, ID: task})
		} else {
			settled, err = q.SettleWireTaskFailed(ctx, task)
		}
		if err == nil && settled == 0 {
			err = fmt.Errorf("wire task %d left EXECUTING", task)
		}
		return err
	})
	if err != nil {
		if _, ok := status.FromError(err); !ok {
			err = status.Error(codes.Unknown, err.Error())
		}
		return nil, err
	}
	return &emptypb.Empty{}, nil
}
