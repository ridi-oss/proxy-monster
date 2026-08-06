package grpcsvc

// GrpcServerTest.kt — 4 cases, the gRPC transport + `x-pm-secret-token` gate tested IN ISOLATION from
// the real handlers' DB work.
//
// The Kotlin's own doc explains the shape and it is worth reproducing rather than folding into the
// end-to-end suite: "a probe service that only reaches the gRPC Context and echoes what it observed.
// This keeps the interceptor test fast + DB-free." Two properties are asserted — the gate is
// fail-closed (wrong/missing secret → UNAUTHENTICATED BEFORE the handler), and it propagates EXACTLY
// the presented token into the handler context, "a null on the open-gate path — never a stale or wrong
// value".
//
// internal/app's TestSecretTokenGateRejectsUnauthenticatedCalls covers the rejection half again over a
// migrated database, and adds the streaming interceptor the Kotlin has no case for. What it cannot
// cover is PROPAGATION: no production handler reads PresentedSecretToken today (F21), so without these
// two cases the forward plumbing of INV-A10-4 has no test at all, and a port that stashed the EXPECTED
// secret instead of the PRESENTED one — or that defaulted the open-gate value to "" — would look green.
//
// The probe also exercises 10-grpc.md §3.3's reason [NewServer] takes the pb.ControlPlaneServer
// INTERFACE: a test can bind a handler without opening the production service.

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
)

// ctxProbeService is the Kotlin's `CtxProbeService`: a Decide handler that reaches the context and
// echoes the propagated secret back in deny_reason, so propagation is observable from the client.
//
// The `<null>` sentinel is the Kotlin's, verbatim: absence has to be distinguishable from the empty
// string, because "" is exactly what a proto3-shaped port would produce for an absent header.
type ctxProbeService struct {
	pb.UnimplementedControlPlaneServer
}

func (ctxProbeService) Decide(ctx context.Context, _ *pb.DecisionRequest) (*pb.WireDecision, error) {
	echoed := "<null>"
	if tok, ok := PresentedSecretToken(ctx); ok {
		echoed = tok
	}
	return &pb.WireDecision{
		Outcome: &pb.WireDecision_Verdict{Verdict: &pb.Verdict{
			Decision:   pb.EnfAction_DENY,
			DenyReason: "ctx:" + echoed,
		}},
	}, nil
}

// discardLogger silences the server's start-time gate-posture line: these cases start five servers and
// the "OPEN — dev only" warning is asserted by nothing here.
func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// probeServer starts a [Server] on an ephemeral port with the probe handler behind the given secret,
// and returns a client. Teardown drains through [Server.Shutdown], which is the force-cancel path
// INV-A10-6 requires.
func probeServer(t *testing.T, secret *string) pb.ControlPlaneClient {
	t.Helper()
	s := NewServer(0, ctxProbeService{}, secret, discardLogger())
	if err := s.Start(); err != nil {
		t.Fatalf("start the probe server: %v", err)
	}
	t.Cleanup(s.Shutdown)

	conn, err := grpc.NewClient(
		fmt.Sprintf("127.0.0.1:%d", s.BoundPort()),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial the probe server: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return pb.NewControlPlaneClient(conn)
}

// callDecide fires one Decide with the given call secret and returns the handler's response. A nil
// callSecret sends NO header at all, which is a different thing from sending an empty one.
func callDecide(t *testing.T, client pb.ControlPlaneClient, callSecret *string) (*pb.WireDecision, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if callSecret != nil {
		ctx = metadata.AppendToOutgoingContext(ctx, SecretTokenMetadataKey, *callSecret)
	}
	return client.Decide(ctx, &pb.DecisionRequest{Token: "t", DatasourceName: "ds", Sql: "select 1"})
}

// decideStatus is the Kotlin's `decideStatus`: the same call, expecting the gate to reject it BEFORE
// the handler, reduced to the resulting status code.
func decideStatus(t *testing.T, client pb.ControlPlaneClient, callSecret *string) codes.Code {
	t.Helper()
	resp, err := callDecide(t, client, callSecret)
	if err == nil {
		t.Fatalf("expected a status error, got a normal return: %v", resp)
	}
	return status.Code(err)
}

// TestCorrectSecretPassesTheGateAndPropagatesTheToken is case 1.
//
// 🔒 INV-A10-4 — the PRESENTED token reaches the handler context verbatim. The Kotlin's phrasing is
// "never a stale or wrong value": a port that stashed the configured secret would be indistinguishable
// here (both are "s3cret"), which is why case 4 pairs with this one — together they pin that the value
// tracks the CALL and not the configuration.
//
// KT: GrpcServerTest.kt#correct secret passes the gate and reaches the handler with the token propagated
func TestCorrectSecretPassesTheGateAndPropagatesTheToken(t *testing.T) {
	secret := "s3cret"
	client := probeServer(t, &secret)

	got, err := callDecide(t, client, &secret)
	if err != nil {
		t.Fatalf("Decide with the correct secret: %v", err)
	}
	if reason := got.GetVerdict().GetDenyReason(); reason != "ctx:s3cret" {
		t.Errorf("the handler observed %q, want \"ctx:s3cret\" — the PRESENTED token must reach the context", reason)
	}
}

// TestWrongSecretIsRejectedUnauthenticatedBeforeTheHandler is case 2.
//
// 🔒 INV-A10-1 — the rejection happens BEFORE the handler, which is what "the request message never
// reaches application code" means in practice. The probe handler cannot fail, so a wrong secret that
// still returned a verdict would prove the gate ran after it; UNAUTHENTICATED with no verdict is the
// only shape that proves it ran first.
//
// KT: GrpcServerTest.kt#wrong secret is rejected UNAUTHENTICATED before the handler
func TestWrongSecretIsRejectedUnauthenticatedBeforeTheHandler(t *testing.T) {
	secret := "s3cret"
	client := probeServer(t, &secret)

	wrong := "wrong"
	if got := decideStatus(t, client, &wrong); got != codes.Unauthenticated {
		t.Errorf("Decide with a wrong secret = %v, want UNAUTHENTICATED", got)
	}
}

// TestMissingSecretIsRejectedUnauthenticatedWhenASecretIsConfigured is case 3: NO header at all, which
// is the case a naive port most easily gets wrong — `md.Get` returns an empty slice, and comparing that
// slice's zero value against the expected secret is the shape that accidentally admits a caller who
// sends nothing when the secret happens to be "".
//
// KT: GrpcServerTest.kt#missing secret is rejected UNAUTHENTICATED when a secret is configured
func TestMissingSecretIsRejectedUnauthenticatedWhenASecretIsConfigured(t *testing.T) {
	secret := "s3cret"
	client := probeServer(t, &secret)

	if got := decideStatus(t, client, nil); got != codes.Unauthenticated {
		t.Errorf("Decide with no secret header = %v, want UNAUTHENTICATED", got)
	}
}

// TestOpenGateReachesTheHandlerWithANullTokenContext is case 4.
//
// 🔒 INV-A10-2 — a nil configured secret OPENS the gate (a documented dev-only state), and INV-A10-4's
// sharp end: what reaches the handler is ABSENCE, not "". The Kotlin asserts the `<null>` sentinel for
// exactly that reason, and [PresentedSecretToken]'s two-value return is what preserves it — a
// single-string port would collapse absence into the empty string and a handler resolving a
// per-datasource secret could not tell "no token presented" from "an empty token presented".
//
// KT: GrpcServerTest.kt#open gate (no secret configured) reaches the handler with a null token context
func TestOpenGateReachesTheHandlerWithANullTokenContext(t *testing.T) {
	client := probeServer(t, nil)

	got, err := callDecide(t, client, nil)
	if err != nil {
		t.Fatalf("Decide against an open gate: %v", err)
	}
	if reason := got.GetVerdict().GetDenyReason(); reason != "ctx:<null>" {
		t.Errorf("the handler observed %q, want \"ctx:<null>\" — an absent token must stay ABSENT, not \"\"", reason)
	}
}

// TestAnOpenGateStillPropagatesAPresentedToken is not a Kotlin case; it is the assertion that makes the
// pair above load-bearing rather than coincidental.
//
// ⚠️ With the gate OPEN a caller may still present a token, and INV-A10-4 says it is propagated
// verbatim — the open gate does not authenticate it, it simply does not check it. A port that only
// stashed the token on the CHECKED path (or that stashed the expected value) passes all four Kotlin
// cases and fails this one, because on the open path there is no expected value to stash.
func TestAnOpenGateStillPropagatesAPresentedToken(t *testing.T) {
	client := probeServer(t, nil)

	presented := "whatever-the-proxy-sent"
	got, err := callDecide(t, client, &presented)
	if err != nil {
		t.Fatalf("Decide against an open gate with a token: %v", err)
	}
	if reason := got.GetVerdict().GetDenyReason(); reason != "ctx:"+presented {
		t.Errorf("the handler observed %q, want %q", reason, "ctx:"+presented)
	}
}

// TestABindFailureIsReturnedNotSwallowed is 🔒 INV-A10-5 (= A1 INV-A1-2), which no Kotlin case covers:
// a control plane that cannot bind its gRPC port must ABORT, not come up serving only HTTP with the
// data plane silently dead. [Server.Start] returning the error is what lets main do that.
func TestABindFailureIsReturnedNotSwallowed(t *testing.T) {
	first := NewServer(0, ctxProbeService{}, nil, discardLogger())
	if err := first.Start(); err != nil {
		t.Fatalf("start the first server: %v", err)
	}
	t.Cleanup(first.Shutdown)

	second := NewServer(first.BoundPort(), ctxProbeService{}, nil, discardLogger())
	if err := second.Start(); err == nil {
		second.Shutdown()
		t.Fatal("Start on an occupied port returned nil; a bind failure must be fatal to the caller")
	} else if !strings.Contains(err.Error(), "control-plane gRPC bind") {
		t.Errorf("bind error = %v, want it to name the port it could not bind", err)
	}
}
