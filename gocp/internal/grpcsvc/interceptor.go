package grpcsvc

import (
	"context"
	"crypto/subtle"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// SecretTokenMetadataKey is `WireMetadata.SECRET_TOKEN_KEY` — the header authenticating the PROXY to
// the control plane. Distinct from DecisionRequest.token / ValidateTokenRequest.token, which
// authenticate the DB CLIENT and are re-resolved server-side on every call.
const SecretTokenMetadataKey = "x-pm-secret-token"

// secretTokenCtxKey is `WireMetadata.SECRET_TOKEN_CTX`.
type secretTokenCtxKey struct{}

// PresentedSecretToken reads the token the interceptor stashed on the context.
//
// 🔒 INV-A10-4 — the presented token is propagated VERBATIM, INCLUDING absence, "so handlers can
// resolve a per-datasource secret later" and never a stale or wrong value. ok=false is Kotlin's null.
// F21 records that no production handler reads it today; this is forward plumbing whose only current
// consumer is the test probe.
func PresentedSecretToken(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(secretTokenCtxKey{}).(*string)
	if !ok || v == nil {
		return "", false
	}
	return *v, true
}

// SecretTokenInterceptor is `class SecretTokenInterceptor(expected: String?)`.
//
// 🔒 INV-A10-1 — the gate runs on EVERY RPC, BEFORE any handler. Because a rejected call is closed
// before the handler is invoked, its request message never reaches application code.
//
// 🔒 INV-A10-2 — a nil `expected` OPENS the gate, and that is a documented dev-only state, logged
// loudly at start ("OPEN — dev only"). A port must not "helpfully" reject an empty secret in the open
// configuration: PM_SECRET_TOKEN unset is a supported local-dev mode whose production guard lives in
// A1's Config.
//
// 🔒 INV-A10-3 — the comparison is CONSTANT-TIME and an absent presented token never matches. Do not
// use == or bytes.Equal. Java's MessageDigest.isEqual leaks the length but not the content;
// crypto/subtle.ConstantTimeCompare returns 0 immediately on a length mismatch — the same leak, so
// the two are equivalent for this purpose.
type SecretTokenInterceptor struct {
	expected *string
}

// NewSecretTokenInterceptor builds the gate. A nil expected leaves it open.
func NewSecretTokenInterceptor(expected *string) *SecretTokenInterceptor {
	return &SecretTokenInterceptor{expected: expected}
}

// Configured reports whether a secret is set — what GrpcServer's start log prints.
func (i *SecretTokenInterceptor) Configured() bool { return i.expected != nil }

const missingOrInvalidSecret = "missing or invalid x-pm-secret-token"

// check is the shared body of the two interceptors. It returns the new context on success.
func (i *SecretTokenInterceptor) check(ctx context.Context) (context.Context, error) {
	var presented *string
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get(SecretTokenMetadataKey); len(vals) > 0 {
			v := vals[0]
			presented = &v
		}
	}
	if i.expected != nil && !constantTimeEquals(presented, *i.expected) {
		return nil, status.Error(codes.Unauthenticated, missingOrInvalidSecret)
	}
	return context.WithValue(ctx, secretTokenCtxKey{}, presented), nil
}

// Unary is the grpc.UnaryServerInterceptor half.
func (i *SecretTokenInterceptor) Unary(
	ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (any, error) {
	next, err := i.check(ctx)
	if err != nil {
		return nil, err
	}
	return handler(next, req)
}

// Stream is the grpc.StreamServerInterceptor half.
//
// ⚠️ GO REQUIRES TWO INTERCEPTORS where Java's single ServerInterceptor covers both call shapes.
// Registering only [SecretTokenInterceptor.Unary] leaves Events, RunExec and TableDetailExec
// UNGATED — 10-grpc.md §3.4 calls that "the single most dangerous mechanical mistake available in
// this area". TestSecretTokenGateRejectsStreamingRPC is the regression test.
func (i *SecretTokenInterceptor) Stream(
	srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler,
) error {
	next, err := i.check(ss.Context())
	if err != nil {
		return err
	}
	return handler(srv, &contextServerStream{ServerStream: ss, ctx: next})
}

// contextServerStream overrides Context() so the stashed token reaches a streaming handler, which is
// the stream-side equivalent of Contexts.interceptCall.
type contextServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *contextServerStream) Context() context.Context { return s.ctx }

// constantTimeEquals is `constantTimeEquals(a: String?, b: String)`: a nil presented token is a plain
// false, handled before any byte work.
func constantTimeEquals(presented *string, expected string) bool {
	if presented == nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(*presented), []byte(expected)) == 1
}

// logGatePosture is the start-time log GrpcServer emits. Split out so both the server and a test can
// assert the wording of the dev-only warning (INV-A10-2).
func logGatePosture(log *slog.Logger, port int, configured bool) {
	posture := "OPEN — dev only"
	if configured {
		posture = "enabled"
	}
	log.Info("control-plane gRPC listening", "port", port, "secret-token gate", posture)
}
