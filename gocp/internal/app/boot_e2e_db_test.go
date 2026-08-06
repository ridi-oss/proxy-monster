package app_test

// The RUNNABILITY PROOF for the Go control plane.
//
// Everything else in this module is a library. This file boots the real [app.Boot] wiring — config →
// pool → Flyway migrations → the ONE shared ControlPlaneCore → gRPC server → HTTP server — against a
// real PostgreSQL container on EPHEMERAL PORTS, then talks to it over the wire with the generated
// gRPC client and an ordinary HTTP client. Nothing is stubbed: the decision that comes back is
// produced by internal/query.DecideQuery reading a catalog the "proxy" pushed over
// PushSchemaFragment, and the audit rows it writes are in the real hash chain.
//
// The three things it must prove, from the increment's brief:
//  1. GET /health returns 200 with the expected shape;
//  2. a gRPC Decide round-trip over the wire returns a correct verdict for a seeded
//     datasource + catalog;
//  3. the secret-token interceptor REJECTS a call with a wrong/missing token when PM_SECRET_TOKEN is
//     set — on a STREAMING RPC as well as a unary one, because registering only the unary
//     interceptor is the single most dangerous mechanical mistake available in A10 (§3.4).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/app"
	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/token"
)

const (
	e2ePrincipal = "analyst@example.com"
	e2eRole      = "analyst"
	e2eSecret    = "e2e-shared-transport-secret"
	e2eSchema    = "public"
	e2eTable     = "app_users"
)

// bootedApp is one running control plane plus the handles a test needs to talk to it.
type bootedApp struct {
	app    *app.App
	client pb.ControlPlaneClient
	// authed carries the secret-token header; anon carries nothing.
	authed context.Context
	dbName string
}

// bootE2E starts the real process wiring on ephemeral ports against a fresh logical database.
//
// PM_HTTP_PORT and PM_GRPC_PORT are both 0, so the OS assigns them and the test reads them back —
// which is also what proves the ephemeral-port readback A10 §3.3 calls load-bearing works.
func bootE2E(t *testing.T, secret *string) *bootedApp {
	t.Helper()
	backend := dbtest.Postgres(t)
	dbName := dbtest.FreshPostgresDatabase(t, "e2e")

	env := map[string]string{
		"PM_HTTP_PORT": "0",
		"PM_GRPC_PORT": "0",
		"PM_DB_URL":    backend.PostgresJDBCURL(dbName),
		"PM_DB_USER":   "proxymonster",
		// PM_AUTH_DEBUG defaults to TRUE and validation rule V5 permits that only in a
		// non-production-looking context: no OIDC config and the dev session secret, which is what
		// this env is. The banner in the boot log is the visible half of that posture.
		"PM_DEV": "true",
	}
	if secret != nil {
		env["PM_SECRET_TOKEN"] = *secret
	}
	cfg, err := config.FromEnv(config.EnvOf(env))
	if err != nil {
		t.Fatalf("config rejected: %v", err)
	}
	// The container's superuser owns the fresh database; PM_DB_PASSWORD's default matches the image's.
	cfg.DBUser, cfg.DBPassword = credsFromJDBC(t, backend.PostgresDSN(dbName))

	a, err := app.Boot(cfg, app.Options{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	if err := a.StartHTTP(); err != nil {
		t.Fatalf("StartHTTP: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		a.Shutdown(ctx)
	})

	conn, err := grpc.NewClient(
		fmt.Sprintf("127.0.0.1:%d", a.Grpc.BoundPort()),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial gRPC: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	authed := context.Background()
	if secret != nil {
		authed = metadata.AppendToOutgoingContext(authed, "x-pm-secret-token", *secret)
	}
	return &bootedApp{app: a, client: pb.NewControlPlaneClient(conn), authed: authed, dbName: dbName}
}

// credsFromJDBC pulls the user/password out of the container DSN dbtest already built, so the test
// does not re-hardcode the image's credentials.
func credsFromJDBC(t *testing.T, dsn string) (string, string) {
	t.Helper()
	// postgres://user:pass@host:port/db?...
	rest, ok := strings.CutPrefix(dsn, "postgres://")
	if !ok {
		t.Fatalf("unexpected DSN shape: %s", dsn)
	}
	creds, _, ok := strings.Cut(rest, "@")
	if !ok {
		t.Fatalf("unexpected DSN shape: %s", dsn)
	}
	user, pass, ok := strings.Cut(creds, ":")
	if !ok {
		t.Fatalf("unexpected DSN shape: %s", dsn)
	}
	return user, pass
}

// ---- 1. /health -------------------------------------------------------------------------------

// TestHealthRouteReportsOkAndDiagnostics is the HTTP half of the runnability proof.
//
// It also pins ReadinessDiagnosticDbTest case 2's contract: on a clean install the response is 200
// with `diagnostics = ["system:admin role has no active assignee"]`, and STATUS STAYS "ok" — an
// unopened install is reported, not marked down. A readiness probe that failed here would prevent the
// very first login that fixes it.
func TestHealthRouteReportsOkAndDiagnostics(t *testing.T) {
	b := bootE2E(t, nil)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/health", b.app.HTTPPort()))
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /health status = %d, want 200", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)

	var body app.HealthResponse
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode /health body %q: %v", raw, err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want ok (an unopened install is reported, never marked down)", body.Status)
	}
	if !contains(body.Diagnostics, "system:admin role has no active assignee") {
		t.Errorf("diagnostics = %v, want it to report the unassigned system:admin role", body.Diagnostics)
	}
	// INV-A1-4: `diagnostics` is always PRESENT as an array, never null.
	if !strings.Contains(string(raw), `"diagnostics":[`) {
		t.Errorf("body = %s, want diagnostics emitted as a JSON array", raw)
	}
}

// ---- 2. the gRPC Decide round trip ------------------------------------------------------------

// TestGrpcDecideRoundTripOverTheWire is the whole point of this increment.
//
// It drives the REAL proxy handshake in order — Register, PushCatalog, ValidateToken, Decide,
// PushSchemaFragment, Decide, ReportCompletion — over a socket, and asserts the enforcement answers
// at each step.
//
// 🔒 The first Decide MUST be a before_decide, not a verdict: the connection holds no schema fragment
// yet, so A5's freshness pre-gate fires BEFORE any analysis and before any audit row (INV-A5-49). A
// port that answered with a verdict there would be authorizing against a catalog it never verified.
func TestGrpcDecideRoundTripOverTheWire(t *testing.T) {
	secret := e2eSecret
	b := bootE2E(t, &secret)
	ctx := b.authed
	dsName := "e2e-postgres"

	// --- Register: the proxy declares its own identity on boot. The control plane never dials the
	// target and holds no credential for it.
	reg, err := b.client.Register(ctx, &pb.RegisterRequest{
		Name:   dsName,
		Engine: enginepb.Engine_POSTGRES,
		Host:   "127.0.0.1",
		Port:   5432,
		DbName: b.dbName,
		// ⚠️ NO POSTURE TAG, deliberately: empty tags means the PRODUCTION FLOOR via deny-by-default
		// (controlplane.proto's `tags` comment). Tagging this `system:development` would pull in the
		// shipped dev relaxation `permit(principal, action == "result.read.unmasked", resource) when
		// { resource in Tag::"system:development" }` (V8__seed.sql:195), which grants unmasked reads of
		// EVERY column on the datasource — and the deny-by-default assertion further down would then
		// pass for the wrong reason, or rather fail loudly, as it did when this test was first written.
		Tags: nil,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if reg.GetName() != dsName {
		t.Fatalf("Register echoed %q, want %q", reg.GetName(), dsName)
	}

	// --- PushCatalog: the config catalog plus the namespace metadata decideQuery reads.
	cat, err := b.client.PushCatalog(ctx, &pb.CatalogRequest{
		DatasourceName: dsName,
		DefaultSchemas: []string{e2eSchema},
		EngineVersion:  "PostgreSQL 17.2 on aarch64-unknown-linux-gnu",
		Columns:        e2eColumns(),
	})
	if err != nil {
		t.Fatalf("PushCatalog: %v", err)
	}
	if cat.GetColumns() != int32(len(e2eColumns())) {
		t.Fatalf("PushCatalog stored %d columns, want %d", cat.GetColumns(), len(e2eColumns()))
	}

	// --- Seed identity + policy. Done AFTER Register so the Cedar Table EUID can name the datasource,
	// and BEFORE the first decision so the engine's first PolicySet build already sees it.
	seedE2EPolicy(t, b, dsName)
	rawToken := issueE2EToken(t, b, token.KindUser)

	// --- ValidateToken: the once-per-session handshake.
	identity, err := b.client.ValidateToken(ctx, &pb.ValidateTokenRequest{Token: rawToken, DatasourceName: dsName})
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if identity.GetPrincipal() != e2ePrincipal {
		t.Fatalf("ValidateToken principal = %q, want %q", identity.GetPrincipal(), e2ePrincipal)
	}
	// 🔒 INV-A10-18 — the connection id is 128 CSPRNG bits and both directions enforce the length.
	if len(identity.GetConnectionId()) != 16 {
		t.Fatalf("connection_id is %d bytes, want exactly 16", len(identity.GetConnectionId()))
	}
	connID := identity.GetConnectionId()
	// The on-open plan is one Refetch per default + system schema.
	if !hasRefetchFor(identity.GetOnOpen(), e2eSchema) {
		t.Fatalf("on_open = %v, want a Refetch for %q", identity.GetOnOpen(), e2eSchema)
	}

	decideReq := func() *pb.DecisionRequest {
		return &pb.DecisionRequest{
			Token:          rawToken,
			DatasourceName: dsName,
			Sql:            fmt.Sprintf("select id, email from %s", e2eTable),
			SearchPath:     []string{e2eSchema},
			ClientAddr:     "10.1.2.3:54321",
			ConnectionId:   connID,
		}
	}

	// --- Decide #1: before_decide. No verdict, and (INV-A5-49) no audit row.
	first, err := b.client.Decide(ctx, decideReq())
	if err != nil {
		t.Fatalf("Decide (pre-fragment): %v", err)
	}
	if first.GetVerdict() != nil {
		t.Fatalf("Decide before any fragment returned a verdict %v; the freshness pre-gate must fire first", first.GetVerdict())
	}
	if first.GetBeforeDecide() == nil {
		t.Fatal("Decide before any fragment set NEITHER outcome arm — a message with neither must never be produced (INV-A10-38)")
	}
	if !hasRefetchFor(first.GetBeforeDecide().GetCommands(), e2eSchema) {
		t.Fatalf("before_decide commands = %v, want a Refetch for %q", first.GetBeforeDecide().GetCommands(), e2eSchema)
	}

	// --- PushSchemaFragment: the proxy answers the pending REFETCH off its held connection.
	ack, err := b.client.PushSchemaFragment(ctx, &pb.SchemaFragmentPush{
		ConnectionId:      connID,
		DatasourceName:    dsName,
		Schema:            e2eSchema,
		ContentHash:       []byte("e2e-content-hash-v1"),
		Columns:           e2eColumns(),
		BackendGeneration: 1,
	})
	if err != nil {
		t.Fatalf("PushSchemaFragment: %v", err)
	}
	if ack.GetGeneration() == 0 {
		t.Fatal("PushSchemaFragment ack carried generation 0; an accepted push advances the connection generation")
	}

	// --- Decide #2: the verdict.
	second, err := b.client.Decide(ctx, decideReq())
	if err != nil {
		t.Fatalf("Decide (post-fragment): %v", err)
	}
	verdict := second.GetVerdict()
	if verdict == nil {
		t.Fatalf("Decide after the fragment returned %v, want a verdict", second)
	}
	if verdict.GetDecision() != pb.EnfAction_ALLOW {
		t.Fatalf("decision = %v (deny_reason %q), want ALLOW for a granted select",
			verdict.GetDecision(), verdict.GetDenyReason())
	}
	if !contains(verdict.GetEffectiveRoles(), e2eRole) {
		t.Errorf("effective_roles = %v, want the SERVER-RESOLVED %q", verdict.GetEffectiveRoles(), e2eRole)
	}
	// 🔒 INV-A10-37 — rewritten_sql is left UNSET when there is no `*`-expansion rewrite; "" would make
	// the proxy send an empty query.
	if verdict.RewrittenSql != nil {
		t.Errorf("rewritten_sql = %q, want ABSENT for a query with no `*` to expand", verdict.GetRewrittenSql())
	}
	if verdict.GetDecisionId() == 0 {
		t.Fatal("decision_id = 0 on a verdict; the audit row must have been written and referenced")
	}
	if verdict.GetGeneration() != ack.GetGeneration() {
		t.Errorf("verdict generation = %d, want the analyzed generation %d (INV-A5-48)",
			verdict.GetGeneration(), ack.GetGeneration())
	}

	// --- Deny-by-default, on the same connection: a table no grant covers.
	denyReq := decideReq()
	denyReq.Sql = "select * from ungranted_orders"
	deniedResp, err := b.client.Decide(ctx, denyReq)
	if err != nil {
		t.Fatalf("Decide (ungranted table): %v", err)
	}
	if d := deniedResp.GetVerdict(); d == nil || d.GetDecision() != pb.EnfAction_DENY {
		t.Fatalf("ungranted table decided %v, want DENY — deny-by-default must never fall through", deniedResp)
	}

	// --- ReportCompletion: the post-relay volume signal, chained onto the decision's audit row.
	if _, err := b.client.ReportCompletion(ctx, &pb.CompletionReport{
		DecisionId: verdict.GetDecisionId(), RowsReturned: 2, BytesReturned: 96, Status: "ok", DurationMs: 7,
	}); err != nil {
		t.Fatalf("ReportCompletion: %v", err)
	}
	// Both request guards run BEFORE any DB work (INV-A10-22), so a malformed report cannot write an
	// uninterpretable outcome into the audit trail.
	_, err = b.client.ReportCompletion(ctx, &pb.CompletionReport{DecisionId: verdict.GetDecisionId(), Status: "weird"})
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Errorf("ReportCompletion with an unknown status → %v, want INVALID_ARGUMENT", got)
	}
	if err != nil && !strings.Contains(err.Error(), "status must be one of ok|error|canceled") {
		t.Errorf("ReportCompletion error = %q, want the verbatim ok|error|canceled message", err)
	}

	// --- The audit chain now holds the decision and its completion.
	var decisions, completions int
	row := b.app.Db.Pool.QueryRow(context.Background(),
		`SELECT count(*) FILTER (WHERE kind='decision'), count(*) FILTER (WHERE kind='completion') FROM audit_event`)
	if err := row.Scan(&decisions, &completions); err != nil {
		t.Fatalf("read audit_event: %v", err)
	}
	if decisions != 2 {
		t.Errorf("audit_event decision rows = %d, want 2 (the ALLOW and the DENY; a before_decide writes NONE)", decisions)
	}
	if completions != 1 {
		t.Errorf("audit_event completion rows = %d, want 1", completions)
	}
}

// TestDecideRejectsAMalformedConnectionID pins INV-A10-18's control-plane half, which 10-grpc.md §3.1
// records as asserted by NO test anywhere in the Kotlin ("add a case before porting").
func TestDecideRejectsAMalformedConnectionID(t *testing.T) {
	b := bootE2E(t, nil)
	dsName := "e2e-shortid"
	mustRegister(t, b, dsName)
	rawToken := issueE2EToken(t, b, token.KindUser)

	_, err := b.client.Decide(context.Background(), &pb.DecisionRequest{
		Token:          rawToken,
		DatasourceName: dsName,
		Sql:            "select 1",
		ConnectionId:   []byte{1, 2, 3},
	})
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("Decide with a 3-byte connection_id → %v, want INVALID_ARGUMENT", got)
	}
	if !strings.Contains(err.Error(), "connection_id must be exactly 16 bytes") {
		t.Errorf("error = %q, want the verbatim 16-byte message", err)
	}
}

// TestDecideRejectsARevokedToken pins INV-A10-9: the RAW token is re-validated on EVERY query, so a
// mid-session revocation takes effect on the NEXT query rather than at session end — and the failure
// is UNAUTHENTICATED (so the proxy tears the session down), never a DENY verdict (INV-A10-11).
func TestDecideRejectsARevokedToken(t *testing.T) {
	b := bootE2E(t, nil)
	dsName := "e2e-revoke"
	mustRegister(t, b, dsName)

	rawToken := issueE2EToken(t, b, token.KindUser)
	identity, err := b.client.ValidateToken(context.Background(), &pb.ValidateTokenRequest{
		Token: rawToken, DatasourceName: dsName,
	})
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}

	if _, err := b.app.Db.Pool.Exec(context.Background(),
		`UPDATE proxy_token SET revoked_at = now() WHERE token_hash = $1`, token.Hash(rawToken)); err != nil {
		t.Fatalf("revoke token: %v", err)
	}

	_, err = b.client.Decide(context.Background(), &pb.DecisionRequest{
		Token: rawToken, DatasourceName: dsName, Sql: "select 1", ConnectionId: identity.GetConnectionId(),
	})
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Fatalf("Decide with a revoked token → %v, want UNAUTHENTICATED", got)
	}
}

// TestValidateTokenRejectsAnEphemeralKind pins INV-A10-21 AT THE RPC, which the Kotlin suite does not
// cover: its case 13 calls TokenStore.validate directly, so nothing there proves ValidateToken the
// RPC refuses an editor token. A leaked ephemeral token must not open a native wire session.
func TestValidateTokenRejectsAnEphemeralKind(t *testing.T) {
	b := bootE2E(t, nil)
	dsName := "e2e-ephemeral"
	mustRegister(t, b, dsName)

	for _, kind := range []token.Kind{token.KindEditor, token.KindApproverExec} {
		raw := issueE2EToken(t, b, kind)
		_, err := b.client.ValidateToken(context.Background(), &pb.ValidateTokenRequest{
			Token: raw, DatasourceName: dsName,
		})
		if got := status.Code(err); got != codes.Unauthenticated {
			t.Errorf("ValidateToken with a %s token → %v, want UNAUTHENTICATED", kind, got)
		}
		// The same token must still RESOLVE on the per-query path — that asymmetry is the whole point.
		if id, err := b.app.Core.TokenStore.Resolve(context.Background(), raw); err != nil || id == nil {
			t.Errorf("resolve(%s) = %v, %v; the per-query path must still accept it", kind, id, err)
		}
	}
}

// TestPostCloseDecideReuseIsRecovered is a CHARACTERIZATION TEST FOR A DOCUMENTED DEFECT (F29,
// INV-A10-20), carried forward from the Kotlin's `@Disabled`/loud-characterization pair.
//
// ⚠️ It asserts the BUGGY behaviour on purpose. A closed — or forged — connection_id is RECOVERED by
// Decide rather than rejected, because there is no tombstone and no mint evidence. The recovery is
// deliberate (it is how a control-plane restart re-learns live proxy connections) and its blast radius
// is bounded, since recovery re-binds to (datasource, principal, kind) from the FRESHLY-RESOLVED
// token. But it is a defect, and this test is its record: the desired behaviour is the sibling the
// Kotlin disables, "post-close Decide reuse is rejected". Making this test fail is the fix.
//
// KT-DEFER: GrpcPerConnectionCatalogDbTest.kt#post-close Decide reuse is rejected — the Kotlin marks it @Disabled
//
//	("closed/forged connection_id is recovered by Decide — no tombstone/mint-evidence"), so it asserts a REJECTION and
//	never runs. This test asserts the OPPOSITE, that the id is RECOVERED, so it cannot be a coverage claim for it.
//	Blocked on a connection tombstone or mint evidence (F29 / INV-A10-20); when that lands this test flips and the case
//	becomes portable. Matches how the suite's other @Disabled case is already accounted
//	(perconnectioncatalog_adversarial_db_test.go:267).
func TestPostCloseDecideReuseIsRecovered(t *testing.T) {
	b := bootE2E(t, nil)
	dsName := "e2e-postclose"
	mustRegister(t, b, dsName)
	rawToken := issueE2EToken(t, b, token.KindUser)

	identity, err := b.client.ValidateToken(context.Background(), &pb.ValidateTokenRequest{
		Token: rawToken, DatasourceName: dsName,
	})
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	connID := identity.GetConnectionId()

	if _, err := b.client.CloseConnection(context.Background(), &pb.CloseConnectionRequest{
		ConnectionId: connID, DatasourceName: dsName,
	}); err != nil {
		t.Fatalf("CloseConnection: %v", err)
	}
	// The id really is gone from the registry.
	if _, err := b.client.PushSchemaFragment(context.Background(), &pb.SchemaFragmentPush{
		ConnectionId: connID, DatasourceName: dsName, Schema: e2eSchema,
	}); status.Code(err) != codes.NotFound {
		t.Fatalf("PushSchemaFragment on a closed id → %v, want NOT_FOUND", status.Code(err))
	}

	// …and yet Decide RECOVERS it, answering before_decide rather than refusing.
	resp, err := b.client.Decide(context.Background(), &pb.DecisionRequest{
		Token: rawToken, DatasourceName: dsName, Sql: "select 1",
		SearchPath: []string{e2eSchema}, ConnectionId: connID,
	})
	if err != nil {
		t.Fatalf("Decide on a closed connection_id → %v; the DEFECT is that it succeeds, so an error here "+
			"means the behaviour changed and F29's record needs updating", err)
	}
	if resp.GetBeforeDecide() == nil {
		t.Fatalf("Decide on a closed connection_id = %v, want the recovery's before_decide", resp)
	}
}

// ---- 3. the secret-token gate -----------------------------------------------------------------

// TestSecretTokenGateRejectsUnauthenticatedCalls proves INV-A10-1 and INV-A10-3 over the wire.
func TestSecretTokenGateRejectsUnauthenticatedCalls(t *testing.T) {
	secret := e2eSecret
	b := bootE2E(t, &secret)

	cases := []struct {
		name string
		ctx  context.Context
	}{
		{"no header at all", context.Background()},
		{"wrong secret", metadata.AppendToOutgoingContext(context.Background(), "x-pm-secret-token", "not-the-secret")},
		{"empty secret", metadata.AppendToOutgoingContext(context.Background(), "x-pm-secret-token", "")},
		// A prefix of the real secret: the comparison must be constant-time over the WHOLE value, so a
		// length-truncated guess is no closer than any other wrong value.
		{"prefix of the secret", metadata.AppendToOutgoingContext(context.Background(), "x-pm-secret-token", e2eSecret[:10])},
	}
	for _, tc := range cases {
		t.Run("unary/"+tc.name, func(t *testing.T) {
			_, err := b.client.Register(tc.ctx, &pb.RegisterRequest{Name: "x", Engine: enginepb.Engine_POSTGRES})
			if got := status.Code(err); got != codes.Unauthenticated {
				t.Fatalf("Register → %v, want UNAUTHENTICATED", got)
			}
			if !strings.Contains(err.Error(), "missing or invalid x-pm-secret-token") {
				t.Errorf("error = %q, want the verbatim gate message", err)
			}
		})
	}

	// 🔒 THE STREAMING HALF. Go needs TWO interceptors where Java's ServerInterceptor covers both call
	// shapes; registering only the unary one leaves Events, RunExec and TableDetailExec UNGATED. The
	// Kotlin's GrpcServerTest only exercises a unary RPC, so this is the case 10-grpc.md §3.4 asks for.
	t.Run("stream/no header at all", func(t *testing.T) {
		stream, err := b.client.Events(context.Background(), &pb.EventsRequest{DatasourceName: "anything"})
		if err == nil {
			_, err = stream.Recv()
		}
		if got := status.Code(err); got != codes.Unauthenticated {
			t.Fatalf("Events → %v, want UNAUTHENTICATED (the STREAM interceptor must gate too)", got)
		}
	})

	t.Run("stream/bidi no header at all", func(t *testing.T) {
		stream, err := b.client.RunExec(context.Background())
		if err == nil {
			err = stream.Send(&pb.ProxyRunMsg{Kind: &pb.ProxyRunMsg_SessionReady{SessionReady: &pb.RunReady{SessionId: "s"}}})
		}
		if err == nil {
			_, err = stream.Recv()
		}
		if got := status.Code(err); got != codes.Unauthenticated {
			t.Fatalf("RunExec → %v, want UNAUTHENTICATED (the STREAM interceptor must gate too)", got)
		}
	})

	// And the authenticated call still works, so the gate is a gate and not a wall.
	if _, err := b.client.Register(b.authed, &pb.RegisterRequest{
		Name: "e2e-gate-ok", Engine: enginepb.Engine_POSTGRES, DbName: b.dbName,
	}); err != nil {
		t.Fatalf("Register with the correct secret: %v", err)
	}
}

// TestIngestRouteIsGatedByTheSameSecret covers the HTTP half of the shared-secret surface.
func TestIngestRouteIsGatedByTheSameSecret(t *testing.T) {
	secret := e2eSecret
	b := bootE2E(t, &secret)
	url := fmt.Sprintf("http://127.0.0.1:%d/api/ingest/decision", b.app.HTTPPort())
	body := `{"principal":"p@example.com","datasource":"ds","statement":"select 1","decision":"ALLOW"}`

	post := func(header string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		// The Content-Type a real client sends. Without it the route now answers 415 before the secret
		// gate is reached (ContentNegotiation's arm, measured against the Kotlin as
		// r3-ingest-anon-nobody), which would make this case assert content negotiation instead of the
		// shared-secret gate it is named for.
		req.Header.Set("Content-Type", "application/json")
		if header != "" {
			req.Header.Set(app.IngestTokenHeader, header)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", url, err)
		}
		return resp
	}

	resp := post("")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("ingest with no token → %d, want 401", resp.StatusCode)
	}

	resp = post("wrong")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("ingest with a wrong token → %d, want 401", resp.StatusCode)
	}

	resp = post(e2eSecret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("ingest with the correct token → %d %s, want 202", resp.StatusCode, raw)
	}
	var accepted app.IngestResponse
	if err := json.NewDecoder(resp.Body).Decode(&accepted); err != nil {
		t.Fatalf("decode ingest body: %v", err)
	}
	if accepted.Status != "accepted" {
		t.Errorf("ingest body status = %q, want accepted", accepted.Status)
	}
}

// ---- helpers ----------------------------------------------------------------------------------

// e2eColumns is the two-table catalog the decision runs against: a granted app_users and an
// UNGRANTED ungranted_orders, so deny-by-default is provable in the same run.
func e2eColumns() []*pb.Column {
	col := func(table, name, typ string, ord int32) *pb.Column {
		return &pb.Column{
			Schema: e2eSchema, Table: table, Column: name, DataType: typ, Ordinal: ord, Nullable: true,
		}
	}
	return []*pb.Column{
		col(e2eTable, "id", "integer", 1),
		col(e2eTable, "email", "character varying", 2),
		col(e2eTable, "rrn", "character varying", 3),
		col("ungranted_orders", "id", "integer", 1),
		col("ungranted_orders", "total", "integer", 2),
	}
}

func mustRegister(t *testing.T, b *bootedApp, name string) {
	t.Helper()
	if _, err := b.client.Register(b.authed, &pb.RegisterRequest{
		Name: name, Engine: enginepb.Engine_POSTGRES, DbName: b.dbName,
	}); err != nil {
		t.Fatalf("Register %s: %v", name, err)
	}
}

// seedE2EPolicy grants `analyst` connect + select on the datasource and unmasked reads of app_users,
// mirroring internal/dbtest's own seedPolicy. `ungranted_orders` deliberately gets nothing.
func seedE2EPolicy(t *testing.T, b *bootedApp, dsName string) {
	t.Helper()
	s := dbtest.NewSeed(t, b.app.Db)
	s.User(e2ePrincipal)
	roleID := s.Role(e2eRole)
	s.AssignRole(e2ePrincipal, roleID)

	table := fmt.Sprintf("%s/%s/%s/%s", dsName, b.dbName, e2eSchema, e2eTable)
	s.CedarPolicy("e2e-connect-select", fmt.Sprintf(
		`permit(principal in Role::%q, action in [Action::"datasource.connect", Action::"sql.select"], resource in Datasource::%q);`,
		e2eRole, dsName))
	s.CedarPolicy("e2e-users-unmasked", fmt.Sprintf(
		`permit(principal in Role::%q, action == Action::"result.read.unmasked", resource in Table::%q);`,
		e2eRole, table))
}

// issueE2EToken mints a raw wire token of the given kind through the PRODUCTION token store, so the
// hash the registry and the row share is the production hash (INV-A4-53).
func issueE2EToken(t *testing.T, b *bootedApp, kind token.Kind) string {
	t.Helper()
	roles := []string{}
	if kind == token.KindEditor || kind == token.KindApproverExec {
		roles = []string{e2eRole}
	}
	issued, err := b.app.Core.TokenStore.Issue(
		context.Background(), b.app.Db.Pool, kind, e2ePrincipal, roles, nil, 3600,
	)
	if err != nil {
		t.Fatalf("issue %s token: %v", kind, err)
	}
	return issued.Token
}

func hasRefetchFor(commands []*pb.ProxyCommand, schema string) bool {
	for _, c := range commands {
		if c.GetRefetch().GetSchema() == schema {
			return true
		}
	}
	return false
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
