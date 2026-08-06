package app_test

// GrpcRunExecDbTest.kt, ported 1:1 — "DB-backed end-to-end coverage for the control-plane half of the
// proxy-dialed editor channel", all 14 cases, plus EditorSessionDecideTimingDbTest.kt's single case.
//
// The Kotlin's fixture constructs `RunExecService(core)` and a `GrpcServer(ControlPlaneGrpcService(core))`
// over one core. This drives the REAL BOOTED APP instead, which is strictly stronger: the service under
// test is the one `app.Boot` wired, so a wiring regression (two cores, a missing PM_QUERY_TIMEOUT, the
// service never constructed) fails here as well as the behaviour.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/policy"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/token"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// exchange is GrpcRunExecDbTest.kt:117-167's `exchange(...)` helper, verbatim in what it ASSERTS.
//
// Its assertions are not incidental — they are the ones every case in the Kotlin inherits, and they are
// the reason the helper exists rather than each case wiring its own proxy:
//
//   - the ephemeral token RESOLVES while the run is in flight, with an EMPTY roles snapshot;
//   - transient EDITOR tokens stay OFF the user-visible token list;
//   - 🔒 the requester-IP carrier holds EXACTLY the ip run() was called with, keyed by the token's hash;
//   - after the exchange the token is REVOKED and the carrier entry is GONE — entry lifetime == token
//     lifetime;
//   - the Events stream detaches.
func (f *runFixture) exchange(
	principal, sql string, maxRows int, requesterIP *string, behave proxyBehaviour,
) (query.QueryResponse, error) {
	f.t.Helper()
	opens, detach := f.events()
	defer func() {
		detach()
		f.awaitDetached()
	}()

	type outcome struct {
		response query.QueryResponse
		err      error
	}
	done := make(chan outcome, 1)
	go func() {
		in := runInput(principal, f.ds, sql, maxRows)
		in.RequesterIP = requesterIP
		response, err := f.svc.Run(context.Background(), in)
		done <- outcome{response, err}
	}()

	open := f.nextOpen(opens)
	tok := open.GetEphemeralToken()

	// The ephemeral token resolves DURING the window, and its roles snapshot is empty (no execute-under-R
	// on this path).
	id := f.tokenIdentity(tok)
	if id == nil || id.Principal != principal {
		f.t.Fatalf("the ephemeral token did not resolve to %q during the editor window: %+v", principal, id)
	}
	if len(id.Roles) != 0 {
		f.t.Errorf("the ephemeral token carries roles %v; the editor path mints an EMPTY snapshot", id.Roles)
	}
	// 🔒 Transient editor tokens stay off the user-visible list — `/api/tokens` must never show one.
	f.assertNoVisibleEphemeralToken(principal)
	// 🔒 The carrier holds EXACTLY what run() was called with, hashed.
	assertCarriedIP(f.t, f.carriedIP(tok), requesterIP,
		"the requester-IP carrier must hold exactly the requesterIp run() was called with")

	proxy := f.dial(open.GetSessionId(), behave)

	var got outcome
	select {
	case got = <-done:
	case <-time.After(runGate):
		f.t.Fatal("the run never returned")
	}
	proxy.awaitClosed()

	if principal := f.tokenResolves(tok); principal != "" {
		f.t.Errorf("the ephemeral token still resolves to %q after the exchange; it must be revoked", principal)
	}
	if ip := f.carriedIP(tok); ip != nil {
		f.t.Errorf("the requester-IP entry survived the token revoke as %q — entry lifetime == token lifetime", *ip)
	}
	return got.response, got.err
}

// assertNoVisibleEphemeralToken is `tokenStore.list(principal).none { it.kind == "EDITOR" }`.
func (f *runFixture) assertNoVisibleEphemeralToken(principal string) {
	f.t.Helper()
	rows, err := f.app.Core.TokenStore.List(context.Background(), principal)
	if err != nil {
		f.t.Fatalf("list tokens: %v", err)
	}
	for _, row := range rows {
		if row.Kind == string(token.KindEditor) || row.Kind == string(token.KindApproverExec) {
			f.t.Errorf("token %d of kind %s is on the user-visible list; ephemeral kinds must be hidden",
				row.ID, row.Kind)
		}
	}
}

func assertCarriedIP(t *testing.T, got, want *string, why string) {
	t.Helper()
	switch {
	case want == nil && got != nil:
		t.Errorf("%s: carried %q, want absent", why, *got)
	case want != nil && got == nil:
		t.Errorf("%s: carried nothing, want %q", why, *want)
	case want != nil && got != nil && *got != *want:
		t.Errorf("%s: carried %q, want %q", why, *got, *want)
	}
}

func ipOf(s string) *string { return &s }

// mustCreatePolicy inserts an ENABLED Cedar policy through the store the engine holds.
//
// 🔒 Two things make it a helper rather than an inline call. First, [policy.NewCedarPolicyInput] is what
// carries the Kotlin's `enabled: Boolean = true` default — the bare struct's zero value is false, which
// stores a policy the engine never compiles and turns an ip-gate assertion into an unrelated
// connect-gate denial. Second, it must go through `f.app.Core.CedarPolicyStore`, the instance the engine
// watches: INV-A1-1 again, and a second store would bump a version counter nothing reads, so the
// freshly-inserted policy would never take effect live.
func (f *runFixture) mustCreatePolicy(name, src string) {
	f.t.Helper()
	created, err := f.app.Core.CedarPolicyStore.Create(context.Background(),
		policy.NewCedarPolicyInput(name, src), nil)
	if err != nil {
		f.t.Fatalf("create cedar policy %q: %v", name, err)
	}
	if !created.Enabled {
		f.t.Fatalf("policy %q was stored DISABLED; the engine will never compile it", name)
	}
}

// --- Case 1 ---------------------------------------------------------------------------------------
//
// KT: GrpcRunExecDbTest.kt#run's requesterIp is carried on ControlPlaneCore for the life of the ephemeral token
//
// [runFixture.exchange] itself asserts the registry holds exactly the requesterIp passed in, both while
// the token is live and (as absent) after the exchange completes — this pins the EXPLICIT, non-default
// case end to end. Every other exchange-based case below implicitly pins the nil/no-op case, since they
// pass no requester IP.
func TestRunsRequesterIPIsCarriedOnTheCoreForTheLifeOfTheEphemeralToken(t *testing.T) {
	f := newRunFixture(t)
	if _, err := f.exchange("editor-user", "select 1", 500, ipOf("203.0.113.99"), allowRows(nil)); err != nil {
		t.Fatalf("run: %v", err)
	}
}

// --- Case 2 ---------------------------------------------------------------------------------------
//
// KT: GrpcRunExecDbTest.kt#ALLOW assembles chunked rows, nulls, metadata, audit PII, and SELECT rowsAffected
func TestAllowAssemblesChunkedRowsNullsMetadataAuditPIIAndSelectRowsAffected(t *testing.T) {
	f := newRunFixture(t)
	decisionID := f.insertAudit(string(types.DecisionAllow), []string{"app.public.users.email"})

	response, err := f.exchange("editor-user", "select id, email from users", 9_000, nil,
		func(send func(*pb.ProxyRunMsg), q *pb.RunQuery) {
			if got := q.GetSql(); got != "select id, email from users" {
				t.Errorf("the proxy saw sql %q", got)
			}
			// 🔒 maxRows is clamped BEFORE crossing the wire: 9000 → 5000.
			if got := q.GetMaxRows(); got != 5000 {
				t.Errorf("max_rows on the wire = %d, want 5000 (clamped before crossing)", got)
			}
			send(decisionOf(&pb.RunDecision{
				Decision:       pb.EnfAction_ALLOW,
				DecisionId:     decisionID,
				EffectiveRoles: []string{"analyst", "reader"},
			}))
			send(rowsOf([]string{"id", "email"}, []*string{sp("1"), sp("a@example.com")}))
			send(rowsOf([]string{"id", "email"}, []*string{sp("2"), nil}))
			send(doneOf(-1))
		})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if pb.EnfAction(response.Decision) != pb.EnfAction_ALLOW {
		t.Errorf("decision = %v, want ALLOW", response.Decision)
	}
	if response.DecisionID == nil || *response.DecisionID != decisionID {
		t.Errorf("decisionId = %v, want %d", response.DecisionID, decisionID)
	}
	if response.DenyReason != nil {
		t.Errorf("denyReason = %q, want absent", *response.DenyReason)
	}
	if len(response.MaskedColumns) != 0 {
		t.Errorf("maskedColumns = %v, want empty", response.MaskedColumns)
	}
	// 🔒 piiTouched is RE-READ from the audit row the decide already wrote — the control plane does not
	// recompute it, and this is the only assertion that proves the lookup happens at all.
	if got := response.PIITouched; len(got) != 1 || got[0] != "app.public.users.email" {
		t.Errorf("piiTouched = %v, want the audit row's [app.public.users.email]", got)
	}
	if got := response.EffectiveRoles; len(got) != 2 || got[0] != "analyst" || got[1] != "reader" {
		t.Errorf("effectiveRoles = %v, want [analyst reader]", got)
	}
	if got := response.Columns; len(got) != 2 || got[0] != "id" || got[1] != "email" {
		t.Errorf("columns = %v, want [id email]", got)
	}
	// 🔒 The FULL assembled result, value by value — the Kotlin asserts the whole
	// [[1, a@example.com], [2, null]] and a length-plus-one-null check would pass for a port that
	// concatenated the two chunks in the wrong order or dropped a value inside a row.
	if len(response.Rows) != 2 {
		t.Fatalf("rows = %v, want the two chunks assembled into two rows", response.Rows)
	}
	wantRows := [][]*string{{sp("1"), sp("a@example.com")}, {sp("2"), nil}}
	for i, want := range wantRows {
		if len(response.Rows[i]) != len(want) {
			t.Errorf("row %d = %v, want %d values", i, response.Rows[i], len(want))
			continue
		}
		for j := range want {
			got := response.Rows[i][j]
			switch {
			case want[j] == nil && got != nil:
				t.Errorf("row %d value %d = %q, want NULL", i, j, *got)
			case want[j] != nil && got == nil:
				t.Errorf("row %d value %d = NULL, want %q", i, j, *want[j])
			case want[j] != nil && got != nil && *got != *want[j]:
				t.Errorf("row %d value %d = %q, want %q", i, j, *got, *want[j])
			}
		}
	}
	if response.RowsAffected != nil {
		t.Errorf("rowsAffected = %d for a SELECT's -1; it must be absent", *response.RowsAffected)
	}
	if response.LatencyMs < 0 {
		t.Errorf("latencyMs = %d, want >= 0", response.LatencyMs)
	}
}

// --- Case 3 ---------------------------------------------------------------------------------------
//
// KT: GrpcRunExecDbTest.kt#MASK preserves masked-column metadata and returns only proxy-produced values
func TestMaskPreservesMaskedColumnMetadataAndReturnsOnlyProxyProducedValues(t *testing.T) {
	f := newRunFixture(t)
	decisionID := f.insertAudit(string(types.DecisionMask), []string{"app.public.users.rrn"})

	response, err := f.exchange("editor-user", "select rrn from users", 0, nil,
		func(send func(*pb.ProxyRunMsg), q *pb.RunQuery) {
			// 🔒 maxRows=0 crosses the wire AS 0 — the proxy's default-500 sentinel. A port that coerced
			// into [1, 5000] would send 1 and every default query would return one row.
			if got := q.GetMaxRows(); got != 0 {
				t.Errorf("max_rows on the wire = %d, want 0 (the proxy's default-500 sentinel)", got)
			}
			send(decisionOf(&pb.RunDecision{
				Decision:       pb.EnfAction_MASK,
				DecisionId:     decisionID,
				MaskedColumns:  []string{"rrn"},
				EffectiveRoles: []string{"analyst"},
			}))
			send(rowsOf([]string{"rrn"}, []*string{sp("######-#######")}))
			send(doneOf(-1))
		})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if pb.EnfAction(response.Decision) != pb.EnfAction_MASK {
		t.Errorf("decision = %v, want MASK", response.Decision)
	}
	if response.DecisionID == nil || *response.DecisionID != decisionID {
		t.Errorf("decisionId = %v, want %d — the MASK response points at the audit row the decide wrote",
			response.DecisionID, decisionID)
	}
	// 🔒 A MASK is not a partial DENY: no deny reason rides along with it.
	if response.DenyReason != nil {
		t.Errorf("denyReason = %q, want absent on a MASK", *response.DenyReason)
	}
	if got := response.MaskedColumns; len(got) != 1 || got[0] != "rrn" {
		t.Errorf("maskedColumns = %v, want [rrn]", got)
	}
	if got := response.PIITouched; len(got) != 1 || got[0] != "app.public.users.rrn" {
		t.Errorf("piiTouched = %v", got)
	}
	if got := response.EffectiveRoles; len(got) != 1 || got[0] != "analyst" {
		t.Errorf("effectiveRoles = %v, want [analyst] — the roles the mask was computed under", got)
	}
	if got := response.Columns; len(got) != 1 || got[0] != "rrn" {
		t.Errorf("columns = %v, want [rrn]", got)
	}
	// 🔒 ONLY proxy-produced values: the control plane never masks here, it relays what the proxy
	// already enforced on the result stream.
	if len(response.Rows) != 1 || response.Rows[0][0] == nil || *response.Rows[0][0] != "######-#######" {
		t.Errorf("rows = %v, want the proxy's masked value verbatim", response.Rows)
	}
	if response.RowsAffected != nil {
		t.Errorf("rowsAffected = %d, want absent", *response.RowsAffected)
	}
}

// --- Case 4 ---------------------------------------------------------------------------------------
//
// KT: GrpcRunExecDbTest.kt#DENY is terminal and never returns rows
func TestDenyIsTerminalAndNeverReturnsRows(t *testing.T) {
	f := newRunFixture(t)
	decisionID := f.insertAudit(string(types.DecisionDeny), []string{"app.public.users.rrn"})

	response, err := f.exchange("editor-user", "select rrn from users", 500, nil,
		func(send func(*pb.ProxyRunMsg), _ *pb.RunQuery) {
			// Nothing follows the DENY — no rows, no Done. The run must return anyway.
			send(decisionOf(&pb.RunDecision{
				Decision:       pb.EnfAction_DENY,
				DecisionId:     decisionID,
				DenyReason:     "policy denies column rrn",
				EffectiveRoles: []string{"contractor"},
			}))
		})
	if err != nil {
		t.Fatalf("a DENY is a successful RESPONSE, not an error: %v", err)
	}
	if pb.EnfAction(response.Decision) != pb.EnfAction_DENY {
		t.Errorf("decision = %v, want DENY", response.Decision)
	}
	if response.DecisionID == nil || *response.DecisionID != decisionID {
		t.Errorf("decisionId = %v, want %d", response.DecisionID, decisionID)
	}
	if response.DenyReason == nil || *response.DenyReason != "policy denies column rrn" {
		t.Errorf("denyReason = %v", response.DenyReason)
	}
	if len(response.MaskedColumns) != 0 {
		t.Errorf("maskedColumns = %v, want empty on a DENY", response.MaskedColumns)
	}
	if got := response.PIITouched; len(got) != 1 || got[0] != "app.public.users.rrn" {
		t.Errorf("piiTouched = %v — a DENY still reports what the decision touched", got)
	}
	if got := response.EffectiveRoles; len(got) != 1 || got[0] != "contractor" {
		t.Errorf("effectiveRoles = %v", got)
	}
	if len(response.Columns) != 0 || len(response.Rows) != 0 {
		t.Errorf("a DENY returned %d columns / %d rows; 🔒 both must be empty",
			len(response.Columns), len(response.Rows))
	}
	if response.RowsAffected != nil {
		t.Errorf("rowsAffected = %d, want absent", *response.RowsAffected)
	}
}

// --- Case 5 ---------------------------------------------------------------------------------------
//
// KT: GrpcRunExecDbTest.kt#an unspecified wire decision fails closed to DENY
//
// 🔒 INV-A7-39 / INV-A6-3 at the transport boundary, over the REAL wire this time: the proxy sends
// ENF_ACTION_UNSPECIFIED and the control plane answers DENY with no rows. A port that relayed the raw
// enum would let an unknown verdict fall OPEN.
func TestAnUnspecifiedWireDecisionFailsClosedToDeny(t *testing.T) {
	f := newRunFixture(t)
	response, err := f.exchange("editor-user", "select 1", 500, nil,
		func(send func(*pb.ProxyRunMsg), _ *pb.RunQuery) {
			send(decisionOf(&pb.RunDecision{
				Decision:   pb.EnfAction_ENF_ACTION_UNSPECIFIED,
				DenyReason: "unspecified verdict",
			}))
		})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if pb.EnfAction(response.Decision) != pb.EnfAction_DENY {
		t.Errorf("decision = %v, want DENY", response.Decision)
	}
	if response.DecisionID != nil {
		t.Errorf("decisionId = %d, want absent (the proto's 0 means none)", *response.DecisionID)
	}
	if response.DenyReason == nil || *response.DenyReason != "unspecified verdict" {
		t.Errorf("denyReason = %v", response.DenyReason)
	}
	if len(response.Rows) != 0 {
		t.Errorf("rows = %v, want none", response.Rows)
	}
}

// --- Case 6 ---------------------------------------------------------------------------------------
//
// KT: GrpcRunExecDbTest.kt#RunError fails the whole exchange without exposing earlier rows
func TestRunErrorFailsTheWholeExchangeWithoutExposingEarlierRows(t *testing.T) {
	f := newRunFixture(t)
	decisionID := f.insertAudit(string(types.DecisionAllow), []string{"app.public.users.email"})

	response, err := f.exchange("editor-user", "select broken", 500, nil,
		func(send func(*pb.ProxyRunMsg), _ *pb.RunQuery) {
			send(decisionOf(&pb.RunDecision{Decision: pb.EnfAction_ALLOW, DecisionId: decisionID}))
			send(rowsOf([]string{"email"}, []*string{sp("must-not-escape@example.com")}))
			send(errorOf("backend disconnected"))
		})

	var pre *query.ProxyRunError
	if !errors.As(err, &pre) {
		t.Fatalf("expected a ProxyRunError, got %T: %v", err, err)
	}
	if pre.Message != "backend disconnected" {
		t.Errorf("message = %q, want the proxy's own text", pre.Message)
	}
	// 🔒 The prefix of a result set that failed halfway is NOT a result. It must not come back.
	if len(response.Rows) != 0 {
		t.Errorf("the failed exchange returned %d rows", len(response.Rows))
	}
}

// --- Case 7 ---------------------------------------------------------------------------------------
//
// KT: GrpcRunExecDbTest.kt#no attached proxy returns the typed service-unavailable outcome and revokes its token
//
// 🔒 THE REVOKE IS THE HALF THAT MATTERS. The typed error only chooses a status code; the token revoke is
// what stops a failed run from leaving a live EDITOR credential behind for its full TTL. This asserts
// both, and the count comes straight from `proxy_token`.
func TestNoAttachedProxyReturnsTheTypedOutcomeAndRevokesItsToken(t *testing.T) {
	f := newRunFixture(t)
	f.awaitUntil("no Events stream attached", func() bool { return !f.isAttached() })

	_, err := f.svc.Run(context.Background(), runInput("no-proxy-user", f.ds, "select 1", 500))
	if !errors.Is(err, query.ErrNoProxyAttached) {
		t.Fatalf("run with no proxy returned %v, want query.ErrNoProxyAttached", err)
	}
	if n := f.activeEphemeralTokens("no-proxy-user", token.KindEditor); n != 0 {
		t.Errorf("%d live EDITOR token(s) survive the no-proxy path; it must revoke its own", n)
	}
	// Both of the Kotlin case's assertions are above. A third line asserting `RunChannels.Remove("")`
	// was removed deliberately: the run token is never observable on this path, so its registry key is
	// unknown, and probing the registry with an empty id asserts nothing about the sweep. An assertion
	// that cannot fail is worse than an acknowledged gap — it reads as coverage.
}

// --- Case 8 ---------------------------------------------------------------------------------------
//
// KT: GrpcRunExecDbTest.kt#dial timeout is typed, leaves no active token, and never needs a proxy stream
//
// A short dial bound is INJECTED. The production one is 120s, sized for a cold session against a remote
// backend ("measured cold opens took ~26s; 10s failed them outright"), and waiting it out here would buy
// nothing but a two-minute test — which is exactly why [query.RunInput] carries the parameter at all.
func TestDialTimeoutIsTypedLeavesNoActiveTokenAndNeverNeedsAProxyStream(t *testing.T) {
	f := newRunFixture(t)
	opens, detach := f.events()
	defer func() {
		detach()
		f.awaitDetached()
	}()

	done := make(chan error, 1)
	go func() {
		in := runInput("timeout-user", f.ds, "select 1", 500)
		in.DialTimeoutMs = 1_000
		_, err := f.svc.Run(context.Background(), in)
		done <- err
	}()

	// The nudge went out — a proxy WAS asked to dial — and the token is live while the dial is awaited.
	open := f.nextOpen(opens)
	if got := f.tokenResolves(open.GetEphemeralToken()); got != "timeout-user" {
		t.Errorf("the ephemeral token resolved to %q during the dial window, want timeout-user", got)
	}

	// Nothing ever claims the session: no RunExec stream is opened at all.
	select {
	case err := <-done:
		if !errors.Is(err, query.ErrProxyRunTimeout) {
			t.Fatalf("the dial timeout returned %v, want query.ErrProxyRunTimeout", err)
		}
	case <-time.After(runGate):
		t.Fatal("the dial never timed out")
	}
	if got := f.tokenResolves(open.GetEphemeralToken()); got != "" {
		t.Errorf("the ephemeral token still resolves to %q; a dial timeout must revoke it", got)
	}
	if n := f.activeEphemeralTokens("timeout-user", token.KindEditor); n != 0 {
		t.Errorf("%d live EDITOR token(s) survive a dial timeout", n)
	}
	// 🔒 INV-A7-36's other half: the pending registration is swept, so a proxy that dials LATE finds
	// nothing to claim rather than attaching to an abandoned run.
	if f.app.Core.RunChannels.Remove(open.GetSessionId()) != nil {
		t.Error("the timed-out run left its session pending; a late dial could still claim it")
	}
}

// --- Case 9 ---------------------------------------------------------------------------------------
//
// KT: GrpcRunExecDbTest.kt#unknown and duplicate session ids fail NOT_FOUND claim-once
//
// 🔒 INV-A7-32 / INV-A10-32 — a session is claimable EXACTLY ONCE, and an unknown id is
// INDISTINGUISHABLE from an already-claimed one BY DESIGN. Both are NOT_FOUND, so a proxy cannot probe
// for live session ids, and a claimed-twice stream can never share another request's token and query.
func TestUnknownAndDuplicateSessionIDsFailNotFoundClaimOnce(t *testing.T) {
	f := newRunFixture(t)

	if code := f.readyStatus("unknown"); code != codesNotFound {
		t.Errorf("an unknown session id answered %s, want NOT_FOUND", code)
	}

	// Register a real pending session, claim it once, then claim it again.
	opens, detach := f.events()
	defer func() {
		detach()
		f.awaitDetached()
	}()
	go func() {
		in := runInput("claim-user", f.ds, "select 1", 500)
		_, _ = f.svc.Run(context.Background(), in)
	}()
	open := f.nextOpen(opens)

	first := f.dial(open.GetSessionId(), allowRows(nil))
	// ⚠️ WAIT FOR THE FIRST CLAIM TO LAND BEFORE ATTEMPTING THE SECOND. The Kotlin awaits
	// `pending.ready.await()` here for exactly this reason. Without it the two Readys RACE, the
	// duplicate can win, and the CONTROL PLANE THEN DISPATCHES THE QUERY DOWN IT — so `readyStatus`
	// reads a RunQuery instead of a status and reports OK. That failure looks like a broken claim-once
	// rule and is really a broken test; the observable "the claim landed" is the query reaching the
	// first stream, which can only happen after that stream won.
	f.awaitUntil("the first stream won the claim", func() bool { return len(first.seenQueries()) == 1 })
	if code := f.readyStatus(open.GetSessionId()); code != codesNotFound {
		t.Errorf("a DUPLICATE claim answered %s, want NOT_FOUND — the claim is once-only", code)
	}
	first.awaitClosed()
}

// --- Case 10 --------------------------------------------------------------------------------------
//
// KT: GrpcRunExecDbTest.kt#a non-ready first message fails FAILED_PRECONDITION
//
// The FIRST message on a RunExec stream must be the Ready that claims a session. Anything else is a
// protocol error, and it is FAILED_PRECONDITION rather than NOT_FOUND because nothing was looked up.
func TestANonReadyFirstMessageFailsFailedPrecondition(t *testing.T) {
	f := newRunFixture(t)
	stream, err := f.client.RunExec(f.authed)
	if err != nil {
		t.Fatalf("open RunExec: %v", err)
	}
	if err := stream.Send(errorOf("not ready")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if _, err := stream.Recv(); statusCodeOf(err) != codesFailedPrecondition {
		t.Errorf("a non-Ready first message answered %s, want FAILED_PRECONDITION", statusCodeOf(err))
	}
}

// --- Case 11 --------------------------------------------------------------------------------------
//
// KT: GrpcRunExecDbTest.kt#a persistent session runs multiple queries on ONE held stream, then closes and revokes
//
// The single largest case in the suite, and the one that pins the whole persistent-session contract:
// ONE stream (hence one backend connection) across N queries, the per-query requester-IP refresh with
// its nil-CLEARS rule, cross-principal rejection on both run and close, and revoke-on-close.
func TestAPersistentSessionRunsMultipleQueriesOnOneHeldStreamThenClosesAndRevokes(t *testing.T) {
	f := newRunFixture(t)
	opens, detach := f.events()
	defer func() {
		detach()
		f.awaitDetached()
	}()

	type opened struct {
		id  string
		err error
	}
	openDone := make(chan opened, 1)
	go func() {
		id, err := f.svc.OpenSession(context.Background(), "session-user", f.ds, ipOf("203.0.113.42"))
		openDone <- opened{id, err}
	}()
	open := f.nextOpen(opens)
	tok := open.GetEphemeralToken()
	// openSession's requesterIp is carried for the life of the SESSION — every query decided on it sees
	// this until a query refreshes it.
	assertCarriedIP(f.t, f.carriedIP(tok), ipOf("203.0.113.42"), "openSession's requesterIp")

	// ONE fake-proxy stream that services every query then a close — the proof the control plane REUSES
	// one stream rather than dialing fresh per statement.
	proxy := f.dial(open.GetSessionId(), echoQuery)

	var session opened
	select {
	case session = <-openDone:
	case <-time.After(runGate):
		t.Fatal("openSession never returned")
	}
	if session.err != nil {
		t.Fatalf("openSession: %v", session.err)
	}
	if got := f.tokenResolves(tok); got != "session-user" {
		t.Errorf("the per-session token resolved to %q; it must stay valid ACROSS the session, "+
			"not be revoked per query", got)
	}

	// 🔒 Each query REFRESHES the carried IP to THIS request's value — resolved fresh per decision,
	// never the stale open-time one.
	r1 := f.runOnSession(session.id, "session-user", "select 1", ipOf("203.0.113.50"))
	assertCarriedIP(f.t, f.carriedIP(tok), ipOf("203.0.113.50"),
		"runOnSession refreshes to the current request's IP, not the open-time 203.0.113.42")

	// 🔒 A query whose IP cannot be resolved CLEARS the entry, fail-closed. A session opened from a
	// trusted network then queried from an untrusted one must NOT inherit the trusted IP.
	r2 := f.runOnSession(session.id, "session-user", "select 2", nil)
	assertCarriedIP(f.t, f.carriedIP(tok), nil,
		"a session query from an unresolvable IP clears the stale open-time IP — the anti-staleness invariant")

	if got := r1.Rows; len(got) != 1 || got[0][0] == nil || *got[0][0] != "select 1" {
		t.Errorf("query 1 rows = %v", got)
	}
	if got := r2.Rows; len(got) != 1 || got[0][0] == nil || *got[0][0] != "select 2" {
		t.Errorf("query 2 rows = %v", got)
	}

	// 🔒 A different principal cannot use someone else's session: the ownership check throws BEFORE the
	// registry is touched, so it neither runs nor perturbs the carried IP.
	_, err := f.svc.RunOnSession(context.Background(), query.SessionRunInput{
		SessionID: session.id, Principal: "other-user", SQL: "select 3", MaxRows: 500,
		RequesterIP: ipOf("203.0.113.60"),
	})
	var pre *query.ProxyRunError
	if !errors.As(err, &pre) {
		t.Fatalf("a non-owner query returned %T (%v), want a ProxyRunError", err, err)
	}
	assertCarriedIP(f.t, f.carriedIP(tok), nil,
		"a rejected non-owner query must not plant a requester_ip on the owner's session")

	// 🔒 ...nor CLOSE it. A leaked sessionId must not let another principal tear down the connection or
	// revoke the token. The non-owner close is a no-op — the session stays live and usable.
	if f.svc.CloseSessionOwnedBy(session.id, "other-user") {
		t.Error("a non-owner closed the session")
	}
	if got := f.tokenResolves(tok); got != "session-user" {
		t.Errorf("a rejected non-owner close left the token resolving to %q; it must stay valid", got)
	}
	r3 := f.runOnSession(session.id, "session-user", "select 4", ipOf("203.0.113.51"))
	if got := r3.Rows; len(got) != 1 || got[0][0] == nil || *got[0][0] != "select 4" {
		t.Errorf("the session must still run after a rejected non-owner close; rows = %v", got)
	}
	assertCarriedIP(f.t, f.carriedIP(tok), ipOf("203.0.113.51"),
		"the latest query's requester_ip is the one carried for the session's next decision")

	if !f.svc.CloseSessionOwnedBy(session.id, "session-user") {
		t.Error("the owner could not close their own session")
	}
	proxy.awaitClosed()

	// 🔒 ALL FOUR queries ran on the SAME held stream. The rejected non-owner one is absent because it
	// never reached the wire.
	want := []string{"select 1", "select 2", "select 4"}
	got := proxy.seenQueries()
	if len(got) != len(want) {
		t.Fatalf("the held stream saw %v, want %v — one stream, N queries", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("query %d on the held stream = %q, want %q", i, got[i], want[i])
		}
	}
	if principal := f.tokenResolves(tok); principal != "" {
		t.Errorf("the session token still resolves to %q; close must revoke it", principal)
	}
	assertCarriedIP(f.t, f.carriedIP(tok), nil,
		"the requester-IP entry is removed alongside the session token on close")
}

// runOnSession is the happy-path shorthand.
func (f *runFixture) runOnSession(sessionID, principal, sql string, ip *string) query.QueryResponse {
	f.t.Helper()
	response, err := f.svc.RunOnSession(context.Background(), query.SessionRunInput{
		SessionID: sessionID, Principal: principal, SQL: sql, MaxRows: 500, RequesterIP: ip,
	})
	if err != nil {
		f.t.Fatalf("runOnSession(%q): %v", sql, err)
	}
	return response
}

// --- Case 12 --------------------------------------------------------------------------------------
//
// KT: GrpcRunExecDbTest.kt#active task registry sends RunCancel on the attached stream
//
// The cancel gate's SEND half, over the real wire: a run registered under a taskId is reachable by
// CancelActiveRun, and the RunCancel lands on the stream AFTER the query it cancels (INV-A7-35).
func TestTheActiveTaskRegistrySendsRunCancelOnTheAttachedStream(t *testing.T) {
	f := newRunFixture(t)
	opens, detach := f.events()
	defer func() {
		detach()
		f.awaitDetached()
	}()

	const taskID int64 = 991
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		in := runInput("cancel-user", f.ds, "select 1", 500)
		id := taskID
		in.TaskID = &id
		_, err := f.svc.Run(context.Background(), in)
		done <- err
	}()
	open := f.nextOpen(opens)

	proxy := f.dial(open.GetSessionId(), func(send func(*pb.ProxyRunMsg), _ *pb.RunQuery) {
		// Hold the statement so the cancel arrives while it is genuinely in flight.
		<-release
		send(decisionOf(&pb.RunDecision{Decision: pb.EnfAction_ALLOW}))
		send(doneOf(-1))
	})

	// Wait until the query is on the wire, then cancel.
	f.awaitUntil("the query reached the proxy", func() bool { return len(proxy.seenQueries()) == 1 })
	if !f.svc.CancelActiveRun(context.Background(), taskID) {
		t.Fatal("CancelActiveRun returned false for a registered in-flight run")
	}
	proxy.awaitCancel()

	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the run itself: %v", err)
		}
	case <-time.After(runGate):
		t.Fatal("the run never completed after the cancel")
	}
	proxy.awaitClosed()
}

// --- Case 13 --------------------------------------------------------------------------------------
//
// KT: GrpcRunExecDbTest.kt#closeSessionsForPrincipal closes only the matching principal's streams
//
// This is the session-end seam's hook (App.kt:385-399 / [onWebSessionEnded]). The property is
// PRINCIPAL-SCOPED teardown: signing out must release YOUR held connections and revoke YOUR session
// tokens, and touch nobody else's.
func TestCloseSessionsForPrincipalClosesOnlyTheMatchingPrincipalsStreams(t *testing.T) {
	f := newRunFixture(t)
	opens, detach := f.events()
	defer func() {
		detach()
		f.awaitDetached()
	}()

	openFor := func(principal string) (string, string, *fakeProxy) {
		f.t.Helper()
		type opened struct {
			id  string
			err error
		}
		done := make(chan opened, 1)
		go func() {
			id, err := f.svc.OpenSession(context.Background(), principal, f.ds, nil)
			done <- opened{id, err}
		}()
		open := f.nextOpen(opens)
		proxy := f.dial(open.GetSessionId(), echoQuery)
		select {
		case got := <-done:
			if got.err != nil {
				f.t.Fatalf("openSession(%s): %v", principal, got.err)
			}
			return got.id, open.GetEphemeralToken(), proxy
		case <-time.After(runGate):
			f.t.Fatalf("openSession(%s) never returned", principal)
			return "", "", nil
		}
	}

	firstID, firstTok, firstProxy := openFor("principal-a")
	secondID, secondTok, secondProxy := openFor("principal-b")

	f.svc.CloseSessionsForPrincipal("principal-a")
	firstProxy.awaitClosed()
	if got := f.tokenResolves(firstTok); got != "" {
		t.Errorf("principal-a's session token still resolves to %q after their sessions were closed", got)
	}
	// 🔒 principal-b is UNTOUCHED — the scoping is what makes this safe to call from a session-end hook.
	if got := f.tokenResolves(secondTok); got != "principal-b" {
		t.Errorf("principal-b's token resolved to %q; closing A's sessions must not touch B's", got)
	}
	if f.svc.OpenSessionCount() != 1 {
		t.Errorf("%d sessions remain, want exactly principal-b's", f.svc.OpenSessionCount())
	}

	f.svc.CloseSessionsForPrincipal("principal-b")
	secondProxy.awaitClosed()
	if f.svc.OpenSessionCount() != 0 {
		t.Errorf("%d sessions remain after both principals were closed", f.svc.OpenSessionCount())
	}
	_ = firstID
	_ = secondID
}

// --- Case 14 --------------------------------------------------------------------------------------
//
// KT: GrpcRunExecDbTest.kt#a run-minted APPROVER_EXEC token's requester_ip reaches a real gRPC decide (approverExec=true, the ONLY APPROVER_EXEC minter)
//
// 🔒 THE POINT IS THAT IT REACHES CEDAR, not that the map holds it. An ip-gated `datasource.connect`
// permit is installed; if the run-supplied IP arrives at decide time the permit FIRES and the deny moves
// off the connect gate onto `sql.select`. An implementation that registered IPs only for EDITOR would
// leave connect denied here — the exact regression a manual-token-insert test cannot catch, because
// `run(approverExec = true)` is the ONLY minter of APPROVER_EXEC tokens in the system.
func TestARunMintedApproverExecTokensRequesterIPReachesARealGrpcDecide(t *testing.T) {
	f := newRunFixture(t)
	// ⚠️ NewCedarPolicyInput, not the bare struct: `enabled` defaults to TRUE in the Kotlin
	// (CedarPolicyStore.kt:43) and the Go constructor is what carries that default. A raw
	// `policy.CedarPolicyInput{...}` leaves the zero value FALSE, the policy is stored disabled, the
	// engine never compiles it, and this test then fails on the connect gate for a reason that has
	// nothing to do with requester_ip.
	f.mustCreatePolicy("editor-run-approver-exec-ip-gate",
		`permit(principal, action == Action::"datasource.connect", resource == Datasource::"`+f.ds.Name+`")
			when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };`)

	opens, detach := f.events()
	defer func() {
		detach()
		f.awaitDetached()
	}()

	done := make(chan error, 1)
	go func() {
		in := runInput("approver-exec-user", f.ds, "select 1 from t", 500)
		in.ApproverExec = true
		in.RequesterIP = ipOf("203.0.113.55")
		_, err := f.svc.Run(context.Background(), in)
		done <- err
	}()
	open := f.nextOpen(opens)
	tok := open.GetEphemeralToken()

	// The minted token is APPROVER_EXEC and carries the run-supplied IP under its hash...
	id := f.tokenIdentity(tok)
	if id == nil || id.Principal != "approver-exec-user" {
		t.Fatalf("the APPROVER_EXEC token did not resolve: %+v", id)
	}
	if id.Kind != string(token.KindApproverExec) {
		t.Errorf("kind = %s, want APPROVER_EXEC — this is the only path that mints one", id.Kind)
	}
	assertCarriedIP(t, f.carriedIP(tok), ipOf("203.0.113.55"), "the APPROVER_EXEC carrier")

	// ...and a REAL gRPC decide against that live token SEES it.
	verdict, err := f.client.Decide(f.authed, &pb.DecisionRequest{
		Token:          tok,
		DatasourceName: f.ds.Name,
		ConnectionId:   open.GetConnectionId(),
		Sql:            "select 1 from t",
	})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if reason := verdict.GetVerdict().GetDenyReason(); !strings.Contains(reason, "sql.select") {
		t.Errorf("denyReason = %q, want it to mention sql.select.\n"+
			"🔒 The ip-gated connect permit must have fired, which only happens if the run-minted "+
			"APPROVER_EXEC token's requester_ip reached Cedar. A connect-gate denial here means the IP "+
			"was registered for EDITOR only.", reason)
	}

	// Service the dial so the run completes cleanly and the registry entry goes with the token revoke.
	proxy := f.dial(open.GetSessionId(), allowRows(nil))
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(runGate):
		t.Fatal("the run never completed")
	}
	proxy.awaitClosed()
	assertCarriedIP(t, f.carriedIP(tok), nil,
		"the APPROVER_EXEC registry entry is removed alongside the token revoke")
}

// --- EditorSessionDecideTimingDbTest.kt ------------------------------------------------------------
//
// KT: EditorSessionDecideTimingDbTest.kt#each session query's real gRPC Decide sees THAT query's refreshed requester_ip, proving refresh-before-send
//
// 🔒 THE TIMING REGRESSION, and the whole reason this suite exists separately from case 11 above. Case 11
// asserts the registry value AFTER runOnSession returns, which holds whether the refresh ran before or
// after the send — so moving the refresh below sendRunQuery leaves it GREEN. Here the fake proxy invokes
// the REAL gRPC Decide (with the session token) WHILE servicing each query, against an ip-gated policy.
//
// A session that first queries from an ALLOWED IP and then from a nil one must see ALLOW then DENY. The
// DENY is the proof: it can only happen if the refresh CLEARED the entry before the query crossed the
// wire. Move the refresh after the send and the second query's decide reads the stale allowed IP →
// ALLOW → this test goes red.
func TestEachSessionQuerysRealDecideSeesThatQuerysRefreshedRequesterIP(t *testing.T) {
	f := newRunFixture(t)
	// connect + sql.select granted to ANY principal ONLY when requester_ip is inside 203.0.113.0/24. A nil
	// or out-of-range IP fails `context has requester_ip` / the range test, the permit never fires, and
	// deny-by-default takes the connect gate. So the verdict is a pure function of the CURRENT IP.
	f.mustCreatePolicy("timing-ip-gated-connect-select",
		`permit(
			principal,
			action in [Action::"datasource.connect", Action::"sql.select"],
			resource in Datasource::"`+f.ds.Name+`"
		) when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };`)

	opens, detach := f.events()
	defer func() {
		detach()
		f.awaitDetached()
	}()

	type opened struct {
		id  string
		err error
	}
	openDone := make(chan opened, 1)
	go func() {
		// Open from an ALLOWED IP, so a stale read would ALLOW — the trap the second query must not fall
		// into.
		id, err := f.svc.OpenSession(context.Background(), "timing-user", f.ds, ipOf("203.0.113.42"))
		openDone <- opened{id, err}
	}()
	open := f.nextOpen(opens)
	tok := open.GetEphemeralToken()

	var (
		verdictMu sync.Mutex
		verdicts  = map[string]pb.EnfAction{}
	)
	proxy := f.dial(open.GetSessionId(), func(send func(*pb.ProxyRunMsg), q *pb.RunQuery) {
		// The REAL Decide, with the session's own token, WHILE the query is in flight. This is the only
		// observation point at which the refresh's timing is visible.
		response, err := f.client.Decide(f.authed, &pb.DecisionRequest{
			Token:          tok,
			DatasourceName: f.ds.Name,
			ConnectionId:   open.GetConnectionId(),
			Sql:            q.GetSql(),
		})
		if err != nil {
			t.Errorf("Decide during %q: %v", q.GetSql(), err)
		} else {
			verdictMu.Lock()
			verdicts[q.GetSql()] = response.GetVerdict().GetDecision()
			verdictMu.Unlock()
		}
		// Fabricate an ALLOW so runOnSession returns normally; the Decide verdict above is the assertion.
		send(decisionOf(&pb.RunDecision{Decision: pb.EnfAction_ALLOW}))
		send(rowsOf([]string{"echo"}, []*string{sp(q.GetSql())}))
		send(doneOf(-1))
	})

	var session opened
	select {
	case session = <-openDone:
	case <-time.After(runGate):
		t.Fatal("openSession never returned")
	}
	if session.err != nil {
		t.Fatalf("openSession: %v", session.err)
	}

	f.runOnSession(session.id, "timing-user", "select 1", ipOf("203.0.113.50"))
	f.runOnSession(session.id, "timing-user", "select 2", nil)

	verdictMu.Lock()
	first, second := verdicts["select 1"], verdicts["select 2"]
	verdictMu.Unlock()

	if first != pb.EnfAction_ALLOW {
		t.Errorf("the first query's Decide = %v, want ALLOW — it must see the refreshed allowed IP 203.0.113.50",
			first)
	}
	if second != pb.EnfAction_DENY {
		t.Errorf("the second query's Decide = %v, want DENY.\n"+
			"🔒 The refresh must happen BEFORE the send: this query passed a nil requester_ip, so the "+
			"entry had to be CLEARED before the proxy's decide, and the ip-gated permit could then not "+
			"fire. An ALLOW here means the decide read the STALE allowed IP — the refresh moved below "+
			"sendRunQuery.", second)
	}
	assertCarriedIP(t, f.carriedIP(tok), nil, "a nil-IP session query clears the stale allowed IP fail-closed")

	if !f.svc.CloseSessionOwnedBy(session.id, "timing-user") {
		t.Error("the owner could not close their own session")
	}
	proxy.awaitClosed()
}

// TestTheRequesterIPRefreshIsObservablyBeforeTheSend is the DETERMINISTIC pin for refresh-before-send,
// and it exists because the ported Kotlin case above is NOT one.
//
// 🔴 MEASURED, NOT ASSUMED: with the refresh moved BELOW sendRunQuery,
// TestEachSessionQuerysRealDecideSeesThatQuerysRefreshedRequesterIP still PASSES. The reason is a race
// the Kotlin has too — `sendRunQuery` returns as soon as the message enters the outbound buffer, so a
// post-send `Set` lands microseconds later while the proxy's own Decide is still a gRPC round-trip away.
// The clear almost always wins, and the test that was written to catch the reordering does not.
//
// This one is deterministic because it observes from INSIDE the service's own call stack. `Preflight` is
// invoked synchronously, under the cancel gate, immediately BEFORE the send (RunExec.kt:233), and the
// refresh sits immediately before that:
//
//	correct:  Set(this query's IP) → preflight() → send
//	reordered: preflight() → send → Set(this query's IP)
//
// So the value the registry holds AT PREFLIGHT TIME distinguishes them with no timing assumption at all:
// this query's IP if the refresh already ran, the PREVIOUS query's if it has not.
func TestTheRequesterIPRefreshIsObservablyBeforeTheSend(t *testing.T) {
	f := newRunFixture(t)
	opens, detach := f.events()
	defer func() {
		detach()
		f.awaitDetached()
	}()

	type opened struct {
		id  string
		err error
	}
	openDone := make(chan opened, 1)
	go func() {
		id, err := f.svc.OpenSession(context.Background(), "preflight-user", f.ds, ipOf("198.51.100.1"))
		openDone <- opened{id, err}
	}()
	open := f.nextOpen(opens)
	tok := open.GetEphemeralToken()
	proxy := f.dial(open.GetSessionId(), echoQuery)

	var session opened
	select {
	case session = <-openDone:
	case <-time.After(runGate):
		t.Fatal("openSession never returned")
	}
	if session.err != nil {
		t.Fatalf("openSession: %v", session.err)
	}

	// Two queries: the first sets a value, the second must have OVERWRITTEN it before its own send.
	for _, tc := range []struct {
		sql  string
		ip   *string
		want *string
	}{
		{"select first", ipOf("203.0.113.7"), ipOf("203.0.113.7")},
		{"select second", ipOf("203.0.113.8"), ipOf("203.0.113.8")},
		// 🔒 And the nil case, which is the fail-closed one: the entry must be GONE at preflight time,
		// not merely overwritten later.
		{"select third", nil, nil},
	} {
		var atPreflight *string
		var observed bool
		taskID := int64(1)
		if _, err := f.svc.RunOnSession(context.Background(), query.SessionRunInput{
			SessionID: session.id, Principal: "preflight-user", SQL: tc.sql, MaxRows: 500,
			RequesterIP: tc.ip,
			TaskID:      &taskID,
			Preflight: func() bool {
				atPreflight, observed = f.carriedIP(tok), true
				return true
			},
		}); err != nil {
			t.Fatalf("runOnSession(%q): %v", tc.sql, err)
		}
		if !observed {
			t.Fatalf("%q: preflight never ran, so nothing was observed — it must run inside the gate "+
				"before the send", tc.sql)
		}
		assertCarriedIP(t, atPreflight, tc.want,
			"the carried requester_ip AT PREFLIGHT TIME for "+tc.sql+
				" — 🔒 the refresh must already have happened, i.e. it is BEFORE the send")
	}

	if !f.svc.CloseSessionOwnedBy(session.id, "preflight-user") {
		t.Error("the owner could not close their own session")
	}
	proxy.awaitClosed()
}

// --- ADDED (not one of the 14) · the §10 coverage gaps this increment closes -----------------------

// TestSweepIdleSessionsReapsByLastUseAndSparesActiveOnes closes the `sweepIdleSessions` gap
// (07-tasks-approvals-results.md §10: "sweepIdleSessions / closeSessionsForPrincipal" — untested).
//
// It is what releases a backend connection for an editor tab that was closed without a DELETE, and A1's
// 15-minute purge loop is its only production caller.
func TestSweepIdleSessionsReapsByLastUseAndSparesActiveOnes(t *testing.T) {
	f := newRunFixture(t)
	opens, detach := f.events()
	defer func() {
		detach()
		f.awaitDetached()
	}()

	type opened struct {
		id  string
		err error
	}
	done := make(chan opened, 1)
	go func() {
		id, err := f.svc.OpenSession(context.Background(), "idle-user", f.ds, nil)
		done <- opened{id, err}
	}()
	open := f.nextOpen(opens)
	proxy := f.dial(open.GetSessionId(), echoQuery)
	var session opened
	select {
	case session = <-done:
	case <-time.After(runGate):
		t.Fatal("openSession never returned")
	}
	if session.err != nil {
		t.Fatalf("openSession: %v", session.err)
	}

	// A generous idle bound spares a session used moments ago.
	if reaped := f.svc.SweepIdleSessions(60 * 60 * 1000); reaped != 0 {
		t.Errorf("the sweep reaped %d session(s) with a one-hour idle bound; the session was just opened", reaped)
	}
	if f.svc.OpenSessionCount() != 1 {
		t.Fatalf("%d sessions after a no-op sweep, want 1", f.svc.OpenSessionCount())
	}

	// A zero bound reaps it, and the reap is a real close: the stream gets its RunClose and the token is
	// revoked.
	if reaped := f.svc.SweepIdleSessions(0); reaped != 1 {
		t.Errorf("the sweep reaped %d session(s) with a zero idle bound, want 1", reaped)
	}
	proxy.awaitClosed()
	if got := f.tokenResolves(open.GetEphemeralToken()); got != "" {
		t.Errorf("the reaped session's token still resolves to %q; the sweep must revoke it", got)
	}
	if f.svc.OpenSessionCount() != 0 {
		t.Errorf("%d sessions survive the sweep", f.svc.OpenSessionCount())
	}
}

// TestSessionDatasourceNameAndCloseAreOwnerScoped closes the other half of the §10 gap and pins the two
// owner-scoped lookups directly.
//
// 🔒 BOTH ANSWER "not found" FOR AN UNKNOWN *OR* A NOT-OWNED ID, so a leaked session id reveals nothing
// and cannot tear down another principal's held connection. Distinguishing the two would be an existence
// oracle over other users' editor tabs.
func TestSessionDatasourceNameAndCloseAreOwnerScoped(t *testing.T) {
	f := newRunFixture(t)
	if name, ok := f.svc.SessionDatasourceName("no-such-session", "anyone"); ok {
		t.Errorf("an unknown session id resolved to datasource %q", name)
	}
	if f.svc.CloseSessionOwnedBy("no-such-session", "anyone") {
		t.Error("closing an unknown session reported success")
	}

	opens, detach := f.events()
	defer func() {
		detach()
		f.awaitDetached()
	}()
	type opened struct {
		id  string
		err error
	}
	done := make(chan opened, 1)
	go func() {
		id, err := f.svc.OpenSession(context.Background(), "owner@example.com", f.ds, nil)
		done <- opened{id, err}
	}()
	open := f.nextOpen(opens)
	proxy := f.dial(open.GetSessionId(), echoQuery)
	var session opened
	select {
	case session = <-done:
	case <-time.After(runGate):
		t.Fatal("openSession never returned")
	}
	if session.err != nil {
		t.Fatalf("openSession: %v", session.err)
	}

	if name, ok := f.svc.SessionDatasourceName(session.id, "owner@example.com"); !ok || name != f.ds.Name {
		t.Errorf("the owner's lookup = (%q, %v), want (%q, true)", name, ok, f.ds.Name)
	}
	// 🔒 A non-owner gets the SAME answer as for an unknown id.
	if name, ok := f.svc.SessionDatasourceName(session.id, "intruder@example.com"); ok {
		t.Errorf("a non-owner resolved the session to datasource %q — that is an existence oracle", name)
	}
	if !f.svc.CloseSessionOwnedBy(session.id, "owner@example.com") {
		t.Error("the owner could not close their own session")
	}
	proxy.awaitClosed()
}

// TestTheServiceComputesTheTTLsFromTheConfiguredQueryTimeout binds A7's two TTL derivations to the
// SHIPPED symbols on the SHIPPED instance.
//
// It exists because internal/config's own case-25 port asserts the pure functions, and a pure function
// proves nothing about whether the composition root actually passed PM_QUERY_TIMEOUT in. Dropping that
// argument compiles, defaults to 600s, and a deployment with a longer timeout then gets UNAUTHENTICATED
// mid-run — with every other test still green.
func TestTheServiceComputesTheTTLsFromTheConfiguredQueryTimeout(t *testing.T) {
	f := newRunFixture(t)
	q := f.app.Config.QueryTimeoutSeconds
	if got, want := f.svc.RunTokenTTLSeconds(), config.RunTokenTTLSeconds(q); got != want {
		t.Errorf("the wired service's run-token TTL = %d, want %d for PM_QUERY_TIMEOUT=%d — "+
			"the composition root did not pass the configured timeout", got, want, q)
	}
	if got, want := f.svc.EditorSessionTTLSeconds(), config.EditorSessionTTLSeconds(q); got != want {
		t.Errorf("the wired service's editor-session TTL = %d, want %d for PM_QUERY_TIMEOUT=%d", got, want, q)
	}
	// 🔒 INV-A7-30, at the value that actually reaches the token store rather than the pure function:
	// both TTLs must outlive the window a single statement may run for.
	if !(f.svc.RunTokenTTLSeconds() > q) || !(f.svc.EditorSessionTTLSeconds() > q) {
		t.Errorf("a TTL does not outlive PM_QUERY_TIMEOUT=%d (run=%d, session=%d)",
			q, f.svc.RunTokenTTLSeconds(), f.svc.EditorSessionTTLSeconds())
	}
}

// sp / contains / statusCodeOf / readyStatus are the small helpers this file leans on.

func sp(s string) *string { return &s }

const (
	codesNotFound           = codes.NotFound
	codesFailedPrecondition = codes.FailedPrecondition
)

func statusCodeOf(err error) codes.Code { return status.Code(err) }

// readyStatus opens a RunExec stream, sends ONE Ready for sessionID, and reports the gRPC code the
// handler answered with. It is the Kotlin's `statusOf { stub.runExec(flowOf(ready)).collect() }`.
func (f *runFixture) readyStatus(sessionID string) codes.Code {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(f.authed, runGate)
	defer cancel()
	stream, err := f.client.RunExec(ctx)
	if err != nil {
		f.t.Fatalf("open RunExec: %v", err)
	}
	if err := stream.Send(&pb.ProxyRunMsg{
		Kind: &pb.ProxyRunMsg_SessionReady{SessionReady: &pb.RunReady{SessionId: sessionID}},
	}); err != nil {
		// A Send failure on a stream the server already rejected is normal; the status comes from Recv.
		f.t.Logf("send RunReady: %v", err)
	}
	_, recvErr := stream.Recv()
	return status.Code(recvErr)
}

// TestOpenSessionUnwindsFullyWhenTheDialCannotBeRequested closes the openSession-failure half of the
// §10 gap list, and it is FALSIFIABLE where the crud-e2e probe only checks a status code.
//
// 🔒 An openSession that fails after the mint must leave NOTHING behind: no live EDITOR token, no
// requester-IP entry, no pending session in the claim registry, and no session in the service's map. A
// port that returned the error without running the recovery block would still answer 503
// `query.no_proxy_attached` — the status is not the assertion, the unwind is.
func TestOpenSessionUnwindsFullyWhenTheDialCannotBeRequested(t *testing.T) {
	f := newRunFixture(t)
	// No Events stream is attached, so RequestOpenRun answers NOT_ATTACHED after the token is already
	// minted and the catalog connection already opened — the exact post-mint failure path.
	f.awaitUntil("no Events stream attached", func() bool { return !f.isAttached() })

	if _, err := f.svc.OpenSession(context.Background(), "unwind-user", f.ds, ipOf("203.0.113.10")); !errors.Is(err, query.ErrNoProxyAttached) {
		t.Fatalf("openSession with no proxy returned %v, want query.ErrNoProxyAttached", err)
	}
	if n := f.activeEphemeralTokens("unwind-user", token.KindEditor); n != 0 {
		t.Errorf("%d live EDITOR token(s) survive a failed openSession; the unwind must revoke the "+
			"per-session token it just minted", n)
	}
	if f.svc.OpenSessionCount() != 0 {
		t.Errorf("%d session(s) are held after a failed openSession", f.svc.OpenSessionCount())
	}
	// A second attempt behaves identically — the failure left no state that changes the next one.
	if _, err := f.svc.OpenSession(context.Background(), "unwind-user", f.ds, nil); !errors.Is(err, query.ErrNoProxyAttached) {
		t.Errorf("the second openSession returned %v, want the same typed failure", err)
	}
	if n := f.activeEphemeralTokens("unwind-user", token.KindEditor); n != 0 {
		t.Errorf("%d live EDITOR token(s) after two failed openSessions", n)
	}
}

// TestNoRequesterIPEntryOutlivesItsSessionTokenWhenACloseRacesAQuery is the POST-CONDITION of
// runOnSession's outer `finally` (07-tasks-approvals-results.md §10's "runOnSession's outer-finally
// registry re-sweep — the specific closeSession-races-query interleaving").
//
// 🔴 READ THIS BEFORE TRUSTING IT AS A REGRESSION TEST. It asserts the post-condition — no
// requester-IP entry survives a session whose close raced its query — and NOT the outer sweep itself.
// On every interleaving a test can force, `CloseSession`'s own `Remove` already suffices, so deleting the
// outer `finally` would leave this GREEN.
//
// The reason is structural rather than a gap in effort. The outer sweep is load-bearing for a window of
// three statements: between `isLive`'s re-check and the registry `Set`, both of which run under the
// session mutex with no seam between them. A close that lands strictly inside that window re-creates an
// entry whose token has already been revoked; a close a millisecond either side does not. There is no
// hook to pause the service mid-window, and the only tests that could reach it are timing lotteries that
// would pass for the wrong reason far more often than they would fail for the right one.
//
// So: the invariant is real, this pins its OBSERVABLE CONSEQUENCE (which is the security-relevant half —
// a live registry entry for a revoked token would let a later decide read an IP it must not), and the
// unreachable window is recorded here rather than papered over.
func TestNoRequesterIPEntryOutlivesItsSessionTokenWhenACloseRacesAQuery(t *testing.T) {
	f := newRunFixture(t)
	opens, detach := f.events()
	defer func() {
		detach()
		f.awaitDetached()
	}()

	type opened struct {
		id  string
		err error
	}
	done := make(chan opened, 1)
	go func() {
		id, err := f.svc.OpenSession(context.Background(), "race-user", f.ds, ipOf("203.0.113.1"))
		done <- opened{id, err}
	}()
	open := f.nextOpen(opens)
	tok := open.GetEphemeralToken()
	proxy := f.dial(open.GetSessionId(), echoQuery)
	var session opened
	select {
	case session = <-done:
	case <-time.After(runGate):
		t.Fatal("openSession never returned")
	}
	if session.err != nil {
		t.Fatalf("openSession: %v", session.err)
	}

	// Close the session from INSIDE the preflight, i.e. under the session mutex and after the refresh —
	// the closest a test can get to the racing close, and enough to make the session not-live at exit.
	//
	// ⚠️ ExchangeTimeoutMs IS LOAD-BEARING HERE, and finding out why was worth the detour. Closing inside
	// the preflight puts the RunClose on the wire BEFORE the RunQuery (CloseSession sends the close; the
	// query goes out immediately after preflight returns), so the fake proxy processes the close first,
	// half-closes its send side, and never answers the query. The control plane then waits — and it waits
	// for the FULL exchange budget rather than noticing the half-close, because grpcsvc's RunExec handler
	// blocks on `<-sendErr` after the client's EOF and only reaches its deferred `close(attached.Inbound)`
	// when the outbound channel closes or the stream deadline fires. Neither happens promptly. That is a
	// PRE-EXISTING A10 property, not something this port introduced, and changing it is out of scope; a
	// short budget makes the case fast, and a typed timeout is the honest outcome for a session closed out
	// from under its own query.
	taskID := int64(1)
	_, err := f.svc.RunOnSession(context.Background(), query.SessionRunInput{
		SessionID: session.id, Principal: "race-user", SQL: "select racing", MaxRows: 500,
		RequesterIP:       ipOf("203.0.113.2"),
		TaskID:            &taskID,
		ExchangeTimeoutMs: 2_000,
		Preflight: func() bool {
			f.svc.CloseSession(session.id)
			return true
		},
	})
	// Some error is expected — the stream was closed under the query — but WHICH one is not this test's
	// subject, so it is not asserted.
	_ = err

	// 🔒 THE POST-CONDITION. The token is revoked and the carrier entry is gone — in that order and with
	// no survivor, so no later decide can read an IP belonging to a credential that no longer exists.
	if principal := f.tokenResolves(tok); principal != "" {
		t.Errorf("the session token still resolves to %q after the racing close", principal)
	}
	assertCarriedIP(t, f.carriedIP(tok), nil,
		"no requester-IP entry may outlive its session token — a stale entry is an IP attribute for a "+
			"revoked credential")
	if f.svc.OpenSessionCount() != 0 {
		t.Errorf("%d session(s) held after the close", f.svc.OpenSessionCount())
	}
	proxy.awaitClosed()
}
