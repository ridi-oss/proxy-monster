package app_test

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/policy"
	"github.com/ridi-oss/proxy-monster/gocp/internal/token"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// PORT of `GrpcDecideHandlerDbTest` — 18 cases over a real Postgres, a real ControlPlaneCore and a
// real gRPC server on a socket.
//
// WHAT THE KOTLIN SUITE IS FOR, from its kdoc: "the focus is what's NEW in the gRPC path: per-query
// token re-validation (the revocation-gap fix), datasource-by-name resolution, deactivation rechecks,
// and the authN-vs-authZ status split. Decision *correctness* (ALLOW/MASK/lineage) is exercised
// directly against `decideAndAudit` by SchemaThreadingDbTest's live-search-path tests, so it is not
// re-proven here."
//
// 🔒 THE STATUS SPLIT IS THE THEME. UNAUTHENTICATED means "this credential is no longer good" and the
// proxy tears the connection down; a DENY verdict means "the credential is fine, the policy said no"
// and the connection survives. Collapsing the two in either direction is a real bug: an
// UNAUTHENTICATED rendered as DENY leaves a revoked token holding a live wire session, and a DENY
// rendered as UNAUTHENTICATED drops connections on ordinary policy outcomes.
//
// The gate is open here (secretToken nil) — the interceptor is GrpcServerTest's subject.
// ---------------------------------------------------------------------------------------------

type decideFixture struct {
	t   *testing.T
	b   *bootedApp
	ctx context.Context
	ds  datasource.Datasource
	// validToken belongs to a principal with NO roles and NO grants — the deny-by-default path.
	validToken string
}

func newDecideFixture(t *testing.T) *decideFixture {
	t.Helper()
	b := bootE2E(t, nil)
	f := &decideFixture{t: t, b: b, ctx: context.Background()}

	ds, err := b.app.Core.DatasourceStore.Create(f.ctx, datasource.DatasourceInput{
		Name: "grpc-ds", Engine: "postgres", Host: "localhost", Port: 5432, DBName: "app",
	})
	if err != nil {
		t.Fatalf("create datasource: %v", err)
	}
	f.ds = ds
	f.validToken = f.issue("grpc-user")
	return f
}

func (f *decideFixture) issue(principal string) string {
	f.t.Helper()
	issued, err := f.b.app.Core.TokenStore.Issue(f.ctx, f.b.app.Db.Pool,
		token.KindUser, principal, nil, nil, 3600)
	if err != nil {
		f.t.Fatalf("issue token for %s: %v", principal, err)
	}
	return issued.Token
}

func (f *decideFixture) issueWithID(principal string) (string, int64) {
	f.t.Helper()
	issued, err := f.b.app.Core.TokenStore.Issue(f.ctx, f.b.app.Db.Pool,
		token.KindUser, principal, nil, nil, 3600)
	if err != nil {
		f.t.Fatalf("issue token for %s: %v", principal, err)
	}
	return issued.Token, issued.ID
}

// open is the Kotlin's `open(token, datasource)`.
//
// ⚠️ IT GOES THROUGH THE STORE AND THE REGISTRY, NOT THROUGH ValidateToken — exactly as the Kotlin
// does (`core.tokenStore.resolve` + `core.connectionCatalog.open`). That is not a shortcut: two of the
// cases below deactivate a principal BEFORE opening, and the RPC would reject the handshake, so
// routing the fixture through it would make those cases assert the handshake rather than the thing
// they are about. Only the PushSchemaFragment half goes over the wire, because the pre-gate reads the
// content hashes the real handler records.
func (f *decideFixture) open(tok string) []byte {
	f.t.Helper()
	resolved, err := f.b.app.Core.TokenStore.Resolve(f.ctx, tok)
	if err != nil || resolved == nil {
		f.t.Fatalf("resolve token: %v", err)
	}
	sys, err := datasource.SystemSchemas(datasource.Engine(f.ds.Engine))
	if err != nil {
		f.t.Fatalf("system schemas: %v", err)
	}
	schemas := append([]string{}, f.ds.DefaultSchemas...)
	for name := range sys {
		schemas = append(schemas, name)
	}
	opened := f.b.app.Core.ConnectionCatalog.Open(datasource.Binding{
		DatasourceName: f.ds.Name, Principal: resolved.Principal, TokenKind: string(resolved.Kind),
	}, schemas, false)

	var generation uint64 = 1
	for _, r := range opened.OnOpen {
		schema := r.GetSchema()
		if schema == "" {
			continue
		}
		if _, err := f.b.client.PushSchemaFragment(f.ctx, &pb.SchemaFragmentPush{
			ConnectionId:      []byte(opened.ConnectionID),
			DatasourceName:    f.ds.Name,
			Schema:            schema,
			ContentHash:       []byte("empty:" + schema),
			BackendGeneration: generation,
		}); err != nil {
			f.t.Fatalf("PushSchemaFragment(%s): %v", schema, err)
		}
		generation++
	}
	return []byte(opened.ConnectionID)
}

func (f *decideFixture) decide(req *pb.DecisionRequest) (*pb.WireDecision, error) {
	return f.b.client.Decide(f.ctx, req)
}

// codeOf is the Kotlin's `statusOf { … }`: the gRPC code of a call that must fail.
func codeOf(t *testing.T, err error) codes.Code {
	t.Helper()
	if err == nil {
		t.Fatal("call succeeded; a failure with a gRPC status was required")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error is not a gRPC status: %v", err)
	}
	return st.Code()
}

// deactivate creates the user row then flips it inactive, which is what `setUserActive(false)` needs
// to have something to act on.
func (f *decideFixture) deactivate(principal string) {
	f.t.Helper()
	if _, err := f.b.app.Core.UserGroupStore.CreateUser(f.ctx,
		identity.AppUserInput{Principal: principal}, nil); err != nil {
		f.t.Fatalf("create user %s: %v", principal, err)
	}
	if _, err := f.b.app.Core.UserGroupStore.SetUserActive(f.ctx, principal, false); err != nil {
		f.t.Fatalf("deactivate %s: %v", principal, err)
	}
}

// --- the cases ------------------------------------------------------------------------------------

// KT: GrpcDecideHandlerDbTest.kt#validateToken returns the identity for a valid token
func TestGrpcValidateTokenReturnsTheIdentity(t *testing.T) {
	f := newDecideFixture(t)
	id, err := f.b.client.ValidateToken(f.ctx, &pb.ValidateTokenRequest{
		Token: f.validToken, DatasourceName: f.ds.Name,
	})
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if id.GetPrincipal() != "grpc-user" {
		t.Errorf("principal = %q, want grpc-user", id.GetPrincipal())
	}
}

// KT: GrpcDecideHandlerDbTest.kt#validateToken rejects an unknown token UNAUTHENTICATED
func TestGrpcValidateTokenRejectsAnUnknownToken(t *testing.T) {
	f := newDecideFixture(t)
	_, err := f.b.client.ValidateToken(f.ctx, &pb.ValidateTokenRequest{
		Token: "nope", DatasourceName: f.ds.Name,
	})
	if got := codeOf(t, err); got != codes.Unauthenticated {
		t.Errorf("code = %s, want UNAUTHENTICATED", got)
	}
}

// KT: GrpcDecideHandlerDbTest.kt#validateToken rejects a revoked token UNAUTHENTICATED
func TestGrpcValidateTokenRejectsARevokedToken(t *testing.T) {
	f := newDecideFixture(t)
	tok, id := f.issueWithID("revoke-user")
	ok, err := f.b.app.Core.TokenStore.Revoke(f.ctx, id, "revoke-user")
	if err != nil || !ok {
		t.Fatalf("revoke: ok=%v err=%v", ok, err)
	}
	_, err = f.b.client.ValidateToken(f.ctx, &pb.ValidateTokenRequest{
		Token: tok, DatasourceName: f.ds.Name,
	})
	if got := codeOf(t, err); got != codes.Unauthenticated {
		t.Errorf("code = %s, want UNAUTHENTICATED", got)
	}
}

// KT: GrpcDecideHandlerDbTest.kt#validateToken rejects a deactivated principal UNAUTHENTICATED
func TestGrpcValidateTokenRejectsADeactivatedPrincipal(t *testing.T) {
	f := newDecideFixture(t)
	f.deactivate("gone-user")
	tok := f.issue("gone-user")
	_, err := f.b.client.ValidateToken(f.ctx, &pb.ValidateTokenRequest{
		Token: tok, DatasourceName: f.ds.Name,
	})
	if got := codeOf(t, err); got != codes.Unauthenticated {
		t.Errorf("code = %s, want UNAUTHENTICATED — a deactivated principal's token is dead even "+
			"though the token row itself is neither revoked nor expired", got)
	}
}

// KT: GrpcDecideHandlerDbTest.kt#decide re-validates the token per query - a token revoked mid-session is rejected
//
// 🔒 THE REVOCATION-GAP FIX, and the most important case in the file. Validating only at handshake
// would let a revoked token keep deciding queries for the life of its connection — the connection is
// long-lived and the token check would be a one-time event. Re-validating PER QUERY is what makes
// revocation take effect immediately.
func TestGrpcDecideRevalidatesTheTokenPerQuery(t *testing.T) {
	f := newDecideFixture(t)
	tok, id := f.issueWithID("session-user")

	// The handshake succeeds while the token is good, and mints the connection state.
	identity, err := f.b.client.ValidateToken(f.ctx, &pb.ValidateTokenRequest{
		Token: tok, DatasourceName: f.ds.Name,
	})
	if err != nil {
		t.Fatalf("ValidateToken while valid: %v", err)
	}

	ok, err := f.b.app.Core.TokenStore.Revoke(f.ctx, id, "session-user")
	if err != nil || !ok {
		t.Fatalf("revoke: ok=%v err=%v", ok, err)
	}

	_, err = f.decide(&pb.DecisionRequest{
		Token: tok, DatasourceName: f.ds.Name,
		ConnectionId: identity.GetConnectionId(), Sql: "select 1",
	})
	if got := codeOf(t, err); got != codes.Unauthenticated {
		t.Errorf("code = %s, want UNAUTHENTICATED — a token revoked mid-session must be rejected on "+
			"the NEXT decide, not honoured for the life of the connection", got)
	}
}

// KT: GrpcDecideHandlerDbTest.kt#decide rejects a deactivated principal UNAUTHENTICATED (session teardown, not a policy deny)
//
// 🔒 THE authN/authZ SPLIT. decideQuery has its own internal deactivation gate that would produce a
// DENY verdict; the handler's explicit check must fire FIRST and turn it into UNAUTHENTICATED, because
// a deactivated principal is a dead credential (tear the session down) rather than a policy outcome
// (keep the connection, refuse the statement).
func TestGrpcDecideRejectsADeactivatedPrincipalAsUnauthenticated(t *testing.T) {
	f := newDecideFixture(t)
	f.deactivate("decide-gone")
	tok := f.issue("decide-gone")
	connID := f.open(tok)

	_, err := f.decide(&pb.DecisionRequest{
		Token: tok, DatasourceName: f.ds.Name, ConnectionId: connID, Sql: "select 1",
	})
	if got := codeOf(t, err); got != codes.Unauthenticated {
		t.Errorf("code = %s, want UNAUTHENTICATED, NOT the DENY decideQuery's internal deactivation "+
			"gate would otherwise produce", got)
	}
}

// KT: GrpcDecideHandlerDbTest.kt#decide rejects an unknown datasource NOT_FOUND
func TestGrpcDecideRejectsAnUnknownDatasource(t *testing.T) {
	f := newDecideFixture(t)
	connID := f.open(f.validToken)
	_, err := f.decide(&pb.DecisionRequest{
		Token: f.validToken, DatasourceName: "does-not-exist", ConnectionId: connID, Sql: "select 1",
	})
	if got := codeOf(t, err); got != codes.NotFound {
		t.Errorf("code = %s, want NOT_FOUND", got)
	}
}

// KT: GrpcDecideHandlerDbTest.kt#decide denies an ungranted principal by default and audits the decision
//
// 🔒 FAIL-CLOSED PLUS AUDITED. The deny is the expected outcome for a principal with no roles, but the
// `decisionId > 0` half is the one that would silently rot: a deny that is never written to the audit
// chain leaves no record that the attempt happened.
func TestGrpcDecideDeniesAnUngrantedPrincipalAndAudits(t *testing.T) {
	f := newDecideFixture(t)
	connID := f.open(f.validToken)

	d, err := f.decide(&pb.DecisionRequest{
		Token: f.validToken, DatasourceName: f.ds.Name, ConnectionId: connID,
		Sql: "select 1 from foo",
	})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	v := d.GetVerdict()
	if v == nil {
		t.Fatal("no verdict; an ungranted principal must get a DENY verdict, not a before_decide")
	}
	if v.GetDecision() != pb.EnfAction_DENY {
		t.Errorf("decision = %s, want DENY", v.GetDecision())
	}
	if v.GetDecisionId() <= 0 {
		t.Error("decisionId = 0; a wire decision must be audited")
	}
	if !strings.Contains(v.GetDenyReason(), "no access to datasource") {
		t.Errorf("denyReason = %q, want it to mention \"no access to datasource\"", v.GetDenyReason())
	}
}

// KT: GrpcDecideHandlerDbTest.kt#decide rejects an expired token UNAUTHENTICATED
func TestGrpcDecideRejectsAnExpiredToken(t *testing.T) {
	f := newDecideFixture(t)
	tok, id := f.issueWithID("expired-user")
	connID := f.open(tok)

	// The minimum configurable TTL is 60s, so the row is force-expired rather than waited out.
	if _, err := f.b.app.Db.Pool.Exec(f.ctx,
		`UPDATE proxy_token SET expires_at = now() - interval '1 hour' WHERE id = $1`, id); err != nil {
		t.Fatalf("force-expire token: %v", err)
	}

	_, err := f.decide(&pb.DecisionRequest{
		Token: tok, DatasourceName: f.ds.Name, ConnectionId: connID, Sql: "select 1",
	})
	if got := codeOf(t, err); got != codes.Unauthenticated {
		t.Errorf("code = %s, want UNAUTHENTICATED", got)
	}
}

// --- helpers for the policy / channel / requester_ip group ----------------------------------------

func (f *decideFixture) addPolicy(name, src string) {
	f.t.Helper()
	if _, err := f.b.app.Core.CedarPolicyStore.Create(f.ctx,
		policy.NewCedarPolicyInput(name, src), nil); err != nil {
		f.t.Fatalf("create policy %s: %v", name, err)
	}
}

// connectPermit is the ip-gated `datasource.connect` permit four of these cases share verbatim.
func (f *decideFixture) ipGatedConnectPermit(name string) {
	f.t.Helper()
	f.addPolicy(name, `permit(principal, action == Action::"datasource.connect", resource == Datasource::"`+f.ds.Name+`")
		when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };`)
}

func (f *decideFixture) issueKind(kind token.Kind, principal string, roles []string) token.Issued {
	f.t.Helper()
	issued, err := f.b.app.Core.TokenStore.Issue(f.ctx, f.b.app.Db.Pool, kind, principal, roles, nil, 3600)
	if err != nil {
		f.t.Fatalf("issue %s token for %s: %v", kind, principal, err)
	}
	return issued
}

// verdictFor runs one decide over an opened connection and demands a verdict.
func (f *decideFixture) verdictFor(tok, sql, clientAddr string) *pb.Verdict {
	f.t.Helper()
	d, err := f.decide(&pb.DecisionRequest{
		Token: tok, DatasourceName: f.ds.Name, ConnectionId: f.open(tok),
		Sql: sql, ClientAddr: clientAddr,
	})
	if err != nil {
		f.t.Fatalf("Decide: %v", err)
	}
	v := d.GetVerdict()
	if v == nil {
		f.t.Fatalf("no verdict (before_decide = %v); the fixture's open() must have satisfied the "+
			"freshness pre-gate", d.GetBeforeDecide())
	}
	return v
}

// KT: GrpcDecideHandlerDbTest.kt#an HTTP-side policy edit is seen by the gRPC decision path
//
// 🔒 THE CASE THAT JUSTIFIES ControlPlaneCore. CedarEngine's cache invalidates only on the shared
// CedarPolicyStore's in-memory state version, so a second or divergent graph would leave this green
// while the gRPC engine served a stale PolicySet. Warm the engine, edit policy through the SAME core
// the HTTP admin routes use, and the next gRPC decision must reflect it.
//
// The assertion is that the deny MOVES — from the connect gate to sql.select — rather than merely that
// something changed. A stale cache would still report "no access to datasource".
func TestGrpcAnHTTPSidePolicyEditIsSeenByTheGrpcDecisionPath(t *testing.T) {
	f := newDecideFixture(t)
	tok := f.issue("cache-user")

	before := f.verdictFor(tok, "select 1 from t", "")
	if before.GetDecision() != pb.EnfAction_DENY {
		t.Fatalf("before: decision = %s, want DENY", before.GetDecision())
	}
	if !strings.Contains(before.GetDenyReason(), "no access to datasource") {
		t.Fatalf("before: denyReason = %q, want the connect-gate deny", before.GetDenyReason())
	}

	role, err := f.b.app.Core.PolicyStore.CreateRole(f.ctx, policy.RoleInput{Name: "cache-role"})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if _, err := f.b.app.Core.PolicyStore.CreateAssignment(f.ctx,
		policy.RoleAssignmentInput{Principal: "cache-user", RoleID: role.ID}); err != nil {
		t.Fatalf("create assignment: %v", err)
	}
	f.addPolicy("cache-connect",
		`permit(principal in Role::"cache-role", action == Action::"datasource.connect", resource == Datasource::"`+f.ds.Name+`");`)

	after := f.verdictFor(tok, "select 1 from t", "")
	if after.GetDecision() != pb.EnfAction_DENY {
		t.Errorf("after: decision = %s, want DENY (now at the sql.select gate)", after.GetDecision())
	}
	if !strings.Contains(after.GetDenyReason(), "sql.select") {
		t.Errorf("after: denyReason = %q, want a sql.select deny", after.GetDenyReason())
	}
	if strings.Contains(after.GetDenyReason(), "no access to datasource") {
		t.Errorf("after: denyReason = %q — the connect gate should now PASS; a stale Cedar cache is "+
			"exactly what this case exists to catch", after.GetDenyReason())
	}
}

// KT: GrpcDecideHandlerDbTest.kt#a native-wire token cannot assert roles from the token, but an approver-exec token's assume-role is honored
//
// 🔒 A NATIVE TOKEN CANNOT ASSERT PRIVILEGE. Both tokens carry `elevated` in their roles column and a
// permit grants that role connect. The USER token must be decided on SERVER-RESOLVED roles (it has no
// such assignment ⇒ deny); the APPROVER_EXEC token's on-token roles ARE its assume-role set
// (execute-under-R ⇒ allow). If on-token roles were ever honoured for wire tokens, minting a token
// would be privilege escalation.
func TestGrpcANativeWireTokenCannotAssertRolesButApproverExecAssumeRoleIsHonored(t *testing.T) {
	f := newDecideFixture(t)
	f.addPolicy("elevated-connect",
		`permit(principal in Role::"elevated", action == Action::"datasource.connect", resource == Datasource::"`+f.ds.Name+`");`)

	userTok := f.issueKind(token.KindUser, "native-asserter", []string{"elevated"})
	uv := f.verdictFor(userTok.Token, "select 1", "")
	if uv.GetDecision() != pb.EnfAction_DENY {
		t.Errorf("native-wire decision = %s, want DENY — on-token roles must be IGNORED", uv.GetDecision())
	}
	if !strings.Contains(uv.GetDenyReason(), "no access to datasource") {
		t.Errorf("native-wire denyReason = %q, want the connect-gate deny", uv.GetDenyReason())
	}

	execTok := f.issueKind(token.KindApproverExec, "exec-asserter", []string{"elevated"})
	ev := f.verdictFor(execTok.Token, "select 1", "")
	if ev.GetDecision() != pb.EnfAction_ALLOW {
		t.Errorf("approver-exec decision = %s, want ALLOW — its on-token roles are the assume-role "+
			"set (deny reason %q)", ev.GetDecision(), ev.GetDenyReason())
	}
}

// KT: GrpcDecideHandlerDbTest.kt#a no-R approver-exec decides at the editor channel, only a with-R token reaches workflow-executor
//
// 🔒 THE NO-R ESCALATION FIX. The channel an APPROVER_EXEC token decides on is derived from whether it
// carries an assume-role: with-R ⇒ workflow-executor, no-R ⇒ editor. A permit gated on
// workflow-executor must therefore fire for the first and not the second. If the channel were derived
// from the token KIND alone, a no-R approver-exec would silently reach workflow-executor policy.
func TestGrpcNoRApproverExecDecidesAtEditorChannel(t *testing.T) {
	f := newDecideFixture(t)
	f.addPolicy("wfexec-only-connect",
		`permit(principal, action == Action::"datasource.connect", resource == Datasource::"`+f.ds.Name+`")
			when { context has channel && context.channel == "workflow-executor" };`)

	withR := f.issueKind(token.KindApproverExec, "with-r", []string{"some-role"})
	wv := f.verdictFor(withR.Token, "select 1", "")
	if wv.GetDecision() != pb.EnfAction_ALLOW {
		t.Errorf("with-R decision = %s, want ALLOW at workflow-executor (deny reason %q)",
			wv.GetDecision(), wv.GetDenyReason())
	}

	noR := f.issueKind(token.KindApproverExec, "no-r", nil)
	nv := f.verdictFor(noR.Token, "select 1", "")
	if nv.GetDecision() != pb.EnfAction_DENY {
		t.Errorf("no-R decision = %s, want DENY — it must decide at EDITOR, not workflow-executor",
			nv.GetDecision())
	}
	if !strings.Contains(nv.GetDenyReason(), "no access to datasource") {
		t.Errorf("no-R denyReason = %q, want the connect-gate deny", nv.GetDenyReason())
	}
}

// KT: GrpcDecideHandlerDbTest.kt#an editor or approver-exec token cannot open a wire session — validate rejects both ephemeral kinds
//
// 🔒 Validate is the WIRE-SESSION handshake, and it is kind-gated: the two ephemeral kinds exist to be
// decided against, never to open a native wire connection. Resolve accepts all four kinds; Validate
// accepts only the wire ones, and that asymmetry is the control.
func TestGrpcValidateRejectsBothEphemeralKinds(t *testing.T) {
	f := newDecideFixture(t)
	editor := f.issueKind(token.KindEditor, "eph-editor", nil)
	approverExec := f.issueKind(token.KindApproverExec, "eph-exec", nil)
	user := f.issueKind(token.KindUser, "wire-user", nil)

	for _, tc := range []struct {
		name string
		tok  string
	}{{"EDITOR", editor.Token}, {"APPROVER_EXEC", approverExec.Token}} {
		got, err := f.b.app.Core.TokenStore.Validate(f.ctx, tc.tok)
		if err != nil {
			t.Fatalf("Validate(%s): %v", tc.name, err)
		}
		if got != nil {
			t.Errorf("Validate(%s) = %+v, want nil — an ephemeral token must not pass the wire-session "+
				"handshake", tc.name, got)
		}
	}
	got, err := f.b.app.Core.TokenStore.Validate(f.ctx, user.Token)
	if err != nil {
		t.Fatalf("Validate(USER): %v", err)
	}
	if got == nil {
		t.Error("Validate(USER) = nil, want an identity — a USER token opens a wire session")
	}
}

// KT: GrpcDecideHandlerDbTest.kt#an EDITOR token's registered requester_ip reaches Cedar and satisfies an ip-gated permit
func TestGrpcAnEditorTokensRegisteredRequesterIPReachesCedar(t *testing.T) {
	f := newDecideFixture(t)
	f.ipGatedConnectPermit("ipgate-editor-ip-gate")
	issued := f.issueKind(token.KindEditor, "ipgate-editor-user", nil)
	f.b.app.Core.RunRequesterIPs.Put(token.Hash(issued.Token), types.Ptr("203.0.113.10"))

	v := f.verdictFor(issued.Token, "select 1 from t", "")
	if !strings.Contains(v.GetDenyReason(), "sql.select") {
		t.Errorf("denyReason = %q, want the connect gate to PASS via the ip-gated permit and the deny "+
			"to move to sql.select", v.GetDenyReason())
	}
}

// KT: GrpcDecideHandlerDbTest.kt#an APPROVER_EXEC token's registered requester_ip also reaches Cedar (run-minted, not just openSession-minted)
//
// APPROVER_EXEC tokens are minted ONLY by RunExecService.Run — OpenSession mints EDITOR — so covering
// the registry read for this kind separately is what makes the second mint path's requester_ip real.
func TestGrpcAnApproverExecTokensRegisteredRequesterIPAlsoReachesCedar(t *testing.T) {
	f := newDecideFixture(t)
	f.ipGatedConnectPermit("ipgate-approver-exec-ip-gate")
	issued := f.issueKind(token.KindApproverExec, "ipgate-approver-exec-user", nil)
	f.b.app.Core.RunRequesterIPs.Put(token.Hash(issued.Token), types.Ptr("203.0.113.20"))

	v := f.verdictFor(issued.Token, "select 1 from t", "")
	if !strings.Contains(v.GetDenyReason(), "sql.select") {
		t.Errorf("denyReason = %q, want the connect gate to pass", v.GetDenyReason())
	}
}

// KT: GrpcDecideHandlerDbTest.kt#a registry entry is ignored for a native-wire (USER) token — gated strictly on kind, never merely 'an entry exists'
//
// 🔒 GATED ON KIND, NOT ON PRESENCE. An entry is planted under a USER token's hash directly. A wire
// token must never read the editor/approver-exec registry even when a matching entry happens to exist —
// otherwise the registry becomes a way to inject a requester_ip into a wire decision.
func TestGrpcARegistryEntryIsIgnoredForANativeWireToken(t *testing.T) {
	f := newDecideFixture(t)
	f.ipGatedConnectPermit("ipgate-kind-gate")
	issued := f.issueKind(token.KindUser, "ipgate-wire-user", nil)
	f.b.app.Core.RunRequesterIPs.Put(token.Hash(issued.Token), types.Ptr("203.0.113.30"))

	v := f.verdictFor(issued.Token, "select 1 from t", "")
	if v.GetDecision() != pb.EnfAction_DENY {
		t.Errorf("decision = %s, want DENY", v.GetDecision())
	}
	if !strings.Contains(v.GetDenyReason(), "no access to datasource") {
		t.Errorf("denyReason = %q — a WIRE token must never read the editor/approver-exec "+
			"requester_ip registry", v.GetDenyReason())
	}
}

// KT: GrpcDecideHandlerDbTest.kt#an EDITOR token with no registry entry does NOT fall back to the proxy client_addr — requester_ip stays absent
//
// 🔒 CHANNEL-SELECTED SOURCE, NOT A NULLABLE FALLBACK. The proxy sends a client_addr that IS in range,
// which on the wire channel would satisfy the permit. An editor decision must not borrow it:
// requester_ip stays ABSENT and the permit never fires. Paired with the next case, this proves the
// source is selected by channel rather than "editor ignores client_addr, wire always trusts it".
func TestGrpcAnEditorTokenWithNoRegistryEntryDoesNotFallBackToClientAddr(t *testing.T) {
	f := newDecideFixture(t)
	f.ipGatedConnectPermit("ipgate-editor-no-entry-ip-gate")
	// Deliberately NOTHING put into RunRequesterIPs.
	issued := f.issueKind(token.KindEditor, "ipgate-editor-no-entry", nil)

	v := f.verdictFor(issued.Token, "select 1 from t", "/203.0.113.10:1234")
	if v.GetDecision() != pb.EnfAction_DENY {
		t.Errorf("decision = %s, want DENY", v.GetDecision())
	}
	if !strings.Contains(v.GetDenyReason(), "no access to datasource") {
		t.Errorf("denyReason = %q — an EDITOR decision must not fall back to client_addr; "+
			"requester_ip must be absent", v.GetDenyReason())
	}
}

// KT: GrpcDecideHandlerDbTest.kt#a native-wire token DOES resolve requester_ip from client_addr (the WIRE-channel source)
//
// The complement of the case above: on the wire channel the proxy observed the DB client's socket peer
// directly, so client_addr IS the attested requester_ip and the same permit fires.
func TestGrpcANativeWireTokenResolvesRequesterIPFromClientAddr(t *testing.T) {
	f := newDecideFixture(t)
	f.ipGatedConnectPermit("ipgate-wire-clientaddr-ip-gate")
	issued := f.issueKind(token.KindUser, "ipgate-wire-clientaddr", nil)

	v := f.verdictFor(issued.Token, "select 1 from t", "/203.0.113.40:5432")
	if !strings.Contains(v.GetDenyReason(), "sql.select") {
		t.Errorf("denyReason = %q — a WIRE token's client_addr must satisfy the ip-gated connect "+
			"permit", v.GetDenyReason())
	}
}
