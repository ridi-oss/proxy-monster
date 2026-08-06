package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/policy"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// PORT of `ElevationContextRouteAuthzDbTest` — the TWO of its eight cases that drive accessRoutes.
//
// The other six drive Approvals.kt (query-approval approve/execute) and Datasources.kt (catalog
// browse, connectable filter), which A7 and A5 own; they belong in those packages when they land.
//
// WHAT THE KOTLIN SUITE IS FOR, verbatim from its kdoc: "whether the PRODUCTION routes actually
// thread `call.httpAuthzContext(config)` + the request's datasource into that helper. Deleting the
// wiring at Access.kt (the ROLE access-request TASK_APPROVE sites) […] leaves the helper test green —
// so this test drives the REAL routes through testApplication end to end."
//
// That is exactly what these two cases do here, against the REAL Cedar engine over a migrated
// database, not the counting fake the rest of the package uses.
//
// NO STUB, AND NO DEVIATION. These were 1:1-with-an-asterisk while A12 was unported: the
// `requester_ip` derivation was supplied by a test-local `trustedEdgeAuthzContext` plugged into the
// production seam. A12 has landed, so [httpapi.Gates.Context] is left NIL — the production shape — and
// the derivation under test is [httpapi.Gates.HTTPAuthzContext] itself.
//
// 🔒 DELETING THE STUB STRENGTHENED THESE CASES, it did not merely tidy them. The stub honored the
// WHOLE X-Forwarded-For value and never validated it, so it was strictly LAXER than production: it
// would have accepted a multi-hop header (handing a client control of requester_ip by prepending an
// entry) and a syntactically invalid address alike. The real path takes the RIGHTMOST entry, strips a
// port strictly, and validates through Cedar's parser. So the fixture can no longer be more permissive
// than the thing it stands in for — which is the failure mode a hand-rolled fixture invites.
// ---------------------------------------------------------------------------------------------

// The two policies the Kotlin fixture writes, verbatim (ElevationContextRouteAuthzDbTest.kt:76-88).
const (
	// trustedNetworkTagRule earns the "trusted-network" tag for a requester_ip in the example range
	// 100.100.0.0/16 (inside the CGNAT block 100.64.0.0/10). Principal-agnostic on purpose: the tag is
	// a property of WHERE the request came from, never of who sent it.
	trustedNetworkTagRule = `permit(
        principal, action == Action::"context.tag::trusted-network", resource
    ) when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };`

	// tagGatedApprovePermit is a task.approve permit gated ONLY on the derived tag — the consuming end
	// of the two-pass. The approver holds Role::"reviewer"; with no derived tag (no requester_ip, or
	// no datasource to derive against) it cannot fire.
	tagGatedApprovePermit = `permit(
        principal in Role::"reviewer", action == Action::"task.approve", resource
    ) when { context has tags && context.tags.contains("trusted-network") };`
)

// trustedEdgeIP is the socket peer httptest.NewRequest reports. It is the sole configured trusted
// edge, so ONLY an XFF appended behind it is honored as requester_ip — the same posture the Kotlin
// gets by trusting the literal "localhost" that Ktor's test host reports.
const trustedEdgeIP = "192.0.2.1"

// cedarFixture is [routeFixture]'s shape over the REAL engine.
type cedarFixture struct {
	t          *testing.T
	ctx        context.Context
	handler    http.Handler
	sessions   *httpapi.Sessions
	resolver   *fakeResolver
	store      *Store
	policies   *policy.CedarPolicyStore
	seed       *dbtest.Seed
	roles      map[string][]string
	datasource int64
	roleID     int64
}

func newCedarFixture(t *testing.T) *cedarFixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)

	cfg := routeConfig()
	// The socket peer httptest reports is the SOLE trusted edge.
	cfg.TrustedProxies = map[string]struct{}{trustedEdgeIP: {}}

	resolver := newFakeResolver()
	sessions := &httpapi.Sessions{
		Codec:           session.NewCookieCodec(cfg.SessionSecret, cfg.MCPIssuer()),
		Storage:         newFakeStorage(),
		Resolver:        resolver,
		AbsoluteSeconds: cfg.WebSessionAbsoluteSeconds,
	}

	cedarPolicies := policy.NewCedarPolicyStore(db.Pool)
	engine, err := authz.NewCedarEngine(cedarPolicies)
	if err != nil {
		t.Fatalf("cedar engine: %v", err)
	}
	roles := map[string][]string{}
	az := authz.New(engine, cedarPolicies, authz.RoleSourceFunc(func(principal string) []string {
		return roles[principal]
	}))

	gates := &httpapi.Gates{
		Config:   cfg,
		Authz:    az,
		Sessions: sessions,
		// Context stays NIL: that is the production shape, and it selects the real
		// Gates.HTTPAuthzContext. See the header — the A12 stub that used to sit here was laxer.
	}

	accessStore := NewStore(db.Pool)
	dsStore := datasource.NewDatasourceStore(db)
	seed := dbtest.NewSeed(t, db)

	router := httpapi.NewRouter(httpapi.RouterOptions{Sessions: sessions})
	// roleResolver here is the SAME map the RoleSource reads, so the `task.request` gate's explicit
	// resolve and Cedar's own RolesOf cannot disagree — which is [Authorizer]'s one-graph rule
	// applied to identity.
	router.Mount(NewRoutes(gates, accessStore, az, dsStore, mapRoleResolver(roles), nil))

	f := &cedarFixture{
		t: t, ctx: context.Background(),
		handler: router.Handler(), sessions: sessions, resolver: resolver,
		store: accessStore, policies: cedarPolicies, seed: seed, roles: roles,
	}

	f.datasource = seed.Datasource(dbtest.DatasourceSpec{
		Name: "elev-ds", Engine: "postgres", Host: "localhost", Port: 5432, DBName: "app",
	})
	f.roleID = seed.Role("target-role")

	// The approver earns Role::"reviewer" server-side, so the tag-gated policy on that role decides
	// the elevation.
	roles[approver] = []string{"reviewer"}

	f.addPolicy("elev-trusted-network-tag", trustedNetworkTagRule)
	f.addPolicy("elev-tag-gated-approve", tagGatedApprovePermit)
	return f
}

// mapRoleResolver adapts the fixture's role map to A6's RoleResolver seam.
type mapRoleResolver map[string][]string

func (m mapRoleResolver) Resolve(_ context.Context, principal string) ([]string, error) {
	return m[principal], nil
}

func (f *cedarFixture) addPolicy(name, src string) policy.CedarPolicy {
	f.t.Helper()
	created, err := f.policies.Create(f.ctx, policy.NewCedarPolicyInput(name, src), types.Ptr("test"))
	if err != nil {
		f.t.Fatalf("create policy %s: %v", name, err)
	}
	return created
}

func (f *cedarFixture) login(principal string) *http.Cookie {
	f.t.Helper()
	return loginAs(f.t, f.sessions, f.resolver, principal)
}

// post sends from the TRUSTED peer (httptest's default 192.0.2.1), which is what makes an
// X-Forwarded-For honored at all.
func (f *cedarFixture) post(
	target, body string, headers map[string]string, cookies ...*http.Cookie,
) *httptest.ResponseRecorder {
	f.t.Helper()
	return request(f.t, f.handler, http.MethodPost, target, body, "", headers, cookies...)
}

// seedRoleRequest is the Kotlin's private helper: a PENDING ROLE request elevating `requester` to
// `target-role` on the tag-gated datasource.
func (f *cedarFixture) seedRoleRequest() int64 {
	f.t.Helper()
	req, err := f.store.CreateRequest(f.ctx, requester, AccessRequestInput{
		RoleID: f.roleID, DatasourceID: &f.datasource, Reason: types.Ptr("need the role"),
	})
	if err != nil {
		f.t.Fatalf("CreateRequest: %v", err)
	}
	return req.ID
}

// ---------------------------------------------------------------------------------------------

// PORT of `ROLE access-request approve fires the tag-gated permit only through a trusted edge
// (Access-kt wiring)`.
//
// 🔒 THE TWO HALVES ARE A MATCHED PAIR AND NEITHER IS INFORMATIVE ALONE. Same route, same request
// shape, same policy set; the ONLY difference is one header. Without the trusted XFF, requester_ip is
// absent, pass 1 derives no tag, and the tag-gated permit cannot fire ⇒ 403. With it, the tag is
// derived and the permit fires ⇒ 200.
//
// What each half catches:
//   - the FORBIDDEN half fails if the route somehow granted approval without the context — i.e. it is
//     the fail-closed control.
//   - the OK half fails if the route drops `gates.AuthzContext(r)` (requester_ip never reaches Cedar)
//     OR drops the datasource tag-scoping (no Datasource in scope ⇒ INV-A2-14 derives nothing). Those
//     are the two deletions the Kotlin kdoc names, and both leave every unit-level authz test green.
//
// KT: ElevationContextRouteAuthzDbTest.kt#ROLE access-request approve fires the tag-gated permit only through a trusted edge (Access-kt wiring)
func TestRoleAccessRequestApproveFiresTheTagGatedPermitOnlyThroughATrustedEdge(t *testing.T) {
	f := newCedarFixture(t)
	cookie := f.login(approver)

	// No trusted XFF ⇒ requester_ip absent ⇒ tag not derived ⇒ the tag-gated approve permit cannot fire.
	forbidden := f.seedRoleRequest()
	denied := f.post("/api/access-requests/"+strconv.FormatInt(forbidden, 10)+"/approve", "", nil, cookie)
	assertStatus(t, denied, http.StatusForbidden,
		"no requester_ip ⇒ no trusted-network tag ⇒ task.approve denied (would still pass if the route dropped httpAuthzContext)")
	assertAPIError(t, denied, CodeNotApprover, "denied approve")

	// A trusted edge's in-range XFF ⇒ requester_ip 100.100.5.5 ⇒ trusted-network tag ⇒ the permit fires.
	approved := f.seedRoleRequest()
	ok := f.post("/api/access-requests/"+strconv.FormatInt(approved, 10)+"/approve", "",
		map[string]string{"X-Forwarded-For": "100.100.5.5"}, cookie)
	assertStatus(t, ok, http.StatusOK,
		"trusted-edge requester_ip ⇒ derived tag ⇒ approve succeeds; FAILS if the route drops httpAuthzContext or the datasource tag-scoping")

	var out AccessRequest
	decodeJSON(t, ok, &out)
	if out.Status != "APPROVED" {
		t.Errorf("status %q, want APPROVED", out.Status)
	}
}

// 🔒 THE ANTI-SPOOF HALF, WHICH THE KOTLIN CANNOT EASILY STATE and this port can: the SAME in-range
// XFF sent from an UNTRUSTED peer must not earn the tag.
//
// It is the invariant `docs/authz-context.md` calls "server-attested, never client-asserted", and it
// is worth an assertion here rather than only in the trusted-edge unit tests, because the route is
// where a header first meets a Cedar decision. If it ever passed, any caller could self-assert their
// way into every tag-gated approval policy by setting one header.
func TestAnInRangeForwardedForFromAnUntrustedPeerEarnsNoTag(t *testing.T) {
	f := newCedarFixture(t)
	cookie := f.login(approver)
	id := f.seedRoleRequest()

	rec := request(t, f.handler, http.MethodPost,
		"/api/access-requests/"+strconv.FormatInt(id, 10)+"/approve", "",
		"203.0.113.9:5555", map[string]string{"X-Forwarded-For": "100.100.5.5"}, cookie)
	assertStatus(t, rec, http.StatusForbidden, "in-range XFF from an untrusted peer")
	assertAPIError(t, rec, CodeNotApprover, "in-range XFF from an untrusted peer")
}

// PORT of `ROLE request creation against a datasource is gated by workflow-request`.
//
// The shipped seed (`V8__seed.sql:119`) permits `task.request` on everything, so creating against the
// datasource succeeds; a per-datasource forbid then denies it. Note this half needs NO requester_ip —
// the gate is `authorizeDatasourceAction` against `Datasource::"elev-ds"`, and INV-A2-2's
// keyed-by-NAME rule is what makes the forbid's `resource == Datasource::"elev-ds"` match at all.
// KT: ElevationContextRouteAuthzDbTest.kt#ROLE request creation against a datasource is gated by workflow-request
func TestRoleRequestCreationAgainstADatasourceIsGatedByTaskRequest(t *testing.T) {
	f := newCedarFixture(t)
	cookie := f.login(requester)
	body := `{"roleId": ` + strconv.FormatInt(f.roleID, 10) +
		`, "datasourceId": ` + strconv.FormatInt(f.datasource, 10) + `, "reason": "need it"}`

	created := f.post("/api/access-requests", body, nil, cookie)
	assertStatus(t, created, http.StatusCreated, "default task.request permit ⇒ create allowed")

	forbid := f.addPolicy("elev-no-request",
		`forbid(principal, action == Action::"task.request", resource == Datasource::"elev-ds");`)

	denied := f.post("/api/access-requests", body, nil, cookie)
	assertStatus(t, denied, http.StatusForbidden, "per-datasource task.request forbid ⇒ create denied")
	assertAPIError(t, denied, CodeRequestNotPermitted, "denied create")

	// Re-enabling is the Kotlin's `finally { setEnabled(forbid.id, false) }`, asserted rather than
	// merely performed: it proves the engine really is re-reading the store (INV-A2-19's state-version
	// bump) rather than having cached the forbid for the life of the process.
	if _, err := f.policies.SetEnabled(f.ctx, forbid.ID, false, types.Ptr("test-cleanup")); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	again := f.post("/api/access-requests", body, nil, cookie)
	assertStatus(t, again, http.StatusCreated, "with the forbid disabled the create is allowed again")
}
