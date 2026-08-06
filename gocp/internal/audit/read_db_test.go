package audit

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

const (
	readAlice   = "alice"
	readBob     = "bob"
	readAuditor = "auditor-user"
)

// countingRoleSource is AuditReadRoutesDbTest's CountingRoleSource.
//
// The lookup count is the only externally visible proof of HOW MANY authorizations a read performed —
// Cedar itself is silent. The Kotlin uses it to assert three separate things: that an unauthenticated
// request never reaches authorization, that a list makes exactly ONE collection check regardless of
// row count, and that a MISSING record never reaches Cedar at all.
type countingRoleSource struct {
	delegate authz.RoleSource
	lookups  atomic.Int64
}

func (c *countingRoleSource) RolesOf(principal string) []string {
	c.lookups.Add(1)
	return c.delegate.RolesOf(principal)
}

func (c *countingRoleSource) reset() { c.lookups.Store(0) }

func (c *countingRoleSource) count() int64 { return c.lookups.Load() }

// readFixture is the wiring AuditReadRoutesDbTest's setup() builds, minus Ktor: a migrated store, the
// audit store over it, a REAL Cedar engine over the seeded policies, and a role source that counts.
//
// The Cedar layer is deliberately the production one (authz.NewCedarEngine over the `policy` table,
// authz.New over it). A fixture that stubbed the decision would prove only that Reader calls something
// — the point of these cases is which SHIPPED policy answers: V8__seed.sql's `audit.read-own` (-4)
// gives every principal their own records, and `audit.read-admin` (-5) gives system:admin the log.
type readFixture struct {
	t      *testing.T
	db     *store.Db
	pool   *pgxpool.Pool
	store  *Store
	roles  *countingRoleSource
	authz  *authz.Authz
	policy *dbtest.DBPolicyStore

	aliceIDs []int64
	bobIDs   []int64
	e3ID     int64
}

func newReadFixture(t *testing.T) *readFixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	pool := db.Pool
	ctx := context.Background()
	seed := dbtest.NewSeed(t, db)

	// "The whole audit log is granted to system:admin by default; there is no separate auditor role."
	// V8 seeds the role, so the fixture only assigns it — creating a second `system:admin` would
	// violate app_role's unique name and, more to the point, would be a fixture inventing policy.
	var adminRoleID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM app_role WHERE name = 'system:admin'`).Scan(&adminRoleID); err != nil {
		t.Fatalf("look up the seeded system:admin role: %v", err)
	}
	seed.AssignRole(readAuditor, adminRoleID)

	f := &readFixture{t: t, db: db, pool: pool, store: New(pool)}
	f.policy = dbtest.NewDBPolicyStore(t, pool)
	f.roles = &countingRoleSource{delegate: dbtest.NewDBRoleSource(t, pool)}
	engine, err := authz.NewCedarEngine(f.policy)
	if err != nil {
		t.Fatalf("build the Cedar engine over the seeded policies: %v", err)
	}
	f.authz = authz.New(engine, f.policy, f.roles)

	f.aliceIDs = []int64{
		f.insertNormal(readAlice, "select alice_one"),
		f.insertNormal(readAlice, "select alice_two"),
	}
	f.bobIDs = []int64{
		f.insertNormal(readBob, "select bob_one"),
		f.insertNormal(readBob, "select bob_two"),
	}
	lifecycle := types.NewAuditEvent(readAlice, "acme", "approval #1 result-viewed-by-requester", types.DecisionAllow)
	lifecycle.Kind = "approval_lifecycle"
	id, err := f.store.Insert(ctx, lifecycle)
	if err != nil {
		t.Fatalf("insert the lifecycle row: %v", err)
	}
	f.e3ID = id
	return f
}

func (f *readFixture) insertNormal(principal, statement string) int64 {
	f.t.Helper()
	id, err := f.store.Insert(context.Background(), types.NewAuditEvent(principal, "acme", statement, types.DecisionAllow))
	if err != nil {
		f.t.Fatalf("insert %s: %v", statement, err)
	}
	return id
}

func (f *readFixture) reader(authDebug bool) *Reader {
	return &Reader{Store: f.store, Authz: f.authz, AuthDebug: authDebug}
}

func (f *readFixture) normalIDs() []int64 {
	return append(append([]int64{}, f.aliceIDs...), f.bobIDs...)
}

func (f *readFixture) allIDs() []int64 {
	return append(f.normalIDs(), f.e3ID)
}

// TestOrdinaryPrincipalSeesOnlyOwnRowsAndDeniedDetailLooksMissing is AuditReadRoutesDbTest case 2 —
// 🔒 INV-A8-6 and INV-A8-7 together, and the most security-load-bearing case in A8.
//
// Four claims:
//
//  1. A denied COLLECTION read degrades to own rows. Alice has no audit.read grant on AuditLog, so the
//     shipped -5 policy does not fire; she still gets her three rows and NOT a 403 (INV-A8-7).
//  2. One authorization for the whole list, whatever the row count.
//  3. Her own DETAIL read is allowed, by the shipped `audit.read-own` policy comparing
//     resource.principal == principal.
//  4. 🔒 Bob's record and a nonexistent id are the SAME answer — nil. Reader.Detail's return type is
//     what enforces this: there is no third state for the HTTP layer to accidentally expose. And the
//     nonexistent id costs ZERO role lookups, i.e. the lookup happens before Cedar is reached, so the
//     two are not even distinguishable by work done.
//
// KT: AuditReadRoutesDbTest.kt#ordinary principal sees only own rows and denied detail is indistinguishable from missing — store half; the byte-identity of the two 404 bodies is routes_db_test.go's
func TestOrdinaryPrincipalSeesOnlyOwnRowsAndDeniedDetailLooksMissing(t *testing.T) {
	f := newReadFixture(t)
	r := f.reader(false)
	ctx := context.Background()
	actx := authz.AuthzContext{}

	f.roles.reset()
	records, err := r.List(ctx, 500, readAlice, actx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	assertIDSet(t, records, append(append([]int64{}, f.aliceIDs...), f.e3ID))
	for _, rec := range records {
		if rec.Principal != readAlice {
			t.Errorf("a denied collection read leaked a row owned by %s", rec.Principal)
		}
	}
	if got := f.roles.count(); got != 1 {
		t.Errorf("the list made %d authorizations, want exactly 1", got)
	}

	f.roles.reset()
	own, err := r.Detail(ctx, f.aliceIDs[0], readAlice, actx)
	if err != nil {
		t.Fatalf("detail of an own row: %v", err)
	}
	if own == nil || own.Principal != readAlice {
		t.Fatalf("alice cannot read her own audit record %d", f.aliceIDs[0])
	}
	if got := f.roles.count(); got != 1 {
		t.Errorf("the own-row detail made %d authorizations, want 1", got)
	}

	// 🔒 Denied and missing are the same answer.
	f.roles.reset()
	denied, err := r.Detail(ctx, f.bobIDs[0], readAlice, actx)
	if err != nil {
		t.Fatalf("detail of a foreign row: %v", err)
	}
	if denied != nil {
		t.Errorf("alice read bob's audit record %d", f.bobIDs[0])
	}
	deniedLookups := f.roles.count()
	if deniedLookups != 1 {
		t.Errorf("the denied detail made %d authorizations, want 1", deniedLookups)
	}

	f.roles.reset()
	missing, err := r.Detail(ctx, 9_999_999, readAlice, actx)
	if err != nil {
		t.Fatalf("detail of a missing row: %v", err)
	}
	if missing != nil {
		t.Errorf("a nonexistent id returned %v", missing)
	}
	if got := f.roles.count(); got != 0 {
		t.Errorf("a missing row reached Cedar (%d lookups) — it must not", got)
	}
}

// TestAuditorSeesEveryRowAndCanReadDetails is AuditReadRoutesDbTest case 5.
//
// The other side of the two-tier model: system:admin holds the shipped -5 grant, so audit.read on
// AuditLog Allows and the collection read returns the WHOLE log — both principals' rows, and the
// lifecycle row. Still exactly one authorization for the list, and one per detail.
// KT: AuditReadRoutesDbTest.kt#auditor sees every row and can read details
func TestAuditorSeesEveryRowAndCanReadDetails(t *testing.T) {
	f := newReadFixture(t)
	r := f.reader(false)
	ctx := context.Background()
	actx := authz.AuthzContext{}

	f.roles.reset()
	records, err := r.List(ctx, 500, readAuditor, actx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	assertIDSet(t, records, f.allIDs())
	principals := map[string]bool{}
	for _, rec := range records {
		principals[rec.Principal] = true
	}
	if !principals[readAlice] || !principals[readBob] {
		t.Errorf("the auditor's feed covers %v, want both alice and bob", principals)
	}
	if findByID(t, records, f.e3ID).Kind != "approval_lifecycle" {
		t.Error("the auditor's feed dropped the lifecycle row's kind")
	}
	if got := f.roles.count(); got != 1 {
		t.Errorf("row count affected collection authorization: %d lookups, want 1", got)
	}

	for _, id := range f.allIDs() {
		f.roles.reset()
		rec, err := r.Detail(ctx, id, readAuditor, actx)
		if err != nil {
			t.Fatalf("detail %d: %v", id, err)
		}
		if rec == nil || *rec.ID != id {
			t.Errorf("the auditor could not read audit record %d", id)
		}
		if got := f.roles.count(); got != 1 {
			t.Errorf("detail %d made %d authorizations, want 1", id, got)
		}
	}
}

// TestAuthDebugReturnsEverythingWithoutAuthorizationOrASession is AuditReadRoutesDbTest case 6 —
// INV-A8-8's observable half.
//
// PM_AUTH_DEBUG returns the whole log and any detail with ZERO role lookups: Cedar is not consulted,
// it is not REACHED (INV-A2-16's framing). The empty principal is the point — the Kotlin route
// short-circuits before `call.userSession()` runs, so a debug request need not have a session at all,
// and Reader must therefore not depend on the principal argument in this mode.
//
// The remaining half of INV-A8-8 (`requireNotNull(call.userSession())` asserting requireApi's
// postcondition afterwards) is a route-layer assertion and is TODO(A1).
//
// KT: AuditReadRoutesDbTest.kt#auth debug returns all rows and details without authorization or a session — store half; the no-cookie route half is routes_db_test.go's
func TestAuthDebugReturnsEverythingWithoutAuthorizationOrASession(t *testing.T) {
	f := newReadFixture(t)
	r := f.reader(true)
	ctx := context.Background()
	actx := authz.AuthzContext{}

	f.roles.reset()
	records, err := r.List(ctx, 500, "", actx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	assertIDSet(t, records, f.allIDs())
	if findByID(t, records, f.e3ID).Kind != "approval_lifecycle" {
		t.Error("the debug feed dropped the lifecycle row's kind")
	}
	if got := f.roles.count(); got != 0 {
		t.Errorf("auth debug made %d authorizations, want 0", got)
	}

	f.roles.reset()
	rec, err := r.Detail(ctx, f.bobIDs[0], "", actx)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if rec == nil || rec.Principal != readBob {
		t.Fatalf("auth debug could not read bob's record %d", f.bobIDs[0])
	}
	if got := f.roles.count(); got != 0 {
		t.Errorf("auth debug made %d authorizations on the detail, want 0", got)
	}

	// The bypass changes who may SEE a record, never whether it exists.
	missing, err := r.Detail(ctx, 9_999_999, "", actx)
	if err != nil {
		t.Fatalf("detail of a missing row under auth debug: %v", err)
	}
	if missing != nil {
		t.Error("auth debug invented a record for a nonexistent id")
	}
}

// TestRequesterIpGatesTheAuditCollectionRead is AuditReadRoutesDbTest case 7, at the store boundary.
//
// 🔒 It pins that the AuthzContext argument reaches the collection authorization. A role whose ONLY
// audit.read grant is ip-gated makes the answer observably sensitive to requester_ip: in range ⇒ the
// whole log, out of range ⇒ the deny path ⇒ own rows, which for this principal is nothing (INV-A8-7
// again, this time with an empty result rather than an error). Drop actx from Reader.List and the
// in-range caller silently stops reading the collection.
//
// The route half — deriving requester_ip from X-Forwarded-For through a TRUSTED edge — is A12's and is
// TODO(A1)/TODO(A12); here the context is supplied directly, which is exactly what the HTTP layer will
// hand in.
//
// ⚠️ NOT A COVERAGE CLAIM — see the KT-DEFER below. This test asserts the AUTHORIZATION half in full
// (both of the Kotlin's arms, plus a fail-closed absent-IP arm the Kotlin does not have), and it is
// worth having on its own. What it cannot assert is the Kotlin case's actual purpose.
//
// The Kotlin case says why it exists: "Pins the httpAuthzContext argument at the audit route: drop it
// and the in-range caller would no longer read the whole collection." That is a claim about the ROUTE's
// wiring, and it is unreproducible here — internal/app/http.go:213 leaves httpapi.Gates.Context nil
// because A12's httpAuthzContext is unported, so NO requester_ip reaches ANY HTTP gate and there is no
// argument to drop. This test supplies the AuthzContext by hand, so it would keep passing even if the
// route never threaded one. Claiming the case would assert an end-to-end property the product does not
// have.
//
// KT-DEFER: AuditReadRoutesDbTest.kt#requester_ip from a trusted edge gates the audit-collection read — blocked on A12's
//
//	httpAuthzContext being wired into httpapi.Gates.Context (internal/app/http.go:213 sets it nil, so no HTTP gate
//	receives a requester_ip and the trusted-edge derivation reaches no authorization). The derivation itself is
//	ported and tested at internal/httpapi/requesterip_test.go (HttpRequesterIpResolutionTest's 11 cases, all mapped);
//	the authorization it gates is asserted by this test. Promote this back to a coverage marker once the two are
//	connected at the route.
func TestRequesterIpGatesTheAuditCollectionRead(t *testing.T) {
	f := newReadFixture(t)
	ctx := context.Background()

	const edgeAuditor = "edge-auditor"
	seed := dbtest.NewSeed(t, f.db)
	roleID := seed.Role("ip-auditor")
	seed.AssignRole(edgeAuditor, roleID)
	seed.CedarPolicy("ip-gated-audit-read",
		`permit(principal in Role::"ip-auditor", action == Action::"audit.read", resource)
		    when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };`)
	// The policy was written AFTER the engine was built, so the cached PolicySet must be invalidated.
	// That is production behaviour (INV-A2-19: the version moves only when a mutation commits), not a
	// fixture wart — the production CedarPolicyStore bumps it inside create().
	f.policy.Bump()

	r := f.reader(false)

	inRange, err := r.List(ctx, 500, edgeAuditor, authz.AuthzContext{RequesterIP: types.Ptr("203.0.113.10")})
	if err != nil {
		t.Fatalf("in-range list: %v", err)
	}
	assertIDSet(t, inRange, f.allIDs())

	outOfRange, err := r.List(ctx, 500, edgeAuditor, authz.AuthzContext{RequesterIP: types.Ptr("198.51.100.10")})
	if err != nil {
		t.Fatalf("out-of-range list: %v", err)
	}
	if len(outOfRange) != 0 {
		t.Errorf("out of range returned %v — no trusted-range requester_ip means own rows only, and this principal authored none", ids(outOfRange))
	}

	// No requester_ip at all is the fail-closed case: INV-A2-8 makes ABSENCE the signal, so the guarded
	// policy simply does not fire.
	noIP, err := r.List(ctx, 500, edgeAuditor, authz.AuthzContext{})
	if err != nil {
		t.Fatalf("no-ip list: %v", err)
	}
	if len(noIP) != 0 {
		t.Errorf("an absent requester_ip granted the collection read: %v", ids(noIP))
	}
}

// TestListAppliesTheLimitOnBothBranches pins that the coerced limit reaches BOTH sides of INV-A8-7's
// fork. A limit honoured only on the allow branch would let a denied caller pull the whole own-row
// history in one request.
func TestListAppliesTheLimitOnBothBranches(t *testing.T) {
	f := newReadFixture(t)
	r := f.reader(false)
	ctx := context.Background()
	actx := authz.AuthzContext{}

	granted, err := r.List(ctx, 2, readAuditor, actx)
	if err != nil {
		t.Fatalf("granted list: %v", err)
	}
	if len(granted) != 2 {
		t.Errorf("granted list returned %d rows, want 2", len(granted))
	}

	denied, err := r.List(ctx, 2, readAlice, actx)
	if err != nil {
		t.Fatalf("denied list: %v", err)
	}
	if len(denied) != 2 {
		t.Errorf("own-rows list returned %d rows, want 2 (alice owns 3)", len(denied))
	}
	for _, rec := range denied {
		if rec.Principal != readAlice {
			t.Errorf("the own-rows branch leaked a row owned by %s", rec.Principal)
		}
	}
}

func assertIDSet(t *testing.T, records []types.AuditEvent, want []int64) {
	t.Helper()
	got := map[int64]bool{}
	for _, r := range records {
		if r.ID == nil {
			t.Fatal("a record came back without an id")
		}
		got[*r.ID] = true
	}
	wantSet := map[int64]bool{}
	for _, id := range want {
		wantSet[id] = true
		if !got[id] {
			t.Errorf("expected id %d in the result, got %v", id, ids(records))
		}
	}
	for id := range got {
		if !wantSet[id] {
			t.Errorf("unexpected id %d in the result", id)
		}
	}
}
