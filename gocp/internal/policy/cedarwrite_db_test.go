package policy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/audit"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// The WRITE half of CedarPolicyStore — 02-authz.md §8, and the four 🔒 invariants it carries:
//
//	INV-A2-19  the version bumps only AFTER commit
//	INV-A2-20  the origin guards live in the STORE, under a row lock
//	INV-A2-21  enabling revalidates; disabling never does
//	INV-A2-22  a SYSTEM toggle writes a sentinel audit row on the SAME connection, so an audit
//	           failure rolls the toggle back
//
// ORACLE: 02-authz.md §8's method table (:466-476) and §10's two DB suites —
// `CedarPolicyStoreTest.kt` (9 cases, :606-615) and `CedarPolicyOriginTest.kt` (4 cases, :616-624).
// No Kotlin runs on this machine, so those enumerations and the spec prose are the oracle, cited per
// case.
//
// 🔴 EVERY CASE HERE IS NEW GO CODE. cedarwrite.go landed in this worktree with no test file at all,
// which meant the four invariants above were asserted by nothing — including the rollback pairing,
// which is the one place in A2 where getting it wrong turns a security-relevant toggle into an
// unlogged one.
// ---------------------------------------------------------------------------------------------

// seededSystemPolicyID is `bootstrap.pm-admin` (V8__seed.sql:81) — the enabled SYSTEM row every
// migrated database has. SYSTEM rows take reserved NEGATIVE ids (V3__policy.sql:31-35), so this is
// also the fixture's proof that the id space is disjoint from the USER sequence.
const seededSystemPolicyID int64 = -1

// seededDisabledSystemPolicyID is `preset.production-connect` (V8__seed.sql:242-244) — shipped
// DISABLED, which is what makes it the row to ENABLE when testing the toggle in the other direction.
const seededDisabledSystemPolicyID int64 = -250

type cedarFixture struct {
	t     *testing.T
	ctx   context.Context
	db    *store.Db
	store *CedarPolicyStore
	audit *audit.Store
}

func newCedarFixture(t *testing.T) *cedarFixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	return &cedarFixture{
		t: t, ctx: context.Background(), db: db,
		store: NewCedarPolicyStore(db.Pool), audit: audit.New(db.Pool),
	}
}

func (f *cedarFixture) mustCreate(name, src string) CedarPolicy {
	f.t.Helper()
	created, err := f.store.Create(f.ctx, NewCedarPolicyInput(name, src), types.Ptr("alice"))
	if err != nil {
		f.t.Fatalf("create %s: %v", name, err)
	}
	return created
}

// rawInsert writes a policy row bypassing every guard in cedarwrite.go — the only way to stage
// INV-A2-21's premise, "a row that became malformed while disabled (or was inserted by a
// migration)". A store-level create cannot produce one, by construction.
func (f *cedarFixture) rawInsert(name, src string, enabled bool) int64 {
	f.t.Helper()
	var id int64
	err := f.db.Pool.QueryRow(f.ctx,
		`INSERT INTO policy (name, cedar_src, enabled, origin) VALUES ($1, $2, $3, 'USER') RETURNING id`,
		name, src, enabled).Scan(&id)
	if err != nil {
		f.t.Fatalf("raw insert %s: %v", name, err)
	}
	return id
}

func (f *cedarFixture) mustGet(id int64) *CedarPolicy {
	f.t.Helper()
	row, err := f.store.Get(f.ctx, id)
	if err != nil {
		f.t.Fatalf("get %d: %v", id, err)
	}
	return row
}

// isEnabledSource answers whether id is in what CedarEngine would LOAD. Several Kotlin cases assert
// membership (or absence) here rather than on the row's `enabled` column, and the distinction is the
// point: `enabled` is what was stored, EnabledSources is what reaches the engine. A read path whose
// WHERE clause drifted from the column would keep every row-level assertion passing while serving a
// policy set that no longer matches the database.
func (f *cedarFixture) isEnabledSource(id int64) bool {
	f.t.Helper()
	for _, src := range f.store.EnabledSources() {
		if src.ID == id {
			return true
		}
	}
	return false
}

// countPolicies is the "nothing was written" assertion's instrument. A guard that rejected AFTER
// inserting would still return the right error.
func (f *cedarFixture) countPolicies(name string) int64 {
	f.t.Helper()
	var n int64
	if err := f.db.Pool.QueryRow(f.ctx, `SELECT count(*) FROM policy WHERE name = $1`, name).Scan(&n); err != nil {
		f.t.Fatalf("count policies named %q: %v", name, err)
	}
	return n
}

// ---- Create ------------------------------------------------------------------------------------

// `CedarPolicyStoreTest` case 2 — "a schema-valid policy is created" — plus the two properties the
// route surface depends on: origin is hardcoded 'USER' (which is why CedarPolicyInput has no origin
// field) and the id comes from the POSITIVE BIGSERIAL sequence, disjoint from the SYSTEM block.
// KT: CedarPolicyStoreTest.kt#a schema-valid policy is created
func TestCreateWritesAUserRowWithAPositiveIdAndNoSystemKey(t *testing.T) {
	f := newCedarFixture(t)

	created := f.mustCreate("tester-audit", validCedarSrc)

	if created.Origin != UserPolicyOrigin {
		t.Errorf("origin: got %q, want %q", created.Origin, UserPolicyOrigin)
	}
	if created.ID <= 0 {
		t.Errorf("id: got %d, want a positive id from the USER sequence", created.ID)
	}
	if created.SystemKey != nil {
		t.Errorf("systemKey: got %q, want nil on a USER row", *created.SystemKey)
	}
	if !created.Enabled {
		t.Error("enabled: NewCedarPolicyInput defaults it to true, so the row must be enabled")
	}
	if created.UpdatedBy == nil || *created.UpdatedBy != "alice" {
		t.Errorf("updatedBy: got %v, want \"alice\"", created.UpdatedBy)
	}
	if created.UpdatedAt == "" {
		t.Error("updatedAt must be rendered, not empty")
	}
	// The Kotlin case's remaining two assertions. `Create` returning a well-formed struct is not the
	// same claim as the row being READABLE BACK, nor as it REACHING THE ENGINE: a create that
	// returned its input without committing would satisfy every assertion above.
	if got := f.mustGet(created.ID); got == nil {
		t.Fatalf("get(%d) found nothing after a successful create", created.ID)
	}
	if !f.isEnabledSource(created.ID) {
		t.Error("a created, enabled policy must appear in EnabledSources() — otherwise CedarEngine never loads it")
	}
}

// 🔒 INV-A2-19 — the version bumps only AFTER commit, and it bumps on create, setEnabled and delete.
// `CedarPolicyStoreTest` case 8: "stateVersion monotonically bumps on create, setEnabled, and
// delete".
//
// The counter is what invalidates the SHARED CedarEngine's cached PolicySet (INV-A1-1). A mutation
// that did not bump would leave the data plane serving decisions from rows that no longer exist,
// permanently — because the version the engine cached is the version the store reports.
// KT: CedarPolicyStoreTest.kt#stateVersion monotonically bumps on create, setEnabled, and delete — CedarEngine's cache-invalidation signal
func TestStateVersionBumpsOnEveryCommittedMutation(t *testing.T) {
	f := newCedarFixture(t)

	if got := f.store.StateVersion(); got != 0 {
		t.Fatalf("a fresh store starts at version 0, got %d", got)
	}

	created := f.mustCreate("bump-me", validCedarSrc)
	afterCreate := f.store.StateVersion()
	if afterCreate <= 0 {
		t.Fatalf("create must bump the version, still %d", afterCreate)
	}

	if _, err := f.store.SetEnabled(f.ctx, created.ID, false, nil); err != nil {
		t.Fatalf("disable: %v", err)
	}
	afterToggle := f.store.StateVersion()
	if afterToggle <= afterCreate {
		t.Fatalf("setEnabled must bump the version: %d -> %d", afterCreate, afterToggle)
	}

	if _, err := f.store.Update(f.ctx, created.ID, NewCedarPolicyInput("bump-me", validCedarSrc), nil); err != nil {
		t.Fatalf("update: %v", err)
	}
	afterUpdate := f.store.StateVersion()
	if afterUpdate <= afterToggle {
		t.Fatalf("update must bump the version: %d -> %d", afterToggle, afterUpdate)
	}

	deleted, err := f.store.Delete(f.ctx, created.ID)
	if err != nil || !deleted {
		t.Fatalf("delete: deleted=%v err=%v", deleted, err)
	}
	if got := f.store.StateVersion(); got <= afterUpdate {
		t.Fatalf("delete must bump the version: %d -> %d", afterUpdate, got)
	}
}

// 🔒 INV-A11-31 — "deletePolicy calls markCommittedMutation() ONLY WHEN A ROW WAS ACTUALLY DELETED."
// The other three mutations bump unconditionally; this one does not, and cedarwrite.go:329-334 cites
// 11-mcp-oauth-management.md:459-460 for the asymmetry.
//
// The contrast with Update below is the whole point: Update DOES bump on a missing row, deliberately
// (a spurious invalidation costs one rebuild; a missing one serves stale decisions).
func TestDeleteOfAMissingIdDoesNotBumpButUpdateOfOneDoes(t *testing.T) {
	f := newCedarFixture(t)
	const absent int64 = 987654

	before := f.store.StateVersion()
	deleted, err := f.store.Delete(f.ctx, absent)
	if err != nil {
		t.Fatalf("delete a missing id: %v", err)
	}
	if deleted {
		t.Error("delete of a missing id must answer false")
	}
	if got := f.store.StateVersion(); got != before {
		t.Errorf("delete of a missing row must NOT bump: %d -> %d", before, got)
	}

	updated, err := f.store.Update(f.ctx, absent, NewCedarPolicyInput("ghost", validCedarSrc), nil)
	if err != nil {
		t.Fatalf("update a missing id: %v", err)
	}
	if updated != nil {
		t.Errorf("update of a missing id must answer nil, got %+v", *updated)
	}
	if got := f.store.StateVersion(); got == before {
		t.Error("update bumps unconditionally, even for a row that was not there (cedarwrite.go:208-212)")
	}
}

// 🔒 `CedarPolicyOriginTest` case 1 — "store rejects system mutation and reserved user names BEFORE
// touching state", and cedarwrite.go:160-163's ordering claim: step 1 (reserved name) precedes step 2
// (validate), so a request that is BOTH reserved-named and syntactically broken answers
// `policy.reserved_name` rather than the compiler's error list.
//
// Testing the ordering needs an input that fails both guards; asserting only the reserved case would
// pass with the guards in either order.
func TestCreateChecksTheReservedNameBeforeValidatingTheSource(t *testing.T) {
	f := newCedarFixture(t)

	_, err := f.store.Create(f.ctx, NewCedarPolicyInput("system:sneaky", invalidCedarSrc), nil)

	var reserved ReservedPolicyNameError
	if !errors.As(err, &reserved) {
		t.Fatalf("a reserved name that is ALSO invalid Cedar must answer ReservedPolicyNameError, got %#v", err)
	}
	if reserved.Name != "system:sneaky" {
		t.Errorf("the error carries the offending name: got %q", reserved.Name)
	}
	var invalid InvalidCedarPolicyError
	if errors.As(err, &invalid) {
		t.Error("validation must not have run: the name guard is step 1 and returns first")
	}
	if n := f.countPolicies("system:sneaky"); n != 0 {
		t.Errorf("the guard must reject BEFORE touching state, found %d rows", n)
	}
}

// `CedarPolicyStoreTest` case 3 — "an unparseable policy is rejected with errors, not written".
// KT: CedarPolicyStoreTest.kt#an unparseable policy is rejected with errors, not written
func TestCreateRejectsUnparseableCedarAndWritesNothing(t *testing.T) {
	f := newCedarFixture(t)

	_, err := f.store.Create(f.ctx, NewCedarPolicyInput("broken", invalidCedarSrc), nil)

	var invalid InvalidCedarPolicyError
	if !errors.As(err, &invalid) {
		t.Fatalf("want InvalidCedarPolicyError, got %#v", err)
	}
	if len(invalid.Errors) == 0 {
		t.Error("the error list is what the editor renders one line at a time; it must not be empty")
	}
	if n := f.countPolicies("broken"); n != 0 {
		t.Errorf("nothing may be written for an invalid source, found %d rows", n)
	}
}

// 🔒 `CedarPolicyStoreTest` case 4 — "a policy referencing an unknown action is rejected — SCHEMA
// validation, not just syntax". This is the case that fails if a port swaps the schema-aware
// validator for a bare parser: the source below parses perfectly and names an action the model does
// not define.
// KT: CedarPolicyStoreTest.kt#a policy referencing an unknown action is rejected — schema validation, not just syntax
func TestCreateRejectsAPolicyNamingAnUnknownAction(t *testing.T) {
	f := newCedarFixture(t)

	src := `permit(principal, action == Action::"totally.not.an.action", resource);`
	_, err := f.store.Create(f.ctx, NewCedarPolicyInput("unknown-action", src), nil)

	var invalid InvalidCedarPolicyError
	if !errors.As(err, &invalid) {
		t.Fatalf("an unknown action must be rejected by schema validation, got %#v", err)
	}
	// The Kotlin case's own assertion: the rejection carries the validator's diagnostics. A
	// schema-validation failure that came back with an empty list would leave the policy editor
	// reporting "invalid" with nothing to point at.
	if len(invalid.Errors) == 0 {
		t.Error("the schema-validation rejection must carry its error list")
	}
	if n := f.countPolicies("unknown-action"); n != 0 {
		t.Errorf("nothing may be written, found %d rows", n)
	}
}

// ---- Update ------------------------------------------------------------------------------------

// 🔒 INV-A2-20 — the immutability guard is in the STORE, not the route. This calls the store
// DIRECTLY, with no HTTP anywhere near it, which is the property the invariant is actually about:
// "a non-HTTP caller (the MCP management tool, a future job) cannot rewrite migration-owned source
// by going around the route."
func TestUpdateOfASystemPolicyIsImmutableAtTheStoreLevel(t *testing.T) {
	f := newCedarFixture(t)

	before := f.mustGet(seededSystemPolicyID)
	if before == nil {
		t.Fatalf("V8 seeds policy %d; the fixture is wrong if it is missing", seededSystemPolicyID)
	}

	_, err := f.store.Update(f.ctx, seededSystemPolicyID,
		NewCedarPolicyInput("system:admin", `permit(principal, action, resource);`), types.Ptr("mallory"))

	if !errors.Is(err, ErrSystemPolicyImmutable) {
		t.Fatalf("want ErrSystemPolicyImmutable, got %#v", err)
	}
	after := f.mustGet(seededSystemPolicyID)
	if after.CedarSrc != before.CedarSrc {
		t.Errorf("the source was rewritten despite the guard:\n got  %s\n want %s", after.CedarSrc, before.CedarSrc)
	}
}

// 🔒 `CedarPolicyRoutesTest` case 2's second half — "POST and USER RENAME reject the reserved
// `system:` namespace". Renaming an existing USER row into the namespace is a separate path from
// creating one there, and cedarwrite.go:228-229 calls it out as its own step.
func TestUpdateRejectsRenamingAUserPolicyIntoTheReservedNamespace(t *testing.T) {
	f := newCedarFixture(t)
	created := f.mustCreate("renameable", validCedarSrc)

	_, err := f.store.Update(f.ctx, created.ID, NewCedarPolicyInput("system:hijack", validCedarSrc), nil)

	var reserved ReservedPolicyNameError
	if !errors.As(err, &reserved) {
		t.Fatalf("want ReservedPolicyNameError, got %#v", err)
	}
	if got := f.mustGet(created.ID); got.Name != "renameable" {
		t.Errorf("the name changed despite the guard: %q", got.Name)
	}
}

// ⚠️ The reserved-name guard is CASE-SENSITIVE, matching V3__policy.sql:38's `name NOT LIKE
// 'system:%'` — also case-sensitive in Postgres. So `System:foo` passes BOTH, and the row is created.
//
// REPRODUCE + PIN: a case-insensitive guard here would reject names the database accepts, which is a
// different API. This test is what a deliberate tightening must change.
func TestTheReservedNamespaceGuardIsCaseSensitiveJustLikeTheCheckConstraint(t *testing.T) {
	f := newCedarFixture(t)

	created, err := f.store.Create(f.ctx, NewCedarPolicyInput("System:allowed", validCedarSrc), nil)
	if err != nil {
		t.Fatalf("`System:` is not the reserved prefix and the CHECK constraint accepts it too: %v", err)
	}
	if created.Origin != UserPolicyOrigin {
		t.Errorf("origin: got %q, want USER", created.Origin)
	}
}

// ---- setEnabled ---------------------------------------------------------------------------------

// 🔒 INV-A2-21 — `CedarPolicyStoreTest` case 6: "enabling a stored-malformed row is rejected and
// leaves it disabled". Both halves matter — the rejection AND the row still being disabled
// afterwards, because a guard that rejected after the UPDATE would leave a malformed policy enabled
// and abort the next engine build at startup.
// KT: CedarPolicyStoreTest.kt#enabling a stored-malformed row is rejected and leaves it disabled (validated on load)
func TestEnablingAStoredMalformedRowIsRejectedAndLeavesItDisabled(t *testing.T) {
	f := newCedarFixture(t)
	id := f.rawInsert("malformed-disabled", invalidCedarSrc, false)

	_, err := f.store.SetEnabled(f.ctx, id, true, types.Ptr("alice"))

	var invalid InvalidCedarPolicyError
	if !errors.As(err, &invalid) {
		t.Fatalf("enabling a malformed row must be rejected, got %#v", err)
	}
	if len(invalid.Errors) == 0 {
		t.Error("the rejection must carry the validation errors — the route renders them to the operator")
	}
	if got := f.mustGet(id); got.Enabled {
		t.Error("the row must STAY disabled — the guard runs before the UPDATE")
	}
	// The Kotlin's fourth assertion, and the one that states the actual consequence: a malformed row
	// that reached EnabledSources() would abort CedarEngine's next build and error-Deny every decision.
	if f.isEnabledSource(id) {
		t.Error("a malformed row must never reach EnabledSources()")
	}
}

// 🔒 INV-A2-21's asymmetry: DISABLING NEVER VALIDATES. The reason is stated in cedarwrite.go:278-281
// — "refusing to disable a malformed policy would leave a deployment unable to turn off the very row
// breaking it, and disabling is always the safe direction."
//
// A port that validated on both directions would pass the test above and fail here, which is exactly
// why the two are separate cases.
func TestDisablingAMalformedRowSucceedsBecauseDisablingNeverValidates(t *testing.T) {
	f := newCedarFixture(t)
	id := f.rawInsert("malformed-enabled", invalidCedarSrc, true)

	toggled, err := f.store.SetEnabled(f.ctx, id, false, types.Ptr("alice"))
	if err != nil {
		t.Fatalf("disabling must not validate: %v", err)
	}
	if toggled == nil || toggled.Enabled {
		t.Fatalf("the row must be disabled, got %+v", toggled)
	}
}

// 🔒 INV-A2-22 — `CedarPolicyOriginTest` case 2: "system toggle changes only mutable fields and
// writes a VISIBLE SENTINEL audit record". Every field of the sentinel is asserted, because the
// statement text is HASHED INTO THE AUDIT CHAIN (cedarwrite.go:437-440) — a divergence there is a
// verification failure that reads as tampering, not a cosmetic difference.
//
// The Kotlin case bundles three claims; this is the sentinel-content + only-mutable-fields half. The
// no-op half is TestANoOpSystemToggleWritesNoAuditRow and the reversed-transition half is
// TestEnablingADisabledSystemPolicyRecordsTheReversedTransition, so all three carry the marker.
// KT: CedarPolicyOriginTest.kt#system toggle changes only mutable fields and writes a visible sentinel audit record
func TestASystemToggleWritesTheSentinelAuditRow(t *testing.T) {
	f := newCedarFixture(t)

	before := f.mustGet(seededSystemPolicyID)
	if before == nil || !before.Enabled {
		t.Fatalf("policy %d must ship enabled for this case", seededSystemPolicyID)
	}

	disabled, err := f.store.SetEnabled(f.ctx, seededSystemPolicyID, false, types.Ptr("alice"))
	if err != nil {
		t.Fatalf("disable the system policy: %v", err)
	}

	// "changes only mutable fields", asserted on the RETURNED row as well as on the re-read one: the
	// route serialises exactly this struct back to the console, so a toggle that returned a rewritten
	// name or a dropped system_key would misreport the row even with the database intact.
	if disabled == nil {
		t.Fatal("setEnabled returned nil for a row that exists")
	}
	if disabled.Enabled {
		t.Error("the returned row must be disabled")
	}
	if disabled.UpdatedBy == nil || *disabled.UpdatedBy != "alice" {
		t.Errorf("returned updatedBy = %v, want \"alice\" — the toggle stamps the caller", disabled.UpdatedBy)
	}
	if disabled.ID != before.ID {
		t.Errorf("returned id = %d, want %d", disabled.ID, before.ID)
	}
	if disabled.Origin != before.Origin {
		t.Errorf("returned origin = %q, want %q", disabled.Origin, before.Origin)
	}
	if disabled.Name != before.Name {
		t.Errorf("returned name = %q, want %q", disabled.Name, before.Name)
	}
	if disabled.CedarSrc != before.CedarSrc {
		t.Errorf("returned cedarSrc = %q, want %q", disabled.CedarSrc, before.CedarSrc)
	}
	if disabled.SystemKey == nil || before.SystemKey == nil || *disabled.SystemKey != *before.SystemKey {
		t.Errorf("returned systemKey = %v, want %v", disabled.SystemKey, before.SystemKey)
	}

	events := f.sentinelEvents()
	if len(events) != 1 {
		t.Fatalf("want exactly one sentinel audit row, got %d", len(events))
	}
	e := events[0]

	// `statement = "[ADMIN policy.toggle] policy <id> (<systemKey>) enabled <old>-><new>"`
	wantStatement := `[ADMIN policy.toggle] policy -1 (bootstrap.pm-admin) enabled true->false`
	if e.Statement != wantStatement {
		t.Errorf("statement:\n got  %q\n want %q", e.Statement, wantStatement)
	}
	if e.Principal != "alice" {
		t.Errorf("principal: got %q, want \"alice\" (updatedBy)", e.Principal)
	}
	if e.Datasource != SystemPolicyToggleDatasource {
		t.Errorf("datasource: got %q, want %q", e.Datasource, SystemPolicyToggleDatasource)
	}
	if e.Decision != types.DecisionAllow {
		t.Errorf("decision: got %v, want ALLOW", e.Decision)
	}
	if e.Detail == nil || *e.Detail != SystemPolicyToggleDetail {
		t.Errorf("detail: got %v, want %q", e.Detail, SystemPolicyToggleDetail)
	}
	// 🔒 "a VISIBLE sentinel": the row must also come back through the BY-ID read the audit detail
	// route uses, not only through the feed. A sentinel written outside the readable range — or with a
	// kind the by-id read filters out — would be invisible to the operator following the feed link.
	if e.ID == nil {
		t.Fatal("the sentinel row carries no id, so it cannot be read back")
	}
	byID, err := f.audit.Get(f.ctx, *e.ID)
	if err != nil {
		t.Fatalf("read the sentinel back by id: %v", err)
	}
	if byID == nil {
		t.Error("ADMIN toggle sentinels must remain visible in /api/audit")
	}

	// "changes only mutable fields" — the origin, id, name, system_key and source are untouched.
	after := f.mustGet(seededSystemPolicyID)
	if after.Enabled {
		t.Error("the toggle did not take effect")
	}
	if after.Origin != before.Origin || after.Name != before.Name || after.CedarSrc != before.CedarSrc {
		t.Errorf("a toggle rewrote an immutable field:\n before %+v\n after  %+v", *before, *after)
	}
	if after.SystemKey == nil || before.SystemKey == nil || *after.SystemKey != *before.SystemKey {
		t.Error("system_key must survive a toggle")
	}
}

// `updatedBy ?: "unknown"` (cedarwrite.go:425-427) — under PM_AUTH_DEBUG requireAdmin admits a
// caller with no session, so the toggle arrives with no identity and the sentinel records the
// literal rather than a fabricated one.
func TestASystemToggleWithNoIdentityRecordsTheUnknownPrincipal(t *testing.T) {
	f := newCedarFixture(t)

	if _, err := f.store.SetEnabled(f.ctx, seededSystemPolicyID, false, nil); err != nil {
		t.Fatalf("disable: %v", err)
	}

	events := f.sentinelEvents()
	if len(events) != 1 {
		t.Fatalf("want one sentinel row, got %d", len(events))
	}
	if events[0].Principal != UnknownPolicyPrincipal {
		t.Errorf("principal: got %q, want %q", events[0].Principal, UnknownPolicyPrincipal)
	}
}

// cedarwrite.go:291-292 — "a no-op toggle (enable an enabled row) writes NO audit row, so the trail
// records state CHANGES rather than requests." The second condition of step 4 (`existing.Enabled !=
// enabled`) is the whole of it, and dropping it would fill the chain with rows for button presses
// that changed nothing.
//
// The no-op half of CedarPolicyOriginTest case 2 ("a no-op setEnabled call must not emit a false flip
// event") — see TestASystemToggleWritesTheSentinelAuditRow for the split.
// KT: CedarPolicyOriginTest.kt#system toggle changes only mutable fields and writes a visible sentinel audit record
func TestANoOpSystemToggleWritesNoAuditRow(t *testing.T) {
	f := newCedarFixture(t)

	// -1 ships ENABLED; enabling it again is the no-op.
	if _, err := f.store.SetEnabled(f.ctx, seededSystemPolicyID, true, types.Ptr("alice")); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	if events := f.sentinelEvents(); len(events) != 0 {
		t.Errorf("a no-op toggle must write nothing, got %d sentinel rows", len(events))
	}
}

// A USER policy toggle writes NO sentinel either — the row exists to record that a MIGRATION-OWNED
// security rule was turned off, and every user policy is already fully attributable through
// updated_by.
func TestAUserPolicyToggleWritesNoSentinelRow(t *testing.T) {
	f := newCedarFixture(t)
	created := f.mustCreate("user-toggle", validCedarSrc)

	if _, err := f.store.SetEnabled(f.ctx, created.ID, false, types.Ptr("alice")); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if events := f.sentinelEvents(); len(events) != 0 {
		t.Errorf("a USER toggle must write no sentinel, got %d", len(events))
	}
}

// 🔒 INV-A2-22, THE LOAD-BEARING HALF — `CedarPolicyOriginTest` case 3: "audit failure rolls back the
// system toggle in the same transaction".
//
// This is the case that fails if anyone "improves" cedarwrite.go by moving the audit insert after
// the commit or onto the pool. Both refactors look harmless and both turn an atomic pair into a
// toggle that silently succeeds UNLOGGED — which is precisely the state the sentinel exists to make
// impossible.
//
// This is the INJECTED-APPENDER half; the DB-TRIGGER half — the Kotlin's own mechanism, which is what
// proves the insert runs on the toggle's transaction rather than merely that a failure propagates — is
// TestAnAuditTriggerFailureRollsBackTheSystemToggleInTheSameTransaction. Both carry the marker.
// KT: CedarPolicyOriginTest.kt#audit failure rolls back the system toggle in the same transaction
func TestAnAuditFailureRollsBackTheSystemToggle(t *testing.T) {
	f := newCedarFixture(t)
	f.store.SetAuditStore(failingAppender{})

	before := f.mustGet(seededSystemPolicyID)
	versionBefore := f.store.StateVersion()

	_, err := f.store.SetEnabled(f.ctx, seededSystemPolicyID, false, types.Ptr("alice"))
	if err == nil {
		t.Fatal("an audit failure must propagate; the toggle cannot succeed unlogged")
	}
	if !strings.Contains(err.Error(), "audit is down") {
		t.Errorf("the underlying failure must not be swallowed: %v", err)
	}

	after := f.mustGet(seededSystemPolicyID)
	if after.Enabled != before.Enabled {
		t.Errorf("the toggle was NOT rolled back: enabled %v -> %v", before.Enabled, after.Enabled)
	}
	// 🔒 INV-A2-19's other half: a failed transaction must not publish a cache invalidation.
	if got := f.store.StateVersion(); got != versionBefore {
		t.Errorf("a rolled-back mutation must not bump the version: %d -> %d", versionBefore, got)
	}
}

// The enable direction of the SYSTEM toggle: -250 ships DISABLED, so enabling it both revalidates
// (INV-A2-21) and writes the sentinel with the reversed transition text.
//
// The reversed-transition half of CedarPolicyOriginTest case 2 — see
// TestASystemToggleWritesTheSentinelAuditRow for the split.
// KT: CedarPolicyOriginTest.kt#system toggle changes only mutable fields and writes a visible sentinel audit record
func TestEnablingADisabledSystemPolicyRecordsTheReversedTransition(t *testing.T) {
	f := newCedarFixture(t)

	enabled, err := f.store.SetEnabled(f.ctx, seededDisabledSystemPolicyID, true, types.Ptr("alice"))
	if err != nil {
		t.Fatalf("enable %d: %v", seededDisabledSystemPolicyID, err)
	}
	// The Kotlin asserts the enable direction on the RETURNED row too: a sentinel that recorded
	// `false->true` while the row came back (or stayed) disabled would be a trail that disagrees with
	// the state it claims to describe.
	if enabled == nil || !enabled.Enabled {
		t.Fatalf("the returned row must be enabled, got %+v", enabled)
	}
	if got := f.mustGet(seededDisabledSystemPolicyID); got == nil || !got.Enabled {
		t.Error("the stored row must be enabled after the toggle")
	}

	events := f.sentinelEvents()
	if len(events) != 1 {
		t.Fatalf("want one sentinel row, got %d", len(events))
	}
	want := `[ADMIN policy.toggle] policy -250 (preset.production-connect) enabled false->true`
	if events[0].Statement != want {
		t.Errorf("statement:\n got  %q\n want %q", events[0].Statement, want)
	}
}

// ---- Delete -------------------------------------------------------------------------------------

// 🔒 INV-A2-20 on the delete path. `CedarPolicyStoreTest` case 7 is the USER half ("delete removes
// the row"); the SYSTEM half is the guard.
// KT: CedarPolicyStoreTest.kt#delete removes the row
func TestDeleteRemovesAUserRowAndRefusesASystemOne(t *testing.T) {
	f := newCedarFixture(t)
	created := f.mustCreate("deletable", validCedarSrc)

	deleted, err := f.store.Delete(f.ctx, created.ID)
	if err != nil || !deleted {
		t.Fatalf("delete a USER row: deleted=%v err=%v", deleted, err)
	}
	if got := f.mustGet(created.ID); got != nil {
		t.Errorf("the row survived the delete: %+v", *got)
	}
	// The Kotlin's third assertion, on the SAME id it just deleted: a second delete answers false
	// rather than true-with-no-row. Delete's boolean is how the route chooses 200 vs 404, so a version
	// that reported success for a row it did not remove would turn every repeat DELETE into a 200.
	again, err := f.store.Delete(f.ctx, created.ID)
	if err != nil {
		t.Fatalf("re-deleting an already-deleted row must not error: %v", err)
	}
	if again {
		t.Error("deleting an already-deleted row must answer false")
	}

	_, err = f.store.Delete(f.ctx, seededSystemPolicyID)
	if !errors.Is(err, ErrSystemPolicyImmutable) {
		t.Fatalf("deleting a SYSTEM row must answer ErrSystemPolicyImmutable, got %#v", err)
	}
	if got := f.mustGet(seededSystemPolicyID); got == nil {
		t.Error("the SYSTEM row was deleted despite the guard")
	}
}

// ---- helpers -------------------------------------------------------------------------------------

// sentinelEvents reads every INV-A2-22 sentinel row out of the audit trail.
//
// It filters on `detail`, which is what the invariant says an operator's audit query filters on
// ("the string an audit query filters on to find 'who turned off a shipped security rule'") — so the
// test uses the same handle production does rather than reaching for the row id.
func (f *cedarFixture) sentinelEvents() []types.AuditEvent {
	f.t.Helper()
	events, err := f.audit.Recent(f.ctx, 100)
	if err != nil {
		f.t.Fatalf("read the audit feed: %v", err)
	}
	var out []types.AuditEvent
	for _, e := range events {
		if e.Detail != nil && *e.Detail == SystemPolicyToggleDetail {
			out = append(out, e)
		}
	}
	return out
}

// failingAppender is the AuditAppender the rollback case needs: one that fails on demand, on the
// caller's connection, exactly where the real one would have inserted.
type failingAppender struct{}

func (failingAppender) InsertOn(context.Context, store.Queryer, types.AuditEvent) (int64, error) {
	return 0, errors.New("audit is down")
}
