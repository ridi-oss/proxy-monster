package policy

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// PORT of PolicyOriginDbTest.kt (5 cases) + the three CedarPolicyStoreTest.kt cases whose subject is
// the SHIPPED SEED rather than CRUD, + CedarPolicyOriginTest.kt's decision-equivalence case, +
// CedarEngineCacheTest.kt's DB-backed invalidation case.
//
// All of them are DB-backed by nature: what they assert is what a FRESH INSTALL enforces (the seeded
// SYSTEM rows, their enabled defaults, the four origin constraints) and what the real
// CedarPolicyStore does to it. internal/conformance/cedar_decisions_test.go:116 records the
// decision-equivalence case as skipped for exactly that reason ("needs both sets plus the store, i.e.
// TODO(A2)'s CedarPolicyStore. DB-backed") — the store has since landed, so it is ported here.
//
// 🔒 THE MIGRATION FILES ARE BYTE-IDENTICAL TO THE KOTLIN'S (verified by diff against
// control-plane/src/main/resources/db/migration), which is what makes the digest in case 1 a genuine
// CROSS-LANGUAGE assertion rather than a self-check: it is the Kotlin's own expected digest, unchanged.
// ---------------------------------------------------------------------------------------------

// The three seeded SYSTEM sources, verbatim from PolicyOriginDbTest.kt:227-236.
const (
	seedAdminSource = `permit (
  principal in Role::"system:admin",
  action in
    [Action::"admin.datasources",
     Action::"admin.policies",
     Action::"admin.identity"],
  resource
);
`

	seedNoSelfApprovalSource = `forbid (
  principal,
  action == Action::"task.approve",
  resource
)
when { principal == resource.requester }
unless
{
  context has channel &&
  (context.channel == "editor" || context.channel == "wire")
};
`

	seedApproverSource = `permit (
  principal in Role::"system:admin",
  action in
    [Action::"task.approve",
     Action::"task.read",
     Action::"grant.revoke",
     Action::"task.request",
     Action::"task.cancel",
     Action::"task.delete"],
  resource
);
`
)

// originFixture is a freshly migrated database plus a real store over it. Every case takes its OWN
// database: the Kotlin calls fullyMigrated(prefix) per case because these assertions are about a CLEAN
// install and rows left behind by a sibling case would corrupt them (the reason CedarPolicyStoreTest
// has to filter its list() calls by id — it shares one database across a PER_CLASS suite).
type originFixture struct {
	t     *testing.T
	ctx   context.Context
	db    *store.Db
	store *CedarPolicyStore
}

func newOriginFixture(t *testing.T) *originFixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	return &originFixture{t: t, ctx: context.Background(), db: db, store: NewCedarPolicyStore(db.Pool)}
}

func (f *originFixture) list() []CedarPolicy {
	f.t.Helper()
	rows, err := f.store.List(f.ctx)
	if err != nil {
		f.t.Fatalf("list policies: %v", err)
	}
	return rows
}

func (f *originFixture) byID() map[int64]CedarPolicy {
	f.t.Helper()
	out := map[int64]CedarPolicy{}
	for _, p := range f.list() {
		out[p.ID] = p
	}
	return out
}

func (f *originFixture) get(id int64) *CedarPolicy {
	f.t.Helper()
	row, err := f.store.Get(f.ctx, id)
	if err != nil {
		f.t.Fatalf("get %d: %v", id, err)
	}
	return row
}

// exec runs raw SQL, returning the error rather than failing — the instrument for the constraint case.
func (f *originFixture) exec(sql string, args ...any) error {
	_, err := f.db.Pool.Exec(f.ctx, sql, args...)
	return err
}

// assertRejected is `assertFailsWith<SQLException>` over a raw insert.
func (f *originFixture) assertRejected(sql string, args ...any) {
	f.t.Helper()
	if err := f.exec(sql, args...); err == nil {
		f.t.Errorf("the database ACCEPTED an insert the origin constraints must reject:\n  %s", sql)
	}
}

// samePolicy compares two rows BY VALUE. The struct holds *string fields, so `*a != *b` compares
// POINTERS and reports a difference between two rows that are identical — the trap this helper exists
// to avoid. updated_at is included: a guard that rejected after touching the row would move it.
func samePolicy(a, b *CedarPolicy) bool {
	if a == nil || b == nil {
		return a == b
	}
	eq := func(x, y *string) bool {
		if x == nil || y == nil {
			return x == y
		}
		return *x == *y
	}
	return a.ID == b.ID && a.Origin == b.Origin && a.Name == b.Name && a.CedarSrc == b.CedarSrc &&
		a.Enabled == b.Enabled && a.UpdatedAt == b.UpdatedAt &&
		eq(a.SystemKey, b.SystemKey) && eq(a.UpdatedBy, b.UpdatedBy)
}

// ---- PolicyOriginDbTest ------------------------------------------------------------------------

// 1. 🔒 the shipped default security posture is unchanged
//
// THE WHOLE SHIPPED POSTURE AS ONE DIGEST — every policy row's id, system_key, name, body, enabled
// flag and origin, plus every role, group and group→role link. The per-row cases below name a handful
// of policies; this one is what catches a narrowed Cedar body that no named assertion mentions.
//
// The SQL and the expected digest are the Kotlin's, unchanged (PolicyOriginDbTest.kt:49-73). When it
// fails, what a fresh install enforces has changed: confirm the change is intended, then update the
// digest in the same commit.
// KT: PolicyOriginDbTest.kt#the shipped default security posture is unchanged
func TestShippedDefaultSecurityPostureIsUnchanged(t *testing.T) {
	f := newOriginFixture(t)

	const digestSQL = `
                    SELECT md5(string_agg(x, '|' ORDER BY x)) FROM (
                      SELECT 'p:' || id::text || coalesce(system_key, '') || name
                             || coalesce(cedar_src, '') || enabled::text || origin AS x FROM policy
                      UNION ALL SELECT 'r:' || name FROM app_role
                      UNION ALL SELECT 'g:' || name FROM app_group
                      UNION ALL SELECT 'gr:' || g.name || '->' || r.name
                        FROM group_role gr
                        JOIN app_group g ON g.id = gr.group_id
                        JOIN app_role r ON r.id = gr.role_id
                    ) t(x)`

	var digest string
	if err := f.db.Pool.QueryRow(f.ctx, digestSQL).Scan(&digest); err != nil {
		t.Fatalf("compute the posture digest: %v", err)
	}
	// ⚠️ CHANGED BY UPSTREAM V12__format_policy_source.sql, which reprints every seeded Cedar policy body.
	// The digest covers policy source, ids, keys, origins, enabled flags, roles, groups and group→role
	// links, so a reformat of the source moves it even though the ENFORCED posture is identical — which is
	// also why the digest is worth having: it cannot tell a reformat from a semantic change, so it forces
	// someone to look. Verified as a reformat by diffing the seeded sources against the Kotlin's V12.
	const want = "6086859b83026f70f4c9b88d54d49519"
	if digest != want {
		t.Errorf("the seeded security posture changed: a policy body, id, key, origin, enabled flag, "+
			"role, group, or group-to-role link differs from what a fresh install is supposed to "+
			"enforce\n got  %s\n want %s", digest, want)
	}
}

// 2. a clean database installs the admin and audit system rows
//
// ⚠️ THE THREE SOURCES BELOW ARE V12's, not the original one-liners. V12__format_policy_source.sql
// reprints every seeded Cedar body across multiple lines; the ENFORCED posture is unchanged, but this
// case compares the source TEXT, so it moves with the reformat. They are lifted verbatim from that
// migration rather than retyped, because a hand-copied Cedar body that happens to parse would pass this
// case while differing from what a fresh install actually stores.
//
// The three bootstrap rows at -1/-2/-3 with their EXACT sources, plus the two audit-read rows at
// -4/-5, all SYSTEM and all enabled — then CedarEngine over the store, which is the assertion that the
// shipped set is not merely present but loadable as one policy set.
// KT: PolicyOriginDbTest.kt#a clean database installs the admin and audit system rows
func TestACleanDatabaseInstallsTheAdminAndAuditSystemRows(t *testing.T) {
	f := newOriginFixture(t)

	type seed struct{ key, name, source string }
	expected := map[int64]seed{
		-1: {"bootstrap.pm-admin", "system:admin", seedAdminSource},
		-2: {"workflow.no-self-approval", "system:no-self-approval", seedNoSelfApprovalSource},
		-3: {"workflow.pm-admin-approve", "system:admin-approver", seedApproverSource},
	}
	rows := f.byID()
	for id, want := range expected {
		got, ok := rows[id]
		if !ok {
			t.Errorf("policy %d is missing from a clean database", id)
			continue
		}
		if got.Origin != SystemPolicyOrigin {
			t.Errorf("policy %d origin: got %q, want SYSTEM", id, got.Origin)
		}
		if got.SystemKey == nil || *got.SystemKey != want.key {
			t.Errorf("policy %d systemKey: got %v, want %q", id, got.SystemKey, want.key)
		}
		if got.Name != want.name {
			t.Errorf("policy %d name: got %q, want %q", id, got.Name, want.name)
		}
		if got.CedarSrc != want.source {
			t.Errorf("policy %d source:\n got  %s\n want %s", id, got.CedarSrc, want.source)
		}
		if !got.Enabled {
			t.Errorf("policy %d must ship enabled", id)
		}
	}

	// -4 is every principal's own-record read, -5 grants the whole log to system:admin.
	//
	// The Kotlin selects these BY system_key and then asserts the resulting id set is exactly
	// {-4, -5} — i.e. no OTHER row claims either audit key. Reproduced in that direction first,
	// because a by-id lookup alone cannot see a third row that also carries `audit.read-admin`.
	byAuditKey := map[int64]bool{}
	for _, p := range f.list() {
		if p.SystemKey != nil && (*p.SystemKey == "audit.read-own" || *p.SystemKey == "audit.read-admin") {
			byAuditKey[p.ID] = true
		}
	}
	if len(byAuditKey) != 2 || !byAuditKey[-4] || !byAuditKey[-5] {
		t.Errorf("the audit-read keys must belong to exactly {-4, -5}; got %v", byAuditKey)
	}

	auditIDs := map[int64]string{-4: "audit.read-own", -5: "audit.read-admin"}
	auditNames := map[int64]string{-4: "system:audit-read-own", -5: "system:audit-read-admin"}
	for id, key := range auditIDs {
		got, ok := rows[id]
		if !ok {
			t.Errorf("audit seed %d is missing", id)
			continue
		}
		if got.SystemKey == nil || *got.SystemKey != key {
			t.Errorf("policy %d systemKey: got %v, want %q", id, got.SystemKey, key)
		}
		if got.Name != auditNames[id] {
			t.Errorf("policy %d name: got %q, want %q", id, got.Name, auditNames[id])
		}
		if got.Origin != SystemPolicyOrigin || !got.Enabled {
			t.Errorf("policy %d must be an enabled SYSTEM row, got origin=%q enabled=%v", id, got.Origin, got.Enabled)
		}
	}

	// `CedarEngine(store)` — the shipped set must load as ONE policy set.
	if _, err := authz.NewCedarEngine(f.store); err != nil {
		t.Fatalf("the shipped policy set must build a CedarEngine: %v", err)
	}
}

// 3. 🔒 the development preset ships enabled and the production preset ships disabled
//
// The enabled defaults ARE the security posture: production access must be OFF until an explicit,
// audited toggle, and the -300 trusted-network producer must stay off until production is enabled
// (otherwise the readiness dangling-tag lint trips on a producer with no consumer).
// KT: PolicyOriginDbTest.kt#the development preset ships enabled and the production preset ships disabled
func TestTheDevelopmentPresetShipsEnabledAndProductionShipsDisabled(t *testing.T) {
	f := newOriginFixture(t)
	rows := f.byID()

	shippedEnabled := []int64{-4, -5, -100, -110, -120, -130, -200, -201, -202}
	for id := int64(230); id <= 235; id++ {
		shippedEnabled = append(shippedEnabled, -id)
	}
	for _, id := range shippedEnabled {
		row, ok := rows[id]
		if !ok {
			t.Errorf("policy %d must ship (absent)", id)
			continue
		}
		if !row.Enabled {
			t.Errorf("policy %d must ship ENABLED", id)
		}
	}

	shippedDisabled := []int64{-300}
	for id := int64(250); id <= 259; id++ {
		shippedDisabled = append(shippedDisabled, -id)
	}
	for _, id := range shippedDisabled {
		row, ok := rows[id]
		if !ok {
			t.Errorf("policy %d must ship (absent)", id)
			continue
		}
		if row.Enabled {
			t.Errorf("policy %d must ship DISABLED", id)
		}
	}
}

// 4. 🔒 the four origin constraints reject every cross-namespace raw insert
//
// The guards in cedarwrite.go are the API's; THESE are the database's, and they are what stops a
// migration, an import or a psql session from putting a USER row in the SYSTEM id space (or vice
// versa). Seven inserts, each violating exactly one rule.
// KT: PolicyOriginDbTest.kt#the four origin constraints reject every cross-namespace raw insert
func TestTheFourOriginConstraintsRejectEveryCrossNamespaceRawInsert(t *testing.T) {
	f := newOriginFixture(t)

	rows, err := f.db.Pool.Query(f.ctx,
		`SELECT conname FROM pg_constraint WHERE conrelid = 'policy'::regclass`)
	if err != nil {
		t.Fatalf("read the policy constraints: %v", err)
	}
	names := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan constraint name: %v", err)
		}
		names[n] = true
	}
	rows.Close()
	for _, want := range []string{
		"policy_origin_check",
		"policy_id_origin_check",
		"policy_name_origin_check",
		"policy_system_key_unique",
	} {
		if !names[want] {
			t.Errorf("constraint %s is missing — the namespace separation is not enforced by the database", want)
		}
	}

	// An origin outside {SYSTEM, USER}.
	f.assertRejected(`INSERT INTO policy (name, cedar_src, origin) VALUES ('bad-origin', $1, 'MIGRATION')`, seedAdminSource)
	// A USER row in the negative (SYSTEM) id space.
	f.assertRejected(`INSERT INTO policy (id, name, cedar_src, origin) VALUES (-1001, 'negative-user', $1, 'USER')`, seedAdminSource)
	// A SYSTEM row in the positive (USER) id space.
	f.assertRejected(`INSERT INTO policy (id, system_key, name, cedar_src, origin) VALUES (1001, 'test.positive-system', 'system:positive-system', $1, 'SYSTEM')`, seedAdminSource)
	// A SYSTEM row with no system_key.
	f.assertRejected(`INSERT INTO policy (id, name, cedar_src, origin) VALUES (-1002, 'system:missing-key', $1, 'SYSTEM')`, seedAdminSource)
	// A USER row inside the reserved `system:` name space.
	f.assertRejected(`INSERT INTO policy (name, cedar_src, origin) VALUES ('system:user-name', $1, 'USER')`, seedAdminSource)
	// A SYSTEM row whose name is OUTSIDE the reserved namespace.
	f.assertRejected(`INSERT INTO policy (id, system_key, name, cedar_src, origin) VALUES (-1003, 'test.bad-system-name', 'bad-system-name', $1, 'SYSTEM')`, seedAdminSource)
	// A duplicate system_key.
	f.assertRejected(`INSERT INTO policy (id, system_key, name, cedar_src, origin) VALUES (-1004, 'bootstrap.pm-admin', 'system:duplicate-key', $1, 'SYSTEM')`, seedAdminSource)
}

// 5. explicit negative ids do not disturb the user sequence and a system upsert preserves disabled
//
// The migration-upgrade shape: a later migration re-upserts a SYSTEM row by id, and `enabled` is
// deliberately ABSENT from its UPDATE list so an operator's audited disable SURVIVES the upgrade. Then
// the sequence half: writing explicit negative ids must not advance or reset the BIGSERIAL, so the
// next USER create still gets a positive id.
// KT: PolicyOriginDbTest.kt#explicit negative ids do not disturb the user sequence and a system upsert preserves disabled
func TestExplicitNegativeIdsDoNotDisturbTheUserSequenceAndASystemUpsertPreservesDisabled(t *testing.T) {
	f := newOriginFixture(t)

	if _, err := f.store.SetEnabled(f.ctx, -1, false, types.Ptr("operator@example.com")); err != nil {
		t.Fatalf("disable the system policy: %v", err)
	}

	const updatedSource = `permit(principal in Role::"system:admin", action == Action::"admin.policies", resource);`
	err := f.exec(`INSERT INTO policy
                       (id, system_key, name, cedar_src, enabled, origin, updated_by, updated_at)
                   VALUES
                       (-1, 'bootstrap.pm-admin', 'system:admin-v2', $1, true, 'SYSTEM', 'migration:test', now())
                   ON CONFLICT (id) DO UPDATE SET
                       name = EXCLUDED.name,
                       cedar_src = EXCLUDED.cedar_src,
                       origin = 'SYSTEM',
                       updated_by = EXCLUDED.updated_by,
                       updated_at = now()
                   WHERE policy.cedar_src IS DISTINCT FROM EXCLUDED.cedar_src
                      OR policy.name IS DISTINCT FROM EXCLUDED.name`, updatedSource)
	if err != nil {
		t.Fatalf("the migration-shaped upsert must succeed: %v", err)
	}

	system := f.get(-1)
	if system == nil {
		t.Fatal("policy -1 vanished")
	}
	if system.SystemKey == nil || *system.SystemKey != "bootstrap.pm-admin" {
		t.Errorf("systemKey: got %v, want bootstrap.pm-admin", system.SystemKey)
	}
	if system.Name != "system:admin-v2" {
		t.Errorf("name: got %q, want system:admin-v2", system.Name)
	}
	if system.CedarSrc != updatedSource {
		t.Errorf("source:\n got  %s\n want %s", system.CedarSrc, updatedSource)
	}
	if system.Enabled {
		t.Error("enabled must be ABSENT from a system-policy upgrade's UPDATE list — an operator's " +
			"audited disable must survive the upgrade")
	}

	user, err := f.store.Create(f.ctx, NewCedarPolicyInput("sequence-user", seedAdminSource),
		types.Ptr("operator@example.com"))
	if err != nil {
		t.Fatalf("create a USER policy: %v", err)
	}
	if user.ID <= 0 {
		t.Errorf("id %d — explicit negative system ids must not advance or reset the BIGSERIAL sequence", user.ID)
	}
	if user.Origin != UserPolicyOrigin {
		t.Errorf("origin: got %q, want USER", user.Origin)
	}
	if user.SystemKey != nil {
		t.Errorf("systemKey: got %q, want nil", *user.SystemKey)
	}
}

// ---- CedarPolicyStoreTest, the seed and enabled-source cases -------------------------------------

// 🔒 CedarPolicyStoreTest case 1 — "V20 system seeds and the V32-converted audit seeds are enabled and
// validate as one Cedar engine".
//
// Overlaps case 2 above on -1..-5 and adds what that case does not have: the two task.assume seeds at
// -21/-22, the `system:auditor` role shipping with ZERO assignments (an auditor role that came
// pre-granted would hand the whole audit log to somebody), that every seed id appears in
// EnabledSources(), and that the set builds one engine.
// KT: CedarPolicyStoreTest.kt#V20 system seeds and the V32-converted audit seeds are enabled and validate as one Cedar engine
func TestSystemSeedsAndAuditSeedsAreEnabledAndValidateAsOneEngine(t *testing.T) {
	f := newOriginFixture(t)
	rows := f.byID()

	systemSeeds := map[int64][2]string{
		-1: {"system:admin", "bootstrap.pm-admin"},
		-2: {"system:no-self-approval", "workflow.no-self-approval"},
		-3: {"system:admin-approver", "workflow.pm-admin-approve"},
	}
	for id, want := range systemSeeds {
		got, ok := rows[id]
		if !ok {
			t.Errorf("system seed %d is missing", id)
			continue
		}
		if got.Name != want[0] {
			t.Errorf("policy %d name: got %q, want %q", id, got.Name, want[0])
		}
		if got.Origin != SystemPolicyOrigin {
			t.Errorf("policy %d origin: got %q, want SYSTEM", id, got.Origin)
		}
		if got.SystemKey == nil || *got.SystemKey != want[1] {
			t.Errorf("policy %d systemKey: got %v, want %q", id, got.SystemKey, want[1])
		}
		if !got.Enabled {
			t.Errorf("system seed %d must be enabled on a clean database", id)
		}
	}

	// The two audit-read SYSTEM rows, found by system_key exactly as the Kotlin finds them.
	auditIDs := map[int64]bool{}
	auditNames := map[string]bool{}
	for _, p := range f.list() {
		if p.SystemKey != nil && (*p.SystemKey == "audit.read-own" || *p.SystemKey == "audit.read-admin") {
			auditIDs[p.ID] = true
			auditNames[p.Name] = true
			if !p.Enabled || p.Origin != SystemPolicyOrigin {
				t.Errorf("audit seed %d must be an enabled SYSTEM row", p.ID)
			}
		}
	}
	if !auditIDs[-4] || !auditIDs[-5] || len(auditIDs) != 2 {
		t.Errorf("the two audit-read SYSTEM rows must ship at -4/-5, got %v", auditIDs)
	}
	if !auditNames["system:audit-read-own"] || !auditNames["system:audit-read-admin"] {
		t.Errorf("audit seed names: got %v", auditNames)
	}

	// The task.assume seeds.
	assumeKeys := map[string]bool{}
	for _, id := range []int64{-21, -22} {
		got, ok := rows[id]
		if !ok {
			t.Errorf("assume seed %d is missing", id)
			continue
		}
		if got.SystemKey != nil {
			assumeKeys[*got.SystemKey] = true
		}
		if !got.Enabled || got.Origin != SystemPolicyOrigin {
			t.Errorf("assume seed %d must be an enabled SYSTEM row", id)
		}
	}
	if !assumeKeys["task.assume-parties"] || !assumeKeys["task.assume-auditor"] {
		t.Errorf("assume seed keys: got %v", assumeKeys)
	}

	// 🔒 `system:auditor` ships with NO assignments.
	var assignments int
	err := f.db.Pool.QueryRow(f.ctx,
		`SELECT count(pr.id) FROM app_role r LEFT JOIN principal_role pr ON pr.role_id = r.id
		 WHERE r.name = 'system:auditor' GROUP BY r.id`).Scan(&assignments)
	if err != nil {
		t.Fatalf("the migrations must seed system:auditor: %v", err)
	}
	if assignments != 0 {
		t.Errorf("system:auditor starts with %d assignments, want 0", assignments)
	}

	// Every seed id must appear in EnabledSources(), and the whole set must build one engine.
	enabled := map[int64]bool{}
	for _, src := range f.store.EnabledSources() {
		enabled[src.ID] = true
	}
	for _, id := range []int64{-1, -2, -3, -4, -5, -21, -22} {
		if !enabled[id] {
			t.Errorf("enabled seed row %d does not appear in EnabledSources()", id)
		}
	}
	if _, err := authz.NewCedarEngine(f.store); err != nil {
		t.Fatalf("the seeded set must build one CedarEngine: %v", err)
	}
}

// CedarPolicyStoreTest case 5 — "enable and disable round-trip into enabledSources".
//
// EnabledSources() is the ONLY thing CedarEngine reads, so the round trip through it — not through
// the row's `enabled` column — is what proves a toggle actually changes what Cedar evaluates.
// KT: CedarPolicyStoreTest.kt#enable and disable round-trip into enabledSources
func TestEnableAndDisableRoundTripIntoEnabledSources(t *testing.T) {
	f := newOriginFixture(t)

	created, err := f.store.Create(f.ctx,
		NewCedarPolicyInput("test-toggle", `permit(principal in Role::"system:admin", action == Action::"admin.policies", resource);`), nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	inSources := func() bool {
		for _, src := range f.store.EnabledSources() {
			if src.ID == created.ID {
				return true
			}
		}
		return false
	}
	if !inSources() {
		t.Fatal("a created, enabled policy must appear in EnabledSources()")
	}

	disabled, err := f.store.SetEnabled(f.ctx, created.ID, false, types.Ptr("tester"))
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if disabled == nil || disabled.Enabled {
		t.Fatalf("setEnabled(false) must answer the disabled row, got %+v", disabled)
	}
	if inSources() {
		t.Error("a disabled policy must NOT appear in EnabledSources()")
	}

	reenabled, err := f.store.SetEnabled(f.ctx, created.ID, true, types.Ptr("tester"))
	if err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	if reenabled == nil || !reenabled.Enabled {
		t.Fatalf("setEnabled(true) must answer the enabled row, got %+v", reenabled)
	}
	if !inSources() {
		t.Error("a re-enabled policy must appear in EnabledSources() again")
	}
}

// 🔒 CedarPolicyStoreTest case 7 — "update rejects invalid cedar and leaves the existing row
// untouched".
//
// BOTH halves. The `updatedBy` assertion is the sharp one: a port that wrote the row first and
// validated afterwards, or that updated the audit columns before failing, would leave `updatedBy` as
// the SECOND caller while the source stayed the first caller's — a row that lies about who last
// touched it.
// KT: CedarPolicyStoreTest.kt#update rejects invalid cedar and leaves the existing row untouched
func TestUpdateRejectsInvalidCedarAndLeavesTheExistingRowUntouched(t *testing.T) {
	f := newOriginFixture(t)

	const src = `permit(principal in Role::"system:admin", action == Action::"admin.identity", resource);`
	created, err := f.store.Create(f.ctx, NewCedarPolicyInput("test-update", src), types.Ptr("tester"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	_, err = f.store.Update(f.ctx, created.ID,
		NewCedarPolicyInput(created.Name, "not cedar"), types.Ptr("tester2"))
	var invalid InvalidCedarPolicyError
	if !errors.As(err, &invalid) {
		t.Fatalf("want InvalidCedarPolicyError, got %#v", err)
	}

	still := f.get(created.ID)
	if still == nil {
		t.Fatal("the row must still exist after a rejected update")
	}
	if still.CedarSrc != created.CedarSrc {
		t.Errorf("source:\n got  %s\n want %s", still.CedarSrc, created.CedarSrc)
	}
	if still.UpdatedBy == nil || *still.UpdatedBy != "tester" {
		t.Errorf("updatedBy: got %v, want \"tester\" — the rejected update must not claim authorship", still.UpdatedBy)
	}
}

// ---- CedarPolicyOriginTest's decision equivalence -----------------------------------------------

// 🔒 CedarPolicyOriginTest case 4 — "negative-id migration is decision-equivalent to the AuthzTest
// seed oracle".
//
// THE BRIDGE BETWEEN THE UNIT ORACLE AND WHAT SHIPS. internal/authz/authz_test.go asserts twelve
// decisions against a five-policy in-memory set; this asserts that the MIGRATED database — 29-odd
// enabled SYSTEM rows, negative ids, preset postures and all — decides every one of them the same
// way. Either set drifting alone is caught: the oracle's expectation is asserted independently of the
// migrated engine's answer, exactly as the Kotlin does it.
//
// Note the seed's audit posture: `system:admin` reads the whole log by default and there is NO
// separate `auditor` role, which is why the oracle's policy 5 names system:admin rather than the
// `auditor` AuthzTest.kt uses.
// KT: CedarPolicyOriginTest.kt#negative-id migration is decision-equivalent to the AuthzTest seed oracle
func TestNegativeIDMigrationIsDecisionEquivalentToTheAuthzTestSeedOracle(t *testing.T) {
	f := newOriginFixture(t)

	roles := map[string][]string{
		"admin@example.com":   {"system:admin"},
		"analyst@example.com": {"analyst"},
	}
	roleSource := authz.RoleSourceFunc(func(p string) []string { return roles[p] })

	// CedarPolicyOriginTest.kt:238-245 — the ORACLE_SOURCES, verbatim.
	oracleEngine, err := authz.NewCedarEngineFromSources([]authz.PolicySource{
		{ID: 1, Src: seedAdminSource},
		{ID: 2, Src: `forbid(principal, action == Action::"task.approve", resource) when { principal == resource.requester };`},
		{ID: 3, Src: `permit(principal in Role::"system:admin", action == Action::"task.approve", resource);`},
		{ID: 4, Src: `permit(principal, action == Action::"audit.read", resource) when { resource is AuditRecord && resource.principal == principal };`},
		{ID: 5, Src: `permit(principal in Role::"system:admin", action == Action::"audit.read", resource);`},
	})
	if err != nil {
		t.Fatalf("build the oracle engine: %v", err)
	}
	oracle := authz.New(oracleEngine, nil, roleSource)

	migratedEngine, err := authz.NewCedarEngine(f.store)
	if err != nil {
		t.Fatalf("build the migrated engine: %v", err)
	}
	migrated := authz.New(migratedEngine, f.store, roleSource)

	cases := []struct {
		principal string
		action    authz.AuthzAction
		resource  authz.AuthzResource
		allowed   bool
	}{
		{"admin@example.com", authz.ActionAdminDatasources, authz.ResourceSystem{}, true},
		{"admin@example.com", authz.ActionAdminPolicies, authz.ResourceSystem{}, true},
		{"admin@example.com", authz.ActionAdminIdentity, authz.ResourceSystem{}, true},
		{"nobody@example.com", authz.ActionAdminPolicies, authz.ResourceSystem{}, false},
		{"analyst@example.com", authz.ActionAdminPolicies, authz.ResourceSystem{}, false},
		{"admin@example.com", authz.ActionTaskApprove, authz.ResourceApprovalRequest{Requester: "requester@example.com"}, true},
		{"admin@example.com", authz.ActionTaskApprove, authz.ResourceApprovalRequest{Requester: "admin@example.com"}, false},
		{"analyst@example.com", authz.ActionAuditRead, authz.ResourceAuditRecord{Principal: "analyst@example.com"}, true},
		{"analyst@example.com", authz.ActionAuditRead, authz.ResourceAuditRecord{Principal: "other@example.com"}, false},
		{"analyst@example.com", authz.ActionAuditRead, authz.ResourceAuditLog{}, false},
		// system:admin reads the whole audit log by default; there is no separate `auditor` role.
		{"admin@example.com", authz.ActionAuditRead, authz.ResourceAuditRecord{Principal: "other@example.com"}, true},
		{"admin@example.com", authz.ActionAuditRead, authz.ResourceAuditLog{}, true},
	}

	for _, c := range cases {
		what := fmt.Sprintf("%s %s %T", c.principal, c.action, c.resource)
		expected := oracle.Authorize(c.principal, c.action, c.resource, authz.AuthzContext{}).Allowed
		actual := migrated.Authorize(c.principal, c.action, c.resource, authz.AuthzContext{}).Allowed
		if expected != c.allowed {
			t.Errorf("the AuthzTest oracle changed for %s: got %v, want %v", what, expected, c.allowed)
		}
		if actual != expected {
			t.Errorf("the MIGRATED policy set changed the effective decision for %s: got %v, want %v",
				what, actual, expected)
		}
	}
}

// ---- CedarPolicyOriginTest's before-touching-state guards ----------------------------------------

// 🔒 CedarPolicyOriginTest case 1 — "store rejects system mutation and reserved user names BEFORE
// touching state".
//
// FIVE guards in one case, and the Kotlin keeps them together because what they share is the
// "before touching state" clause: each rejection must leave the row byte-identical AND must not bump
// the state version. A guard that rejected after writing, or after bumping, would pass a
// rejection-only assertion while either corrupting a migration-owned row or invalidating every
// engine's cache on each rejected request.
//
// cedarwrite_db_test.go covers the individual rejections in isolation (reserved-name ordering,
// SYSTEM-update immutability, the rename guard); what is here and nowhere else is the UNCHANGED-STATE
// half, version included.
// KT: CedarPolicyOriginTest.kt#store rejects system mutation and reserved user names before touching state
func TestStoreRejectsSystemMutationAndReservedUserNamesBeforeTouchingState(t *testing.T) {
	f := newOriginFixture(t)

	systemBefore := f.get(-1)
	if systemBefore == nil {
		t.Fatal("policy -1 must ship")
	}
	versionBefore := f.store.StateVersion()

	_, err := f.store.Update(f.ctx, -1,
		CedarPolicyInput{Name: "system:rewritten", CedarSrc: "not cedar", Enabled: false},
		types.Ptr("operator@example.com"))
	if !errors.Is(err, ErrSystemPolicyImmutable) {
		t.Errorf("update of a SYSTEM row: want ErrSystemPolicyImmutable, got %#v", err)
	}
	if _, err := f.store.Delete(f.ctx, -1); !errors.Is(err, ErrSystemPolicyImmutable) {
		t.Errorf("delete of a SYSTEM row: want ErrSystemPolicyImmutable, got %#v", err)
	}
	if after := f.get(-1); !samePolicy(after, systemBefore) {
		t.Errorf("failed system mutations must leave every field unchanged:\n before %+v\n after  %+v",
			*systemBefore, after)
	}
	if got := f.store.StateVersion(); got != versionBefore {
		t.Errorf("rejected mutations must not invalidate the engine cache: version %d -> %d", versionBefore, got)
	}

	var reserved ReservedPolicyNameError
	_, err = f.store.Create(f.ctx, NewCedarPolicyInput("system:user-created", seedAdminSource),
		types.Ptr("operator@example.com"))
	if !errors.As(err, &reserved) {
		t.Errorf("create in the reserved namespace: want ReservedPolicyNameError, got %#v", err)
	}

	const testRoleSource = `permit(principal in Role::"origin-test-role", action == Action::"admin.policies", resource);`
	user, err := f.store.Create(f.ctx, NewCedarPolicyInput("origin-user", testRoleSource),
		types.Ptr("operator@example.com"))
	if err != nil {
		t.Fatalf("create a USER policy: %v", err)
	}
	userBefore := f.get(user.ID)

	_, err = f.store.Update(f.ctx, user.ID, NewCedarPolicyInput("system:user-renamed", testRoleSource),
		types.Ptr("other@example.com"))
	if !errors.As(err, &reserved) {
		t.Errorf("rename into the reserved namespace: want ReservedPolicyNameError, got %#v", err)
	}
	if after := f.get(user.ID); !samePolicy(after, userBefore) {
		t.Errorf("a rejected reserved rename must not alter the USER row:\n before %+v\n after  %+v",
			*userBefore, after)
	}
	if user.ID <= 0 || user.Origin != UserPolicyOrigin || user.SystemKey != nil {
		t.Errorf("a USER create must land positive-id/USER/no-key, got id=%d origin=%q key=%v",
			user.ID, user.Origin, user.SystemKey)
	}
}

// 🔒 CedarPolicyOriginTest case 3 — "audit failure rolls back the system toggle in the same
// transaction" — BY THE KOTLIN'S OWN MECHANISM.
//
// cedarwrite_db_test.go's TestAnAuditFailureRollsBackTheSystemToggle injects a failing appender, which
// proves the error propagates and the toggle rolls back. This one instead installs the Kotlin's
// BEFORE INSERT trigger on audit_event, so the failure originates INSIDE Postgres — which is what
// proves the audit insert really runs on the toggle's own transaction. Move the insert onto the pool
// (a refactor that looks harmless and leaves the appender version green) and the trigger aborts only
// the audit transaction, the toggle commits, and this case goes red.
//
// Both carry the marker: they are two halves of the one Kotlin assertion.
// KT: CedarPolicyOriginTest.kt#audit failure rolls back the system toggle in the same transaction
func TestAnAuditTriggerFailureRollsBackTheSystemToggleInTheSameTransaction(t *testing.T) {
	f := newOriginFixture(t)

	if err := f.exec(`CREATE FUNCTION reject_system_policy_toggle() RETURNS trigger
                       LANGUAGE plpgsql AS $$
                       BEGIN
                           IF NEW.detail = 'SYSTEM_POLICY_TOGGLE' THEN
                               RAISE EXCEPTION 'reject test system-policy audit';
                           END IF;
                           RETURN NEW;
                       END
                       $$`); err != nil {
		t.Fatalf("create the rejecting function: %v", err)
	}
	if err := f.exec(`CREATE TRIGGER reject_system_policy_toggle
                       BEFORE INSERT ON audit_event
                       FOR EACH ROW EXECUTE FUNCTION reject_system_policy_toggle()`); err != nil {
		t.Fatalf("create the rejecting trigger: %v", err)
	}
	t.Cleanup(func() {
		_ = f.exec(`DROP TRIGGER IF EXISTS reject_system_policy_toggle ON audit_event`)
		_ = f.exec(`DROP FUNCTION IF EXISTS reject_system_policy_toggle()`)
	})

	// -2 ships enabled; the Kotlin enables it explicitly first because its suite shares one database.
	if _, err := f.store.SetEnabled(f.ctx, -2, true, types.Ptr("setup@example.com")); err != nil {
		t.Fatalf("pre-enable -2: %v", err)
	}
	versionBefore := f.store.StateVersion()

	if _, err := f.store.SetEnabled(f.ctx, -2, false, types.Ptr("operator@example.com")); err == nil {
		t.Fatal("the audit insert failed inside Postgres; the toggle cannot report success")
	}
	if row := f.get(-2); row == nil || !row.Enabled {
		t.Error("the policy update must roll back when its audit insert fails — a SYSTEM toggle may " +
			"never take effect unlogged")
	}
	if got := f.store.StateVersion(); got != versionBefore {
		t.Errorf("a rolled-back toggle must not bump the store version: %d -> %d", versionBefore, got)
	}
}

// ---- CedarEngineCacheTest's DB half --------------------------------------------------------------

// 🔒 CedarEngineCacheTest case 1 — "disable invalidates the cache, re-enable and delete both take
// effect on the next call".
//
// internal/authz/engine_test.go covers the version GATING against a hand-driven fake store; what only
// a real store can prove is that SetEnabled and Delete actually BUMP it, so a policy edit is visible to
// the very next decision. A store that forgot to bump would leave the shared engine (INV-A1-1) serving
// decisions from rows that no longer exist, permanently — and every fake-store test would still pass.
//
// The Kotlin's `delete` half is the one the fake cannot reach at all: engine_test.go stops at
// re-enable because a fake has no delete.
// KT: CedarEngineCacheTest.kt#disable invalidates the cache, re-enable and delete both take effect on the next call
func TestDisableReEnableAndDeleteAllTakeEffectOnTheNextDecision(t *testing.T) {
	f := newOriginFixture(t)

	const principal = "cache-alice@example.com"
	const role = "cache-role"
	a := authz.New(mustEngineOver(t, f.store), f.store,
		authz.RoleSourceFunc(func(p string) []string {
			if p == principal {
				return []string{role}
			}
			return nil
		}))

	created, err := f.store.Create(f.ctx, NewCedarPolicyInput("cache-test-toggle",
		fmt.Sprintf(`permit(principal in Role::%q, action == Action::"admin.datasources", resource);`, role)), nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	decide := func() bool {
		return a.Authorize(principal, authz.ActionAdminDatasources, authz.ResourceSystem{}, authz.AuthzContext{}).Allowed
	}

	if !decide() {
		t.Fatal("the cache must warm to Allow with the policy enabled")
	}

	if _, err := f.store.SetEnabled(f.ctx, created.ID, false, nil); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if decide() {
		t.Error("disabling must invalidate the cached PolicySet — the very next call must not serve a stale Allow")
	}

	if _, err := f.store.SetEnabled(f.ctx, created.ID, true, nil); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	if !decide() {
		t.Error("re-enabling must invalidate the cache back to Allow")
	}

	deleted, err := f.store.Delete(f.ctx, created.ID)
	if err != nil || !deleted {
		t.Fatalf("delete: deleted=%v err=%v", deleted, err)
	}
	if decide() {
		t.Error("deleting the granting policy must invalidate the cache")
	}
}

func mustEngineOver(t *testing.T, s *CedarPolicyStore) *authz.CedarEngine {
	t.Helper()
	e, err := authz.NewCedarEngine(s)
	if err != nil {
		t.Fatalf("build a CedarEngine over the store: %v", err)
	}
	return e
}
