package query_test

import (
	"context"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/oidc"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/policy"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// PORT of PresetPolicyDbTest.kt — 286 LOC, 9 cases. The SHIPPED bootstrap-policy package
// (V8__seed.sql §6-7: -200..-202, -230..-235, -250..-259, -300) on a real Postgres target through the
// real Cedar engine and the production decision.
//
// The central fact the whole suite turns on, from the Kotlin's kdoc: a DEVELOPMENT datasource holds no
// PII by definition, so
//   - development reads CLEARTEXT — pii-tagged columns included — for anyone who reached the
//     datasource; roles gate only connect + the matching sql.* kind;
//   - the system-object floor permits catalog everywhere and activity/data-leak on dev, but critical is
//     ALWAYS forbidden, dev included;
//   - production ships DISABLED; once enabled it masks PII, and only a production-pii-accessor whose
//     request earns `trusted-network` (the shipped -300 example, 100.100.0.0/16) or runs on the
//     workflow-executor channel (-259) reads cleartext;
//   - the shipped `system:developer` GROUP aggregates the five development roles.
//
// internal/conformance/cedar_decisions_test.go:118 records this suite as skipped from the corpus replay
// ("DB-backed: the preset posture arrives via Flyway and CedarPolicyStore, and the records assert whole
// role MATRICES over it. TODO(A2)"). The store has landed, so it is ported here for real.
//
// The Kotlin's PER_CLASS `@BeforeAll` + `@BeforeEach` shape maps to ONE fixture per Go test function
// (presetFixture), each of which re-establishes the reset state itself — the same isolation the
// `@BeforeEach` provides, without sharing mutable enabled-flags across cases.
// ---------------------------------------------------------------------------------------------

// The ten preset roles and the principal that holds each — PresetPolicyDbTest.kt:33-45.
var presetPrincipals = map[string]string{
	"system:development-viewer":       "dev-viewer@example.com",
	"system:development-pii-accessor": "dev-pii@example.com",
	"system:development-updater":      "dev-updater@example.com",
	"system:development-deleter":      "dev-deleter@example.com",
	"system:development-architect":    "dev-architect@example.com",
	"system:production-viewer":        "prod-viewer@example.com",
	"system:production-pii-accessor":  "prod-pii@example.com",
	"system:production-updater":       "prod-updater@example.com",
	"system:production-deleter":       "prod-deleter@example.com",
	"system:production-architect":     "prod-architect@example.com",
}

// presetDeveloper reaches its five roles through the SHIPPED system:developer group, not through a
// direct assignment — the Kotlin provisions it from an OIDC claim for exactly that reason.
const presetDeveloper = "developer@example.com"

// presetEngineVersion is the version string the Kotlin pins on the datasource, so which system-object
// manifest governs is a fixture fact rather than a container-version accident.
const presetEngineVersion = "PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc"

type presetFixture struct {
	t   *testing.T
	ctx context.Context
	fx  *dbtest.EnforcementFixture
	// policies is the PRODUCTION store, used for the enabled-flag toggles the Kotlin's reset() does
	// through `fx.cedarPolicyStore.setEnabled`.
	policies *policy.CedarPolicyStore
	// classifier is the SHIPPED system-object manifest set. The Kotlin passes
	// `systemClassification = SystemClassificationService()` on every decide(), and it is not optional
	// here: with no classifier NOTHING is tagged system:catalog/activity/data-leak/critical, so
	// -130's critical forbid never matches and cases 4 and 7 pass vacuously in the WRONG direction
	// (a pg_authid read would read as ALLOW). Measured: both cases fail without it.
	classifier query.SystemClassifier
}

// newPresetFixture is `@BeforeAll setup()` + `@BeforeEach reset()`: the preset roles assigned, the
// developer provisioned through the shipped group, the development package enabled as migrated and the
// production package (including -259) plus the -300 producer disabled.
func newPresetFixture(t *testing.T) *presetFixture {
	t.Helper()
	fx := newEnforcementFixture(t, dbtest.EnginePostgres)
	fx.SetEngineVersion(types.Ptr(presetEngineVersion))

	p := &presetFixture{
		t: t, ctx: context.Background(), fx: fx,
		policies:   policy.NewCedarPolicyStore(fx.Store.Pool),
		classifier: shippedClassifier(t),
	}

	// The preset roles are MIGRATION-seeded, so they are ASSIGNED, not created: assignExistingRole goes
	// through the production policy store exactly as the Kotlin's
	// `fx.policyStore.createAssignment(RoleAssignmentInput(principal, roles.getValue(roleName).id))`
	// does. (dbtest's Seed.Role would fail on the unique name, and a second row under the same name is
	// what V1's constraint exists to prevent.)
	for role, principal := range presetPrincipals {
		assignExistingRole(t, fx, principal, role)
	}

	// Exercise the real default aggregate group rather than manually assigning its five roles: the
	// claim `okta-developers` maps to the shipped `system:developer` group, whose group_role rows are
	// what turn it into the five development roles (the IdP never mints a role).
	provisioner := oidc.NewDirectoryProvisioner(fx.Store.Pool)
	if _, err := provisioner.Provision(p.ctx, presetDeveloper, types.Ptr(presetDeveloper),
		[]string{"okta-developers"},
		oidc.GroupMapping{Map: map[string]string{"okta-developers": "system:developer"}}); err != nil {
		t.Fatalf("provision the developer from the OIDC claim: %v", err)
	}

	p.setPosture("system:development")
	// No test-authored trusted-network producer: the shipped -300 example (100.100.0.0/16) is THE
	// producer, and a fixture-authored one would prove the fixture rather than the seed.
	p.enable(true, -200)
	p.enable(true, -230, -231, -232, -233, -234, -235)
	p.enable(false, -300)
	p.enable(false, -250, -251, -252, -253, -254, -255, -256, -257, -258, -259)
	return p
}

// setPosture writes the datasource's single posture tag and re-reads the row (SetTags does both — see
// its doc on why the re-read is load-bearing).
func (p *presetFixture) setPosture(posture string) {
	p.t.Helper()
	p.fx.SetTags(posture)
}

// enable toggles shipped policies through the PRODUCTION store and then bumps the fixture's policy
// store, which is what invalidates the already-built engine's cached PolicySet (INV-A2-19). Without
// the bump the engine keeps serving the pre-toggle set and every assertion below would be vacuous.
func (p *presetFixture) enable(enabled bool, ids ...int64) {
	p.t.Helper()
	for _, id := range ids {
		if _, err := p.policies.SetEnabled(p.ctx, id, enabled, types.Ptr("test-reset")); err != nil {
			p.t.Fatalf("setEnabled(%d, %v): %v", id, enabled, err)
		}
	}
	p.fx.PolicyStore.Bump()
}

// enableProductionPackage is the Kotlin's recurring
// `(listOf(-300L) + (250L..258L).map { -it }).forEach { setEnabled(it, true) }` — the production
// package WITHOUT -259, plus its trusted-network producer.
func (p *presetFixture) enableProductionPackage() {
	p.t.Helper()
	p.enable(true, -300, -250, -251, -252, -253, -254, -255, -256, -257, -258)
}

// decide runs the production decision. requesterIP "" means absent — the fail-closed state, not an
// empty ip.
func (p *presetFixture) decide(principal, sql, requesterIP string, channel query.Channel) pb.EnfAction {
	p.t.Helper()
	in := query.DecideQueryInput{
		Principal: principal, SQL: sql, Channel: channel,
		SystemClassification: p.classifier,
	}
	if requesterIP != "" {
		in.Context = authz.AuthzContext{RequesterIP: types.Ptr(requesterIP)}
	}
	return p.fx.DecideWith(in).Action
}

// wire is `decide(principal, sql, requesterIp)` — the Kotlin's default channel.
func (p *presetFixture) wire(principal, sql, requesterIP string) pb.EnfAction {
	p.t.Helper()
	return p.decide(principal, sql, requesterIP, query.ChannelWire)
}

// actionAllowed is the Kotlin's `actionAllowed(principal, action)`: the once-per-query datasource gate
// over the principal's SERVER-RESOLVED roles and the datasource's current posture tags.
func (p *presetFixture) actionAllowed(principal string, action authz.AuthzAction) bool {
	p.t.Helper()
	roles, err := p.fx.RoleResolver.Resolve(p.ctx, principal)
	if err != nil {
		p.t.Fatalf("resolve roles for %s: %v", principal, err)
	}
	return p.fx.Authz.AuthorizeDatasourceAction(principal, roles, action,
		p.fx.DatasourceRow.Name, authz.AuthzContext{}, p.fx.DatasourceRow.Tags).Allowed
}

// presetSQLActions is the five statement kinds the two matrix cases sweep.
var presetSQLActions = []authz.AuthzAction{
	authz.ActionSQLSelect, authz.ActionSQLInsert, authz.ActionSQLUpdate,
	authz.ActionSQLDelete, authz.ActionSQLDDL,
}

// assertRoleMatrix is the shared body of the two matrix cases: every role connects, and each is granted
// EXACTLY its own statement kind — the `assertEquals(action in granted, actionAllowed(...))` sweep,
// whose negative half is the load-bearing one (it is what catches a preset that granted a kind it
// should not).
func (p *presetFixture) assertRoleMatrix(expected map[string][]authz.AuthzAction) {
	p.t.Helper()
	for role, granted := range expected {
		principal := presetPrincipals[role]
		if !p.actionAllowed(principal, authz.ActionDatasourceConnect) {
			p.t.Errorf("%s: datasource.connect must be granted", role)
		}
		grantedSet := map[authz.AuthzAction]bool{}
		for _, a := range granted {
			grantedSet[a] = true
		}
		for _, action := range presetSQLActions {
			if got := p.actionAllowed(principal, action); got != grantedSet[action] {
				p.t.Errorf("%s %s: got allowed=%v, want %v", role, action, got, grantedSet[action])
			}
		}
	}
}

// 1. development role matrix grants connect and only the corresponding SQL kind
// KT: PresetPolicyDbTest.kt#development role matrix grants connect and only the corresponding SQL kind
func TestPresetDevelopmentRoleMatrix(t *testing.T) {
	p := newPresetFixture(t)
	p.assertRoleMatrix(map[string][]authz.AuthzAction{
		"system:development-viewer":       {authz.ActionSQLSelect},
		"system:development-pii-accessor": {authz.ActionSQLSelect},
		"system:development-updater":      {authz.ActionSQLInsert, authz.ActionSQLUpdate},
		"system:development-deleter":      {authz.ActionSQLDelete},
		"system:development-architect":    {authz.ActionSQLDDL},
	})
}

// 2. production role matrix grants connect and only the corresponding SQL kind ONCE ENABLED
// KT: PresetPolicyDbTest.kt#production role matrix grants connect and only the corresponding SQL kind once enabled
func TestPresetProductionRoleMatrixOnceEnabled(t *testing.T) {
	p := newPresetFixture(t)
	p.setPosture("system:production")
	p.enableProductionPackage()
	p.assertRoleMatrix(map[string][]authz.AuthzAction{
		"system:production-viewer":       {authz.ActionSQLSelect},
		"system:production-pii-accessor": {authz.ActionSQLSelect},
		"system:production-updater":      {authz.ActionSQLInsert, authz.ActionSQLUpdate},
		"system:production-deleter":      {authz.ActionSQLDelete},
		"system:production-architect":    {authz.ActionSQLDDL},
	})
}

// 3. 🔒 development reads cleartext INCLUDING PII because dev holds no PII
//
// The -200 permit is role-agnostic and posture-scoped: on a dev datasource a pii-tagged column reads
// cleartext for anyone who got through the connect gate, and the trusted network is irrelevant there.
// KT: PresetPolicyDbTest.kt#development reads cleartext including PII because dev holds no PII
func TestPresetDevelopmentReadsCleartextIncludingPII(t *testing.T) {
	p := newPresetFixture(t)
	viewer := presetPrincipals["system:development-viewer"]
	accessor := presetPrincipals["system:development-pii-accessor"]

	if got := p.wire(viewer, "select id, region from users", ""); got != pb.EnfAction_ALLOW {
		t.Errorf("ordinary columns: got %v, want ALLOW", got)
	}
	if got := p.wire(viewer, "select rrn from users", ""); got != pb.EnfAction_ALLOW {
		t.Errorf("dev has no PII -> rrn is cleartext: got %v, want ALLOW", got)
	}
	if got := p.wire(accessor, "select rrn from users", "100.99.1.10"); got != pb.EnfAction_ALLOW {
		t.Errorf("off trusted-network is still cleartext on dev: got %v, want ALLOW", got)
	}
}

// 4. 🔒 development system floor permits catalog, activity and data-leak but NEVER critical
//
// -130's forbid is what makes the last line hold: the dev relaxation widens three of the four system
// classes and the fourth stays shut, on dev as everywhere else.
// KT: PresetPolicyDbTest.kt#development system floor permits catalog activity and data-leak but never critical
func TestPresetDevelopmentSystemFloor(t *testing.T) {
	p := newPresetFixture(t)
	viewer := presetPrincipals["system:development-viewer"]

	for _, c := range []struct {
		sql  string
		want pb.EnfAction
		what string
	}{
		{"select count(*) from pg_catalog.pg_class", pb.EnfAction_ALLOW, "catalog"},
		{"select count(*) from pg_catalog.pg_stat_activity", pb.EnfAction_ALLOW, "activity on dev"},
		{"select count(*) from pg_catalog.pg_stats", pb.EnfAction_ALLOW, "data-leak on dev"},
		{"select count(*) from pg_catalog.pg_authid", pb.EnfAction_DENY, "critical stays forbidden even on dev"},
	} {
		if got := p.wire(viewer, c.sql, ""); got != c.want {
			t.Errorf("%s: got %v, want %v", c.what, got, c.want)
		}
	}
}

// 5. 🔒 production is denied until enabled, then masks PII unless a pii-accessor earns trusted-network
//
// The first assertion is the one that matters most on a fresh install: a correctly-assigned production
// role is DENIED because the package ships disabled. Then, enabled, the widening is narrow — the role
// AND the network, not either alone.
// KT: PresetPolicyDbTest.kt#production is denied until enabled then masks PII unless a pii-accessor earns trusted-network
func TestPresetProductionDeniedUntilEnabledThenMasksPII(t *testing.T) {
	p := newPresetFixture(t)
	p.setPosture("system:production")
	viewer := presetPrincipals["system:production-viewer"]
	accessor := presetPrincipals["system:production-pii-accessor"]

	if got := p.wire(viewer, "select id from users", ""); got != pb.EnfAction_DENY {
		t.Errorf("production select is disabled by default: got %v, want DENY", got)
	}

	// Enabling production PII access means enabling its trusted-network producer (-300) too.
	p.enableProductionPackage()

	for _, c := range []struct {
		principal, sql, ip string
		want               pb.EnfAction
		what               string
	}{
		{viewer, "select id from users", "", pb.EnfAction_ALLOW, "non-PII cleartext"},
		{viewer, "select rrn from users", "", pb.EnfAction_MASK, "viewer masks PII"},
		{viewer, "select rrn from users", "100.100.1.10", pb.EnfAction_MASK,
			"viewer never gets PII cleartext, trusted-network or not"},
		{accessor, "select rrn from users", "100.99.1.10", pb.EnfAction_MASK,
			"pii-accessor masks off trusted-network"},
		// The SHIPPED -300 example trusts 100.100.0.0/16, so an in-range request earns the tag and -258 fires.
		{accessor, "select rrn from users", "100.100.1.10", pb.EnfAction_ALLOW,
			"pii-accessor reads cleartext on trusted-network"},
	} {
		if got := p.wire(c.principal, c.sql, c.ip); got != c.want {
			t.Errorf("%s: got %v, want %v", c.what, got, c.want)
		}
	}
}

// 6. 🔒 production PII unmasks via the workflow-executor channel OFF trusted-network and re-masks at
// the viewer
//
// -259 is what lets an approved run store the maximal result the elevated role is entitled to, from
// anywhere; the viewer channel deliberately does NOT match it, which is the re-mask that bounds a
// saved result at view time. The last assertion — with -259 back at its shipped DISABLED default the
// executor channel masks again — is the one that catches deleting the row or dropping its channel
// guard.
// KT: PresetPolicyDbTest.kt#production PII unmasks via the workflow-executor channel off trusted-network and re-masks at the viewer
func TestPresetProductionPIIUnmasksOnTheWorkflowExecutorChannel(t *testing.T) {
	p := newPresetFixture(t)
	p.setPosture("system:production")
	accessor := presetPrincipals["system:production-pii-accessor"]
	viewer := presetPrincipals["system:production-viewer"]
	const offNetwork = "100.99.1.10" // outside the shipped -300 range (100.100.0.0/16)

	// The whole production package INCLUDING -259, plus the -300 producer.
	p.enableProductionPackage()
	p.enable(true, -259)

	const sql = "select rrn from users"
	if got := p.decide(accessor, sql, offNetwork, query.ChannelWorkflowExecutor); got != pb.EnfAction_ALLOW {
		t.Errorf("-259: pii-accessor unmasks off-network on the workflow-executor channel: got %v, want ALLOW", got)
	}
	if got := p.decide(accessor, sql, offNetwork, query.ChannelWorkflowViewer); got != pb.EnfAction_MASK {
		t.Errorf("workflow-viewer re-masks off-network (-259 does not match the viewer channel): got %v, want MASK", got)
	}
	if got := p.decide(accessor, sql, offNetwork, query.ChannelWire); got != pb.EnfAction_MASK {
		t.Errorf("wire masks off-network (the executor-channel unmask never reaches the native wire): got %v, want MASK", got)
	}
	if got := p.decide(viewer, sql, offNetwork, query.ChannelWorkflowExecutor); got != pb.EnfAction_MASK {
		t.Errorf("-259 grants only system:production-pii-accessor; a viewer still masks: got %v, want MASK", got)
	}

	// Load-bearing: with -259 DISABLED (its shipped default), even the workflow-executor channel masks
	// off-network.
	p.enable(false, -259)
	if got := p.decide(accessor, sql, offNetwork, query.ChannelWorkflowExecutor); got != pb.EnfAction_MASK {
		t.Errorf("-259 disabled (shipped default) -> workflow-executor masks off-network: got %v, want MASK", got)
	}
}

// 7. 🔒 production system surfaces stay closed even for a pii-accessor on trusted-network
//
// activity and data-leak have NO production permit (the relaxation is dev-only) and critical is
// forbidden outright. Neither the trusted network nor the pii-accessor role opens any of them — while
// catalog structure stays browsable, because -100 is environment-agnostic.
// KT: PresetPolicyDbTest.kt#production system surfaces stay closed even for a pii-accessor on trusted-network
func TestPresetProductionSystemSurfacesStayClosed(t *testing.T) {
	p := newPresetFixture(t)
	p.setPosture("system:production")
	accessor := presetPrincipals["system:production-pii-accessor"]
	p.enableProductionPackage()

	for _, c := range []struct {
		sql  string
		want pb.EnfAction
		what string
	}{
		{"select count(*) from pg_catalog.pg_stat_activity", pb.EnfAction_DENY, "no production activity permit"},
		{"select count(*) from pg_catalog.pg_stats", pb.EnfAction_DENY, "no production data-leak permit"},
		{"select count(*) from pg_catalog.pg_authid", pb.EnfAction_DENY, "critical forbid"},
		{"select count(*) from pg_catalog.pg_class", pb.EnfAction_ALLOW, "catalog remains browsable"},
	} {
		if got := p.wire(accessor, c.sql, "100.100.1.10"); got != c.want {
			t.Errorf("%s: got %v, want %v", c.what, got, c.want)
		}
	}
}

// 8. default developer group connects, selects, writes and reads dev data cleartext
//
// The aggregate group is the only path here: `developer@example.com` holds NO direct role, so every
// assertion below fails if the shipped group_role rows for system:developer are lost or if role
// resolution stops following group membership.
// KT: PresetPolicyDbTest.kt#default developer group connects selects writes and reads dev data cleartext
func TestPresetDefaultDeveloperGroup(t *testing.T) {
	p := newPresetFixture(t)

	for _, action := range append([]authz.AuthzAction{authz.ActionDatasourceConnect}, presetSQLActions...) {
		if !p.actionAllowed(presetDeveloper, action) {
			t.Errorf("the system:developer group must grant %s", action)
		}
	}
	if got := p.wire(presetDeveloper, "select rrn from users", ""); got != pb.EnfAction_ALLOW {
		t.Errorf("developer reads dev PII cleartext: got %v, want ALLOW", got)
	}
}

// 9. 🔒 a forged preset-development tag is honored on a datasource but STRIPPED off a column
//
// THE TYPE-SCOPING INVARIANT that makes the role-agnostic -200 permit safe: a reserved preset tag is
// valid only on a Datasource. A column whose (forged or legacy) catalog row carries
// `system:development` must NOT unmask a PRODUCTION column. Both halves are needed — the strip is
// TYPE-scoped, not a blanket drop, so the same tag on the DATASOURCE still unmasks its columns.
//
// `nobody@example.com` holds no preset role at all, which is what isolates -200 as the only permit
// that could fire.
// KT: PresetPolicyDbTest.kt#a forged preset-development tag is honored on a datasource but stripped off a column
func TestPresetForgedDevelopmentTagIsStrippedOffAColumn(t *testing.T) {
	p := newPresetFixture(t)

	forged := []authz.ColumnRef{{
		Key: "k", Catalog: "pm", Schema: "public", Table: "users", Column: "rrn",
		Tags: []string{"system:development"},
	}}
	const nobody = "nobody@example.com"

	stripped := p.fx.Authz.AuthorizeColumns(nobody, nil, p.fx.DatasourceName, forged,
		authz.AuthzContext{}, nil, []string{"system:production"})
	if got := stripped["k"]; got != authz.ColumnDenied {
		t.Errorf("a forged system:development on a COLUMN must be stripped -> deny-by-default: got %v", got)
	}

	honored := p.fx.Authz.AuthorizeColumns(nobody, nil, p.fx.DatasourceName, forged,
		authz.AuthzContext{}, nil, []string{"system:development"})
	if got := honored["k"]; got != authz.ColumnUnmasked {
		t.Errorf("system:development on the DATASOURCE must unmask its columns (the -200 permit): got %v", got)
	}
}
