package query_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	probepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/authz"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/query"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// The pipeline end to end, over the REAL analyzer and the REAL Cedar policy set — plus direct pins
// for the three step ORDERINGS that no output-only assertion can catch.
//
// 06-query-decision.md §3 is explicit that decideQuery's step order is the security contract, not
// merely its outputs. INV-A6-7 and INV-A6-8 are both statements about what has NOT run yet by the
// time a decision returns, so they are asserted with SPY seams: a test that only looked at the
// verdict would pass just as happily with the steps reordered.

// spyRoles records whether step 6 ran, and answers with the fixture's real roles when it does.
type spyRoles struct {
	inner  query.RoleResolver
	called bool
}

func (s *spyRoles) Resolve(ctx context.Context, principal string) ([]string, error) {
	s.called = true
	return s.inner.Resolve(ctx, principal)
}

// spyGroups records whether step 5 ran, and can force the principal deactivated.
type spyGroups struct {
	inner      query.UserGroupStore
	called     bool
	forceDeact bool
}

func (s *spyGroups) IsDeactivated(ctx context.Context, principal string) (bool, error) {
	s.called = true
	if s.forceDeact {
		return true, nil
	}
	return s.inner.IsDeactivated(ctx, principal)
}

// 🔒 INV-A6-7 — role resolution is step 6, deliberately AFTER admission. An INADMISSIBLE statement
// hard-denies before ANY role resolution or grant walk happens at all. `authorizeColumns`' doc in A2
// calls this out as a SECURITY INVARIANT: moving resolution earlier would let an inadmissible
// statement trigger role/grant work and — worse — would change the ordering guarantee the
// deactivation gate depends on.
func TestInadmissibleDeniesBeforeAnyRoleResolution(t *testing.T) {
	g := newGrantLoopFixture(t)
	roles := &spyRoles{inner: g.fx.RoleResolver}
	groups := &spyGroups{inner: g.fx.UserGroups}
	g.fx.RoleResolver, g.fx.UserGroups = roles, groups

	ctx := g.fx.DecideWith(query.DecideQueryInput{
		Principal: grantLoopPrincipal,
		SQL:       "-- synthetic facts --",
		Channel:   query.ChannelEditor,
		FactsOverride: &probepb.StatementFacts{
			Resolved:     false,
			FailureClass: probepb.FailureClass_FAILURE_CLASS_INADMISSIBLE,
			Detail:       "multi-statement is not admissible",
		},
	})

	if ctx.Action != pb.EnfAction_DENY || !ctx.Structural {
		t.Fatalf("action = %v structural = %v, want DENY/true", ctx.Action, ctx.Structural)
	}
	if stage(ctx) != "admission" {
		t.Errorf("failedStage = %q, want %q", stage(ctx), "admission")
	}
	if reason(ctx) != "multi-statement is not admissible" {
		t.Errorf("denyReason = %q, want facts.detail verbatim", reason(ctx))
	}
	// 🔒 The ordering assertions. Both stores sit AFTER step 4.
	if roles.called {
		t.Error("INV-A6-7 VIOLATED: role resolution ran for an inadmissible statement")
	}
	if groups.called {
		t.Error("INV-A6-7/8 VIOLATED: the deactivation gate ran for an inadmissible statement")
	}
	// INV-A6-4's legitimate exception #1: a pre-derivation early deny carries NO contextTags, and no
	// roles, because neither had been computed.
	if len(ctx.ContextTags) != 0 || len(ctx.EffectiveRoles) != 0 {
		t.Errorf("contextTags = %v effectiveRoles = %v, want both empty on a pre-derivation deny",
			ctx.ContextTags, ctx.EffectiveRoles)
	}
	// An inadmissible statement with a BLANK detail falls back to the fixed prose (`ifBlank`).
	blank := g.fx.DecideWith(query.DecideQueryInput{
		Principal: grantLoopPrincipal, SQL: "x", Channel: query.ChannelEditor,
		FactsOverride: &probepb.StatementFacts{
			Resolved: false, FailureClass: probepb.FailureClass_FAILURE_CLASS_INADMISSIBLE, Detail: "  ",
		},
	})
	if reason(blank) != "statement is inadmissible" {
		t.Errorf("blank-detail denyReason = %q, want the fallback", reason(blank))
	}
}

// 🔒 INV-A6-8 — the deactivation gate DOMINATES passthrough. Step 5 sits BEFORE the metadata/session
// passthrough dispatch (step 14), so a deprovisioned principal cannot ride a `readonly-meta`
// passthrough to an ALLOW. DeactivationEnforcementDbTest case 3 pins exactly this in the Kotlin.
//
// The statement below is the one that WOULD passthrough-ALLOW for an active principal — the previous
// suite's case 20 proves it does — so a port that ran the dispatch first would return ALLOW here.
func TestDeactivationGateDominatesTheMetadataPassthrough(t *testing.T) {
	g := newGrantLoopFixture(t)
	metadata := &probepb.StatementFacts{
		Resolved:       true,
		StatementClass: probepb.StatementClass_STATEMENT_CLASS_METADATA,
	}

	active := g.fx.DecideWith(query.DecideQueryInput{
		Principal: grantLoopPrincipal, SQL: "-- meta --", Channel: query.ChannelEditor,
		FactsOverride: metadata,
	})
	if active.Action != pb.EnfAction_ALLOW || !active.Passthrough {
		t.Fatalf("baseline: action = %v passthrough = %v, want ALLOW/true (%s)",
			active.Action, active.Passthrough, reason(active))
	}

	g.fx.UserGroups = &spyGroups{inner: g.fx.UserGroups, forceDeact: true}
	deactivated := g.fx.DecideWith(query.DecideQueryInput{
		Principal: grantLoopPrincipal, SQL: "-- meta --", Channel: query.ChannelEditor,
		FactsOverride: metadata,
	})
	if deactivated.Action != pb.EnfAction_DENY {
		t.Fatalf("INV-A6-8 VIOLATED: a deprovisioned principal rode a readonly-meta passthrough to %v",
			deactivated.Action)
	}
	if !deactivated.Structural {
		t.Error("a deactivation deny is structural — no JIT grant can override deprovisioning")
	}
	if stage(deactivated) != "deprovisioned" {
		t.Errorf("failedStage = %q, want %q", stage(deactivated), "deprovisioned")
	}
	if reason(deactivated) != "principal is deprovisioned (deactivated) — access denied" {
		t.Errorf("denyReason = %q", reason(deactivated))
	}
	// INV-A6-4's legitimate exception #2.
	if len(deactivated.ContextTags) != 0 {
		t.Errorf("contextTags = %v, want empty on the pre-derivation deactivation deny", deactivated.ContextTags)
	}
}

// 🔒 INV-A6-16 — `channel` and `tags` are both AUTHORITATIVE OVERWRITES of any caller-supplied value.
// INV-A6-1 says the same thing from the channel's side: the channel is server-attested and never
// client-asserted.
func TestEffectiveAuthzContextOverwritesCallerChannelAndTags(t *testing.T) {
	g := newGrantLoopFixture(t)
	forgedChannel := "wire"
	forgedIP := "10.9.8.7"
	caller := authz.AuthzContext{
		Channel:      &forgedChannel,         // a client-asserted persistent-connection channel
		Tags:         []string{"forged-tag"}, // a client-asserted derived tag
		RequesterIP:  &forgedIP,              // CP-attested, and must be PRESERVED
		NetworkZones: []string{"corp"},       // ditto
	}

	// The channel half, observable through the gate it drives: a SESSION statement decided on the MCP
	// channel must DENY even though the caller claimed "wire".
	session := &probepb.StatementFacts{
		Resolved: true, StatementClass: probepb.StatementClass_STATEMENT_CLASS_SESSION,
	}
	ctx := g.fx.DecideWith(query.DecideQueryInput{
		Principal: grantLoopPrincipal, SQL: "SET x = 1", Channel: query.ChannelMCP,
		Context: caller, FactsOverride: session,
	})
	if ctx.Action != pb.EnfAction_DENY {
		t.Fatalf("INV-A6-1 VIOLATED: a client-asserted channel:\"wire\" let MCP relay a session statement (%v)",
			ctx.Action)
	}

	// The tags half. The fixture's policy set declares no context.tag:: action, so the derived
	// vocabulary is empty and the decision must run under NO tags — never the caller's.
	if len(ctx.ContextTags) != 0 {
		t.Errorf("contextTags = %v, want empty — pass-1 OVERWRITES the caller's tags", ctx.ContextTags)
	}

	// The raw, CP-attested inputs survive untouched. Asserted directly on the helper, since a
	// decision does not surface them.
	eff := query.EffectiveAuthzContext(caller, query.ChannelEditor, g.fx.Authz,
		grantLoopPrincipal, []string{dbtest.FixtureRole}, g.fx.DatasourceName, nil)
	if eff.Channel == nil || *eff.Channel != "editor" {
		t.Errorf("channel = %v, want the SERVER's \"editor\"", eff.Channel)
	}
	if eff.RequesterIP == nil || *eff.RequesterIP != forgedIP {
		t.Errorf("requesterIp = %v, want it preserved from the caller", eff.RequesterIP)
	}
	if !reflect.DeepEqual(eff.NetworkZones, []string{"corp"}) {
		t.Errorf("networkZones = %v, want them preserved from the caller", eff.NetworkZones)
	}
	if len(eff.Tags) != 0 {
		t.Errorf("tags = %v, want the DERIVED set (empty here), not the caller's", eff.Tags)
	}
}

// The whole pipeline over REAL SQL and the REAL analyzer, through internal/dbtest's enforcement
// harness — the Go form of EnforcementPostgresDbTest's first case, `masked query returns masked rrn
// never cleartext`.
//
// 🔒 It also proves the harness's audit row IS the production one: the record it builds is compared
// against a direct call to query.DecisionRecord. The Kotlin harness reuses production `decisionRecord`
// for exactly this reason, and a harness that re-derived the record would prove only that the fixture
// agrees with itself.
func TestPipelineMasksRRNEndToEndAndSharesTheProductionAuditRecord(t *testing.T) {
	g := newGrantLoopFixture(t)
	const sql = "SELECT id, rrn FROM users ORDER BY id"

	resp := g.fx.Run(grantLoopPrincipal, sql, 100)
	if pb.EnfAction(resp.Decision) != pb.EnfAction_MASK {
		t.Fatalf("decision = %v, want MASK (%v)", pb.EnfAction(resp.Decision), resp.DenyReason)
	}
	if !reflect.DeepEqual(resp.MaskedColumns, []string{"rrn"}) {
		t.Fatalf("maskedColumns = %v, want [rrn]", resp.MaskedColumns)
	}
	if len(resp.Rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(resp.Rows))
	}
	// 🔒 The security assertion: no cell anywhere carries a cleartext RRN.
	for _, row := range resp.Rows {
		for _, cell := range row {
			if cell == nil {
				continue
			}
			for _, clear := range dbtest.FixtureCleartextRRN {
				if strings.Contains(*cell, clear) {
					t.Fatalf("cleartext RRN %q reached the client in %q", clear, *cell)
				}
			}
		}
	}

	// The decision, and the audit row the harness builds from it.
	ctx := g.fx.Decide(grantLoopPrincipal, sql, query.ChannelEditor)
	if ctx.Action != pb.EnfAction_MASK {
		t.Fatalf("decide action = %v, want MASK (%s)", ctx.Action, reason(ctx))
	}
	// 🔒 INV-A6-5 — the analyzer's ordered output names ride on the decision, for A7's drift check.
	if !reflect.DeepEqual(ctx.OutputColumns, []string{"id", "rrn"}) {
		t.Errorf("outputColumns = %v, want [id rrn]", ctx.OutputColumns)
	}
	// Step 28's PII set is the REAL pii predicate (classification tags contain "pii").
	wantPII := []string{g.rrn.Catalog + "." + g.rrn.Schema + ".users.rrn"}
	if !reflect.DeepEqual(ctx.PIITouched, wantPII) {
		t.Errorf("piiTouched = %v, want %v", ctx.PIITouched, wantPII)
	}
	// Step 29 — the schema is referenced and is not a pg_temp one.
	if !reflect.DeepEqual(ctx.ReferencedSchemas, []string{g.rrn.Schema}) {
		t.Errorf("referencedSchemas = %v, want [%s]", ctx.ReferencedSchemas, g.rrn.Schema)
	}
	// Step 31 — PostgreSQL leaks on ALLOW, and `analyst` is not a datasource-wide unmasked reader, so
	// a MASK decision must sanitize.
	if !ctx.SanitizeDiagnostics {
		t.Error("sanitizeDiagnostics must be set for a PostgreSQL MASK by a non-unmasked reader")
	}

	addr := "/10.0.0.5:5432"
	viaHarness := g.fx.DecisionRecord(grantLoopPrincipal, sql, query.ParseRequesterIp(&addr), ctx, 7,
		[]string{g.rrn.Schema}, query.ChannelEditor)
	viaProduction := query.DecisionRecord(grantLoopPrincipal, g.fx.DatasourceRow, sql,
		query.ParseRequesterIp(&addr), ctx, 7, []string{g.rrn.Schema}, query.ChannelEditor)
	if !reflect.DeepEqual(viaHarness, viaProduction) {
		t.Fatalf("the harness audit row DIVERGED from production's:\n harness = %+v\n prod    = %+v",
			viaHarness, viaProduction)
	}
	if viaHarness.Decision != types.DecisionMask {
		t.Errorf("audit decision = %v, want MASK", viaHarness.Decision)
	}
	if !reflect.DeepEqual(viaHarness.MaskedColumns, []string{"rrn"}) {
		t.Errorf("audit maskedColumns = %v, want [rrn]", viaHarness.MaskedColumns)
	}
	if viaHarness.ClientAddr == nil || *viaHarness.ClientAddr != "10.0.0.5" {
		t.Errorf("audit clientAddr = %v, want the parsed bare IP", viaHarness.ClientAddr)
	}
}

// Step 12 runs BEFORE step 15: `sql.select` without `datasource.connect` is denied FIRST, and with
// the connect message — EnforcementPostgresDbTest's `sql.select without datasource.connect denied
// first`. The fixture seeds `reader@example.com` with sql.select + result.read.unmasked and
// deliberately NO datasource.connect precisely so this ordering is provable.
func TestConnectGateDeniesBeforeTheStatementKindGate(t *testing.T) {
	g := newGrantLoopFixture(t)
	ctx := g.fx.Decide(dbtest.FixtureNoConnectPrincipal, "SELECT id FROM users", query.ChannelEditor)
	if ctx.Action != pb.EnfAction_DENY {
		t.Fatalf("action = %v, want DENY", ctx.Action)
	}
	want := "no access to datasource '" + g.fx.DatasourceName + "'"
	if reason(ctx) != want {
		t.Fatalf("denyReason = %q, want %q — the CONNECT gate must fire first", reason(ctx), want)
	}
	if ctx.Structural {
		t.Error("a missing Cedar grant is a POLICY deny — a JIT grant could add the missing role")
	}
	if stage(ctx) != "policy" {
		t.Errorf("failedStage = %q, want %q", stage(ctx), "policy")
	}
}

// An ungranted table denies end to end, over real SQL — `ungranted table denied end-to-end`. The
// deny-by-default floor: `orders` has no Cedar grant at all, so nothing about it may be read.
func TestUngrantedTableDeniesEndToEnd(t *testing.T) {
	g := newGrantLoopFixture(t)
	resp := g.fx.Run(grantLoopPrincipal, "SELECT amount FROM orders", 100)
	if pb.EnfAction(resp.Decision) != pb.EnfAction_DENY {
		t.Fatalf("decision = %v, want DENY", pb.EnfAction(resp.Decision))
	}
	if len(resp.Rows) != 0 {
		t.Fatalf("a denied statement must return no rows, got %d", len(resp.Rows))
	}
}

// Step 1 — a live search path that is non-nil but EMPTY, against a non-empty catalog, is a catalog
// deny with catalogMiss set. `SchemaThreadingDbTest`'s "invalid/unresolvable live search paths fail
// closed" is the Kotlin case; this is its floor.
func TestEmptyLiveSearchPathFailsClosedBeforeAnythingIsAnalyzed(t *testing.T) {
	g := newGrantLoopFixture(t)
	empty := []string{}
	ctx := g.fx.DecideWith(query.DecideQueryInput{
		Principal:      grantLoopPrincipal,
		SQL:            "SELECT id FROM users",
		Channel:        query.ChannelWire,
		LiveSearchPath: &empty,
	})
	if ctx.Action != pb.EnfAction_DENY || !ctx.Structural {
		t.Fatalf("action = %v structural = %v, want DENY/true", ctx.Action, ctx.Structural)
	}
	if stage(ctx) != "catalog" {
		t.Errorf("failedStage = %q, want %q", stage(ctx), "catalog")
	}
	if !ctx.CatalogMiss {
		t.Error("catalogMiss must be set so the connection layer can refetch and retry")
	}
	if reason(ctx) != "fail-closed: invalid catalog or analyzer namespace configuration" {
		t.Errorf("denyReason = %q", reason(ctx))
	}
	// It returns BEFORE step 5, so no role and no tag were derived — the same pre-derivation shape as
	// the admission deny.
	if len(ctx.EffectiveRoles) != 0 || len(ctx.ContextTags) != 0 {
		t.Errorf("roles = %v tags = %v, want both empty", ctx.EffectiveRoles, ctx.ContextTags)
	}
}
