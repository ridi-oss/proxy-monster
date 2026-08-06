package query_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/audit"
	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/policy"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// PORT of ChannelDecideAuditDbTest.kt — 210 LOC, 7 cases.
//
// WHAT THE SUITE IS FOR, from the Kotlin's kdoc: prove the request-context overlay is actually WIRED
// THROUGH decideQuery — "not just correct in isolation" — against a real store and a real Cedar
// engine. "This is the boundary the mechanism tests (ChannelContextAuthzTest / TagResolutionTest)
// don't reach: here a channel-gated grant's verdict FLIPS with the server channel, so if the overlay
// were removed the test fails." Plus: the audit row records the channel and the derived context tags,
// through the real run path.
//
// The temp-overlay cases (5, 6, 7) go through REAL SQL and the REAL analyzer, which is the half
// unmasked_temp_linchpin_db_test.go deliberately does not have — it drives the same step-24 branches
// through the FactsOverride seam for determinism, and says so. Case 6 therefore carries the marker in
// BOTH files: the linchpin file pins the coupling branch-by-branch, this one pins that a real CTAS and
// a real INSERT-select actually reach it.
//
// One shape difference, forced and documented: internal/dbtest's harness does NOT write the audit row
// (enforcement_run.go says so — dbtest cannot import internal/audit), where Kotlin's
// `fx.run` does and returns `decisionId`. So cases 1 and 3 build the record with the PRODUCTION
// [query.DecisionRecord] through the fixture, insert it with the production audit store and read it
// back — which is exactly what the Kotlin harness does internally, minus the convenience.
// ---------------------------------------------------------------------------------------------

type channelAuditFixture struct {
	t     *testing.T
	ctx   context.Context
	fx    *dbtest.EnforcementFixture
	audit *audit.Store
	// classifier is the shipped manifest set, which the Kotlin's decide() passes on every call.
	classifier query.SystemClassifier
}

func newChannelAuditFixture(t *testing.T) *channelAuditFixture {
	t.Helper()
	fx := newEnforcementFixture(t, dbtest.EnginePostgres)
	return &channelAuditFixture{
		t: t, ctx: context.Background(), fx: fx,
		audit:      audit.New(fx.Store.Pool),
		classifier: shippedClassifier(t),
	}
}

// decide is the Kotlin's `decide(sql, channel, clientContext)`.
func (f *channelAuditFixture) decide(
	principal, sql string, channel query.Channel, client authz.AuthzContext,
) query.DecisionContext {
	f.t.Helper()
	return f.fx.DecideWith(query.DecideQueryInput{
		Principal: principal, SQL: sql, Channel: channel,
		Context:              client,
		SystemClassification: f.classifier,
	})
}

// decideTemps is `decide(...)` with the per-connection overlay the proxy supplies: the live search path
// plus the connection's temp columns.
func (f *channelAuditFixture) decideTemps(
	principal, sql string, searchPath []string, temps []datasource.CatalogColumn,
) query.DecisionContext {
	f.t.Helper()
	return f.fx.DecideWith(query.DecideQueryInput{
		Principal: principal, SQL: sql, Channel: query.ChannelEditor,
		LiveSearchPath:       &searchPath,
		TempColumns:          temps,
		SystemClassification: f.classifier,
	})
}

// auditDecision inserts the PRODUCTION audit record for a decision and reads it back — the Kotlin's
// `fx.run(...)` + `fx.auditStore.get(r.decisionId!!)` pair, whose insert half internal/dbtest cannot
// perform. The record itself is production's, so what is asserted below is what production writes.
func (f *channelAuditFixture) auditDecision(
	principal, sql string, ctx query.DecisionContext, channel query.Channel,
) types.AuditEvent {
	f.t.Helper()
	rec := f.fx.DecisionRecord(principal, sql, nil, ctx, 7, nil, channel)
	id, err := f.audit.Insert(f.ctx, rec)
	if err != nil {
		f.t.Fatalf("insert the decision's audit row: %v", err)
	}
	got, err := f.audit.Get(f.ctx, id)
	if err != nil || got == nil {
		f.t.Fatalf("read audit row %d back: got=%v err=%v", id, got, err)
	}
	return *got
}

// addCedarPolicy creates a USER policy through the PRODUCTION store (validate-on-write, origin guards)
// and invalidates the fixture engine's cached policy set.
func (f *channelAuditFixture) addCedarPolicy(name, src string) {
	f.t.Helper()
	store := policy.NewCedarPolicyStore(f.fx.Store.Pool)
	if _, err := store.Create(f.ctx, policy.NewCedarPolicyInput(name, src), types.Ptr("test")); err != nil {
		f.t.Fatalf("create policy %s: %v", name, err)
	}
	f.fx.PolicyStore.Bump()
}

// tempScratch is the session temp the proxy overlays: schema pg_temp_9, table `scratch`.
func (f *channelAuditFixture) tempScratch(column string) datasource.CatalogColumn {
	return datasource.CatalogColumn{
		Catalog: f.fx.Catalog, Schema: channelTempSchema, Table: "scratch", Column: column,
		DataType: "text", SQLType: "text", Ordinal: 1, Nullable: true, IsTemp: true,
	}
}

const channelTempSchema = "pg_temp_9"

func denyReasonOf(ctx query.DecisionContext) string {
	if ctx.DenyReason == nil {
		return "<nil>"
	}
	return *ctx.DenyReason
}

// 1. the audit record carries the channel through the real run path
//
// `fx.Run` decides on ChannelEditor (enforcement_run.go:102, the Kotlin's runEnforcedQuery default), so
// the record for that decision must carry channel="editor". An audit trail that lost the channel could
// not answer "was this read on the wire or inside an approved run", which is the question the
// workflow-executor/viewer split exists to make answerable.
// KT: ChannelDecideAuditDbTest.kt#the audit record carries the channel through the real run path
func TestChannelAuditRecordCarriesTheChannelThroughTheRealRunPath(t *testing.T) {
	f := newChannelAuditFixture(t)
	const sql = "select id, rrn from users order by id"

	// The real run path, asserted to actually run (the Kotlin's `fx.run` half).
	resp := run(t, f.fx, sql)
	if pb.EnfAction(resp.Decision) != pb.EnfAction_MASK {
		t.Fatalf("the run path decided %v, want MASK on a pii column", pb.EnfAction(resp.Decision))
	}

	ctx := f.fx.Decide(dbtest.FixturePrincipal, sql, query.ChannelEditor)
	rec := f.auditDecision(dbtest.FixturePrincipal, sql, ctx, query.ChannelEditor)
	if rec.Channel == nil || *rec.Channel != "editor" {
		t.Errorf("channel = %v, want \"editor\" — a run decision must audit its channel", rec.Channel)
	}
}

// 2. the editor channel passthrough-allows a session statement, workflow phases still deny
//
// The stateful editor holds its connection, so SET/BEGIN persist on it and the proxy re-probes the live
// path per query — safe to relay. A one-shot workflow phase has no such connection, so the same
// statement must DENY. Both halves are needed: the ALLOW alone would pass on an implementation that
// relayed session statements on EVERY channel.
// KT: ChannelDecideAuditDbTest.kt#the editor channel passthrough-allows a session statement, workflow phases still deny
func TestChannelEditorPassthroughAllowsASessionStatement(t *testing.T) {
	f := newChannelAuditFixture(t)
	p := dbtest.FixturePrincipal

	editor := f.decide(p, "SET search_path = public", query.ChannelEditor, authz.AuthzContext{})
	if editor.Action != pb.EnfAction_ALLOW {
		t.Errorf("editor session may passthrough SET: got %v (%s)", editor.Action, denyReasonOf(editor))
	}
	if !editor.Passthrough {
		t.Error("SET is a session-mutating passthrough on the editor channel")
	}

	begin := f.decide(p, "BEGIN", query.ChannelEditor, authz.AuthzContext{})
	if begin.Action != pb.EnfAction_ALLOW {
		t.Errorf("editor session may passthrough BEGIN: got %v (%s)", begin.Action, denyReasonOf(begin))
	}

	wfexec := f.decide(p, "SET search_path = public", query.ChannelWorkflowExecutor, authz.AuthzContext{})
	if wfexec.Action != pb.EnfAction_DENY {
		t.Errorf("a workflow-executor one-shot may not run a session statement: got %v", wfexec.Action)
	}
}

// 3. 🔒 a DENY decision's audit row carries the derived context tag
//
// AUDIT FIDELITY ON THE DENY PATH. A derived context tag must be recorded on EVERY decision, not only
// the ALLOW/MASK column path — and the deny-by-default column gate is the exit most likely to drop
// them, because it returns through the policy-deny helper rather than the main path. A helper that
// stopped carrying ContextTags would thin every DENY row in the trail and nothing else would notice.
// KT: ChannelDecideAuditDbTest.kt#a DENY decision's audit row carries the derived context tag
func TestChannelDenyAuditRowCarriesTheDerivedContextTag(t *testing.T) {
	f := newChannelAuditFixture(t)
	f.addCedarPolicy("derive-editor-origin-tag",
		`permit(principal, action == Action::"context.tag::editor-origin", resource) when { context has channel && context.channel == "editor" };`)

	// `orders` carries no Cedar grant, so the column decision DENYs through the policy-deny path.
	const sql = "select amount from orders"
	ctx := f.fx.Decide(dbtest.FixturePrincipal, sql, query.ChannelEditor)
	if ctx.Action != pb.EnfAction_DENY {
		t.Fatalf("an ungranted table must DENY at the column gate: got %v (%s)", ctx.Action, denyReasonOf(ctx))
	}

	rec := f.auditDecision(dbtest.FixturePrincipal, sql, ctx, query.ChannelEditor)
	if rec.Decision != types.DecisionDeny {
		t.Errorf("decision = %v, want DENY", rec.Decision)
	}
	if !slices.Contains(rec.ContextTags, "editor-origin") {
		t.Errorf("a DENY audit row must carry the derived context.tag it was evaluated under, got %v",
			rec.ContextTags)
	}
}

// 4. 🔒 a channel-gated grant follows the SERVER channel and ignores a client-injected one
//
// THE WIRING CASE. The fixture grants analyst select/insert but NOT delete; a delete grant that fires
// only on the editor channel makes the sql.<kind> gate's verdict depend on the channel decideQuery
// overlays. WIRE denies, EDITOR clears — so deleting the overlay makes the second half fail. The third
// half is INV-A6-16: a client asserting channel="wire" (plus tags) on an EDITOR request changes
// nothing, because the server's enum is authoritative.
// KT: ChannelDecideAuditDbTest.kt#a channel-gated grant follows the server channel and ignores a client-injected channel
func TestChannelGatedGrantFollowsTheServerChannel(t *testing.T) {
	f := newChannelAuditFixture(t)
	f.addCedarPolicy("analyst-delete-editor-only",
		`permit(principal in Role::"analyst", action == Action::"sql.delete", resource in Datasource::"`+
			f.fx.DatasourceName+`") when { context has channel && context.channel == "editor" };`)

	const sql = "delete from users where id = 999999"
	p := dbtest.FixturePrincipal

	wire := f.decide(p, sql, query.ChannelWire, authz.AuthzContext{})
	if wire.Action != pb.EnfAction_DENY {
		t.Errorf("wire delete must deny at the kind gate: got %v", wire.Action)
	}
	if !strings.Contains(denyReasonOf(wire), "sql.delete") {
		t.Errorf("wire deny reason must name the gate: %s", denyReasonOf(wire))
	}

	editor := f.decide(p, sql, query.ChannelEditor, authz.AuthzContext{})
	if strings.Contains(denyReasonOf(editor), "sql.delete") {
		t.Errorf("the editor channel must clear the sql.delete gate, got: %s", denyReasonOf(editor))
	}

	injected := f.decide(p, sql, query.ChannelEditor, authz.AuthzContext{
		Channel: types.Ptr("wire"),
		Tags:    []string{"injected"},
	})
	if strings.Contains(denyReasonOf(injected), "sql.delete") {
		t.Errorf("a client-injected channel must be ignored, got: %s", denyReasonOf(injected))
	}
}

// 5. a session temp resolves and reads unmasked via the overlay, unresolvable without it
//
// The proxy sends the connection's temp columns and the control plane overlays them, so a bare name
// resolves to the TEMP the backend will bind. A temp is unclassified and owned by the caller, so it
// reads UNMASKED — and the second half is what makes that a statement about the overlay rather than
// about a grant: with no overlay the same name is unresolvable and the decision fails CLOSED.
// KT: ChannelDecideAuditDbTest.kt#a session temp resolves and reads unmasked via the overlay, unresolvable without it
func TestChannelSessionTempResolvesAndReadsUnmasked(t *testing.T) {
	f := newChannelAuditFixture(t)
	const sql = "select secret from scratch"
	searchPath := []string{channelTempSchema, "public"}

	withTemp := f.decideTemps(dbtest.FixturePrincipal, sql, searchPath,
		[]datasource.CatalogColumn{f.tempScratch("secret")})
	if withTemp.Action != pb.EnfAction_ALLOW {
		t.Errorf("a session temp reads unmasked (the caller owns it): got %v (%s)",
			withTemp.Action, denyReasonOf(withTemp))
	}

	without := f.decideTemps(dbtest.FixturePrincipal, sql, searchPath, nil)
	if without.Action != pb.EnfAction_DENY {
		t.Errorf("without the overlay the temp is unresolvable -> fail-closed: got %v", without.Action)
	}
	// UNRESOLVABLE, specifically — not merely ungranted. Measured: `fail-closed: could not analyze
	// (validate)`. Checking it keeps the control honest about WHY the second half denies.
	if !strings.Contains(denyReasonOf(without), "could not analyze") {
		t.Errorf("the no-overlay deny must be the unresolvable/analyze failure, got: %s", denyReasonOf(without))
	}
}

// 6. 🔒 a write cannot launder a masked column into a session temp (THE UNMASKED-TEMP LINCHPIN)
//
// A session temp reads UNMASKED only because a write cannot copy masked or denied data into one. A
// CTAS and an INSERT-select reading users.rrn (masked) must both DENY on the editor channel, even with
// the temp overlay ACTIVE and even when the INSERT's sink is a temp the caller already holds — the
// strongest form. If this regressed, "temps read unmasked" would become an exfiltration primitive:
// write masked, read plain.
//
// unmasked_temp_linchpin_db_test.go pins the same coupling branch-by-branch through the FactsOverride
// seam; this half pins that REAL SQL through the REAL analyzer actually reaches those branches. Both
// carry the marker.
// KT: ChannelDecideAuditDbTest.kt#a write cannot launder a masked column into a session temp (the unmasked-temp linchpin)
func TestChannelAWriteCannotLaunderAMaskedColumnIntoASessionTemp(t *testing.T) {
	f := newChannelAuditFixture(t)
	searchPath := []string{channelTempSchema, "public"}
	// The INSERT sink: a session temp the caller already holds, in the overlay.
	sink := []datasource.CatalogColumn{f.tempScratch("rrn")}

	// FixtureDDLPrincipal holds sql.ddl (the CTAS), FixtureInsertPrincipal holds sql.insert; both read
	// users.rrn as MASKED.
	ctas := f.decideTemps(dbtest.FixtureDDLPrincipal,
		"create temporary table t2 as select rrn from users", searchPath, sink)
	if ctas.Action != pb.EnfAction_DENY {
		t.Errorf("CTAS from a masked column must DENY: got %v (%s)", ctas.Action, denyReasonOf(ctas))
	}
	// The Kotlin asserts only the verdict. The reason is checked here so the case cannot pass
	// vacuously on some unrelated deny (a missing sql.ddl grant would also be a DENY, and would prove
	// nothing about the linchpin).
	if !strings.Contains(denyReasonOf(ctas), "a write cannot be masked") {
		t.Errorf("CTAS must deny via the write-payload rule, got: %s", denyReasonOf(ctas))
	}

	insert := f.decideTemps(dbtest.FixtureInsertPrincipal,
		"insert into scratch select rrn from users", searchPath, sink)
	if insert.Action != pb.EnfAction_DENY {
		t.Errorf("INSERT-select from a masked column into a temp must DENY: got %v (%s)",
			insert.Action, denyReasonOf(insert))
	}
	if !strings.Contains(denyReasonOf(insert), "a write cannot be masked") {
		t.Errorf("the INSERT must deny via the write-payload rule, got: %s", denyReasonOf(insert))
	}
}

// 7. a bare count over a session temp is allowed (the uncovered-scan gate skips temps)
//
// A temp scan that traces no column (count(*)) would otherwise hit the uncovered-scan fail-closed gate
// like any unknown table; the temp exclusion lets the owner scan their own temp. The second half is
// again the non-vacuity control: with no overlay the same scan is unresolvable and DENIES, so the
// exclusion is what ALLOWs it — not a hole in the gate.
// KT: ChannelDecideAuditDbTest.kt#a bare count over a session temp is allowed (uncovered-scan gate skips temps)
func TestChannelABareCountOverASessionTempIsAllowed(t *testing.T) {
	f := newChannelAuditFixture(t)
	const sql = "select count(*) from scratch"
	searchPath := []string{channelTempSchema, "public"}

	withTemp := f.decideTemps(dbtest.FixturePrincipal, sql, searchPath,
		[]datasource.CatalogColumn{f.tempScratch("secret")})
	if withTemp.Action != pb.EnfAction_ALLOW {
		t.Errorf("count(*) over an owned session temp is allowed: got %v (%s)",
			withTemp.Action, denyReasonOf(withTemp))
	}

	without := f.decideTemps(dbtest.FixturePrincipal, sql, searchPath, nil)
	if without.Action != pb.EnfAction_DENY {
		t.Errorf("without the overlay the temp scan is unresolvable -> DENY: got %v", without.Action)
	}
	if !strings.Contains(denyReasonOf(without), "could not analyze") {
		t.Errorf("the no-overlay deny must be the unresolvable/analyze failure, got: %s", denyReasonOf(without))
	}
}
