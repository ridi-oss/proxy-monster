package approval

// PORT of `ApprovalResultAssumeMysqlDbTest` — the MySQL-leading proof that a saved workflow result
// holds R's EXECUTION-enforced output while `task.assume` exposes R's LIVE view.
//
// 🔒 IT RUNS ON MYSQL AND OVER THE SHIPPED PRESET, and both halves of that are the point:
//
//   - MySQL is the correctness bar for shipping (AGENTS.md), and this is the only assume/view case the
//     Kotlin states there rather than on Postgres.
//   - the policies are the SHIPPED production preset (V8__seed.sql -250, -251, -256, -257, -258),
//     enabled exactly as an operator enables them, not a fixture's hand-written grants. That is what
//     makes it a statement about what proxy-monster ships: `system:production-pii-accessor` reads
//     production PII in cleartext ONLY from the trusted network, and the same role's stored result
//     re-masks the moment the viewer's context leaves it.
//
// ⚠️ -259 (`preset.production-pii-unmasked`, the workflow-executor channel arm) is deliberately NOT
// enabled, exactly as the Kotlin leaves it: with it on, an off-network EXECUTION would store cleartext
// and case 2's first assertion would be about the wrong policy.

import (
	"context"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/result"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

const (
	// productionPIIRole is a SHIPPED role (V8__seed.sql:35), not a fixture one.
	productionPIIRole = "system:production-pii-accessor"
	// assumeRequester holds NO ambient role: every grant it reads comes from the assumed R.
	assumeRequester = "assume-requester@example.com"
	assumeApprover  = "assume-approver@example.com"
	// onTrustedNetwork / offTrustedNetwork straddle the 100.100.0.0/16 example range.
	onTrustedNetwork  = "100.100.1.10"
	offTrustedNetwork = "100.99.1.10"
)

// assumeFixture is the Kotlin's @BeforeAll: a MySQL target, the datasource tagged
// `system:production`, the five preset policies enabled, and the trusted-network tag producer.
type assumeFixture struct {
	t       *testing.T
	fx      *dbtest.EnforcementFixture
	decider *Decider
	sql     string
}

func newAssumeFixture(t *testing.T) *assumeFixture {
	t.Helper()
	fx := dbtest.NewEnforcementFixture(t, dbtest.EngineMySQL)

	// The preset is keyed on the datasource's posture tag; without it every policy below is inert.
	fx.SetTags("system:production")

	// Enable the shipped preset — the operator action, not a policy rewrite. -259 stays OFF (see the
	// file header).
	tag, err := fx.Store.Pool.Exec(context.Background(),
		`UPDATE policy SET enabled = TRUE WHERE id = ANY($1::bigint[])`,
		[]int64{-250, -251, -256, -257, -258})
	if err != nil {
		t.Fatalf("enable the production preset: %v", err)
	}
	if tag.RowsAffected() != 5 {
		t.Fatalf("enabled %d preset policies, want 5 (-250,-251,-256,-257,-258 must all exist in V8__seed.sql)",
			tag.RowsAffected())
	}
	fx.PolicyStore.Bump()

	// The tag PRODUCER, verbatim from the Kotlin's `trusted-network-test`: an in-range requester_ip
	// earns `trusted-network`, which is what -258 consumes. Principal-agnostic — the tag is a property
	// of where the request came from.
	fx.AddCedarPolicy("trusted-network-test",
		`permit(principal, action == Action::"context.tag::trusted-network", resource) `+
			`when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };`)

	// PREMISE: the requester holds no ambient PII role, so nothing below can pass through their own
	// grants instead of through R.
	roles, err := fx.RoleResolver.Resolve(context.Background(), assumeRequester)
	if err != nil {
		t.Fatalf("resolve roles: %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("premise broken: the requester already holds %v", roles)
	}

	return &assumeFixture{
		t:   t,
		fx:  fx,
		sql: "SELECT rrn FROM users",
		decider: &Decider{
			Datasources: fx.DatasourceStore,
			MaskFns:     fx.MaskFns,
			UserGroups:  fx.UserGroups,
			Roles:       fx.RoleResolver,
			Authz:       fx.Authz,
		},
	}
}

// request is the Kotlin's private `request()`: an EXECUTED workflow task whose R is the production
// PII role, approved and executed by the approver.
func (a *assumeFixture) request() access.AccessRequest {
	name := a.fx.DatasourceName
	role := productionPIIRole
	id := a.fx.DatasourceID
	return access.AccessRequest{
		ID: 1, Principal: assumeRequester, RoleID: types.Ptr(int64(0)), RoleName: &role,
		DatasourceID: &id, DatasourceName: &name, RequestedDurationSec: 3600,
		Status: "EXECUTED", DecidedBy: types.Ptr(assumeApprover), ExecutedBy: types.Ptr(assumeApprover),
		CreatedAt: "2026-07-23T00:00:00Z", Kind: "QUERY", SQL: types.Ptr(a.sql),
		ExecuteAs: []string{productionPIIRole}, CreatorKind: types.Ptr("WORKFLOW"),
	}
}

// viewAs re-decides the stored cleartext result for the requester at the given address.
func (a *assumeFixture) viewAs(ip string, stored result.DecryptedResult) ResultViewDecision {
	a.t.Helper()
	req := a.request()
	got, err := a.decider.DecideResultView(context.Background(), ResultViewInput{
		Viewer: assumeRequester, Req: req, ChildSQL: req.SQL, DS: a.fx.DatasourceRow,
		Decrypted: stored, CallerContext: authz.AuthzContext{RequesterIP: &ip},
		Channel: query.ChannelWorkflowViewer,
	})
	if err != nil {
		a.t.Fatalf("DecideResultView at %s: %v", ip, err)
	}
	if got.IsDenied() {
		a.t.Fatalf("DecideResultView at %s was DENIED (%q); the shipped preset must allow the view",
			ip, *got.DeniedReason)
	}
	return got
}

// 🔒 THE REQUESTER ASSUMES R AND SEES THE SHIPPED PRODUCTION VIEW FOR THEIR LIVE NETWORK.
//
// Two claims, and the second is only meaningful because of the first: `task.assume` admits the
// requester at all (the shipped party policy), and the view they then get is decided under R IN THEIR
// OWN CONTEXT — cleartext from the trusted network, masked from outside it, off ONE stored row that is
// cleartext either way.
//
// KT: ApprovalResultAssumeMysqlDbTest.kt#requester assumes R and sees the shipped production view for their live network
func TestTheRequesterAssumesRAndSeesTheShippedProductionViewForTheirLiveNetwork(t *testing.T) {
	a := newAssumeFixture(t)
	req := a.request()

	decision := a.fx.Authz.Authorize(assumeRequester, authz.ActionTaskAssume, authz.ResourceApprovalRequest{
		Requester: assumeRequester, Approver: req.DecidedBy, ExecutedBy: req.ExecutedBy,
		DatasourceName: req.DatasourceName, RoleName: req.RoleName,
	}, authz.AuthzContext{})
	if !decision.Allowed {
		t.Fatalf("task.assume for the requester: got DENY (%v), want the shipped party permit", decision.Reason)
	}

	stored := result.DecryptedResult{
		Columns: []string{"rrn"},
		Rows:    [][]*string{{types.Ptr(dbtest.FixtureCleartextRRN[0])}},
	}

	trusted := a.viewAs(onTrustedNetwork, stored)
	if got := cell(t, QueryResultView{Rows: trusted.Rows}, 0, 0); got != dbtest.FixtureCleartextRRN[0] {
		t.Errorf("on the trusted network: got %q, want the cleartext %q", got, dbtest.FixtureCleartextRRN[0])
	}

	outside := a.viewAs(offTrustedNetwork, stored)
	if got := cell(t, QueryResultView{Rows: outside.Rows}, 0, 0); got != maskedRRN {
		t.Errorf("off the trusted network: got %q, want the masked %q", got, maskedRRN)
	}
}

// 🔒 THE EXECUTOR STORES R's EXECUTION-CONTEXT MASK PLAN — NEVER WIDENED — AND THE VIEWER RE-DECIDES
// PER CONTEXT.
//
// Four decisions over the two channels and the two networks. The first is the one that matters most:
// off the trusted network R CANNOT unmask, so what execution stores is the MASKED form. Storage is
// never widened to what some other context would reveal, which is what makes the view's re-decision a
// narrowing (INV-A7-3) rather than a gate on a cleartext snapshot.
//
// KT: ApprovalResultAssumeMysqlDbTest.kt#workflow executor stores R's execution-enforced masks and the viewer re-decides per context
func TestTheWorkflowExecutorStoresRsExecutionEnforcedMasksAndTheViewerReDecidesPerContext(t *testing.T) {
	a := newAssumeFixture(t)

	decide := func(channel query.Channel, ip string) query.DecisionContext {
		t.Helper()
		return a.fx.DecideWith(query.DecideQueryInput{
			Principal: assumeRequester, SQL: a.sql, Channel: channel,
			ProvidedRoles: types.Ptr([]string{productionPIIRole}),
			Context:       authz.AuthzContext{RequesterIP: &ip},
		})
	}
	maskedColumns := func(d query.DecisionContext) []string {
		out := make([]string, 0, len(d.Masks))
		for _, m := range d.Masks {
			out = append(out, m.GetColumn())
		}
		return out
	}

	storedOffNetwork := decide(query.ChannelWorkflowExecutor, offTrustedNetwork)
	if storedOffNetwork.Action != pb.EnfAction_MASK {
		t.Errorf("off-network execution: got %v, want MASK (R cannot unmask production pii off the "+
			"trusted network, so that is what is stored)", storedOffNetwork.Action)
	}
	if cols := maskedColumns(storedOffNetwork); len(cols) != 1 || cols[0] != "rrn" {
		t.Errorf("off-network execution masks %v, want [rrn] — storage holds R's execution-context mask "+
			"plan, never widened", cols)
	}

	if got := decide(query.ChannelWorkflowExecutor, onTrustedNetwork); got.Action != pb.EnfAction_ALLOW {
		t.Errorf("on-network execution: got %v, want ALLOW (R stores rrn cleartext)", got.Action)
	}

	viewedOffNetwork := decide(query.ChannelWorkflowViewer, offTrustedNetwork)
	if viewedOffNetwork.Action != pb.EnfAction_MASK {
		t.Errorf("off-network view: got %v, want MASK", viewedOffNetwork.Action)
	}
	if cols := maskedColumns(viewedOffNetwork); len(cols) != 1 || cols[0] != "rrn" {
		t.Errorf("off-network view masks %v, want [rrn]", cols)
	}
	if got := decide(query.ChannelWorkflowViewer, onTrustedNetwork); got.Action != pb.EnfAction_ALLOW {
		t.Errorf("on-network view: got %v, want ALLOW", got.Action)
	}
}
