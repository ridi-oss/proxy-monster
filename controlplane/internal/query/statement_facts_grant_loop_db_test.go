package query_test

import (
	"context"
	"strings"
	"testing"

	probepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/access"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/datasource"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/identity"
	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/policy"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/query"
)

// StatementFactsGrantLoopTest.kt — 367 LOC, 21 cases, unit-in-Kotlin / DB here
// (06-query-decision.md §7).
//
// Drives the PRODUCTION [query.DecideQuery] grant walk over SYNTHETIC StatementFacts (the
// `factsOverride` test seam) against a real Cedar/catalog fixture. **This is the only way to exercise
// the fail-closed contract branches a resolved Go analyzer can never emit** — UNSPECIFIED
// action/disposition/class, an out-of-range ordinal, a resourceless grant — plus the disposition
// triad, resource-kind dispatch, multi-ordinal first-wins, and metadata preservation, each against
// the fixture's LIVE authorization.
//
// Fixture (dbtest.NewEnforcementFixture / EnginePostgres): `analyst@example.com` may read `users`
// unmasked EXCEPT the pii `rrn` column (masked with `last4`); the `orders` table has no grant at all
// (deny-by-default).
//
// ⚠️ The Kotlin suite is `unit` only in the sense that it has no target-side execution; it stands up
// EnforcementFixture.postgres(), which is Testcontainers-backed. So is this. Every Kotlin case name is
// carried VERBATIM as a comment above its Go test so the two map 1:1.
//
// ⚠️ This file is `package query_test` (external). internal/dbtest imports internal/query — so the
// fixture calls the production decide/audit functions rather than reimplementing them — which makes
// `package query` illegal for any file that touches the fixture. See internal/query/doc.go.

const grantLoopPrincipal = dbtest.FixturePrincipal // "analyst@example.com"

// grantLoopFixture is the Kotlin's @BeforeAll: one fixture per suite, plus the three catalog rows the
// cases name.
type grantLoopFixture struct {
	fx      *dbtest.EnforcementFixture
	catalog []datasource.CatalogColumn
	rrn     datasource.CatalogColumn
	region  datasource.CatalogColumn
	amount  datasource.CatalogColumn
}

func newGrantLoopFixture(t *testing.T) *grantLoopFixture {
	t.Helper()
	fx := dbtest.NewEnforcementFixture(t, dbtest.EnginePostgres)

	// 🔒 Wire the PRODUCTION stores over the fixture's seams, rather than leaning on the fixture's
	// direct-SQL defaults. This is the promise internal/query/doc.go makes about the seams: the
	// identity types satisfy them with NO adapter, and policy needs only a three-line one because Go
	// cannot convert []policy.MaskFn to []query.MaskFn implicitly. The wiring itself lives in
	// enforcement_db_test.go (wireProductionSeams) so every A6 suite decides against the same stack.
	wireProductionSeams(fx)

	catalog := fx.CatalogRows()
	return &grantLoopFixture{
		fx:      fx,
		catalog: catalog,
		rrn:     col(t, catalog, "users", "rrn"),
		region:  col(t, catalog, "users", "region"),
		amount:  col(t, catalog, "orders", "amount"),
	}
}

// maskFnsOf is the three-line adapter over the PRODUCTION *policy.PolicyStore that internal/query's
// doc.go names. Nothing is reimplemented — ListMaskFns is the store's own read; only the element type
// is re-shaped, which is the whole cost of keeping internal/query free of an internal/policy import.
func maskFnsOf(ps *policy.PolicyStore) query.MaskFnLister {
	return func(ctx context.Context) ([]query.MaskFn, error) {
		fns, err := ps.ListMaskFns(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]query.MaskFn, 0, len(fns))
		for _, f := range fns {
			out = append(out, query.MaskFn{Name: f.Name, Kind: f.Kind})
		}
		return out, nil
	}
}

// grantRolesOf is `AccessStore.listGrants(principal, activeOnly).map { it.roleName }` — the adapter
// internal/identity's `AccessGrants` seam documents as "TODO(A6): … a one-line adapter that keeps the
// `.map { roleName }` on A6's side".
//
// ⚠️ It is deliberately kept HERE, in a test file, rather than added to internal/query's production
// surface: F12's disposition is that decideQuery does not depend on AccessStore at all, and giving
// the package an internal/access import for one adapter would contradict that on sight. Whether the
// production home is a `ListGrantRoles` method on access.Store or an adapter elsewhere is a design
// decision for whoever wires ControlPlaneCore, not something the enforcement port should settle.
func grantRolesOf(s *access.Store) identity.AccessGrants {
	return grantRolesFunc(func(ctx context.Context, principal string, activeOnly bool) ([]string, error) {
		grants, err := s.ListGrants(ctx, &principal, activeOnly)
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(grants))
		for _, g := range grants {
			out = append(out, g.RoleName)
		}
		return out, nil
	})
}

type grantRolesFunc func(ctx context.Context, principal string, activeOnly bool) ([]string, error)

func (f grantRolesFunc) ListGrantRoles(ctx context.Context, principal string, activeOnly bool) ([]string, error) {
	return f(ctx, principal, activeOnly)
}

// col is the Kotlin's `fixtureCatalog.first { it.table == table && it.column == name }`.
func col(t *testing.T, catalog []datasource.CatalogColumn, table, name string) datasource.CatalogColumn {
	t.Helper()
	for _, c := range catalog {
		if c.Table == table && c.Column == name {
			return c
		}
	}
	t.Fatalf("fixture catalog has no %s.%s", table, name)
	return datasource.CatalogColumn{}
}

// decide is the Kotlin's private `decide(facts, channel = Channel.EDITOR)`.
func (g *grantLoopFixture) decide(facts *probepb.StatementFacts) query.DecisionContext {
	return g.decideOn(facts, query.ChannelEditor)
}

func (g *grantLoopFixture) decideOn(facts *probepb.StatementFacts, channel query.Channel) query.DecisionContext {
	return g.fx.DecideWith(query.DecideQueryInput{
		Principal:     grantLoopPrincipal,
		SQL:           "-- synthetic facts --",
		Channel:       channel,
		FactsOverride: facts,
	})
}

// columnGrant is the Kotlin's private helper of the same name. Its default action is RESULT_READ and
// its default ordinals are empty, matching the Kotlin defaults.
func columnGrant(
	c datasource.CatalogColumn,
	disposition probepb.MaskedDisposition,
	ordinals []int32,
	action probepb.GrantAction,
) *probepb.RequiredGrant {
	return &probepb.RequiredGrant{
		Action: action,
		Resource: &probepb.RequiredGrant_Column{Column: &probepb.ColumnResource{
			Catalog:  c.Catalog,
			Identity: &probepb.RelationIdentity{Schema: c.Schema, Table: c.Table, Column: c.Column},
		}},
		MaskedDisposition: disposition,
		OutputOrdinals:    ordinals,
	}
}

func resultReadColumnGrant(c datasource.CatalogColumn, d probepb.MaskedDisposition, ordinals ...int32) *probepb.RequiredGrant {
	return columnGrant(c, d, ordinals, probepb.GrantAction_GRANT_ACTION_RESULT_READ)
}

// analyzed is the Kotlin's private `analyzed(vararg grants, isWrite, outputCols, rewrite)`.
type analyzedOpts struct {
	isWrite    bool
	outputCols []string
	rewrite    *string
}

func analyzed(opts analyzedOpts, grants ...*probepb.RequiredGrant) *probepb.StatementFacts {
	f := &probepb.StatementFacts{
		Resolved:       true,
		StatementClass: probepb.StatementClass_STATEMENT_CLASS_ANALYZED,
		Detail:         "synthetic",
		IsWrite:        opts.isWrite,
		RequiredGrants: grants,
		OutputColumns:  opts.outputCols,
	}
	if opts.rewrite != nil {
		f.RewrittenSql = opts.rewrite
	}
	return f
}

// datasourceGrant is the Kotlin's private helper of the same name.
func datasourceGrant(action probepb.GrantAction) *probepb.RequiredGrant {
	return &probepb.RequiredGrant{
		Action:            action,
		Resource:          &probepb.RequiredGrant_Datasource{Datasource: true},
		MaskedDisposition: probepb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT,
	}
}

func reason(d query.DecisionContext) string {
	if d.DenyReason == nil {
		return "<nil>"
	}
	return *d.DenyReason
}

func stage(d query.DecisionContext) string {
	if d.FailedStage == nil {
		return "<nil>"
	}
	return *d.FailedStage
}

// ---- happy paths / disposition triad --------------------------------------------------------

// 1. `all-granted analyzed statement allows`
func TestStatementFactsGrantLoop(t *testing.T) {
	g := newGrantLoopFixture(t)

	t.Run("all-granted analyzed statement allows", func(t *testing.T) {
		ctx := g.decide(analyzed(
			analyzedOpts{outputCols: []string{"region"}},
			datasourceGrant(probepb.GrantAction_GRANT_ACTION_SQL_SELECT),
			resultReadColumnGrant(g.region, probepb.MaskedDisposition_MASKED_DISPOSITION_MASK_OUTPUT, 0),
		))
		if ctx.Action != pb.EnfAction_ALLOW {
			t.Fatalf("action = %v, want ALLOW (%s)", ctx.Action, reason(ctx))
		}
		if len(ctx.Masks) != 0 {
			t.Fatalf("masks = %d, want none — `region` authorizes UNMASKED", len(ctx.Masks))
		}
	})

	// 2. `masked verdict with MASK_OUTPUT applies the configured mask`
	t.Run("masked verdict with MASK_OUTPUT applies the configured mask", func(t *testing.T) {
		ctx := g.decide(analyzed(
			analyzedOpts{outputCols: []string{"rrn"}},
			resultReadColumnGrant(g.rrn, probepb.MaskedDisposition_MASKED_DISPOSITION_MASK_OUTPUT, 0),
		))
		if ctx.Action != pb.EnfAction_MASK {
			t.Fatalf("action = %v, want MASK (%s)", ctx.Action, reason(ctx))
		}
		if len(ctx.Masks) != 1 {
			t.Fatalf("masks = %d, want 1", len(ctx.Masks))
		}
		if got := ctx.Masks[0].GetColumn(); got != "rrn" {
			t.Errorf("mask column = %q, want %q", got, "rrn")
		}
		if got := ctx.Masks[0].GetMaskFn(); got != "last4" {
			t.Errorf("maskFn = %q, want the classification's configured fn %q", got, "last4")
		}
		// The kind comes from the mask_fn vocabulary (step 19) — through the PRODUCTION PolicyStore.
		if got := ctx.Masks[0].GetKind(); got != "LAST_N" {
			t.Errorf("kind = %q, want %q", got, "LAST_N")
		}
	})

	// 3. `masked verdict with REDACT_OUTPUT_NULL redacts to NULL`
	t.Run("masked verdict with REDACT_OUTPUT_NULL redacts to NULL", func(t *testing.T) {
		ctx := g.decide(analyzed(
			analyzedOpts{outputCols: []string{"rrn"}},
			resultReadColumnGrant(g.rrn, probepb.MaskedDisposition_MASKED_DISPOSITION_REDACT_OUTPUT_NULL, 0),
		))
		if ctx.Action != pb.EnfAction_MASK {
			t.Fatalf("action = %v, want MASK (%s)", ctx.Action, reason(ctx))
		}
		if got := ctx.Masks[0].GetMaskFn(); got != "redact" {
			t.Errorf("maskFn = %q, want %q", got, "redact")
		}
		if got := ctx.Masks[0].GetKind(); got != "NULL" {
			t.Errorf("kind = %q, want %q", got, "NULL")
		}
	})

	// 4. `masked verdict with DENY_STATEMENT disposition denies`
	t.Run("masked verdict with DENY_STATEMENT disposition denies", func(t *testing.T) {
		ctx := g.decide(analyzed(analyzedOpts{},
			resultReadColumnGrant(g.rrn, probepb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT)))
		if ctx.Action != pb.EnfAction_DENY {
			t.Fatalf("action = %v, want DENY", ctx.Action)
		}
	})

	// 5. `write read-set membership of a masked column denies`
	t.Run("write read-set membership of a masked column denies", func(t *testing.T) {
		ctx := g.decide(analyzed(
			analyzedOpts{isWrite: true},
			resultReadColumnGrant(g.rrn, probepb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT),
		))
		if ctx.Action != pb.EnfAction_DENY {
			t.Fatalf("action = %v, want DENY", ctx.Action)
		}
		// 🔒 INV-A6-11 half 2 — the WRITE branch. The message branching on facts.isWrite is how the
		// write rule is observable at all; see unmasked_temp_linchpin_db_test.go for why it and the
		// temp bypass are ONE invariant.
		if !strings.Contains(reason(ctx), "write") {
			t.Errorf("denyReason = %q, want the write-specific message", reason(ctx))
		}
	})

	// 6. `denied verdict denies regardless of disposition`
	t.Run("denied verdict denies regardless of disposition", func(t *testing.T) {
		ctx := g.decide(analyzed(
			analyzedOpts{outputCols: []string{"amount"}},
			resultReadColumnGrant(g.amount, probepb.MaskedDisposition_MASKED_DISPOSITION_MASK_OUTPUT, 0),
		))
		if ctx.Action != pb.EnfAction_DENY {
			t.Fatalf("action = %v, want DENY — `orders` has no grant at all", ctx.Action)
		}
	})

	// 7. `multi-grant same ordinal is first-wins`
	t.Run("multi-grant same ordinal is first-wins", func(t *testing.T) {
		ctx := g.decide(analyzed(
			analyzedOpts{outputCols: []string{"rrn"}},
			resultReadColumnGrant(g.rrn, probepb.MaskedDisposition_MASKED_DISPOSITION_REDACT_OUTPUT_NULL, 0),
			resultReadColumnGrant(g.rrn, probepb.MaskedDisposition_MASKED_DISPOSITION_MASK_OUTPUT, 0),
		))
		if ctx.Action != pb.EnfAction_MASK {
			t.Fatalf("action = %v, want MASK (%s)", ctx.Action, reason(ctx))
		}
		if len(ctx.Masks) != 1 {
			t.Fatalf("masks = %d, want 1", len(ctx.Masks))
		}
		// 🔒 INV-A6-12 — the FIRST grant for an ordinal wins. Appending and letting the last win would
		// read "LAST_N" here and would invert the semantics everywhere.
		if got := ctx.Masks[0].GetKind(); got != "NULL" {
			t.Errorf("kind = %q, want %q — the first grant for an ordinal wins", got, "NULL")
		}
	})

	// 8. `output columns and rewritten sql are preserved on the decision`
	t.Run("output columns and rewritten sql are preserved on the decision", func(t *testing.T) {
		rewrite := "SELECT rrn FROM users"
		ctx := g.decide(analyzed(
			analyzedOpts{outputCols: []string{"rrn"}, rewrite: &rewrite},
			resultReadColumnGrant(g.rrn, probepb.MaskedDisposition_MASKED_DISPOSITION_MASK_OUTPUT, 0),
		))
		if ctx.Action != pb.EnfAction_MASK {
			t.Fatalf("action = %v, want MASK (%s)", ctx.Action, reason(ctx))
		}
		// 🔒 INV-A6-5 — outputColumns is a DRIFT DETECTOR that A7 compares against the stored result.
		if len(ctx.OutputColumns) != 1 || ctx.OutputColumns[0] != "rrn" {
			t.Errorf("outputColumns = %v, want [rrn]", ctx.OutputColumns)
		}
		if ctx.RewrittenSQL == nil || *ctx.RewrittenSQL != rewrite {
			t.Errorf("rewrittenSql = %v, want %q", ctx.RewrittenSQL, rewrite)
		}
	})

	// ---- fail-closed contract branches (unreachable from real SQL) ------------------------------

	// 9. `grant with no resource fails closed`
	t.Run("grant with no resource fails closed", func(t *testing.T) {
		// 🔒 INV-A6-10 — a resourceless grant is INVISIBLE to the has*-filtered category walk, so
		// without step 8 it would ride this resolved-METADATA statement to a passthrough ALLOW.
		ctx := g.decide(&probepb.StatementFacts{
			Resolved:       true,
			StatementClass: probepb.StatementClass_STATEMENT_CLASS_METADATA,
			RequiredGrants: []*probepb.RequiredGrant{{Action: probepb.GrantAction_GRANT_ACTION_UNSPECIFIED}},
		})
		if ctx.Action != pb.EnfAction_DENY || !ctx.Structural {
			t.Fatalf("action = %v structural = %v, want DENY/true (%s)", ctx.Action, ctx.Structural, reason(ctx))
		}
	})

	// 10. `resource grant with a non-RESULT_READ action fails closed`
	t.Run("resource grant with a non-RESULT_READ action fails closed", func(t *testing.T) {
		ctx := g.decide(analyzed(
			analyzedOpts{outputCols: []string{"rrn"}},
			columnGrant(g.rrn, probepb.MaskedDisposition_MASKED_DISPOSITION_MASK_OUTPUT, []int32{0},
				probepb.GrantAction_GRANT_ACTION_SQL_SELECT),
		))
		if ctx.Action != pb.EnfAction_DENY || !ctx.Structural {
			t.Fatalf("action = %v structural = %v, want DENY/true (%s)", ctx.Action, ctx.Structural, reason(ctx))
		}
	})

	// 11. `masked verdict with an unspecified disposition fails closed`
	t.Run("masked verdict with an unspecified disposition fails closed", func(t *testing.T) {
		ctx := g.decide(analyzed(analyzedOpts{},
			resultReadColumnGrant(g.rrn, probepb.MaskedDisposition_MASKED_DISPOSITION_UNSPECIFIED)))
		if ctx.Action != pb.EnfAction_DENY {
			t.Fatalf("action = %v, want DENY", ctx.Action)
		}
	})

	// 12. `an out-of-range mask ordinal fails closed`
	t.Run("an out-of-range mask ordinal fails closed", func(t *testing.T) {
		ctx := g.decide(analyzed(
			analyzedOpts{outputCols: []string{"rrn"}},
			resultReadColumnGrant(g.rrn, probepb.MaskedDisposition_MASKED_DISPOSITION_MASK_OUTPUT, 5),
		))
		if ctx.Action != pb.EnfAction_DENY {
			t.Fatalf("action = %v, want DENY", ctx.Action)
		}
		if stage(ctx) != "mask-binding" {
			t.Errorf("failedStage = %q, want %q", stage(ctx), "mask-binding")
		}
	})

	// 13. `unspecified statement class fails closed`
	t.Run("unspecified statement class fails closed", func(t *testing.T) {
		ctx := g.decide(&probepb.StatementFacts{
			Resolved:       true,
			StatementClass: probepb.StatementClass_STATEMENT_CLASS_UNSPECIFIED,
		})
		if ctx.Action != pb.EnfAction_DENY || !ctx.Structural {
			t.Fatalf("action = %v structural = %v, want DENY/true (%s)", ctx.Action, ctx.Structural, reason(ctx))
		}
	})

	// 14. `unspecified statement class with a column grant fails closed independent of the verdict`
	t.Run("unspecified statement class with a column grant fails closed independent of the verdict", func(t *testing.T) {
		// A resolved statement carrying a column grant SKIPS the empty-grant class switch (step 14),
		// so the class must be validated up front — an UNSPECIFIED class must deny even though the
		// grant would otherwise mask.
		ctx := g.decide(&probepb.StatementFacts{
			Resolved:       true,
			StatementClass: probepb.StatementClass_STATEMENT_CLASS_UNSPECIFIED,
			RequiredGrants: []*probepb.RequiredGrant{
				resultReadColumnGrant(g.rrn, probepb.MaskedDisposition_MASKED_DISPOSITION_MASK_OUTPUT, 0),
			},
			OutputColumns: []string{"rrn"},
		})
		if ctx.Action != pb.EnfAction_DENY || !ctx.Structural {
			t.Fatalf("action = %v structural = %v, want DENY/true (%s)", ctx.Action, ctx.Structural, reason(ctx))
		}
	})

	// 15. `unspecified disposition on an UNMASKED column fails closed`
	t.Run("unspecified disposition on an UNMASKED column fails closed", func(t *testing.T) {
		// 🔒 INV-A6-9. `region` authorizes to UNMASKED, whose branch NEVER inspects the disposition —
		// so an UNSPECIFIED disposition must be rejected by the up-front contract validation (step
		// 11), not silently allowed. This case exists ONLY for the UNMASKED variant.
		ctx := g.decide(analyzed(
			analyzedOpts{outputCols: []string{"region"}},
			resultReadColumnGrant(g.region, probepb.MaskedDisposition_MASKED_DISPOSITION_UNSPECIFIED, 0),
		))
		if ctx.Action != pb.EnfAction_DENY || !ctx.Structural {
			t.Fatalf("action = %v structural = %v, want DENY/true (%s)", ctx.Action, ctx.Structural, reason(ctx))
		}
	})

	// 16. `out-of-range ordinal on an UNMASKED column fails closed`
	t.Run("out-of-range ordinal on an UNMASKED column fails closed", func(t *testing.T) {
		// 🔒 INV-A6-9, same independence: a bogus ordinal on a column that authorizes to UNMASKED must
		// still fail closed (step 10).
		ctx := g.decide(analyzed(
			analyzedOpts{outputCols: []string{"region"}},
			resultReadColumnGrant(g.region, probepb.MaskedDisposition_MASKED_DISPOSITION_MASK_OUTPUT, 9),
		))
		if ctx.Action != pb.EnfAction_DENY {
			t.Fatalf("action = %v, want DENY", ctx.Action)
		}
		if stage(ctx) != "mask-binding" {
			t.Errorf("failedStage = %q, want %q", stage(ctx), "mask-binding")
		}
	})

	// 17. `unanalyzable deny carries schema candidates for a bounded catalog refetch`
	t.Run("unanalyzable deny carries schema candidates for a bounded catalog refetch", func(t *testing.T) {
		// 🔒 INV-A6-14. An UNANALYZABLE statement referencing an uncatalogued schema denies (analyst
		// lacks sql.unanalyzable) but MUST surface its schema qualifiers + catalogMiss so
		// ConnectionDecide can refetch and retry.
		ctx := g.decide(&probepb.StatementFacts{
			Resolved:                  false,
			FailureClass:              probepb.FailureClass_FAILURE_CLASS_UNANALYZABLE,
			SchemaQualifierCandidates: []string{"newly_created_schema"},
		})
		if ctx.Action != pb.EnfAction_DENY {
			t.Fatalf("action = %v, want DENY", ctx.Action)
		}
		if !ctx.CatalogMiss {
			t.Error("catalogMiss must be set so the connection layer refetches")
		}
		if len(ctx.SchemaCandidates) != 1 || ctx.SchemaCandidates[0] != "newly_created_schema" {
			t.Errorf("schemaCandidates = %v, want [newly_created_schema]", ctx.SchemaCandidates)
		}
	})

	// 18. `datasource grant with an unspecified action is a policy deny`
	t.Run("datasource grant with an unspecified action is a policy deny", func(t *testing.T) {
		ctx := g.decide(analyzed(analyzedOpts{}, datasourceGrant(probepb.GrantAction_GRANT_ACTION_UNSPECIFIED)))
		if ctx.Action != pb.EnfAction_DENY {
			t.Fatalf("action = %v, want DENY", ctx.Action)
		}
		if ctx.Structural {
			t.Error("kind-not-permitted is a policy deny, not structural")
		}
	})

	// 19. `ungranted table grant denies through table dispatch`
	t.Run("ungranted table grant denies through table dispatch", func(t *testing.T) {
		tableGrant := &probepb.RequiredGrant{
			Action: probepb.GrantAction_GRANT_ACTION_RESULT_READ,
			Resource: &probepb.RequiredGrant_Table{Table: &probepb.TableResource{
				Catalog: g.amount.Catalog, Schema: g.amount.Schema, Table: g.amount.Table,
			}},
			MaskedDisposition: probepb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT,
		}
		if got := g.decide(analyzed(analyzedOpts{}, tableGrant)).Action; got != pb.EnfAction_DENY {
			t.Fatalf("action = %v, want DENY", got)
		}
	})

	// ---- empty-grant channel matrix -------------------------------------------------------------

	// 20. `metadata with no grants is an allow passthrough`
	t.Run("metadata with no grants is an allow passthrough", func(t *testing.T) {
		ctx := g.decide(&probepb.StatementFacts{
			Resolved:                  true,
			StatementClass:            probepb.StatementClass_STATEMENT_CLASS_METADATA,
			SchemaQualifierCandidates: []string{"public"},
		})
		if ctx.Action != pb.EnfAction_ALLOW {
			t.Fatalf("action = %v, want ALLOW (%s)", ctx.Action, reason(ctx))
		}
		if !ctx.Passthrough {
			t.Error("a readonly-meta statement relays verbatim")
		}
		if len(ctx.SchemaCandidates) != 1 || ctx.SchemaCandidates[0] != "public" {
			t.Errorf("schemaCandidates = %v, want [public]", ctx.SchemaCandidates)
		}
	})

	// 21. `session statement passes through only on persistent-connection channels`
	t.Run("session statement passes through only on persistent-connection channels", func(t *testing.T) {
		// 🔒 INV-A6-2. WIRE and EDITOR hold a connection so the session state carries; the workflow
		// channels and MCP each run on a FRESH connection, so they refuse.
		session := &probepb.StatementFacts{
			Resolved:       true,
			StatementClass: probepb.StatementClass_STATEMENT_CLASS_SESSION,
		}
		for _, tc := range []struct {
			channel query.Channel
			want    pb.EnfAction
		}{
			{query.ChannelWire, pb.EnfAction_ALLOW},
			{query.ChannelEditor, pb.EnfAction_ALLOW},
			{query.ChannelMCP, pb.EnfAction_DENY},
			{query.ChannelWorkflowExecutor, pb.EnfAction_DENY},
		} {
			if got := g.decideOn(session, tc.channel).Action; got != tc.want {
				t.Errorf("channel %q: action = %v, want %v", tc.channel, got, tc.want)
			}
		}
	})
}
