package dbtest

import (
	"context"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/datasource"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/engine"
	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/query"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// The decide → execute → mask half of the enforcement harness — the Go form of
// `support/EnforcementHarness.kt:106-169`'s runEnforcedForTest. doc.go listed it as TODO(A6); A6 has
// landed, so this is it.
//
// 🔒 IT CALLS PRODUCTION [query.DecideQuery] AND [query.DecisionRecord] DIRECTLY, and that is the
// whole point of the file. The Kotlin harness reuses production `decisionRecord`, which is the ONLY
// reason the audit rows its suites assert on are the audit rows production writes. A harness that
// re-derived either would prove that the fixture agrees with itself and nothing else. If a future
// change makes this file stop compiling against internal/query, fix the wiring — do not fork the
// logic back in here.

// EnforcedResponse is `QueryResponse` as the harness produces it (EnforcementHarness.kt:131-168).
//
// It is deliberately [query.QueryResponse], not a harness-local twin: the response shape is A6's, and
// a second one here would be a second definition of what an enforced run returns.
type EnforcedResponse = query.QueryResponse

// Decide runs the PRODUCTION decision for this fixture's datasource and principal, over the
// datasource's persisted config catalog.
//
// It is the Go form of `decideAndAudit`'s decision half (EnforcementHarness.kt:62-70) minus the audit
// insert, which [EnforcementFixture.DecisionRecord] and the caller's AuditStore compose.
//
// ⚠️ This reads the GLOBAL catalog (DatasourceStore.Catalog), exactly as the Kotlin harness does, and
// for the same reason it is kept strictly in test scope: the production wire path is
// `decideConnection`'s per-connection held fragments, and the whole point of that design is that the
// enforcing path can never read the global catalog. Never wire this onto an enforcing path.
func (f *EnforcementFixture) Decide(principal, sql string, channel query.Channel) query.DecisionContext {
	f.T.Helper()
	return f.DecideWith(query.DecideQueryInput{Principal: principal, SQL: sql, Channel: channel})
}

// DecideWith is [EnforcementFixture.Decide] with the caller filling in any of decideQuery's other
// inputs (a live search path, temp columns, provided roles, or the FactsOverride test seam).
//
// The fields the fixture owns — Datasource, Catalog, and the three store seams plus Authz — are
// overwritten here, so a caller cannot accidentally decide against a different stack than the one the
// fixture seeded. Everything else is passed through untouched.
func (f *EnforcementFixture) DecideWith(in query.DecideQueryInput) query.DecisionContext {
	f.T.Helper()
	in.Datasource = f.DatasourceRow
	in.Catalog = f.CatalogRows()
	in.MaskFns = f.MaskFns
	in.UserGroups = f.UserGroups
	in.Roles = f.RoleResolver
	in.Authz = f.Authz
	ctx, err := query.DecideQuery(context.Background(), in)
	if err != nil {
		// A returned error is one of the Kotlin's PROPAGATING throws (an engine mapping, or a store
		// read failing) — never a DENY. Failing the test here keeps the two distinguishable, the same
		// reason TargetQueryError is distinct from a policy deny.
		f.T.Fatalf("decideQuery failed for %q: %v", in.SQL, err)
	}
	return ctx
}

// DecisionRecord builds the audit row for a decision — a straight call to the PRODUCTION
// [query.DecisionRecord]. It exists so a suite writes `fx.DecisionRecord(...)` instead of threading
// the datasource and channel by hand, NOT so the shape can differ.
func (f *EnforcementFixture) DecisionRecord(
	principal, sql string,
	clientAddr *string,
	ctx query.DecisionContext,
	latencyMs int64,
	effectiveNamespace []string,
	channel query.Channel,
) types.AuditEvent {
	return query.DecisionRecord(principal, f.DatasourceRow, sql, clientAddr, ctx, latencyMs, effectiveNamespace, channel)
}

// Run is the in-process decide → execute → mask composition
// (`EnforcementHarness.kt:106-169`), so a suite can exercise the full pipeline against a real target
// without standing up a proxy. The execute step runs on the connection the TEST owns: the control
// plane never dials a target and holds no credential to one.
//
// It does NOT write an audit row — [EnforcementFixture.DecisionRecord] plus a suite's own AuditStore
// do that — because internal/dbtest cannot import internal/audit (audit's DB tests are in-package and
// import this package). The three audit points the Kotlin harness has are therefore the caller's, and
// the record they insert is production's either way.
//
// 🔒 The mask-binding failure branch is load-bearing, not defensive garnish: `bindMasks` reports an
// absent or out-of-range ordinal as UNBOUND, and the caller MUST fail closed on it (INV-A13-8). A
// harness that applied the masks it could bind and relayed the rest would leak exactly the column the
// mask was for.
func (f *EnforcementFixture) Run(principal, sql string, maxRows int) EnforcedResponse {
	f.T.Helper()
	started := time.Now()
	ctx := f.Decide(principal, sql, query.ChannelEditor)

	if ctx.Action == pb.EnfAction_DENY {
		return EnforcedResponse{
			Decision:       query.WireEnfAction(pb.EnfAction_DENY),
			DenyReason:     ctx.DenyReason,
			PIITouched:     ctx.PIITouched,
			EffectiveRoles: ctx.EffectiveRoles,
			LatencyMs:      elapsedMs(started),
		}
	}

	// Run the `*`-expanded query when the analyzer produced one, so the result columns arrive in the
	// exact order ctx.Masks index — robust even if the catalog's column order has drifted. Nil =
	// verbatim.
	toRun := sql
	if ctx.RewrittenSQL != nil {
		toRun = *ctx.RewrittenSQL
	}
	rows, err := ExecOnTarget(f.Target, toRun, clampMaxRows(maxRows))
	if err != nil {
		f.T.Fatalf("target query failed: %v", err)
	}

	binding := engine.BindMasks(ctx.Masks, len(rows.Columns))
	if !binding.AllBound() {
		return EnforcedResponse{
			Decision:       query.WireEnfAction(pb.EnfAction_DENY),
			DenyReason:     stringPtr(query.MaskBindDeny),
			PIITouched:     ctx.PIITouched,
			EffectiveRoles: ctx.EffectiveRoles,
			LatencyMs:      elapsedMs(started),
		}
	}

	masked := rows.Rows
	if len(binding.ByIndex) > 0 {
		masked = make([][]*string, 0, len(rows.Rows))
		for _, row := range rows.Rows {
			out := make([]*string, len(row))
			for i, v := range row {
				kind, ok := binding.ByIndex[i]
				if !ok {
					out[i] = v
					continue
				}
				// NOT `?: v`. ApplyMaskKind returns nil for a full redaction (kind NULL), and falling
				// a redacted cell back to its cleartext value is precisely the bug the Kotlin's
				// comment at EnforcementHarness.kt:156-158 warns about.
				out[i] = engine.ApplyMaskKind(v, kind)
			}
			masked = append(masked, out)
		}
	}

	var rowsAffected *int32
	if rows.RowsAffected != nil {
		v := int32(*rows.RowsAffected)
		rowsAffected = &v
	}
	return EnforcedResponse{
		Decision:       query.WireEnfAction(ctx.Action),
		MaskedColumns:  maskedColumns(ctx.Masks),
		PIITouched:     ctx.PIITouched,
		EffectiveRoles: ctx.EffectiveRoles,
		Columns:        rows.Columns,
		Rows:           masked,
		RowsAffected:   rowsAffected,
		LatencyMs:      elapsedMs(started),
	}
}

// CatalogRows is the datasource's persisted config catalog, through the PRODUCTION DatasourceStore.
func (f *EnforcementFixture) CatalogRows() []datasource.CatalogColumn {
	f.T.Helper()
	cols, err := f.DatasourceStore.Catalog(context.Background(), f.DatasourceID)
	if err != nil {
		f.T.Fatalf("read catalog for datasource %d: %v", f.DatasourceID, err)
	}
	return cols
}

// NewDBMaskFnLister reads the `mask_fn` vocabulary straight from the table.
//
// ⚠️ TODO(A9): this is a stand-in for `policy.PolicyStore.ListMaskFns`, in the same spirit — and with
// the same hazard — as [NewDBPolicyStore]'s TODO(A2). internal/dbtest cannot import internal/policy
// (`policy [policy.test] → dbtest → policy` is an import cycle, since internal/policy's DB test is
// in-package), so the fixture cannot default to the production store. A suite that CAN import
// internal/policy should overwrite [EnforcementFixture.MaskFns] with a three-line adapter over the
// production store — statement_facts_grant_loop_db_test.go does exactly that, and is the reason this
// default is never the thing the A6 suites actually assert against.
//
// The SQL is `PolicyStore.listMaskFns`' verbatim, ORDER BY included.
func NewDBMaskFnLister(t testing.TB, f *EnforcementFixture) query.MaskFnLister {
	return func(ctx context.Context) ([]query.MaskFn, error) {
		rows, err := f.Store.Pool.Query(ctx, `SELECT name, kind FROM mask_fn ORDER BY name`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []query.MaskFn
		for rows.Next() {
			var fn query.MaskFn
			if err := rows.Scan(&fn.Name, &fn.Kind); err != nil {
				return nil, err
			}
			out = append(out, fn)
		}
		return out, rows.Err()
	}
}

// dbUserGroupStore answers decideQuery's step-5 deactivation gate from `app_user`.
//
// ⚠️ TODO(A3): replace with the production *identity.UserGroupStore, which satisfies
// [query.UserGroupStore] structurally and with no adapter. Same cycle constraint as
// [NewDBMaskFnLister]: internal/identity's DB test is in-package and imports this package. The SQL is
// `UserGroupStore.isDeactivated`' verbatim, including the "no row ⇒ NOT deactivated" contract
// (INV-A3-10) the single EXISTS encodes.
type dbUserGroupStore struct{ f *EnforcementFixture }

func (s dbUserGroupStore) IsDeactivated(ctx context.Context, principal string) (bool, error) {
	var out bool
	err := s.f.Store.Pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM app_user WHERE principal=$1 AND NOT active)`, principal).Scan(&out)
	return out, err
}

// dbRoleResolver answers decideQuery's step-6 role resolution.
//
// 🔒 TODO(A3): replace with the production *identity.RoleResolver. This covers `principal_role` ∪
// `group_role` only — it reuses [NewDBRoleSource]'s query, which is already the fixture's role source
// for Cedar — and so it is MISSING active JIT grants and the deactivation short-circuit
// (RoleResolver.kt:45-54). Reusing that one query keeps the fixture from having a THIRD definition of
// "what roles does this principal hold"; growing this one instead of replacing it would create it.
type dbRoleResolver struct{ f *EnforcementFixture }

func (r dbRoleResolver) Resolve(_ context.Context, principal string) ([]string, error) {
	return r.f.RoleSource.RolesOf(principal), nil
}

func elapsedMs(started time.Time) int64 { return time.Since(started).Milliseconds() }

// clampMaxRows is Kotlin's `maxRows.coerceIn(1, 5000)` (EnforcementHarness.kt:140).
func clampMaxRows(n int) int {
	if n < 1 {
		return 1
	}
	if n > 5000 {
		return 5000
	}
	return n
}

func maskedColumns(masks []*pb.ColumnMask) []string {
	out := make([]string, 0, len(masks))
	for _, m := range masks {
		out = append(out, m.GetColumn())
	}
	return out
}

func stringPtr(s string) *string { return &s }
