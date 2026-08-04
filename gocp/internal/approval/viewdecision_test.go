package approval

import (
	"context"
	"reflect"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/result"
)

// ---------------------------------------------------------------------------------------------
// `decideResultView`'s SEVEN DENY GATES — Approvals.kt:186-256, 07-tasks-approvals-results.md §5.
//
// These are the four drift/uncertainty gates of `ApprovalResultViewContextDbTest` cases 9-12 plus
// the three structural ones, driven directly rather than through HTTP.
//
// 🔒 WHY UNIT AND NOT DB: gates 5, 6 and 7 are reachable ONLY when the stored bytes and the live
// decision DISAGREE — catalog drift between execute and view. Against a real analyzer the two agree
// by construction, so a DB suite either cannot reach them or has to corrupt the stored row into a
// shape production never writes. Scripting the DecisionContext reaches each gate exactly, and the
// route-level DB suite covers the composition. Each gate is a DISTINCT LEAK PATH; the area doc says
// to port them as a group, and this is that group.
// ---------------------------------------------------------------------------------------------

// stubDatasources answers only what DecideResultView needs: the catalog read.
type stubDatasources struct{ catalog []datasource.CatalogColumn }

func (s stubDatasources) Get(context.Context, int64) (datasource.Datasource, bool, error) {
	return datasource.Datasource{}, false, nil
}

func (s stubDatasources) GetByName(context.Context, string) (datasource.Datasource, bool, error) {
	return datasource.Datasource{}, false, nil
}

func (s stubDatasources) List(context.Context) ([]datasource.Datasource, error) { return nil, nil }

func (s stubDatasources) Catalog(context.Context, int64) ([]datasource.CatalogColumn, error) {
	return s.catalog, nil
}

// viewDecider builds a Decider whose pipeline answers `decision` regardless of input.
func viewDecider(decision query.DecisionContext) *Decider {
	return &Decider{
		Datasources: stubDatasources{},
		Decide: func(context.Context, query.DecideQueryInput) (query.DecisionContext, error) {
			return decision, nil
		},
	}
}

// storedResultRequest is a WORKFLOW task with execute-as {analyst}.
func storedResultRequest() access.AccessRequest {
	return access.AccessRequest{
		ID: 1, Principal: "requester", Kind: "QUERY",
		CreatorKind: strptr("WORKFLOW"), ExecuteAs: []string{"analyst"},
		DatasourceID: ptr64(1),
	}
}

func ptr64(v int64) *int64 { return &v }

func viewInput(decrypted result.DecryptedResult) ResultViewInput {
	return ResultViewInput{
		Viewer: "viewer", Req: storedResultRequest(), ChildSQL: strptr("SELECT rrn FROM users"),
		DS: datasource.Datasource{ID: 1, Name: "ds"}, Decrypted: decrypted,
		CallerContext: authz.AuthzContext{}, Channel: query.ChannelWorkflowViewer,
	}
}

func allowWithColumns(columns ...string) query.DecisionContext {
	return query.DecisionContext{Action: pb.EnfAction_ALLOW, OutputColumns: columns}
}

func mustDecideView(t *testing.T, d *Decider, in ResultViewInput) ResultViewDecision {
	t.Helper()
	got, err := d.DecideResultView(context.Background(), in)
	if err != nil {
		t.Fatalf("DecideResultView: %v", err)
	}
	return got
}

func assertDenied(t *testing.T, got ResultViewDecision, wantReason string) {
	t.Helper()
	if !got.IsDenied() {
		t.Fatalf("expected a DENY (%q), got Allowed with columns %v and %d rows",
			wantReason, got.Columns, len(got.Rows))
	}
	if *got.DeniedReason != wantReason {
		t.Errorf("reason: got %q, want %q", *got.DeniedReason, wantReason)
	}
}

// GATE 1 — no child SQL.
func TestViewGate1DeniesWhenTheSavedChildHasNoSQL(t *testing.T) {
	in := viewInput(result.DecryptedResult{Columns: []string{"rrn"}})
	in.ChildSQL = nil
	assertDenied(t, mustDecideView(t, viewDecider(allowWithColumns("rrn")), in), denyNoChildSQL)
}

// 🔒 GATE 2 — INV-A7-2: an EMPTY {R} fails closed at the view end too. There is no raw-snapshot side
// channel: with no role to re-decide under, the stored bytes are never released.
func TestViewGate2DeniesAnEmptyExecuteAsRatherThanReleasingTheStoredBytes(t *testing.T) {
	in := viewInput(result.DecryptedResult{Columns: []string{"rrn"}, Rows: [][]*string{{strptr("secret")}}})
	in.Req.ExecuteAs = nil
	got := mustDecideView(t, viewDecider(allowWithColumns("rrn")), in)
	assertDenied(t, got, denyNoExecuteAs)
	if len(got.Rows) != 0 {
		t.Error("INV-A7-2: an empty {R} must release NO rows")
	}
}

// GATE 3 — a live DENY. The reason falls back denyReason → detail → the constant, in that order.
func TestViewGate3DeniesOnALiveDenyAndPrefersDenyReasonThenDetail(t *testing.T) {
	in := viewInput(result.DecryptedResult{Columns: []string{"rrn"}})

	t.Run("denyReason wins", func(t *testing.T) {
		d := query.DecisionContext{Action: pb.EnfAction_DENY, DenyReason: strptr("no read grant"), Detail: strptr("detail")}
		assertDenied(t, mustDecideView(t, viewDecider(d), in), "no read grant")
	})
	t.Run("detail when there is no denyReason", func(t *testing.T) {
		d := query.DecisionContext{Action: pb.EnfAction_DENY, Detail: strptr("detail")}
		assertDenied(t, mustDecideView(t, viewDecider(d), in), "detail")
	})
	t.Run("the constant when there is neither", func(t *testing.T) {
		d := query.DecisionContext{Action: pb.EnfAction_DENY}
		assertDenied(t, mustDecideView(t, viewDecider(d), in), denyViewDecision)
	})
}

// GATE 4 — a stored result that re-decides as PASSTHROUGH has no mask binding to apply, so releasing
// it would release whatever is stored with no live verdict behind it.
func TestViewGate4DeniesAPassthroughRedecision(t *testing.T) {
	d := allowWithColumns("rrn")
	d.Passthrough = true
	in := viewInput(result.DecryptedResult{Columns: []string{"rrn"}})
	assertDenied(t, mustDecideView(t, viewDecider(d), in), denyPassthrough)
}

// 🔒 GATE 5 — INV-A7-14, OUTPUT-COLUMN DRIFT, the consumer of A6 INV-A6-5.
//
// A `SELECT *` re-expansion between execute and view would slide a mask onto the WRONG stored column
// and leak a value, so both a size mismatch and a POSITIONAL mismatch deny. The comparison is
// case-INSENSITIVE, which the third sub-case pins from the other side: an engine that changed only
// the case must NOT be treated as drift, or every MySQL view would 403.
func TestViewGate5DeniesOutputColumnDriftPositionallyAndCaseInsensitively(t *testing.T) {
	stored := result.DecryptedResult{Columns: []string{"id", "rrn"}, Rows: [][]*string{{strptr("1"), strptr("x")}}}

	t.Run("size mismatch", func(t *testing.T) {
		assertDenied(t, mustDecideView(t, viewDecider(allowWithColumns("id")), viewInput(stored)), denyColumnDrift)
	})
	t.Run("positional mismatch — the same NAMES in a different ORDER still drift", func(t *testing.T) {
		got := mustDecideView(t, viewDecider(allowWithColumns("rrn", "id")), viewInput(stored))
		assertDenied(t, got, denyColumnDrift)
		if len(got.Rows) != 0 {
			t.Error("INV-A7-14: gate 5 must fail closed BEFORE any partially matched row is returned")
		}
	})
	t.Run("case-only difference is NOT drift", func(t *testing.T) {
		got := mustDecideView(t, viewDecider(allowWithColumns("ID", "RRN")), viewInput(stored))
		if got.IsDenied() {
			t.Errorf("a case-only difference must not deny; got %q", *got.DeniedReason)
		}
	})
}

// GATE 6 — a stored row wider or narrower than its own columns cannot be bound safely; releasing it
// would hand back an unbound extra value.
func TestViewGate6DeniesStoredRowWidthDrift(t *testing.T) {
	stored := result.DecryptedResult{
		Columns: []string{"id", "rrn"},
		Rows:    [][]*string{{strptr("1"), strptr("x")}, {strptr("2"), strptr("y"), strptr("EXTRA")}},
	}
	got := mustDecideView(t, viewDecider(allowWithColumns("id", "rrn")), viewInput(stored))
	assertDenied(t, got, denyRowWidthDrift)
	if len(got.Rows) != 0 {
		t.Error("gate 6 must return no rows at all, not the well-formed prefix")
	}
}

// GATE 7 — a required mask that cannot be bound to a live result column denies. An out-of-range
// ordinal is the reachable case.
func TestViewGate7DeniesWhenARequiredMaskCannotBeBound(t *testing.T) {
	ord := int32(9)
	d := allowWithColumns("id")
	d.Masks = []*pb.ColumnMask{{Column: "rrn", MaskFn: "last4", Kind: "LAST_N", Ordinal: &ord}}
	stored := result.DecryptedResult{Columns: []string{"id"}, Rows: [][]*string{{strptr("1")}}}
	assertDenied(t, mustDecideView(t, viewDecider(d), viewInput(stored)), denyUnboundViewMask)
}

// 🔒 INV-A7-15 — A NULL-KIND REDACTION BLANKS THE CELL, IT DOES NOT FALL BACK TO THE STORED
// CLEARTEXT.
//
// This is the one-character bug the invariant exists for: `ApplyMaskKind(v, kind) ?: value` looks
// like a tidy simplification and silently returns the cleartext for every full redaction, because
// ApplyMaskKind returns nil for kind "NULL". The assertion is not "the cell changed" — it is "the
// cell is nil AND is not the stored value", which the buggy form fails on both counts.
//
// KT: ApprovalResultViewContextDbTest.kt#a NULL-kind redaction of a derived output blanks the cell on view, not the stored cleartext — the Kotlin reaches kind NULL through a real `upper(rrn)` derivation; here the kind is scripted, which holds everything else equal
func TestANullKindRedactionBlanksTheCellRatherThanFallingBackToCleartext(t *testing.T) {
	ord := int32(1)
	d := allowWithColumns("id", "secret")
	d.Masks = []*pb.ColumnMask{{Column: "secret", MaskFn: "redact", Kind: "NULL", Ordinal: &ord}}
	cleartext := "900101-1234567"
	stored := result.DecryptedResult{
		Columns: []string{"id", "secret"},
		Rows:    [][]*string{{strptr("1"), &cleartext}},
	}

	got := mustDecideView(t, viewDecider(d), viewInput(stored))
	if got.IsDenied() {
		t.Fatalf("unexpected deny: %q", *got.DeniedReason)
	}
	cell := got.Rows[0][1]
	if cell != nil {
		t.Fatalf("INV-A7-15: a NULL-kind redaction fell back to %q instead of blanking the cell", *cell)
	}
	// The unmasked neighbour is untouched, so the test cannot pass by blanking everything.
	if got.Rows[0][0] == nil || *got.Rows[0][0] != "1" {
		t.Errorf("the unmasked column was altered: %v", got.Rows[0][0])
	}
}

// 🔒 INV-A7-16 — `maskedColumns` is named from the BOUND INDICES and the STORED column names, sorted.
//
// Reading it off `ctx.masks` instead would report a mask the decision asked for but could not bind as
// applied — and would report the DECISION's column name where the stored name is what the caller's
// rows are keyed by. The script makes those two disagree in case, so a port reading ctx.masks emits
// "RRN" where this emits "rrn".
func TestMaskedColumnsAreNamedFromTheBoundIndicesAndTheStoredColumnNames(t *testing.T) {
	ord0, ord1 := int32(1), int32(0)
	d := allowWithColumns("ID", "RRN")
	d.Masks = []*pb.ColumnMask{
		{Column: "RRN", MaskFn: "last4", Kind: "LAST_N", Ordinal: &ord0},
		{Column: "ID", MaskFn: "mask", Kind: "FIXED", Ordinal: &ord1},
	}
	stored := result.DecryptedResult{
		Columns: []string{"id", "rrn"},
		Rows:    [][]*string{{strptr("1"), strptr("900101-1234567")}},
	}

	got := mustDecideView(t, viewDecider(d), viewInput(stored))
	if got.IsDenied() {
		t.Fatalf("unexpected deny: %q", *got.DeniedReason)
	}
	if want := []string{"id", "rrn"}; !reflect.DeepEqual(got.MaskedColumns, want) {
		t.Errorf("maskedColumns: got %v, want %v (sorted by BOUND INDEX, named from the STORED columns)",
			got.MaskedColumns, want)
	}
	if *got.Rows[0][0] != "####" {
		t.Errorf("FIXED mask: got %q", *got.Rows[0][0])
	}
	if *got.Rows[0][1] != "**********4567" {
		t.Errorf("LAST_N mask: got %q", *got.Rows[0][1])
	}
}

// 🔒 INV-A7-3 — THE VIEW CAN ONLY NARROW. The stored bytes are already R-enforced, and nothing in the
// view reads anything else: a live decision that masks NOTHING still returns exactly the stored
// values, and a live decision that masks MORE returns fewer.
//
// Stated as one test over both directions, because the property is about the pair.
func TestTheViewNarrowsAndNeverWidens(t *testing.T) {
	storedAlreadyMasked := "****4567"
	stored := result.DecryptedResult{
		Columns: []string{"rrn"},
		Rows:    [][]*string{{&storedAlreadyMasked}},
	}

	t.Run("a live ALLOW returns the stored (already masked) bytes verbatim", func(t *testing.T) {
		got := mustDecideView(t, viewDecider(allowWithColumns("rrn")), viewInput(stored))
		if got.IsDenied() {
			t.Fatalf("unexpected deny: %q", *got.DeniedReason)
		}
		if *got.Rows[0][0] != storedAlreadyMasked {
			t.Errorf("got %q, want the stored %q — the view must not widen", *got.Rows[0][0], storedAlreadyMasked)
		}
		if len(got.MaskedColumns) != 0 {
			t.Errorf("maskedColumns: got %v, want [] (this view masked nothing)", got.MaskedColumns)
		}
	})

	t.Run("a live MASK narrows further", func(t *testing.T) {
		ord := int32(0)
		d := allowWithColumns("rrn")
		d.Masks = []*pb.ColumnMask{{Column: "rrn", MaskFn: "redact", Kind: "NULL", Ordinal: &ord}}
		got := mustDecideView(t, viewDecider(d), viewInput(stored))
		if got.Rows[0][0] != nil {
			t.Errorf("got %v, want a blanked cell", *got.Rows[0][0])
		}
	})
}

// A store failure inside the live decision PROPAGATES as an error (a 500 at the route), never as a
// silent Allowed or a Denied that the console would render as "you may not see this".
func TestADecideFailureInTheViewPropagatesRatherThanBecomingADeny(t *testing.T) {
	d := &Decider{
		Datasources: stubDatasources{},
		Decide: func(context.Context, query.DecideQueryInput) (query.DecisionContext, error) {
			return query.DecisionContext{}, errorString("catalog read failed")
		},
	}
	_, err := d.DecideResultView(context.Background(), viewInput(result.DecryptedResult{Columns: []string{"rrn"}}))
	if err == nil {
		t.Fatal("a decide failure must propagate to the route as a 500, not be reported as a view deny")
	}
}
