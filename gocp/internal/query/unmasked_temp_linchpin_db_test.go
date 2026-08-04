package query_test

import (
	"strings"
	"testing"

	probepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
)

// 🔒 INV-A6-11 — THE UNMASKED-TEMP LINCHPIN. **One coupled invariant, deliberately pinned in one
// file**, because its two halves live ~100 lines apart in different branches of decideQuery's step-24
// loop and nothing in the code makes their dependence visible:
//
//	HALF 1 (the bypass)     `row.isTemp` unconditionally forces the column verdict to UNMASKED,
//	                        BYPASSING Cedar column authorization entirely.
//	HALF 2 (the write rule) a MASKED column whose grant carries DENY_STATEMENT denies the whole
//	                        statement, and the message branches on facts.isWrite.
//
// Half 1 is safe ONLY because half 2 (plus the analyzer's read-set membership rules) makes it
// impossible for a masked value to become the payload of a write. Remove or weaken half 2 and half 1
// stops being a convenience and becomes a CLEARTEXT EXFILTRATION PATH: write the masked column into a
// session temp, then read the temp back — the temp read bypasses authorization by design.
//
// **A port that keeps the bypass but weakens the write rule is fail-open, and both halves will still
// look individually reasonable in review.** That is what this file exists to prevent. The Kotlin's
// equivalent is ChannelDecideAuditDbTest case 6, named "a write cannot launder a masked column into a
// session temp (the unmasked-temp linchpin)".
//
// The cases below drive the decision through the `factsOverride` seam rather than real SQL, so the
// step-24 branch under test is reached deterministically and the assertion cannot be satisfied by an
// unrelated analyzer outcome.

// tempColumn is a per-connection session/temp column, as the proxy's overlay supplies it.
//
// 🔒 INV-A5-1 — IsTemp is set ONLY here, by the per-request overlay. Neither A5 producer sets it, and
// a base-catalog column carrying it would turn every column into an ungranted cleartext read.
func tempColumn(catalog, schema, table, column string) datasource.CatalogColumn {
	return datasource.CatalogColumn{
		Catalog: catalog, Schema: schema, Table: table, Column: column,
		DataType: "character varying", SQLType: "VARCHAR", Ordinal: 1, Nullable: true,
		IsTemp: true,
	}
}

func columnGrantFor(c datasource.CatalogColumn, d probepb.MaskedDisposition, ordinals ...int32) *probepb.RequiredGrant {
	return &probepb.RequiredGrant{
		Action: probepb.GrantAction_GRANT_ACTION_RESULT_READ,
		Resource: &probepb.RequiredGrant_Column{Column: &probepb.ColumnResource{
			Catalog:  c.Catalog,
			Identity: &probepb.RelationIdentity{Schema: c.Schema, Table: c.Table, Column: c.Column},
		}},
		MaskedDisposition: d,
		OutputOrdinals:    ordinals,
	}
}

func TestUnmaskedTempLinchpin(t *testing.T) {
	g := newGrantLoopFixture(t)

	// The session temp the proxy overlays. `pm_scratch` has NO Cedar grant of any kind — the fixture
	// grants only `users`, and `orders` is deliberately ungranted — so Cedar would resolve every
	// column of it to DENIED.
	scratch := tempColumn(g.fx.Catalog, "pg_temp_1", "pm_scratch", "rrn")

	decideWithTemp := func(facts *probepb.StatementFacts, temps ...datasource.CatalogColumn) query.DecisionContext {
		return g.fx.DecideWith(query.DecideQueryInput{
			Principal:     grantLoopPrincipal,
			SQL:           "-- synthetic facts --",
			Channel:       query.ChannelWire,
			TempColumns:   temps,
			FactsOverride: facts,
		})
	}

	// HALF 1 — the bypass. A temp row reads UNMASKED with no grant at all.
	t.Run("half 1: a session temp column reads unmasked, bypassing column authz", func(t *testing.T) {
		ctx := decideWithTemp(analyzed(
			analyzedOpts{outputCols: []string{"rrn"}},
			columnGrantFor(scratch, probepb.MaskedDisposition_MASKED_DISPOSITION_MASK_OUTPUT, 0),
		), scratch)
		if ctx.Action != pb.EnfAction_ALLOW {
			t.Fatalf("action = %v, want ALLOW — row.isTemp forces UNMASKED (%s)", ctx.Action, reason(ctx))
		}
		if len(ctx.Masks) != 0 {
			t.Fatalf("masks = %d, want none: an UNMASKED verdict binds no mask", len(ctx.Masks))
		}
	})

	// 🔒 THE NON-VACUITY CONTROL. Exactly the same grant over the same identity, with IsTemp cleared,
	// must DENY. Without this, half 1's assertion could be satisfied by a fixture that happened to
	// grant the column, and the pin would prove nothing.
	t.Run("control: the same column WITHOUT isTemp is denied by Cedar", func(t *testing.T) {
		notTemp := scratch
		notTemp.IsTemp = false
		ctx := decideWithTemp(analyzed(
			analyzedOpts{outputCols: []string{"rrn"}},
			columnGrantFor(notTemp, probepb.MaskedDisposition_MASKED_DISPOSITION_MASK_OUTPUT, 0),
		), notTemp)
		if ctx.Action != pb.EnfAction_DENY {
			t.Fatalf("action = %v, want DENY — an ungranted NON-temp column is deny-by-default", ctx.Action)
		}
		if !strings.Contains(reason(ctx), "policy denies column") {
			t.Errorf("denyReason = %q, want the column-verdict deny", reason(ctx))
		}
	})

	// HALF 2 — the write rule. This is what makes half 1 safe.
	t.Run("half 2: a write referencing a masked column denies the statement", func(t *testing.T) {
		ctx := decideWithTemp(analyzed(
			analyzedOpts{isWrite: true},
			columnGrantFor(g.rrn, probepb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT),
		))
		if ctx.Action != pb.EnfAction_DENY {
			t.Fatalf("action = %v, want DENY", ctx.Action)
		}
		want := "write references protected column " +
			g.rrn.Catalog + "." + g.rrn.Schema + ".users.rrn (a write cannot be masked)"
		if reason(ctx) != want {
			t.Errorf("denyReason =\n  %q\nwant\n  %q", reason(ctx), want)
		}
	})

	// The same branch on a READ, to pin that the message — and only the message — branches on isWrite.
	// A port that collapsed the two messages would lose the signal an operator triages on.
	t.Run("half 2: the same branch on a read denies with the subquery/reference message", func(t *testing.T) {
		ctx := decideWithTemp(analyzed(
			analyzedOpts{},
			columnGrantFor(g.rrn, probepb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT),
		))
		if ctx.Action != pb.EnfAction_DENY {
			t.Fatalf("action = %v, want DENY", ctx.Action)
		}
		want := "sensitive column " + g.rrn.Catalog + "." + g.rrn.Schema +
			".users.rrn used in a subquery/reference position (cannot be masked)"
		if reason(ctx) != want {
			t.Errorf("denyReason =\n  %q\nwant\n  %q", reason(ctx), want)
		}
	})

	// 🔒 THE COUPLING ITSELF — the laundering attempt, in one statement. A write whose read-set
	// contains the masked `users.rrn` and whose target is the unauthorized session temp: half 1 waves
	// the temp column through, and half 2 must still deny the STATEMENT. If half 2 is ever weakened,
	// THIS is the case that turns green and ships a cleartext exfiltration path.
	//
	// This is the SEAM half of the Kotlin case (deterministic facts, branch-by-branch); the REAL-SQL
	// half — an actual CTAS and INSERT-select through the analyzer — is
	// channel_decide_audit_db_test.go's TestChannelAWriteCannotLaunderAMaskedColumnIntoASessionTemp.
	// Both carry the marker.
	// KT: ChannelDecideAuditDbTest.kt#a write cannot launder a masked column into a session temp (the unmasked-temp linchpin)
	t.Run("coupled: a write cannot launder a masked column into a session temp", func(t *testing.T) {
		ctx := decideWithTemp(analyzed(
			analyzedOpts{isWrite: true, outputCols: []string{"rrn"}},
			// The write target — an unauthorized temp, waved through by half 1.
			columnGrantFor(scratch, probepb.MaskedDisposition_MASKED_DISPOSITION_MASK_OUTPUT, 0),
			// The read-set source — masked, and unmaskable in a write payload.
			columnGrantFor(g.rrn, probepb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT),
		), scratch)
		if ctx.Action != pb.EnfAction_DENY {
			t.Fatalf("action = %v, want DENY — the masked source must deny the whole write (%s)",
				ctx.Action, reason(ctx))
		}
		if !strings.Contains(reason(ctx), "a write cannot be masked") {
			t.Errorf("denyReason = %q, want the write-payload deny", reason(ctx))
		}
	})

	// 🔒 The temp bypass is a COLUMN-authz bypass only — it does not extend to the step-25 table gate,
	// and it does not extend to a non-temp table of the same name. Kotlin's ChannelDecideAuditDbTest
	// case 7 covers the "bare count over a session temp is allowed" side; this covers the other: a
	// TABLE grant naming a non-temp ungranted relation still denies, even while a temp column of the
	// same statement is waved through.
	t.Run("the bypass does not extend to the scanned-table gate", func(t *testing.T) {
		ctx := decideWithTemp(analyzed(
			analyzedOpts{outputCols: []string{"rrn"}},
			columnGrantFor(scratch, probepb.MaskedDisposition_MASKED_DISPOSITION_MASK_OUTPUT, 0),
			&probepb.RequiredGrant{
				Action: probepb.GrantAction_GRANT_ACTION_RESULT_READ,
				Resource: &probepb.RequiredGrant_Table{Table: &probepb.TableResource{
					Catalog: g.amount.Catalog, Schema: g.amount.Schema, Table: g.amount.Table,
				}},
				MaskedDisposition: probepb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT,
			},
		), scratch)
		if ctx.Action != pb.EnfAction_DENY {
			t.Fatalf("action = %v, want DENY — the ungranted scanned table is still gated", ctx.Action)
		}
		if !strings.Contains(reason(ctx), "no read grant for scanned table") {
			t.Errorf("denyReason = %q, want the scanned-table deny", reason(ctx))
		}
	})

	// The temp EXCLUSION on the step-25 table gate, which is the counterpart of the column bypass: a
	// table grant naming a TEMP relation is dropped from the gate entirely, so a scan of a session
	// temp is not denied for want of a grant nobody can hold.
	t.Run("a table grant naming a temp relation is excluded from the table gate", func(t *testing.T) {
		ctx := decideWithTemp(analyzed(
			analyzedOpts{},
			&probepb.RequiredGrant{
				Action: probepb.GrantAction_GRANT_ACTION_RESULT_READ,
				Resource: &probepb.RequiredGrant_Table{Table: &probepb.TableResource{
					Catalog: scratch.Catalog, Schema: scratch.Schema, Table: scratch.Table,
				}},
				MaskedDisposition: probepb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT,
			},
		), scratch)
		if ctx.Action != pb.EnfAction_ALLOW {
			t.Fatalf("action = %v, want ALLOW — temp tables are excluded from the scan gate (%s)",
				ctx.Action, reason(ctx))
		}
	})
}
