package query_test

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/query"
)

// DiagnosticRedactionDecideDbTest.kt — 64 LOC, 2 cases (06-query-decision.md §7, step 31 — DB).
//
// End to end through the real decision path (Cedar + PostgreSQL): the diagnostic-redaction flag on
// DecisionContext is driven by the `result.read.unmasked`-on-DATASOURCE Cedar authorization, NOT a
// datasource-tag check. On a `system:development` datasource the -200 preset permits unmasked reads,
// so no redaction; on the production floor an ordinary principal is redacted.
//
// PostgreSQL is used because it LEAKS ON ALLOW (the whole-row `DETAIL: Failing row contains (…)`), so
// the dev/prod difference shows on a plain SELECT — on MySQL both would be false and the test would be
// vacuous. [TestMySQLAllowSkipsTheCedarUnmaskedReaderCheck] in diagnostics_redaction_test.go is the
// unit half of the same invariant (INV-A6-15) and asserts the other property: that on the one
// engine/action pair which cannot leak, the Cedar thunk is never called at all.
//
// ⚠️ The two cases are ORDER-DEPENDENT on one shared fixture, exactly as the Kotlin's are: case 1
// leaves the datasource tagged `system:development` and case 2 flips it to `system:production` and
// back. Go subtests run in declaration order, which is the same guarantee the Kotlin relies on.
func TestDiagnosticRedactionDecideDb(t *testing.T) {
	fx := newEnforcementFixture(t, dbtest.EnginePostgres)
	classifier := shippedClassifier(t)

	decide := func(sql string) query.DecisionContext {
		return gateDecide(fx, dbtest.FixturePrincipal, sql, classifier)
	}

	// `a system-development datasource never redacts (Cedar permits unmasked reads there)`
	t.Run("a system-development datasource never redacts (Cedar permits unmasked reads there)", func(t *testing.T) {
		fx.SetTags("system:development")
		r := decide("select id from users order by id")
		if r.Action != pb.EnfAction_ALLOW {
			t.Fatalf("action = %v, want ALLOW (%s)", r.Action, reason(r))
		}
		if r.SanitizeDiagnostics {
			t.Error("dev holds no PII → the -200 unmasked permit fires → no redaction")
		}
	})

	// `a production datasource redacts an ordinary principal, even on an ALLOW (Postgres whole-row leak)`
	t.Run("a production datasource redacts an ordinary principal, even on an ALLOW (Postgres whole-row leak)", func(t *testing.T) {
		fx.SetTags("system:production")

		allow := decide("select id from users order by id")
		if allow.Action != pb.EnfAction_ALLOW {
			t.Fatalf("action = %v, want ALLOW (%s)", allow.Action, reason(allow))
		}
		if !allow.SanitizeDiagnostics {
			t.Error("production + not a full-cleartext reader + PG leaks on ALLOW → redact")
		}

		mask := decide("select id, rrn from users order by id")
		if mask.Action != pb.EnfAction_MASK {
			t.Fatalf("action = %v, want MASK (%s)", mask.Action, reason(mask))
		}
		if !mask.SanitizeDiagnostics {
			t.Error("a MASK decision touches protected data → redact")
		}

		// The Kotlin restores the dev posture on the way out; kept so the fixture is left as the Kotlin
		// leaves it rather than as this file happened to need it last.
		fx.SetTags("system:development")
	})
}
