package query

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/datasource"
	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
)

// DiagnosticsRedactionTest.kt — 5 cases, unit (06-query-decision.md §7, step 31).
//
// The per-decision redaction predicate. `mayReadUnmasked` is the Cedar `result.read.unmasked`-on-
// datasource authorization (dev preset, or a production unmasked grant), supplied as a THUNK so the
// Cedar call is skipped when the diagnostic cannot carry a protected value anyway. See
// docs/diagnostic-redaction.md.
//
// Kotlin case names are carried verbatim as comments so the two suites map 1:1.

func redact(e datasource.Engine, action pb.EnfAction, mayReadUnmasked bool) bool {
	return RedactsDiagnostics(e, action, func() bool { return mayReadUnmasked })
}

// `MySQL ALLOW never redacts, whatever the principal`
func TestMySQLAllowNeverRedacts(t *testing.T) {
	if redact(datasource.EngineMySQL, pb.EnfAction_ALLOW, false) {
		t.Fatal("MySQL ALLOW must not redact for a non-unmasked reader")
	}
	if redact(datasource.EngineMySQL, pb.EnfAction_ALLOW, true) {
		t.Fatal("MySQL ALLOW must not redact for an unmasked reader")
	}
}

// `MySQL ALLOW skips the Cedar unmasked-reader check (cannot leak on allow)`
//
// 🔒 INV-A6-15's thunk half. This is the reason mayReadUnmasked is a function and not a bool: on the
// one engine/action pair that cannot leak, Cedar is never asked at all.
func TestMySQLAllowSkipsTheCedarUnmaskedReaderCheck(t *testing.T) {
	called := false
	got := RedactsDiagnostics(datasource.EngineMySQL, pb.EnfAction_ALLOW, func() bool {
		called = true
		return false
	})
	if got {
		t.Fatal("MySQL ALLOW must not redact")
	}
	if called {
		t.Fatal("the Cedar check must be skipped when the engine cannot leak on ALLOW")
	}
}

// `MySQL MASK or DENY redacts unless the principal reads the datasource unmasked`
func TestMySQLMaskOrDenyRedactsUnlessUnmaskedReader(t *testing.T) {
	if !redact(datasource.EngineMySQL, pb.EnfAction_MASK, false) {
		t.Fatal("MySQL MASK must redact for a non-unmasked reader")
	}
	if !redact(datasource.EngineMySQL, pb.EnfAction_DENY, false) {
		t.Fatal("MySQL DENY must redact for a non-unmasked reader")
	}
	if redact(datasource.EngineMySQL, pb.EnfAction_MASK, true) {
		t.Fatal("MySQL MASK must not redact for an unmasked reader")
	}
}

// `PostgreSQL redacts even an ALLOW unless the principal reads the datasource unmasked`
//
// ⚠️ 06-query-decision.md §7 lists the PG-ALLOW case where the Cedar call IS required to run as a
// coverage gap in the Kotlin suite. The extra assertion below closes it: on PostgreSQL the thunk must
// be invoked even for an ALLOW, because that is exactly where the engine can still leak.
func TestPostgresRedactsEvenAnAllowUnlessUnmaskedReader(t *testing.T) {
	if !redact(datasource.EnginePostgres, pb.EnfAction_ALLOW, false) {
		t.Fatal("PostgreSQL ALLOW must redact for a non-unmasked reader")
	}
	if redact(datasource.EnginePostgres, pb.EnfAction_ALLOW, true) {
		t.Fatal("PostgreSQL ALLOW must not redact for an unmasked reader")
	}
	if !redact(datasource.EnginePostgres, pb.EnfAction_MASK, false) {
		t.Fatal("PostgreSQL MASK must redact for a non-unmasked reader")
	}

	called := false
	RedactsDiagnostics(datasource.EnginePostgres, pb.EnfAction_ALLOW, func() bool {
		called = true
		return true
	})
	if !called {
		t.Fatal("PostgreSQL ALLOW must CONSULT Cedar — the engine can leak even on an allow")
	}
}

// `only PostgreSQL leaks diagnostics on an allowed query`
func TestOnlyPostgresLeaksDiagnosticsOnAnAllowedQuery(t *testing.T) {
	if !LeaksDiagnosticsOnAllow(datasource.EnginePostgres) {
		t.Fatal("PostgreSQL leaks diagnostics on allow")
	}
	if LeaksDiagnosticsOnAllow(datasource.EngineMySQL) {
		t.Fatal("MySQL does not leak diagnostics on allow")
	}
	// The unspecified engine is not PostgreSQL, so it does not leak — which makes MySQL's arm the
	// fail-closed direction here (redact-on-MASK/DENY still applies). Asserted so a future engine
	// added to the enum is a deliberate decision rather than a silent inherit.
	if LeaksDiagnosticsOnAllow(datasource.EngineUnspecified) {
		t.Fatal("only POSTGRES leaks on allow")
	}
}
