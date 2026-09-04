package mysqlproxy

import (
	"errors"
	"testing"
)

// TestSqlModeClassifyUnit locks the ANSI_QUOTES split of the sql_mode guard, which is fail-closed by
// ALLOWLIST: ANSI_QUOTES alone is OBSERVED and forwarded (the analyzer models it via mysql_ansi_quotes, so a
// masked column quoted with " is still masked); a known parse-safe runtime/semantic flag is ignored; and
// ANYTHING ELSE — a known parse-affecting flag the analyzer cannot model (NO_BACKSLASH_ESCAPES /
// PIPES_AS_CONCAT / IGNORE_SPACE / HIGH_NOT_PRECEDENCE) OR a flag this build does not recognize (a future
// MySQL / fork extension) — fails the session closed. Both guard paths (the per-statement probe and the
// SESSION_TRACK invariant check) honor the same allowlist, matching the PG standard_conforming_strings guard.
func TestSqlModeClassifyUnit(t *testing.T) {
	// Known parse-safe flags: ansiQuotes=false, no error.
	safe := []string{"", "STRICT_TRANS_TABLES", "STRICT_TRANS_TABLES,NO_ZERO_DATE",
		"ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION",
		"STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION"}
	for _, m := range safe {
		if aq, err := classifyMySQLSqlMode(m); err != nil || aq {
			t.Errorf("classifyMySQLSqlMode(%q) = (%v, %v), want (false, nil)", m, aq, err)
		}
	}

	// ANSI_QUOTES alone (any case/position/spacing) is observed and forwarded, not failed.
	forwarded := []string{"ANSI_QUOTES", "ansi_quotes", "STRICT_TRANS_TABLES,ANSI_QUOTES", " ansi_quotes "}
	for _, m := range forwarded {
		if aq, err := classifyMySQLSqlMode(m); err != nil || !aq {
			t.Errorf("classifyMySQLSqlMode(%q) = (%v, %v), want (true, nil)", m, aq, err)
		}
	}

	// Everything not on the allowlist fails closed. That covers: the known parse-affecting flags; the
	// EXPANDED components of sql_mode=ANSI (…,PIPES_AS_CONCAT,ANSI_QUOTES,IGNORE_SPACE,…) — MySQL never
	// reports the literal "ANSI", so the guard catches PIPES_AS_CONCAT / IGNORE_SPACE on their own or an ANSI
	// session would look like plain ANSI_QUOTES and slip its || / function-name grammar past the analyzer; an
	// unsafe member alongside an ANSI_QUOTES; a compound-mode LITERAL that never appears expanded
	// (TRADITIONAL / ORACLE); and an UNRECOGNIZED flag (a future MySQL / fork extension), which is the whole
	// point of the allowlist — a denylist would fail OPEN on it.
	unsafe := []string{"NO_BACKSLASH_ESCAPES", "PIPES_AS_CONCAT", "IGNORE_SPACE", "HIGH_NOT_PRECEDENCE", "ANSI",
		"ANSI_QUOTES,NO_BACKSLASH_ESCAPES", "REAL_AS_FLOAT,PIPES_AS_CONCAT,ANSI_QUOTES,IGNORE_SPACE,ONLY_FULL_GROUP_BY",
		"TRADITIONAL", "ORACLE", "SOME_FUTURE_MODE", "STRICT_TRANS_TABLES,MADE_UP_FLAG",
		"STRICT_TRANS_TABLES,ANSI_QUOTES,MADE_UP_FLAG"}
	for _, m := range unsafe {
		if _, err := classifyMySQLSqlMode(m); !errors.Is(err, errUnsafeSqlMode) {
			t.Errorf("classifyMySQLSqlMode(%q) err = %v, want errUnsafeSqlMode", m, err)
		}
	}

	// The SESSION_TRACK invariant path (direct SET, caught on the OK): ANSI_QUOTES alone passes (the probe
	// forwards it instead of failing), while a non-modeled flag fails closed.
	if err := checkSysVarInvariants([]sysVarChange{{name: "sql_mode", value: "STRICT_TRANS_TABLES,ANSI_QUOTES"}}); err != nil {
		t.Errorf("checkSysVarInvariants(ANSI_QUOTES) = %v, want nil (forwarded via probe, not failed)", err)
	}
	if err := checkSysVarInvariants([]sysVarChange{{name: "sql_mode", value: "PIPES_AS_CONCAT"}}); !errors.Is(err, errUnsafeSqlMode) {
		t.Errorf("checkSysVarInvariants(PIPES_AS_CONCAT) = %v, want errUnsafeSqlMode", err)
	}
	if err := checkSysVarInvariants([]sysVarChange{{name: "sql_mode", value: "STRICT_TRANS_TABLES"}}); err != nil {
		t.Errorf("checkSysVarInvariants(safe sql_mode) = %v, want nil", err)
	}
	// sql_mode is a required tracked sysvar now, so dropping it from the list fails closed too.
	if err := requireTrackedMembers("session_track_system_variables,session_track_schema,character_set_client,character_set_connection,character_set_results"); !errors.Is(err, errSessionTrackingDropped) {
		t.Errorf("dropping sql_mode from the tracked list = %v, want errSessionTrackingDropped", err)
	}

	// The per-statement probe path (backstop, catches a tracker bypass): ANSI_QUOTES yields ansiQuotes=true
	// with the namespace; a non-modeled flag fails closed on the 5th column; a safe mode yields false.
	sp := func(s string) *string { return &s }
	if ns, aq, err := interpretSessionProbeRow([]*string{sp("db"), sp("utf8mb4"), sp("utf8mb4"), sp("utf8mb4"), sp("STRICT_TRANS_TABLES,ANSI_QUOTES")}); err != nil || !aq || len(ns) != 1 || ns[0] != "db" {
		t.Errorf("probe row with ANSI_QUOTES = (%v, %v, %v), want ([db], true, nil)", ns, aq, err)
	}
	if _, _, err := interpretSessionProbeRow([]*string{sp("db"), sp("utf8mb4"), sp("utf8mb4"), sp("utf8mb4"), sp("NO_BACKSLASH_ESCAPES")}); !errors.Is(err, errUnsafeSqlMode) {
		t.Errorf("probe row with NO_BACKSLASH_ESCAPES err = %v, want errUnsafeSqlMode", err)
	}
	if ns, aq, err := interpretSessionProbeRow([]*string{sp("db"), sp("utf8mb4"), sp("utf8mb4"), sp("utf8mb4"), sp("STRICT_TRANS_TABLES")}); err != nil || aq || len(ns) != 1 || ns[0] != "db" {
		t.Errorf("probe row with safe sql_mode = (%v, %v, %v), want ([db], false, nil)", ns, aq, err)
	}
}
