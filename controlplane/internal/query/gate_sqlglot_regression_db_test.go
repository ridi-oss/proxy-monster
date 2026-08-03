package query_test

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/query"
)

// GateSqlglotRegressionTest.kt — 129 LOC, 9 cases (06-query-decision.md §7, "whole pipeline, both
// engines").
//
// High-value LINEAGE and CLASSIFICATION regressions driven through the production grant loop. Unlike
// the single-step gate suites, each case here is an end-to-end statement: it asserts what the whole
// pipeline does with a shape that has, at some point, been a bypass.
//
// ⚠️ It runs through [dbtest.EnforcementFixture.Run], whose Kotlin twin `runEnforcedForTest` leaves
// `systemClassification` at its `= null` default (EnforcementHarness.kt:120). So the `query_to_xml`
// deny in case 4 comes from the BASELINE FLOOR, not from a manifest — which is precisely what makes it
// a statement about the floor. The one case that needs a decision rather than a run (case 8, the
// ANSI_QUOTES pair) calls decideQuery directly, as the Kotlin does.
//
// Both fixtures are built once and shared by all nine cases (the Kotlin's `@BeforeAll` + PER_CLASS).
func TestGateSqlglotRegression(t *testing.T) {
	postgres := newEnforcementFixture(t, dbtest.EnginePostgres)
	mysql := newEnforcementFixture(t, dbtest.EngineMySQL)

	// denied is the Kotlin's private helper: DENY, and NO ROWS. Both halves — a DENY that still
	// streamed rows is the failure the suite exists to catch.
	denied := func(t *testing.T, fx *dbtest.EnforcementFixture, sql string) {
		t.Helper()
		r := run(t, fx, sql)
		if action(r) != pb.EnfAction_DENY {
			t.Errorf("must deny: %s; %s", sql, respReason(r))
			return
		}
		if len(r.Rows) != 0 {
			t.Errorf("must deny with no rows: %s; got %d rows", sql, len(r.Rows))
		}
	}
	bothEngines := []*dbtest.EnforcementFixture{postgres, mysql}

	// `reference and membership oracles deny on both engines`
	//
	// A masked column used in a PREDICATE, an IN-subquery, or a set operation is an ORACLE: the caller
	// learns the protected value one comparison at a time without it ever appearing in a result column,
	// so masking the output buys nothing and the statement must deny.
	t.Run("reference and membership oracles deny on both engines", func(t *testing.T) {
		for _, fx := range bothEngines {
			denied(t, fx, "select id from users where rrn = 'secret'")
			denied(t, fx, "select id from users where email in (select rrn from users)")
			denied(t, fx, "select region from users intersect select rrn from users")
		}
	})

	// `unknown table and UNION TABLE forms fail closed`
	t.Run("unknown table and UNION TABLE forms fail closed", func(t *testing.T) {
		for _, fx := range bothEngines {
			denied(t, fx, "select * from no_such_table")
			denied(t, fx, "select 0,'x','x','x' union table users")
		}
	})

	// `derived transforms redact while row-shaping use denies`
	//
	// The two halves are the whole point: a provably-total transform OF a masked column is redacted in
	// full (the derived value could otherwise leak the input), while using the same column to SHAPE THE
	// ROW ORDER is an oracle and denies. Masking cannot save an ORDER BY.
	t.Run("derived transforms redact while row-shaping use denies", func(t *testing.T) {
		for _, fx := range bothEngines {
			redacted := run(t, fx, "select id, upper(rrn) from users")
			if action(redacted) != pb.EnfAction_MASK {
				t.Errorf("decision = %v, want MASK: %s", action(redacted), respReason(redacted))
				continue
			}
			for i, row := range redacted.Rows {
				if len(row) < 2 {
					t.Errorf("row %d has %d cells, want at least 2", i, len(row))
					continue
				}
				if row[1] != nil {
					t.Errorf("row %d: upper(rrn) = %q, want a full NULL redaction", i, *row[1])
				}
			}
			denied(t, fx, "select id from users order by rrn")
		}
	})

	// `query-to-xml and session-state exfiltration stay closed`
	t.Run("query-to-xml and session-state exfiltration stay closed", func(t *testing.T) {
		denied(t, postgres, "select query_to_xml('SELECT rrn FROM users', true, false, '')")
		denied(t, mysql, "set @x=(select rrn from users)")
	})

	// `cast or typed literal to a user type denies through the production walk`
	//
	// A user DOMAIN/type coercion runs its CHECK function on the shared backend session — code
	// execution plus an error-oracle leak. The analyzer marks it INADMISSIBLE; this proves the
	// control-plane walk denies.
	t.Run("cast or typed literal to a user type denies through the production walk", func(t *testing.T) {
		for _, sql := range []string{
			"SELECT CAST('x' AS public.pm_leak_domain)",
			"SELECT 'x'::public.pm_leak_domain",
			"SELECT 1::public.pm_leak_domain FROM users",
		} {
			denied(t, postgres, sql)
		}
	})

	// `schema-qualified user function denies through the production walk`
	//
	// `public.version()` is USER CODE, not the safe metadata `version()` — a user function shadowing a
	// safe name is an exfil vector, so the qualified Function grant must hard-deny.
	t.Run("schema-qualified user function denies through the production walk", func(t *testing.T) {
		denied(t, postgres, "SELECT public.version()")
		denied(t, postgres, "SELECT pm_leak.upper('x')")
	})

	// `non-literal sql_mode assignment denies on MySQL`
	//
	// A session-variable / CONCAT right-hand side can flip the LEXER (ANSI_QUOTES) while the analyzer
	// keeps parsing the default dialect — the analyzer would then be reading a different language than
	// the backend. INADMISSIBLE, and it must deny end to end.
	t.Run("non-literal sql_mode assignment denies on MySQL", func(t *testing.T) {
		denied(t, mysql, "SET sql_mode = @m")
		denied(t, mysql, "SET sql_mode = CONCAT('AN','SI_QUOTES')")
		denied(t, mysql, "SET SESSION sql_mode = @m")
	})

	// 🔒 `MySQL ANSI_QUOTES masks a double-quoted pii column, default mode leaves it a string literal`
	//
	// Under `sql_mode=ANSI_QUOTES` the backend reads `"rrn"` as the pii COLUMN, not a string. Told
	// liveAnsiQuotes=true the analyzer parses it the same way, so the control plane must MASK it instead
	// of skipping it as a literal — that is the whole reason the proxy can forward an ANSI_QUOTES
	// session at all instead of failing it closed. Without the flag (default mode) `"rrn"` is the
	// constant string 'rrn', no pii column is touched, and the answer is ALLOW.
	//
	// Proving BOTH directions is what proves the FLAG is what flips the decision, closing the
	// cleartext-via-quoting bypass. One direction alone would be satisfied by an implementation that
	// ignored the flag entirely. This exercises the liveAnsiQuotes threading
	// (decideQuery → EngineConfig.mysqlAnsiQuotes) through the real analyzer.
	t.Run("MySQL ANSI_QUOTES masks a double-quoted pii column, default mode leaves it a string literal", func(t *testing.T) {
		decide := func(ansiQuotes bool) query.DecisionContext {
			return mysql.DecideWith(query.DecideQueryInput{
				Principal:      dbtest.FixturePrincipal,
				SQL:            `SELECT "rrn" FROM users`,
				Channel:        query.ChannelWire,
				LiveAnsiQuotes: ansiQuotes,
			})
		}

		masked := decide(true)
		wantAction(t, masked, pb.EnfAction_MASK, `ANSI_QUOTES: "rrn" must mask the pii column`)
		found := false
		for _, m := range masked.Masks {
			if m.GetColumn() == "rrn" {
				found = true
			}
		}
		if !found {
			t.Errorf("the rrn mask must be selected under ANSI_QUOTES; masks = %v", masked.Masks)
		}

		allowed := decide(false)
		wantAction(t, allowed, pb.EnfAction_ALLOW, `default mode: "rrn" is a string literal, not the pii column`)
		if len(allowed.Masks) != 0 {
			t.Errorf("default mode must select no mask for a quoted string literal, got %d", len(allowed.Masks))
		}
	})

	// `explain of query and reset master deny through the production walk`
	//
	// EXPLAIN TABLE analyzes `SELECT *` over the ungranted `orders`; DESC ANALYZE PLANS the inner query
	// (an EXPLAIN alias that executes) and inherits its verdict; RESET MASTER is administrative; and the
	// last one is `set_config` hidden behind a PostgreSQL U& escape — the name must be un-escaped before
	// it is classified, or the escape is a bypass.
	t.Run("explain of query and reset master deny through the production walk", func(t *testing.T) {
		denied(t, mysql, "EXPLAIN TABLE orders")
		denied(t, postgres, "DESC ANALYZE SELECT rrn FROM users")
		denied(t, mysql, "RESET MASTER")
		denied(t, postgres, `SELECT U&"set_confi\0067"('search_path','restricted',false)`)
	})
}
