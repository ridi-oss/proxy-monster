package probe

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// Admission-parity corpus: queries spanning every admission-style verdict, run through the Go
// EmitFacts mechanism, asserting the equivalent SECURITY outcome. These verdicts map onto
// StatementFacts as:
//   - Rejected / Denied (batch, unlexable, privilege, injection, user-type, RESET-mysql, set_config,
//     SET-subquery, DESCRIBE-of-query, TABLE-query-block, INTO-OUTFILE) → Resolved=false (fail closed).
//   - no-FROM data-reading function (allowlist deny) → Resolved=true carrying a Function grant; the
//     control-plane function gate then denies any grant whose name isn't a classified-safe builtin
//     (see StatementFactsGrantLoopTest / decideQuery). Here we assert the grant is emitted.
//   - READONLY_META → StatementClass METADATA; TX_CONTROL / SESSION_MUTATING → SESSION;
//     the analyzed classes (SELECT-with-FROM, DML, DDL, SELECT-INTO write) → ANALYZED.
//   - utility facts (SHOW WARNINGS…, SET GLOBAL/PASSWORD) → a Utility grant with the command id.
//   - sql.<kind> → the datasource grant's GrantAction.
// Auxiliary Admission fields that were intentionally dropped in the migration (statementVerb,
// statementToAnalyze, explainStripped, transactionBoundary) are not asserted — the behavior they drove
// now lives in the facts (class/grants), which the cases below cover.

func factsFor(t *testing.T, sql string, dialect string) *pb.StatementFacts {
	if dialect == "mysql" {
		return mysqlFacts(t, sql)
	}
	return postgresFacts(t, sql)
}

func bothDialects(fn func(string)) {
	fn("postgres")
	fn("mysql")
}

func parityDenied(t *testing.T, sql, dialect string) {
	t.Helper()
	f := factsFor(t, sql, dialect)
	if f.Resolved {
		t.Errorf("[%s] expected fail-closed (Resolved=false) for %q, got class=%s grants=%d", dialect, sql, f.StatementClass, len(f.RequiredGrants))
	}
}

func parityFunctionGrant(t *testing.T, sql, dialect string) {
	t.Helper()
	f := factsFor(t, sql, dialect)
	has := false
	for _, g := range f.RequiredGrants {
		if g.GetFunction() != nil {
			has = true
		}
	}
	if !has {
		t.Errorf("[%s] expected a Function grant (control-plane denies unclassified) for %q, got resolved=%v grants=%d", dialect, sql, f.Resolved, len(f.RequiredGrants))
	}
}

// parityFunctionGated asserts the control-plane will gate the named function — it appears EITHER as a
// no-FROM Function grant OR in facts.functions (the with-FROM function-fact list). decideQuery denies a
// function grant whose name isn't classified-safe, and denies a facts.functions entry classified
// dangerous — so either home means the statement is gated on that function.
func parityFunctionGated(t *testing.T, sql, dialect, name string) {
	t.Helper()
	f := factsFor(t, sql, dialect)
	for _, g := range f.RequiredGrants {
		if fn := g.GetFunction(); fn != nil && fn.Name == name {
			return
		}
	}
	for _, fn := range f.Functions {
		if fn == name {
			return
		}
	}
	t.Errorf("[%s] %q: expected function %q gated (grant or facts.functions), got resolved=%v grants=%d functions=%v", dialect, sql, name, f.Resolved, len(f.RequiredGrants), f.Functions)
}

func parityClass(t *testing.T, sql, dialect string, want pb.StatementClass) {
	t.Helper()
	f := factsFor(t, sql, dialect)
	if !f.Resolved || f.StatementClass != want {
		t.Errorf("[%s] %q: want resolved+%s, got resolved=%v class=%s (detail=%s)", dialect, sql, want, f.Resolved, f.StatementClass, f.Detail)
	}
}

func parityUtility(t *testing.T, sql, dialect, command string) {
	t.Helper()
	f := factsFor(t, sql, dialect)
	found := false
	for _, g := range f.RequiredGrants {
		if u := g.GetUtility(); u != nil && u.Command == command {
			found = true
		}
	}
	if !found {
		t.Errorf("[%s] %q: expected utility grant %q, not present (resolved=%v)", dialect, sql, command, f.Resolved)
	}
}

func parityNoUtility(t *testing.T, sql, dialect string) {
	t.Helper()
	f := factsFor(t, sql, dialect)
	for _, g := range f.RequiredGrants {
		if g.GetUtility() != nil {
			t.Errorf("[%s] %q: expected NO utility grant, got %q", dialect, sql, g.GetUtility().Command)
		}
	}
}

func parityDatasourceAction(t *testing.T, sql, dialect string, action pb.GrantAction) {
	t.Helper()
	f := factsFor(t, sql, dialect)
	found := false
	for _, g := range f.RequiredGrants {
		if g.GetDatasource() && g.Action == action {
			found = true
		}
	}
	if !found {
		t.Errorf("[%s] %q: expected datasource grant %s, not present (resolved=%v grants=%d)", dialect, sql, action, f.Resolved, len(f.RequiredGrants))
	}
}

// parityColumnGrant asserts the statement resolves and emits a result grant for the named column — proof
// the column read was traced and will be gated (masked/denied) rather than slipping through unenforced.
func parityColumnGrant(t *testing.T, sql, dialect, column string) {
	t.Helper()
	f := factsFor(t, sql, dialect)
	for _, g := range f.RequiredGrants {
		if c := g.GetColumn(); c != nil && c.GetIdentity().GetColumn() == column {
			return
		}
	}
	t.Errorf("[%s] %q: expected a column grant for %q (read must be gated), got resolved=%v grants=%d", dialect, sql, column, f.Resolved, len(f.RequiredGrants))
}

func TestParityBatchAndLex(t *testing.T) {
	for _, sql := range []string{
		"SELECT 1; SELECT 2",
		"SELECT 1; DROP TABLE x",
		"SELECT 1 -- x\r; SELECT ssn FROM users",
		"SET x = 'a\\'; SELECT ssn FROM users; --'",
		"SELECT 'unterminated",
		"SELECT id /* unterminated",
		"SELECT $$unterminated",
		"", "   \n\t ", ";", ";;", "-- just a comment",
	} {
		parityDenied(t, sql, "postgres")
	}
	for _, sql := range []string{
		"SELECT 1--2; SELECT ssn FROM users",
		"# just a comment",
	} {
		parityDenied(t, sql, "mysql")
	}
	// MySQL executable comments are not blanket-rejected — with a known server version the analyzer
	// decodes them and analyzes the real statement (`SELECT 1 /*! , ssn FROM users */` → traces ssn, which
	// the column gate then masks/denies).
	if f := mysqlFacts(t, "SELECT 1 /*! , ssn FROM users */"); !f.Resolved {
		t.Errorf("executable comment should now be analyzed, not rejected: %s", f.Detail)
	}
	// Single statements / trailing semicolons / semicolons inside quotes are NOT batches.
	for _, sql := range []string{"SELECT 1", "SELECT 1;", "SELECT 1;   \n\t"} {
		f := postgresFacts(t, sql)
		if !f.Resolved {
			t.Errorf("single statement %q wrongly denied: %s", sql, f.Detail)
		}
	}
}

func TestParityPrivilegeAndLexerMutation(t *testing.T) {
	// Session-privilege / lexer-mutation SETs are the "engine-safety" danger set: they RESOLVE carrying a
	// system-classified Utility grant, and the control-plane's shipped system:critical floor forbids it —
	// a Cedar decision (preset-relaxable), not a hard admission deny. Both spellings of the identity
	// change — keyword (SET ROLE) and GUC-alias (SET role = x) — map to the same command.
	// The GUC-alias assignment forms (SET role = x / SET SESSION role = x) structure as a readable EQ on
	// both engines → SET_ROLE. The KEYWORD forms SET ROLE / SET DEFAULT ROLE now structure on BOTH engines
	// (sqlglot-go v0.18+ structures MySQL SET ROLE / SET DEFAULT ROLE off SetItem.kind), so they gate as the
	// SET_ROLE system:critical Utility — the shipped floor-forbid denies it, a Cedar decision rather than a
	// hard admission deny.
	bothDialects(func(d string) {
		for _, sql := range []string{"SET role = attacker", "SET SESSION role = attacker"} {
			parityUtility(t, sql, d, "SET_ROLE")
		}
	})
	parityUtility(t, "SET ROLE admin", "postgres", "SET_ROLE")
	parityUtility(t, "SET ROLE admin", "mysql", "SET_ROLE")
	// SET DEFAULT ROLE (MySQL) persistently reconfigures a user's default roles — a distinct privileged
	// statement (SetItem.kind="DEFAULT ROLE") gating as its own SET_DEFAULT_ROLE system:critical command; it
	// must not slip through as a benign passthrough now that it structures (it would, without an explicit
	// kind case). Every operand shape, plus the exec-comment spelling, keeps the kind.
	for _, sql := range []string{
		"SET DEFAULT ROLE NONE TO u", "SET DEFAULT ROLE ALL TO u", "SET DEFAULT ROLE admin TO u",
		"SET DEFAULT ROLE r1, r2 TO u1, u2", "SET /*! DEFAULT ROLE */ admin TO acme",
	} {
		parityUtility(t, sql, "mysql", "SET_DEFAULT_ROLE")
	}
	// A role/default-role/credential item buried in a multi-item SET fails closed to Command (sqlglot-go's
	// standalone guard rejects the list) → denied, never a passthrough that smuggles the privileged item.
	for _, sql := range []string{"SET NAMES utf8, ROLE admin", "SET NAMES utf8, DEFAULT ROLE admin TO u", "SET @x = 1, DEFAULT ROLE r TO u"} {
		parityDenied(t, sql, "mysql")
	}
	for _, sql := range []string{"SET SESSION AUTHORIZATION bob", "SET session_authorization = attacker"} {
		parityUtility(t, sql, "postgres", "SET_SESSION_AUTHORIZATION")
	}
	// A SET whose RHS reads data (subquery / unsafe function) → SET_SUBQUERY; a cast to a user type →
	// USER_TYPE_CAST. Both system:critical (the whole-statement gate; per-column masking of the read is
	// backlogged). A top-level TABLE query-primary in the RHS is still a fail-closed structural deny.
	bothDialects(func(d string) {
		for _, sql := range []string{
			"SET @x = (SELECT ssn FROM users LIMIT 1)", "SET @x = leak_ssn()", "SET @x = acme.leak_ssn()",
			"SET @x = query_to_xml('SELECT ssn FROM users', true, false, '')", "SET @x = (VALUES ROW(1))",
		} {
			parityUtility(t, sql, d, "SET_SUBQUERY")
		}
		parityDenied(t, "SET @x = (TABLE users LIMIT 1)", d)
		// set_config() is a dangerous function — gated via the Function path (already Cedar-decided).
		parityFunctionGated(t, "SELECT set_config('search_path','restricted',false)", d, "set_config")
	})
	for _, sql := range []string{"SET @x = CAST('x' AS public.pm_leak_domain)", "SET @x = 'x'::public.pm_leak_domain"} {
		parityUtility(t, sql, "postgres", "USER_TYPE_CAST")
	}
	// Lexer-mutation SETs (a value that flips the SQL lexer, or one the analyzer can't read) → Utility.
	for _, sql := range []string{
		"SET sql_mode='ANSI_QUOTES'", "SET sql_mode = 'NO_BACKSLASH_ESCAPES'", "SET sql_mode=ANSI",
		"SET sql_mode='STRICT_TRANS_TABLES,ANSI_QUOTES'", "SET sql_mode=CONCAT(@@sql_mode,',ANSI_QUOTES')",
	} {
		parityUtility(t, sql, "mysql", "SET_SQL_MODE")
	}
	parityUtility(t, "SET standard_conforming_strings = off", "postgres", "SET_STANDARD_CONFORMING_STRINGS")
	parityFunctionGated(t, "SELECT x FROM (SELECT set_config('search_path','restricted',false) AS x) t", "postgres", "set_config")
	parityUtility(t, "SET GLOBAL max_connections = 100", "mysql", "SET_GLOBAL")
	parityUtility(t, "SET PASSWORD = 'x'", "mysql", "SET_PASSWORD")
	// A SET to a safe builtin value stays a benign session mutation.
	bothDialects(func(d string) { parityClass(t, "SET @x = version()", d, pb.StatementClass_STATEMENT_CLASS_SESSION) })
}

func TestParityMySQLResetFamily(t *testing.T) {
	for _, sql := range []string{
		"RESET MASTER", "RESET BINARY LOGS AND GTIDS", "RESET REPLICA", "RESET SLAVE", "RESET SLAVE ALL",
		"RESET PERSIST", "RESET QUERY CACHE",
	} {
		parityDenied(t, sql, "mysql")
	}
	// PostgreSQL RESET is a benign session reset → SESSION passthrough.
	for _, sql := range []string{"RESET search_path", "RESET ALL", "RESET ROLE", "RESET SESSION AUTHORIZATION", "RESET TIME ZONE"} {
		parityClass(t, sql, "postgres", pb.StatementClass_STATEMENT_CLASS_SESSION)
	}
}

// TestParityPGTransactionCharacteristics guards the sqlglot-go v0.20.0 fix. The uniform Command-SET
// fail-close denies any SET that degrades to Kind=Command; before v0.20.0 the PG transaction-
// characteristics forms carrying [NOT] DEFERRABLE degraded to Command and were false-denied, even though
// they carry no privilege or lexer mutation. v0.20.0 makes them structure as readable session SETs, so
// they resolve to a benign SESSION passthrough. The comma form and single-mode work; the space-separated
// multi-mode form ("READ ONLY DEFERRABLE") is a documented degrade that still lands as Command → denied.
func TestParityPGTransactionCharacteristics(t *testing.T) {
	for _, sql := range []string{
		"SET TRANSACTION DEFERRABLE",
		"SET TRANSACTION NOT DEFERRABLE",
		"SET SESSION CHARACTERISTICS AS TRANSACTION DEFERRABLE",
		"SET SESSION CHARACTERISTICS AS TRANSACTION NOT DEFERRABLE",
		"SET TRANSACTION READ ONLY, DEFERRABLE",
	} {
		parityClass(t, sql, "postgres", pb.StatementClass_STATEMENT_CLASS_SESSION)
	}
	// Documented boundary, not a desired end-state: space-separated multi-mode still degrades to Command.
	parityDenied(t, "SET TRANSACTION READ ONLY DEFERRABLE", "postgres")
}

func TestParityUnicodeEscape(t *testing.T) {
	// U& literals now DECODE (v0.10.0): the set_config alias resolves to the real function and is gated.
	parityFunctionGrant(t, "SELECT U&\"set_confi\\0067\"('search_path','x',false)", "postgres")
	parityFunctionGrant(t, "SELECT x FROM (SELECT U&\"set_confi\\0067\"('search_path','x',false) AS x) t", "postgres")
	// Benign bitwise-and is unaffected (not mistaken for a U& literal).
	if f := postgresFacts(t, "SELECT id & 1 FROM users"); !f.Resolved {
		t.Errorf("benign & wrongly denied: %s", f.Detail)
	}
}

func TestParityUserTypeAndTableBlock(t *testing.T) {
	// User-type / DOMAIN casts (every position + spelling) resolve carrying a USER_TYPE_CAST Utility grant
	// (system:critical) — the type's coercion / CHECK runs user code. PostgreSQL cast syntax (::, typed literal).
	for _, sql := range []string{
		"SELECT CAST('x' AS public.pm_leak_domain)", "SELECT 'x'::public.pm_leak_domain",
		"SELECT 'x'::pm_leak_domain", "SELECT public.pm_leak_domain 'x'",
		"SELECT \"pm_leak_domain\" 'x'", "SELECT CAST('x' AS \"pm_leak_domain\")",
		"SELECT pm_leak.\"text\" 'x'", "SELECT 'x'::pm_leak.text",
	} {
		parityUtility(t, sql, "postgres", "USER_TYPE_CAST")
	}
	// An array typed literal (`type[] '{…}'`) doesn't parse to a Cast the DataType walk catches — it stays
	// a fail-closed structural deny (safe, never a leak). And a top-level TABLE query-primary reading a
	// table with no FROM word is likewise a structural deny.
	parityDenied(t, "SELECT pm_leak.pm_leak_domain[] '{x}'", "postgres")
	bothDialects(func(d string) { parityDenied(t, "SELECT (TABLE users)", d) })
	// A qualified user FUNCTION call whose leaf shadows a builtin is gated as a function (call syntax),
	// not a typed-literal — same deny outcome via the function path.
	parityFunctionGated(t, "SELECT pm_leak.\"text\"('x')", "postgres", "pm_leak.text")
	// Built-in casts / typed literals stay readonly-meta chatter.
	for _, sql := range []string{
		"SELECT 1::int", "SELECT '1'::integer", "SELECT 'x'::text", "SELECT now()::date",
		"SELECT '2020-01-01'::timestamp", "SELECT CAST('1' AS numeric(10,2))", "SELECT CAST(1 AS double precision)",
		"SELECT DATE '2020-01-01'", "SELECT INTERVAL '1' DAY", "SELECT 'x'::pg_catalog.text", "SELECT '{1,2}'::int[]",
	} {
		parityClass(t, sql, "postgres", pb.StatementClass_STATEMENT_CLASS_METADATA)
	}
	parityClass(t, "SELECT CAST('1' AS SIGNED)", "mysql", pb.StatementClass_STATEMENT_CLASS_METADATA)
	parityClass(t, "SET @x = CAST('1' AS SIGNED)", "mysql", pb.StatementClass_STATEMENT_CLASS_SESSION)
	// A top-level TABLE query-primary reading a table with no FROM word is denied.
	bothDialects(func(d string) {
		for _, sql := range []string{"select 0,'x','x','x' union table users", "SELECT 1 UNION ALL TABLE users", "select 1 intersect table users"} {
			parityDenied(t, sql, d)
		}
	})
}

func TestParityShowDescribe(t *testing.T) {
	// Data-bearing / diagnostic SHOWs (MySQL) emit a utility fact; injection SHOWs are denied; ordinary
	// metadata passes. (On PostgreSQL, `SHOW warnings` is a benign GUC read, not the diagnostics buffer —
	// it parses to a Command and is metadata passthrough, tested in TestParityShowPgGuc.)
	parityUtility(t, "SHOW WARNINGS", "mysql", "SHOW_WARNINGS")
	parityUtility(t, "SHOW ERRORS", "mysql", "SHOW_ERRORS")
	parityUtility(t, "SHOW PROCESSLIST", "mysql", "SHOW_PROCESSLIST")
	parityUtility(t, "SHOW FULL PROCESSLIST", "mysql", "SHOW_PROCESSLIST")
	parityUtility(t, "SHOW BINLOG EVENTS", "mysql", "SHOW_BINLOG_EVENTS")
	parityUtility(t, "SHOW RELAYLOG EVENTS", "mysql", "SHOW_RELAYLOG_EVENTS")
	parityUtility(t, "SHOW ENGINE INNODB STATUS", "mysql", "SHOW_ENGINE_STATUS")
	// A SHOW with a subquery / unsafe-function WHERE reads data outside a plain query → SHOW_SUBQUERY
	// Utility grant (system:critical). Same fail-closed outcome as before, now a Cedar decision.
	for _, sql := range []string{
		"SHOW TABLES WHERE UPDATEXML(1, CONCAT(0x7e, (SELECT ssn FROM users LIMIT 1), 0x7e), 1)",
		"SHOW TABLES WHERE Tables_in_db IN (SELECT ssn FROM users)",
		"SHOW COLUMNS FROM users WHERE extractvalue(1, concat(0x7e, (SELECT ssn FROM users), 0x7e))",
	} {
		parityUtility(t, sql, "mysql", "SHOW_SUBQUERY")
	}
	for _, sql := range []string{
		"SHOW TABLES", "SHOW DATABASES", "SHOW COLUMNS FROM users", "SHOW TABLES FROM acme",
		"SHOW TABLES LIKE 'user%'", "SHOW CREATE TABLE users", "SHOW ENGINES", "SHOW STATUS",
		"SHOW VARIABLES", "SHOW TABLE STATUS",
	} {
		parityClass(t, sql, "mysql", pb.StatementClass_STATEMENT_CLASS_METADATA)
		parityNoUtility(t, sql, "mysql")
	}
	// DESCRIBE/DESC of a query (EXPLAIN alias) is now ANALYZED as its inner query — it inherits the
	// inner's column enforcement (ssn gets a column grant that masks/denies) rather than a blanket
	// admission deny. Assert it's resolved+analyzed (the inner query's grants apply, so ssn is protected).
	bothDialects(func(d string) {
		for _, sql := range []string{
			"DESC ANALYZE SELECT UUID_TO_BIN(ssn) FROM users LIMIT 1",
			"DESCRIBE ANALYZE SELECT UUID_TO_BIN(ssn) FROM users LIMIT 1",
		} {
			f := factsFor(t, sql, d)
			if !f.Resolved || f.StatementClass != pb.StatementClass_STATEMENT_CLASS_ANALYZED {
				t.Errorf("[%s] %q: want resolved+ANALYZED (inner-query enforcement), got resolved=%v class=%s", d, sql, f.Resolved, f.StatementClass)
			}
		}
	})
	for _, sql := range []string{"DESC users", "DESCRIBE users", "DESCRIBE users col_name"} {
		parityClass(t, sql, "mysql", pb.StatementClass_STATEMENT_CLASS_METADATA)
	}
}

func TestParityNoFromDataReaders(t *testing.T) {
	// no-FROM SELECT calling a data/file reader → a Function grant the control-plane denies.
	bothDialects(func(d string) {
		for _, sql := range []string{
			"SELECT query_to_xml('SELECT ssn FROM users WHERE id = 1', true, false, '')",
			"SELECT leak_ssn()",
		} {
			parityFunctionGrant(t, sql, d)
		}
	})
	for _, sql := range []string{
		"SELECT table_to_xml('users', true, false, '')",
		"SELECT database_to_xml(true, false, '')",
		"SELECT pg_read_file('/etc/passwd')",
		"SELECT \"query_to_xml\"('SELECT ssn FROM users', true, false, '')",
		"SELECT public.version()", "SELECT public.now()", "SELECT app.get_ssn()",
		"SELECT pm_leak.filter()", "SELECT pm_leak.\"text\"('x')",
	} {
		parityFunctionGrant(t, sql, "postgres")
	}
	for _, sql := range []string{"SELECT load_file('/etc/passwd')", "SELECT mydb.leak()"} {
		parityFunctionGrant(t, sql, "mysql")
	}
	// A keyword-argument FROM must NOT mask an unsafe function (old KNOWN GAP, closed by the migration).
	parityFunctionGrant(t, "select substring('abc' from 1), leak_ssn()", "postgres")
}

func TestParityNoFromSafeChatter(t *testing.T) {
	// Parenful safe builtins + literals + a peeled top-level (SELECT 1) wrapper stay readonly-meta chatter.
	safe := []string{
		"SELECT 1", "SELECT 1 + 1", "SELECT (1 + 2) * 3", "SELECT 'x'", "SELECT 'from x'",
		"SELECT VERSION()", "SELECT current_schema()", "SELECT current_database()",
		"SELECT now()", "SELECT pg_backend_pid()",
		"SELECT current_setting('TIMEZONE')", "SELECT CAST('1' AS INTEGER)", "SELECT coalesce(NULL, 1)",
		"SELECT upper('abc')", "(SELECT 1)", "SELECT pg_catalog.version()",
		// Postgres-only bare (parenless) niladic system functions — modeled as dedicated function nodes
		// since sqlglot-go v0.14.0, so they resolve as safe chatter rather than over-denying as
		// unresolvable columns.
		"SELECT session_user", "SELECT current_catalog", "SELECT current_schema",
	}
	for _, sql := range safe {
		parityClass(t, sql, "postgres", pb.StatementClass_STATEMENT_CLASS_METADATA)
	}
	// Bare niladics valid AND modeled (v0.14.0) in BOTH engines.
	bothDialects(func(d string) {
		for _, sql := range []string{
			"SELECT current_user", "SELECT current_timestamp", "SELECT current_date",
			"SELECT current_time", "SELECT localtime", "SELECT localtimestamp",
		} {
			parityClass(t, sql, d, pb.StatementClass_STATEMENT_CLASS_METADATA)
		}
	})
	for _, sql := range []string{"SELECT @@version_comment", "SELECT DATABASE()", "SELECT USER()", "SELECT CONNECTION_ID()", "SELECT last_insert_id()"} {
		parityClass(t, sql, "mysql", pb.StatementClass_STATEMENT_CLASS_METADATA)
	}
}

// TestParityNiladicRemainingOverDeny documents the one niladic still over-denied after v0.14.0's
// bare-keyword fix: current_role has no bare keyword in either engine, so it parses as a Column that fails lineage
// (fail-safe, not a leak). current_schema is dual — bare is a safe function (above), but the typed-literal
// form `current_schema 'x'` is a user-type cast and still denies.
func TestParityNiladicRemainingOverDeny(t *testing.T) {
	bothDialects(func(d string) { parityDenied(t, "SELECT current_role", d) })
	// current_schema is dual: bare → function (safe); `current_schema 'x'` is a typed literal to type
	// current_schema → USER_TYPE_CAST Utility grant (system:critical).
	parityUtility(t, "SELECT current_schema 'x'", "postgres", "USER_TYPE_CAST")
}

func TestParityBenignSessionAndTx(t *testing.T) {
	// PostgreSQL: benign session config STRUCTURES → SESSION passthrough. Single- and multi-value assignments
	// (incl. LOCAL / SESSION scope), quoted SET NAMES, autocommit, timezone, and the lexer gucs with a safe
	// value all structure and stay a benign SESSION passthrough — pm fully supports search_path / charset
	// changes, which the connection layer relays, tracks, and re-probes.
	for _, sql := range []string{
		"SET search_path TO public", "SET LOCAL search_path TO x", "SET SESSION search_path = a, b",
		"SET NAMES 'utf8'", "set autocommit=0", "SET sql_mode='STRICT_TRANS_TABLES'",
		"SET standard_conforming_strings = on", "SET TIME ZONE 'UTC'",
	} {
		parityClass(t, sql, "postgres", pb.StatementClass_STATEMENT_CLASS_SESSION)
	}
	// A PG SET that DEGRADES to Command is fail-closed UNIFORMLY. No
	// BENIGN form degrades — unquoted `SET NAMES utf8mb4` is invalid PG (only the quoted form is valid PG and
	// structures), so its denial is correct fail-closed, not a false-deny.
	parityDenied(t, "SET NAMES utf8mb4", "postgres")
	// MySQL: the forms that structure stay SESSION. A MySQL SET that reaches Command is fail-closed — the
	// SAME uniform fail-close as PG — so a PostgreSQL-only spelling that degrades here (SET TIME ZONE, which
	// MySQL spells `SET time_zone=`, or a multi-value `search_path` list) is denied. Both are invalid MySQL.
	for _, sql := range []string{
		"SET NAMES utf8mb4", "set autocommit=0", "SET sql_mode='STRICT_TRANS_TABLES'",
		"SET standard_conforming_strings = on", "SET search_path TO public",
	} {
		parityClass(t, sql, "mysql", pb.StatementClass_STATEMENT_CLASS_SESSION)
	}
	for _, sql := range []string{"SET TIME ZONE 'UTC'", "SET SESSION search_path = a, b"} {
		parityDenied(t, sql, "mysql")
	}
	for _, sql := range []string{"USE analytics", "USE `analytics`", "/* c */ use analytics", "ANALYZE TABLE users"} {
		parityClass(t, sql, "mysql", pb.StatementClass_STATEMENT_CLASS_SESSION)
	}
	for _, sql := range []string{"BEGIN", "COMMIT", "ROLLBACK"} {
		parityClass(t, sql, "postgres", pb.StatementClass_STATEMENT_CLASS_SESSION)
	}
	// START TRANSACTION (with any transaction modes) parses to a Transaction root since v0.14.0 and joins
	// the SESSION passthrough family on both engines.
	bothDialects(func(d string) { parityClass(t, "START TRANSACTION", d, pb.StatementClass_STATEMENT_CLASS_SESSION) })
	for _, sql := range []string{
		"START TRANSACTION READ ONLY",
		"START TRANSACTION ISOLATION LEVEL SERIALIZABLE",
		"START TRANSACTION READ WRITE, DEFERRABLE",
	} {
		parityClass(t, sql, "postgres", pb.StatementClass_STATEMENT_CLASS_SESSION)
	}
	parityClass(t, "START TRANSACTION WITH CONSISTENT SNAPSHOT", "mysql", pb.StatementClass_STATEMENT_CLASS_SESSION)
}

func TestParitySqlKind(t *testing.T) {
	bothDialects(func(d string) {
		parityDatasourceAction(t, "select id from users", d, pb.GrantAction_GRANT_ACTION_SQL_SELECT)
		parityDatasourceAction(t, "insert into users values(1)", d, pb.GrantAction_GRANT_ACTION_SQL_INSERT)
		parityDatasourceAction(t, "update users set region='x'", d, pb.GrantAction_GRANT_ACTION_SQL_UPDATE)
		parityDatasourceAction(t, "delete from users where id=1", d, pb.GrantAction_GRANT_ACTION_SQL_DELETE)
		parityDatasourceAction(t, "create table t (id int)", d, pb.GrantAction_GRANT_ACTION_SQL_DDL)
		parityDatasourceAction(t, "alter table users add c int", d, pb.GrantAction_GRANT_ACTION_SQL_DDL)
		parityDatasourceAction(t, "drop table users", d, pb.GrantAction_GRANT_ACTION_SQL_DDL)
		parityDatasourceAction(t, "truncate table users", d, pb.GrantAction_GRANT_ACTION_SQL_DDL)
		// CTE-header strip: classify off the real leading verb.
		parityDatasourceAction(t, "with c as (select 1) select * from c", d, pb.GrantAction_GRANT_ACTION_SQL_SELECT)
		// EXPLAIN inherits the wrapped statement's kind.
		parityDatasourceAction(t, "explain insert into users values(1)", d, pb.GrantAction_GRANT_ACTION_SQL_INSERT)
	})
	// SELECT .. INTO is a write (DDL), and a no-FROM SELECT INTO is a write, not readonly-meta.
	parityDatasourceAction(t, "select id into leaked from users", "postgres", pb.GrantAction_GRANT_ACTION_SQL_DDL)
	bothDialects(func(d string) {
		parityClass(t, "select 1 into stmt_gate_bypass", d, pb.StatementClass_STATEMENT_CLASS_ANALYZED)
	})
	// A data-modifying CTE (a write in the CTE body) is fail-closed: sqlglot-go does not model it, so it
	// resolves false at VALIDATE ("data-modifying CTE not supported") and the grant-walk denies it. The
	// outer verb still classifies SQL_SELECT, so this is ALSO the tripwire for the day sqlglot-go gains
	// data-modifying-CTE support — resolved would flip true and the bare SQL_SELECT kind would then need a
	// real write classification before it could be trusted. Verified fail-closed through sqlglot-go v0.20.0.
	for _, sql := range []string{
		"with t as (insert into users values (1) returning id) select id from t",
		"with t as (update users set region='x' returning id) select id from t",
		"with t as (delete from users where id=1 returning id) select id from t",
	} {
		parityDenied(t, sql, "postgres")
	}
}

func TestParityUpsertAdditionalGrant(t *testing.T) {
	hasUpdate := func(sql, dialect string) bool {
		f := factsFor(t, sql, dialect)
		for _, g := range f.RequiredGrants {
			if g.GetDatasource() && g.Action == pb.GrantAction_GRANT_ACTION_SQL_UPDATE {
				return true
			}
		}
		return false
	}
	for _, tc := range []struct {
		sql, dialect string
		wantUpdate   bool
	}{
		{"insert into users (id) values (1) on conflict (id) do update set region = 'x'", "postgres", true},
		{"insert into users (id, region) values (1, 'x') on duplicate key update region = 'x'", "mysql", true},
		{"insert into users (id) values (1) on conflict (id) do nothing", "postgres", false},
		{"insert into users (id) values (1)", "postgres", false},
	} {
		if got := hasUpdate(tc.sql, tc.dialect); got != tc.wantUpdate {
			t.Errorf("[%s] %q: upsert-adds-update = %v, want %v", tc.dialect, tc.sql, got, tc.wantUpdate)
		}
	}
}

// TestParityInjectionVariants locks the batch/comment/dollar-quote injection surface: a `;` that opens a
// REAL second statement (reading ssn, or a DROP) is a batch → fail closed; a `;` buried in a line comment,
// block comment, or dollar-quoted string does NOT split, so the injected ssn read is inert chatter, not a
// hidden read. The security property is that the injected ssn read never executes silently.
func TestParityInjectionVariants(t *testing.T) {
	// A real second statement after the comment/string closes → batch → deny.
	parityDenied(t, "SELECT 1; /* c */ SELECT ssn FROM users", "postgres")
	parityDenied(t, "SELECT 1; SELECT ssn FROM users", "postgres")
	parityDenied(t, "SELECT $$'$$; SELECT ssn FROM users", "postgres")
	parityDenied(t, "SELECT $tag$'$tag$; SELECT ssn FROM users", "postgres")
	parityDenied(t, "SET a=1; SELECT ssn FROM users", "mysql")
	bothDialects(func(d string) { parityDenied(t, "EXPLAIN SELECT 1; DROP TABLE x", d) })
	// The `;` and the ssn read are commented out / inside a comment → a single benign `SELECT 1`, not a
	// batch and not an ssn read. Resolves as ordinary chatter (proves the injected read is truly absent).
	for _, sql := range []string{
		"SELECT 1 -- ; SELECT ssn FROM users",
		"SELECT /* ; SELECT ssn FROM users */ 1",
	} {
		parityClass(t, sql, "postgres", pb.StatementClass_STATEMENT_CLASS_METADATA)
	}
	parityClass(t, "SELECT 1 # c ; SELECT ssn FROM users", "mysql", pb.StatementClass_STATEMENT_CLASS_METADATA)
}

// TestParitySetVariantSpellings locks the alternate spellings of the privilege / session-mutation SETs:
// quoted GUC-alias, keyword-in-executable-comment, TO-form, subquery RHS. Each must reach the same outcome
// as its canonical spelling (privilege → deny; SET GLOBAL → utility).
func TestParitySetVariantSpellings(t *testing.T) {
	// Privilege SETs in alternate spellings — quoted GUC-alias, TO-form, LOCAL scope — all resolve to a
	// system-classified Utility grant (the shipped system:critical floor forbids it).
	parityUtility(t, `SET "role" TO x`, "postgres", "SET_ROLE")
	parityUtility(t, "SET session_authorization TO x", "postgres", "SET_SESSION_AUTHORIZATION")
	parityUtility(t, "SET LOCAL ROLE x", "postgres", "SET_ROLE")
	// A subquery RHS reads data → SET_SUBQUERY Utility grant (system:critical).
	parityUtility(t, "SET SESSION x = (SELECT ssn FROM users)", "postgres", "SET_SUBQUERY")
	// MySQL executable comments hide the keyword form: /*! role */ decodes to the keyword SET ROLE, which
	// structures (sqlglot-go v0.18+) off SetItem.kind → SET_ROLE system:critical Utility. /*!global*/
	// decodes to a structured SET GLOBAL → Utility. The analyzer decodes the comment and classifies the real
	// statement either way.
	parityUtility(t, "SET /*! role */ admin", "mysql", "SET_ROLE")
	parityUtility(t, "SET /*!global*/ x=1", "mysql", "SET_GLOBAL")
}

// TestParityFunctionVariantSpellings locks the alternate spellings of a dangerous function call —
// double-quoted, schema-qualified, and wrapped in a parenthesized query-primary — each must still be gated
// on the underlying function name.
func TestParityFunctionVariantSpellings(t *testing.T) {
	parityFunctionGated(t, `SELECT "set_config"('role','admin',false)`, "postgres", "set_config")
	parityFunctionGated(t, "SELECT pg_catalog.set_config('search_path','evil',false)", "postgres", "set_config")
	parityFunctionGated(t, "SELECT pg_catalog.query_to_xml('SELECT ssn FROM users', true, false, '')", "postgres", "query_to_xml")
	parityFunctionGated(t, "SELECT query_to_xmlschema('SELECT ssn FROM users', true, false, '')", "postgres", "query_to_xmlschema")
	parityFunctionGated(t, "(SELECT table_to_xml('users', true, false, ''))", "postgres", "table_to_xml")
}

// TestParityIntoWriteAndExplainInner locks two lineage-through-a-wrapper properties: SELECT ... INTO (a
// file, a variable, or nested in a UNION branch) is a write requiring sql.ddl, and EXPLAIN ANALYZE of a
// query EXECUTES the inner statement, so its columns (ssn) must be traced and gated — an EXPLAIN wrapper is
// not a metadata escape hatch.
func TestParityIntoWriteAndExplainInner(t *testing.T) {
	for _, sql := range []string{
		"SELECT 1 INTO OUTFILE '/tmp/x'",
		"SELECT ssn INTO OUTFILE '/tmp/x' FROM users",
		"(SELECT 1) UNION SELECT 1 INTO @a",
	} {
		parityDatasourceAction(t, sql, "mysql", pb.GrantAction_GRANT_ACTION_SQL_DDL)
	}
	// An INTO buried in a UNION branch is still a write AND its ssn read is column-gated.
	exfil := "SELECT id FROM users WHERE 1=0 UNION (SELECT ssn INTO @pm_leak FROM users LIMIT 1)"
	parityDatasourceAction(t, exfil, "mysql", pb.GrantAction_GRANT_ACTION_SQL_DDL)
	parityColumnGrant(t, exfil, "mysql", "ssn")
	// EXPLAIN ANALYZE / EXPLAIN (ANALYZE ...) execute the inner query → ssn is traced and gated.
	parityColumnGrant(t, "EXPLAIN ANALYZE SELECT ssn FROM users", "postgres", "ssn")
	parityColumnGrant(t, "EXPLAIN (ANALYZE, FORMAT JSON) SELECT 1 FROM users WHERE ssn = 'x'", "postgres", "ssn")
	parityFunctionGated(t, "EXPLAIN SELECT query_to_xml('SELECT ssn FROM users', true, false, '')", "postgres", "query_to_xml")
}

// TestParityTransactionControlSavepoint locks SAVEPOINT / RELEASE SAVEPOINT as SESSION passthrough — since
// v0.15.0 they parse to a dedicated Savepoint root (benign tx state, never a data read), joining
// BEGIN/COMMIT/ROLLBACK. String/number savepoint names are not a Savepoint node and fail closed, matching
// both engines. Bare RELEASE <name> (no SAVEPOINT keyword) is Postgres-only — real MySQL requires the
// keyword, so MySQL bare RELEASE stays a denied Alias.
func TestParityTransactionControlSavepoint(t *testing.T) {
	bothDialects(func(d string) {
		parityClass(t, "SAVEPOINT s", d, pb.StatementClass_STATEMENT_CLASS_SESSION)
		parityClass(t, "RELEASE SAVEPOINT s", d, pb.StatementClass_STATEMENT_CLASS_SESSION)
		parityClass(t, "ROLLBACK TO SAVEPOINT s", d, pb.StatementClass_STATEMENT_CLASS_SESSION)
		parityClass(t, "SAVEPOINT commit", d, pb.StatementClass_STATEMENT_CLASS_SESSION) // unreserved-keyword name
		parityDenied(t, "SAVEPOINT 'foo'", d)                                            // string name → not a Savepoint
		parityDenied(t, "SAVEPOINT 1", d)                                                // number name → not a Savepoint
	})
	parityClass(t, "RELEASE s", "postgres", pb.StatementClass_STATEMENT_CLASS_SESSION) // PG bare RELEASE (no keyword)
	parityDenied(t, "RELEASE s", "mysql")                                              // MySQL requires SAVEPOINT keyword
}
