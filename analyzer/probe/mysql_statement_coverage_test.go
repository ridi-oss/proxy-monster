package probe

import (
	"sort"
	"strings"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// factsKind reads a statement's kind off its single execute grant — the one per-statement authorization
// signal. A statement that parse-errors before a root exists carries no execute grant, so its kind reads as
// STMT_UNKNOWN (the deny-by-default-but-grantable unknown category).
func factsKind(f *pb.StatementFacts) pb.StatementKind {
	if f.GetStatementExec() == nil {
		return pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN
	}
	return f.GetStatementExec().GetStatementKind()
}

// nonExecuteGrants returns the result-read grants — the column/table/function/utility requirements beyond
// the single execute grant. So a test that means "no requirement beyond running the statement" asserts
// this slice is empty.
func nonExecuteGrants(f *pb.StatementFacts) []*pb.RequireResultReadGrant {
	return f.GetResultReads()
}

// resolve runs one statement through the real analyzer and reduces its emitted facts to the requirement
// fingerprint for the WIRE data-plane path — the grants decideQuery would require and the fail-closed bucket
// it would hit, named in the terms an operator reasons in. It is the analyzer's actual output, reduced; it
// is deliberately NOT a full decideQuery replica. It models decideQuery's short-circuit ORDER (INADMISSIBLE
// deny, then the unanalyzable gate) but not: the channel (a bare `session` is passthrough only on
// WIRE/EDITOR — MCP and workflow channels DENY it), the Cedar verdict (it reports what is REQUIRED, never
// ALLOW/DENY), or that a datasource holding `exception.unanalyzable` can relay the unanalyzable gate. For those,
// read Query.kt.
//
// The vocabulary:
//
//	stmt.kind.<kind>              — a resolved statement's execute grant, carrying the classified kind
//	                                (STATEMENT_KIND_ prefix stripped, lowercased). The control-plane
//	                                authorizes it as stmt.kind.<kind>; Cedar's schema maps it to a category.
//	                                Every resolved statement carries exactly one — a former metadata/session
//	                                passthrough (SHOW TABLES, SET, BEGIN) now surfaces as its own kind, since
//	                                the derived class is no longer on the contract; on WIRE/EDITOR the
//	                                connect-only passthrough kinds ask nothing more (MCP/workflow deny SET).
//	unanalyzable→exception.unanalyzable — not resolved, UNANALYZABLE: routed to the deny-by-default gate a dev
//	                                datasource can override. A modeled-but-unanalyzable statement carries a
//	                                real kind too (ALTER, KILL), so stmt.kind.<kind> surfaces beside it.
//	INADMISSIBLE                  — not resolved, INADMISSIBLE: hard deny, no gate.
//	result.read                   — a resolved statement touched a column/table/function: result.read.* is
//	                                authorized per resource (joined with the execute grant's kind).
//	utility:<CMD>                 — carries a Utility grant; authorized as result.read.* on that utility,
//	                                which the shipped forbids deny for the dangerous ones.
//	allow(connect-only)           — resolved, ANALYZED, zero grants: nothing asked beyond connect.
func resolve(t *testing.T, sql string) string {
	t.Helper()
	f := mysqlFacts(t, sql)

	// INADMISSIBLE is a structural hard deny before any grant is considered (Query.kt ~357); it dominates.
	if !f.Resolved && f.FailureClass == pb.FailureClass_FAILURE_CLASS_INADMISSIBLE {
		return "INADMISSIBLE-deny"
	}

	var parts []string
	utilities := map[string]bool{}
	touchesData := false
	// The kind comes from the single execute grant (factsKind below); each result-read grant is a
	// column/table/function read or a utility.
	for _, g := range f.GetResultReads() {
		switch {
		case g.GetUtility() != nil:
			utilities["utility:"+g.GetUtility().Command] = true
		case g.GetColumn() != nil || g.GetTable() != nil || g.GetFunction() != nil:
			touchesData = true
		}
	}
	parts = append(parts, mapKeys(utilities)...)

	// STMT_UNKNOWN maps to exception.unanalyzable, so surfacing it as a kind alongside the gate would double-print;
	// a real kind is surfaced beside the gate (a modeled statement the lineage engine cannot analyze).
	kindTerm := ""
	if kind := factsKind(f); kind != pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN {
		kindTerm = "stmt.kind." + strings.ToLower(strings.TrimPrefix(kind.String(), "STATEMENT_KIND_"))
	}

	switch {
	case !f.Resolved && f.FailureClass == pb.FailureClass_FAILURE_CLASS_UNANALYZABLE:
		if kindTerm != "" {
			parts = append(parts, kindTerm)
		}
		parts = append(parts, "unanalyzable→exception.unanalyzable")
	case !f.Resolved:
		parts = append(parts, "UNRESOLVED("+f.FailureClass.String()+")")
	default:
		// A resolved statement's authorization is its single execute grant's kind (the derived
		// metadata/session/analyzed class is no longer on the contract), plus result.read when it touched
		// a column/table/function.
		if kindTerm != "" {
			parts = append(parts, kindTerm)
		}
		if touchesData {
			parts = append(parts, "result.read")
		}
	}
	if len(parts) == 0 {
		return "allow(connect-only)"
	}
	sort.Strings(parts)
	return strings.Join(parts, " + ")
}

func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// mysqlStatement is one MySQL 8.0/8.4 statement kind, its minimal example, and the resolution the analyzer
// must produce for it. The list is curated from the MySQL 8.0/8.4 reference manual (§15 SQL Statements) —
// broad, but not a machine-verified extract, so it is not proven exhaustive. A kind absent from the list is
// simply untested; the guard below catches REGRESSIONS on the kinds that are listed, not the ones that are
// not. Exhaustiveness is the job of the statement-typing redesign (docs/statement-typing.md), whose type
// enum a coverage check can enforce against the parser.
type mysqlStatement struct {
	name string
	sql  string
	want string
	// kind is the StatementKind the analyzer computes from the parsed AST (TestMysqlStatementKind). It is
	// orthogonal to want: a statement can fail closed (unanalyzable/inadmissible) yet still carry a specific
	// kind (KILL, CREATE_USER), while a statement that parse-errors before a root exists is STMT_UNKNOWN.
	kind pb.StatementKind
}

// mysqlStatements enumerates the MySQL statement kinds a client can send as one statement. `want` is the
// resolution OBSERVED from the analyzer and then audited for correctness: every privileged or
// data-exposing kind must be fail-closed (an execute grant whose kind the operator must authorize, a
// utility the shipped forbids deny, `unanalyzable→exception.unanalyzable`, or an outright deny), and no kind may resolve to
// `allow(connect-only)` unless it genuinely exposes nothing. Where a kind is under-gated today, its `want`
// records that and it is enumerated in knownConnectOnlyGaps below — the audit documents the gap rather than
// hiding it.
var mysqlStatements = []mysqlStatement{
	// ---- DML (§15.2) ----
	{"SELECT", "SELECT id FROM users", "result.read + stmt.kind.select", pb.StatementKind_STATEMENT_KIND_SELECT},
	{"SELECT (no table)", "SELECT 1", "stmt.kind.select", pb.StatementKind_STATEMENT_KIND_SELECT},
	{"SELECT INTO OUTFILE", "SELECT id INTO OUTFILE 'f' FROM users", "result.read + stmt.kind.select_into_outfile", pb.StatementKind_STATEMENT_KIND_SELECT_INTO_OUTFILE},
	{"SELECT INTO DUMPFILE", "SELECT id INTO DUMPFILE 'f' FROM users", "result.read + stmt.kind.select_into_dumpfile", pb.StatementKind_STATEMENT_KIND_SELECT_INTO_DUMPFILE},
	{"SELECT INTO @var", "SELECT id INTO @a FROM users", "result.read + stmt.kind.select_into", pb.StatementKind_STATEMENT_KIND_SELECT_INTO}, // INTO a var: a masking-bypass write, gated as ddl not read
	{"SELECT INTO @var (nested)", "(SELECT 1) UNION SELECT id INTO @a FROM users", "result.read + stmt.kind.select_into", pb.StatementKind_STATEMENT_KIND_SELECT_INTO},
	{"SELECT INTO OUTFILE (nested)", "SELECT id FROM users UNION SELECT id FROM users INTO OUTFILE 'f'", "result.read + stmt.kind.select_into_outfile", pb.StatementKind_STATEMENT_KIND_SELECT_INTO_OUTFILE}, // a set-op-nested file INTO is still admin.file, not read
	{"UNION", "SELECT id FROM users UNION SELECT id FROM users", "result.read + stmt.kind.set_op", pb.StatementKind_STATEMENT_KIND_SET_OP},
	{"INTERSECT", "SELECT id FROM users INTERSECT SELECT id FROM users", "result.read + stmt.kind.set_op", pb.StatementKind_STATEMENT_KIND_SET_OP},
	{"EXCEPT", "SELECT id FROM users EXCEPT SELECT id FROM users", "result.read + stmt.kind.set_op", pb.StatementKind_STATEMENT_KIND_SET_OP},
	{"TABLE", "TABLE users", "result.read + stmt.kind.select", pb.StatementKind_STATEMENT_KIND_SELECT}, // v0.22: parses as SELECT * FROM users, indistinguishable from SELECT
	{"VALUES", "VALUES ROW(1)", "stmt.kind.values + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_VALUES},
	{"WITH (CTE)", "WITH c AS (SELECT id FROM users) SELECT id FROM c", "result.read + stmt.kind.with_select", pb.StatementKind_STATEMENT_KIND_WITH_SELECT},
	{"INSERT", "INSERT INTO users (id) VALUES (1)", "stmt.kind.insert", pb.StatementKind_STATEMENT_KIND_INSERT},
	{"INSERT SELECT", "INSERT INTO users (id) SELECT id FROM users", "result.read + stmt.kind.insert_select", pb.StatementKind_STATEMENT_KIND_INSERT_SELECT},
	{"INSERT ODKU", "INSERT INTO users (id) VALUES (1) ON DUPLICATE KEY UPDATE id=id", "result.read + stmt.kind.insert_on_dup", pb.StatementKind_STATEMENT_KIND_INSERT_ON_DUP},
	{"INSERT SELECT ODKU", "INSERT INTO users (id) SELECT id FROM users ON DUPLICATE KEY UPDATE id=id", "result.read + stmt.kind.insert_on_dup", pb.StatementKind_STATEMENT_KIND_INSERT_ON_DUP}, // upsert-from-select is still an upsert (write.update), not a plain insert_select
	{"REPLACE", "REPLACE INTO users (id) VALUES (1)", "stmt.kind.replace", pb.StatementKind_STATEMENT_KIND_REPLACE},
	{"UPDATE", "UPDATE users SET email='x'", "stmt.kind.update", pb.StatementKind_STATEMENT_KIND_UPDATE},
	{"DELETE", "DELETE FROM users", "stmt.kind.delete", pb.StatementKind_STATEMENT_KIND_DELETE},
	{"DO", "DO 1", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},                                         // parse error
	{"CALL", "CALL p()", "stmt.kind.call + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_CALL},                          // denied at the datasource loop before the unanalyzable gate
	{"HANDLER OPEN", "HANDLER users OPEN", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},                 // parse error
	{"HANDLER READ", "HANDLER users READ FIRST", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},           // parse error
	{"HANDLER CLOSE", "HANDLER users CLOSE", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},               // parse error
	{"LOAD DATA", "LOAD DATA INFILE 'f' INTO TABLE users", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error
	{"LOAD XML", "LOAD XML INFILE 'f' INTO TABLE users", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"IMPORT TABLE", "IMPORT TABLE FROM 'users.sdi'", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error

	// ---- DDL (§15.1) ----
	// Table/index/view/schema DDL that sqlglot models structurally (Create / Alter / Drop / TruncateTable)
	// is catalog-changing: fully determined, reads no column values, gated by sql.ddl alone. Forms sqlglot
	// leaves as a Command (routines, events, servers, tablespaces, SRS, RENAME TABLE) stay unresolved and
	// route to the exception.unanalyzable gate — an over-deny, not a leak.
	{"CREATE TABLE", "CREATE TABLE t (id INT)", "stmt.kind.create_table", pb.StatementKind_STATEMENT_KIND_CREATE_TABLE},
	{"CREATE TABLE AS SELECT", "CREATE TABLE t AS SELECT id FROM users", "result.read + stmt.kind.create_table", pb.StatementKind_STATEMENT_KIND_CREATE_TABLE},
	{"CREATE TABLE LIKE", "CREATE TABLE t LIKE users", "stmt.kind.create_table", pb.StatementKind_STATEMENT_KIND_CREATE_TABLE},
	{"CREATE INDEX", "CREATE INDEX i ON users (id)", "stmt.kind.create_index", pb.StatementKind_STATEMENT_KIND_CREATE_INDEX},
	{"CREATE VIEW", "CREATE VIEW v AS SELECT 1", "stmt.kind.create_view", pb.StatementKind_STATEMENT_KIND_CREATE_VIEW},
	{"CREATE DATABASE", "CREATE DATABASE d", "stmt.kind.create_database", pb.StatementKind_STATEMENT_KIND_CREATE_DATABASE},
	{"CREATE TRIGGER", "CREATE TRIGGER trg BEFORE INSERT ON users FOR EACH ROW SET @a = 1", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"CREATE PROCEDURE", "CREATE PROCEDURE p() SELECT 1", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"CREATE FUNCTION (stored)", "CREATE FUNCTION f() RETURNS INT RETURN 1", "stmt.kind.create_function", pb.StatementKind_STATEMENT_KIND_CREATE_FUNCTION},
	// A routine body carrying a query (RETURN (SELECT …)) is not a CTAS: the read happens at invocation,
	// not at CREATE. Lineage cannot analyze the routine body, so it over-denies (unresolved) rather than
	// resolving catalog-changing like the bare form above — a fail-closed asymmetry, not a leak.
	{"CREATE FUNCTION (stored, query body)", "CREATE FUNCTION f() RETURNS INT RETURN (SELECT id FROM users)", "stmt.kind.create_function + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_CREATE_FUNCTION},
	{"CREATE FUNCTION (UDF)", "CREATE FUNCTION f RETURNS INTEGER SONAME 'f.so'", "stmt.kind.create_function", pb.StatementKind_STATEMENT_KIND_CREATE_FUNCTION},
	{"CREATE EVENT", "CREATE EVENT e ON SCHEDULE AT NOW() DO SET @a = 1", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"CREATE SERVER", "CREATE SERVER s FOREIGN DATA WRAPPER mysql OPTIONS (USER 'u')", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"CREATE TABLESPACE", "CREATE TABLESPACE ts ADD DATAFILE 'ts.ibd'", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"CREATE SRS", "CREATE SPATIAL REFERENCE SYSTEM 4000 NAME 'x' DEFINITION 'y'", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"ALTER TABLE", "ALTER TABLE users ADD COLUMN x INT", "stmt.kind.alter_table", pb.StatementKind_STATEMENT_KIND_ALTER_TABLE},
	{"ALTER DATABASE", "ALTER DATABASE d CHARACTER SET utf8mb4", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"ALTER VIEW", "ALTER VIEW v AS SELECT 1", "stmt.kind.alter_view", pb.StatementKind_STATEMENT_KIND_ALTER_VIEW},
	{"ALTER EVENT", "ALTER EVENT e DISABLE", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"ALTER PROCEDURE", "ALTER PROCEDURE p COMMENT 'x'", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"ALTER FUNCTION", "ALTER FUNCTION f COMMENT 'x'", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"ALTER SERVER", "ALTER SERVER s OPTIONS (USER 'u')", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"ALTER TABLESPACE", "ALTER TABLESPACE ts RENAME TO ts2", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"ALTER INSTANCE", "ALTER INSTANCE ROTATE INNODB MASTER KEY", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"DROP TABLE", "DROP TABLE users", "stmt.kind.drop_table", pb.StatementKind_STATEMENT_KIND_DROP_TABLE},
	{"DROP INDEX", "DROP INDEX i ON users", "stmt.kind.drop_index", pb.StatementKind_STATEMENT_KIND_DROP_INDEX}, // sqlglot-go v0.22.0 models this as a structured Drop, unlike RENAME TABLE
	{"DROP VIEW", "DROP VIEW v", "stmt.kind.drop_view", pb.StatementKind_STATEMENT_KIND_DROP_VIEW},
	{"DROP DATABASE", "DROP DATABASE d", "stmt.kind.drop_database", pb.StatementKind_STATEMENT_KIND_DROP_DATABASE},
	{"DROP TRIGGER", "DROP TRIGGER trg", "stmt.kind.drop_trigger", pb.StatementKind_STATEMENT_KIND_DROP_TRIGGER},
	{"DROP PROCEDURE", "DROP PROCEDURE p", "stmt.kind.drop_procedure", pb.StatementKind_STATEMENT_KIND_DROP_PROCEDURE},
	{"DROP FUNCTION", "DROP FUNCTION f", "stmt.kind.drop_function", pb.StatementKind_STATEMENT_KIND_DROP_FUNCTION},
	{"DROP EVENT", "DROP EVENT e", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"DROP SERVER", "DROP SERVER s", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"DROP TABLESPACE", "DROP TABLESPACE ts", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"DROP SRS", "DROP SPATIAL REFERENCE SYSTEM 4000", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"TRUNCATE TABLE", "TRUNCATE TABLE users", "stmt.kind.truncate_table", pb.StatementKind_STATEMENT_KIND_TRUNCATE_TABLE},
	{"RENAME TABLE", "RENAME TABLE users TO u2", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},

	// ---- Transaction / locking (§15.3) ----
	{"START TRANSACTION", "START TRANSACTION", "stmt.kind.start_transaction", pb.StatementKind_STATEMENT_KIND_START_TRANSACTION},
	{"BEGIN", "BEGIN", "stmt.kind.start_transaction", pb.StatementKind_STATEMENT_KIND_START_TRANSACTION},
	{"COMMIT", "COMMIT", "stmt.kind.commit", pb.StatementKind_STATEMENT_KIND_COMMIT},
	{"ROLLBACK", "ROLLBACK", "stmt.kind.rollback", pb.StatementKind_STATEMENT_KIND_ROLLBACK},
	{"SAVEPOINT", "SAVEPOINT s", "stmt.kind.savepoint", pb.StatementKind_STATEMENT_KIND_SAVEPOINT},
	{"ROLLBACK TO SAVEPOINT", "ROLLBACK TO SAVEPOINT s", "stmt.kind.rollback", pb.StatementKind_STATEMENT_KIND_ROLLBACK},
	{"RELEASE SAVEPOINT", "RELEASE SAVEPOINT s", "stmt.kind.savepoint", pb.StatementKind_STATEMENT_KIND_SAVEPOINT},
	{"SET TRANSACTION", "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE", "stmt.kind.set_transaction", pb.StatementKind_STATEMENT_KIND_SET_TRANSACTION},
	{"SET autocommit", "SET autocommit=0", "stmt.kind.set_session_var", pb.StatementKind_STATEMENT_KIND_SET_SESSION_VAR},
	{"LOCK TABLES", "LOCK TABLES users READ", "stmt.kind.lock_tables + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_LOCK_TABLES},
	{"UNLOCK TABLES", "UNLOCK TABLES", "stmt.kind.unlock_tables + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_UNLOCK_TABLES},
	{"LOCK INSTANCE FOR BACKUP", "LOCK INSTANCE FOR BACKUP", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error
	{"UNLOCK INSTANCE", "UNLOCK INSTANCE", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"XA START", "XA START 'x'", "stmt.kind.xa + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_XA},
	{"XA END", "XA END 'x'", "stmt.kind.xa + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_XA},
	{"XA PREPARE", "XA PREPARE 'x'", "stmt.kind.xa + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_XA},
	{"XA COMMIT", "XA COMMIT 'x'", "stmt.kind.xa + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_XA},
	{"XA ROLLBACK", "XA ROLLBACK 'x'", "stmt.kind.xa + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_XA},
	{"XA RECOVER", "XA RECOVER", "stmt.kind.xa + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_XA},

	// ---- Prepared statements (§15.5) — SQL-injection surface, must fail closed ----
	{"PREPARE", "PREPARE s FROM 'SELECT 1'", "stmt.kind.prepare + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_PREPARE},
	{"EXECUTE", "EXECUTE s", "stmt.kind.execute + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_EXECUTE},
	{"DEALLOCATE PREPARE", "DEALLOCATE PREPARE s", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error

	// ---- Replication (§15.4) — privileged, must fail closed ----
	{"CHANGE REPLICATION SOURCE TO", "CHANGE REPLICATION SOURCE TO SOURCE_HOST='h'", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},  // parse error
	{"CHANGE MASTER TO", "CHANGE MASTER TO MASTER_HOST='h'", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},                          // parse error
	{"CHANGE REPLICATION FILTER", "CHANGE REPLICATION FILTER REPLICATE_DO_DB = (d1)", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error
	{"START REPLICA", "START REPLICA", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"START SLAVE", "START SLAVE", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"STOP REPLICA", "STOP REPLICA", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"STOP SLAVE", "STOP SLAVE", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"RESET REPLICA", "RESET REPLICA", "INADMISSIBLE-deny", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"RESET SLAVE", "RESET SLAVE", "INADMISSIBLE-deny", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"START GROUP_REPLICATION", "START GROUP_REPLICATION", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"STOP GROUP_REPLICATION", "STOP GROUP_REPLICATION", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"PURGE BINARY LOGS", "PURGE BINARY LOGS BEFORE '2020-01-01'", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error
	{"RESET MASTER", "RESET MASTER", "INADMISSIBLE-deny", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"RESET BINARY LOGS AND GTIDS", "RESET BINARY LOGS AND GTIDS", "INADMISSIBLE-deny", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // 8.4 replacement for RESET MASTER

	// ---- Account management (§15.7.1) — privileged, must fail closed ----
	{"CREATE USER", "CREATE USER 'u'@'h'", "stmt.kind.create_user", pb.StatementKind_STATEMENT_KIND_CREATE_USER},
	{"CREATE USER RANDOM PASSWORD", "CREATE USER 'u'@'h' IDENTIFIED BY RANDOM PASSWORD", "stmt.kind.create_user", pb.StatementKind_STATEMENT_KIND_CREATE_USER},
	{"ALTER USER", "ALTER USER 'u'@'h' IDENTIFIED BY 'p'", "stmt.kind.alter_user", pb.StatementKind_STATEMENT_KIND_ALTER_USER},
	{"DROP USER", "DROP USER 'u'@'h'", "stmt.kind.drop_user", pb.StatementKind_STATEMENT_KIND_DROP_USER},
	// RENAME USER is the one account-mgmt form sqlglot-go leaves as an opaque Command, so it stays
	// unanalyzable where its CREATE/ALTER/DROP siblings resolve to a classified kind.
	{"RENAME USER", "RENAME USER 'u'@'h' TO 'v'@'h'", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"CREATE ROLE", "CREATE ROLE 'r'", "stmt.kind.create_role", pb.StatementKind_STATEMENT_KIND_CREATE_ROLE},
	{"DROP ROLE", "DROP ROLE 'r'", "stmt.kind.drop_role", pb.StatementKind_STATEMENT_KIND_DROP_ROLE},
	{"GRANT (priv)", "GRANT SELECT ON *.* TO 'u'@'h'", "stmt.kind.grant_priv + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_GRANT_PRIV},
	{"GRANT (role)", "GRANT 'r' TO 'u'@'h'", "stmt.kind.grant_priv + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_GRANT_PRIV},
	{"REVOKE (priv)", "REVOKE SELECT ON *.* FROM 'u'@'h'", "stmt.kind.revoke_priv + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_REVOKE_PRIV},
	{"REVOKE (role)", "REVOKE 'r' FROM 'u'@'h'", "stmt.kind.revoke_priv + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_REVOKE_PRIV},
	{"SET PASSWORD", "SET PASSWORD FOR 'u'@'h' = 'p'", "stmt.kind.set_password + utility:SET_PASSWORD", pb.StatementKind_STATEMENT_KIND_SET_PASSWORD},
	{"SET ROLE", "SET ROLE 'r'", "stmt.kind.set_role + utility:SET_ROLE", pb.StatementKind_STATEMENT_KIND_SET_ROLE},
	{"SET DEFAULT ROLE", "SET DEFAULT ROLE 'r' TO 'u'@'h'", "stmt.kind.set_default_role + utility:SET_DEFAULT_ROLE", pb.StatementKind_STATEMENT_KIND_SET_DEFAULT_ROLE},

	// ---- Table maintenance (§15.7.3) ----
	// ANALYZE gates the target table's read (facts.go), so it is not connect-only; CHECK/OPTIMIZE/REPAIR fail closed.
	{"ANALYZE TABLE", "ANALYZE TABLE users", "result.read + stmt.kind.analyze_table", pb.StatementKind_STATEMENT_KIND_ANALYZE_TABLE},
	{"CHECK TABLE", "CHECK TABLE users", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},       // parse error
	{"CHECKSUM TABLE", "CHECKSUM TABLE users", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error
	{"OPTIMIZE TABLE", "OPTIMIZE TABLE users", "stmt.kind.optimize_table + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_OPTIMIZE_TABLE},
	{"REPAIR TABLE", "REPAIR TABLE users", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error

	// ---- Other server administration (§15.7) — privileged, must fail closed ----
	{"INSTALL PLUGIN", "INSTALL PLUGIN p SONAME 'p.so'", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},      // parse error
	{"UNINSTALL PLUGIN", "UNINSTALL PLUGIN p", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},                // parse error
	{"INSTALL COMPONENT", "INSTALL COMPONENT 'file://c'", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},     // parse error
	{"UNINSTALL COMPONENT", "UNINSTALL COMPONENT 'file://c'", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error
	{"CLONE", "CLONE LOCAL DATA DIRECTORY = '/tmp/c'", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},        // parse error
	{"FLUSH", "FLUSH TABLES", "stmt.kind.flush + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_FLUSH},
	{"FLUSH PRIVILEGES", "FLUSH PRIVILEGES", "stmt.kind.flush + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_FLUSH},
	{"KILL", "KILL 1", "stmt.kind.kill + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_KILL},
	{"CACHE INDEX", "CACHE INDEX users IN c", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error
	{"LOAD INDEX INTO CACHE", "LOAD INDEX INTO CACHE users", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"BINLOG", "BINLOG 'x'", "stmt.kind.binlog + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_BINLOG},
	{"RESET PERSIST", "RESET PERSIST", "INADMISSIBLE-deny", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"RESTART", "RESTART", "stmt.kind.restart + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_RESTART},
	{"SHUTDOWN", "SHUTDOWN", "stmt.kind.shutdown + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_SHUTDOWN},
	{"SET RESOURCE GROUP", "SET RESOURCE GROUP grp", "INADMISSIBLE-deny", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"CREATE RESOURCE GROUP", "CREATE RESOURCE GROUP grp TYPE = USER", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"ALTER RESOURCE GROUP", "ALTER RESOURCE GROUP grp VCPU = 0", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"DROP RESOURCE GROUP", "DROP RESOURCE GROUP grp", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},

	// ---- SET forms (§15.7.6) ----
	{"SET user var", "SET @x = 1", "stmt.kind.set_session_var", pb.StatementKind_STATEMENT_KIND_SET_SESSION_VAR},
	{"SET GLOBAL var", "SET GLOBAL max_connections = 100", "stmt.kind.set_global + utility:SET_GLOBAL", pb.StatementKind_STATEMENT_KIND_SET_GLOBAL},
	{"SET PERSIST var", "SET PERSIST max_connections = 100", "stmt.kind.set_persist + utility:SET_PERSIST", pb.StatementKind_STATEMENT_KIND_SET_PERSIST},
	{"SET PERSIST_ONLY var", "SET PERSIST_ONLY max_connections = 100", "stmt.kind.set_persist_only + utility:SET_PERSIST_ONLY", pb.StatementKind_STATEMENT_KIND_SET_PERSIST_ONLY},
	{"SET NAMES", "SET NAMES utf8mb4", "stmt.kind.set_session_var", pb.StatementKind_STATEMENT_KIND_SET_SESSION_VAR},
	{"SET CHARACTER SET", "SET CHARACTER SET utf8mb4", "stmt.kind.set_session_var", pb.StatementKind_STATEMENT_KIND_SET_SESSION_VAR},
	// GAP: sql_log_bin is a restricted SESSION variable (needs SESSION_VARIABLES_ADMIN); disabling it drops
	// the session's writes from the binlog/GTID stream. The analyzer gates SET by scope (GLOBAL/PERSIST) and
	// PASSWORD only, so a session-scoped assignment is a bare passthrough. See knownConnectOnlyGaps.
	{"SET sql_log_bin", "SET SESSION sql_log_bin = 0", "stmt.kind.set_sql_log_bin", pb.StatementKind_STATEMENT_KIND_SET_SQL_LOG_BIN},

	// ---- SHOW: benign metadata (§15.7.7) ----
	{"SHOW DATABASES", "SHOW DATABASES", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW TABLES", "SHOW TABLES", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW COLUMNS", "SHOW COLUMNS FROM users", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW INDEX", "SHOW INDEX FROM users", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW CREATE TABLE", "SHOW CREATE TABLE users", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW CREATE DATABASE", "SHOW CREATE DATABASE d", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW CREATE VIEW", "SHOW CREATE VIEW v", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW CREATE PROCEDURE", "SHOW CREATE PROCEDURE p", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW CREATE FUNCTION", "SHOW CREATE FUNCTION f", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW CREATE TRIGGER", "SHOW CREATE TRIGGER trg", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW CREATE EVENT", "SHOW CREATE EVENT e", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW ENGINES", "SHOW ENGINES", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW STATUS", "SHOW STATUS", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW VARIABLES", "SHOW VARIABLES", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW WARNINGS", "SHOW WARNINGS", "stmt.kind.show_warnings + utility:SHOW_WARNINGS", pb.StatementKind_STATEMENT_KIND_SHOW_WARNINGS},
	{"SHOW ERRORS", "SHOW ERRORS", "stmt.kind.show_errors + utility:SHOW_ERRORS", pb.StatementKind_STATEMENT_KIND_SHOW_ERRORS},
	{"SHOW CHARACTER SET", "SHOW CHARACTER SET", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW COLLATION", "SHOW COLLATION", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW PRIVILEGES", "SHOW PRIVILEGES", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW PLUGINS", "SHOW PLUGINS", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW TABLE STATUS", "SHOW TABLE STATUS", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW OPEN TABLES", "SHOW OPEN TABLES", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW TRIGGERS", "SHOW TRIGGERS", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW EVENTS", "SHOW EVENTS", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW PROCEDURE STATUS", "SHOW PROCEDURE STATUS", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW FUNCTION STATUS", "SHOW FUNCTION STATUS", "stmt.kind.show_metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},

	// ---- SHOW: data/credential/topology-exposing — must be a utility or fail closed ----
	// The `metadata`-only rows here are UNDER-GATED today (see knownConnectOnlyGaps): the analyzer emits no
	// utility for them, so they relay connect-only on wire. The statement-typing redesign closes them.
	{"SHOW PROCESSLIST", "SHOW PROCESSLIST", "stmt.kind.show_processlist", pb.StatementKind_STATEMENT_KIND_SHOW_PROCESSLIST},
	{"SHOW GRANTS", "SHOW GRANTS", "stmt.kind.show_grants", pb.StatementKind_STATEMENT_KIND_SHOW_GRANTS},
	{"SHOW CREATE USER", "SHOW CREATE USER CURRENT_USER", "stmt.kind.show_create_user + utility:SHOW_CREATE_USER", pb.StatementKind_STATEMENT_KIND_SHOW_CREATE_USER},
	{"SHOW ENGINE INNODB STATUS", "SHOW ENGINE INNODB STATUS", "stmt.kind.show_engine_status + utility:SHOW_ENGINE_STATUS", pb.StatementKind_STATEMENT_KIND_SHOW_ENGINE_STATUS},
	{"SHOW BINLOG EVENTS", "SHOW BINLOG EVENTS", "stmt.kind.show_binlog_events + utility:SHOW_BINLOG_EVENTS", pb.StatementKind_STATEMENT_KIND_SHOW_BINLOG_EVENTS},
	{"SHOW RELAYLOG EVENTS", "SHOW RELAYLOG EVENTS", "stmt.kind.show_relaylog_events + utility:SHOW_RELAYLOG_EVENTS", pb.StatementKind_STATEMENT_KIND_SHOW_RELAYLOG_EVENTS},
	{"SHOW BINARY LOGS", "SHOW BINARY LOGS", "stmt.kind.show_binary_logs", pb.StatementKind_STATEMENT_KIND_SHOW_BINARY_LOGS},                  // GAP: needs REPLICATION CLIENT
	{"SHOW MASTER STATUS", "SHOW MASTER STATUS", "stmt.kind.show_master_status", pb.StatementKind_STATEMENT_KIND_SHOW_MASTER_STATUS},          // GAP: needs REPLICATION CLIENT
	{"SHOW BINARY LOG STATUS", "SHOW BINARY LOG STATUS", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // 8.4 rename; degrades to Command, fails closed (unlike SHOW MASTER STATUS)
	{"SHOW REPLICA STATUS", "SHOW REPLICA STATUS", "stmt.kind.show_replica_status + utility:SHOW_REPLICA_STATUS", pb.StatementKind_STATEMENT_KIND_SHOW_REPLICA_STATUS},
	{"SHOW SLAVE STATUS", "SHOW SLAVE STATUS", "stmt.kind.show_replica_status + utility:SHOW_REPLICA_STATUS", pb.StatementKind_STATEMENT_KIND_SHOW_REPLICA_STATUS},
	{"SHOW REPLICAS", "SHOW REPLICAS", "stmt.kind.show_replicas", pb.StatementKind_STATEMENT_KIND_SHOW_REPLICAS},       // GAP: needs REPLICATION SLAVE
	{"SHOW SLAVE HOSTS", "SHOW SLAVE HOSTS", "stmt.kind.show_replicas", pb.StatementKind_STATEMENT_KIND_SHOW_REPLICAS}, // GAP: alias of SHOW REPLICAS
	{"SHOW WHERE subquery", "SHOW TABLES WHERE Tables_in_db IN (SELECT ssn FROM users)", "stmt.kind.show_metadata + utility:SHOW_SUBQUERY", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},

	// ---- Utility (§15.8) ----
	{"DESCRIBE", "DESCRIBE users", "stmt.kind.describe", pb.StatementKind_STATEMENT_KIND_DESCRIBE},
	{"DESC", "DESC users", "stmt.kind.describe", pb.StatementKind_STATEMENT_KIND_DESCRIBE},
	{"EXPLAIN (query)", "EXPLAIN SELECT id FROM users", "result.read + stmt.kind.explain", pb.StatementKind_STATEMENT_KIND_EXPLAIN},
	{"EXPLAIN ANALYZE", "EXPLAIN ANALYZE SELECT id FROM users", "result.read + stmt.kind.explain", pb.StatementKind_STATEMENT_KIND_EXPLAIN},
	{"EXPLAIN (table)", "EXPLAIN users", "stmt.kind.describe", pb.StatementKind_STATEMENT_KIND_DESCRIBE}, // EXPLAIN <table> is AST-identical to DESCRIBE <table>
	{"HELP", "HELP 'contents'", "stmt.kind.help + unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_HELP},
	{"USE", "USE acme", "stmt.kind.use", pb.StatementKind_STATEMENT_KIND_USE},

	// ---- Compound (§15.6) ----
	// Compound BEGIN...END blocks are valid only inside a stored program; a client reaches them via CALL
	// (above), never as a standalone statement. Sent standalone it is a parse error → fail-closed.
	{"BEGIN...END (standalone)", "BEGIN SELECT 1; END", "unanalyzable→exception.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error
}

// TestMysqlStatementResolution pins the analyzer's resolution for every MySQL 8.0/8.4 statement kind in the
// curated list above. Each `want` was OBSERVED from the analyzer and then audited. A change to any
// resolution — a statement that stops failing closed — breaks this test on purpose.
func TestMysqlStatementResolution(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range mysqlStatements {
		if seen[s.name] {
			t.Errorf("duplicate statement name %q", s.name)
		}
		seen[s.name] = true
		if got := resolve(t, s.sql); got != s.want {
			t.Errorf("%-28s %-60q\n    got  %s\n    want %s", s.name, s.sql, got, s.want)
		}
	}
}

// TestMysqlStatementKind pins the StatementKind the analyzer computes from the parsed AST for every MySQL
// statement kind in the curated list. Each `kind` was OBSERVED from the analyzer and audited: a statement
// that parses to a real node carries a specific kind (even when it fails closed — KILL, CREATE_USER), and
// only the ones that parse-error before a root exists are STMT_UNKNOWN. The guard asserts no statement leaves the kind UNSPECIFIED (the invalid zero value the
// control-plane must deny), so a new dispatch path that forgets to set a kind fails this test on purpose.
func TestMysqlStatementKind(t *testing.T) {
	for _, s := range mysqlStatements {
		got := factsKind(mysqlFacts(t, s.sql))
		if got == pb.StatementKind_STATEMENT_KIND_UNSPECIFIED {
			t.Errorf("%-28s %-60q left StatementKind UNSPECIFIED — every classified statement must set a kind or STMT_UNKNOWN", s.name, s.sql)
		}
		if got != s.kind {
			t.Errorf("%-28s %-60q\n    got  %s\n    want %s", s.name, s.sql, got, s.kind)
		}
	}
}

// privilegedNeedingGate is the set of statement kinds that expose data/credentials/topology, change the
// catalog, or exercise a server-admin/replication/account privilege — the kinds that must NOT resolve to a
// bare connect-only passthrough (a lone `stmt.kind.<k>` with no utility gate). The utility-gated kinds
// (`SET ROLE`, `SHOW GRANTS`, …) are listed too: they are not bare today, but listing them makes a
// regression from `… + utility:X` back to bare passthrough fail this test. Names must match the table.
//
// This hand-maintained map is a drift risk — a new privileged row is unguarded until its name is copied
// here. The statement-typing redesign (docs/statement-typing.md) removes the risk: every type carries its
// category, so the privileged set is derived, not re-typed by hand.
var privilegedNeedingGate = map[string]bool{
	"START REPLICA": true, "START SLAVE": true, "STOP REPLICA": true, "STOP SLAVE": true,
	"RESET REPLICA": true, "RESET SLAVE": true, "RESET MASTER": true, "RESET BINARY LOGS AND GTIDS": true,
	"START GROUP_REPLICATION": true, "STOP GROUP_REPLICATION": true, "PURGE BINARY LOGS": true,
	"CHANGE REPLICATION SOURCE TO": true, "CHANGE MASTER TO": true, "CHANGE REPLICATION FILTER": true,
	"CREATE USER": true, "CREATE USER RANDOM PASSWORD": true, "ALTER USER": true, "DROP USER": true, "RENAME USER": true, "CREATE ROLE": true,
	"DROP ROLE": true, "GRANT (priv)": true, "GRANT (role)": true, "REVOKE (priv)": true, "REVOKE (role)": true,
	"ANALYZE TABLE": true, "CHECK TABLE": true, "CHECKSUM TABLE": true, "OPTIMIZE TABLE": true, "REPAIR TABLE": true,
	"INSTALL PLUGIN": true, "UNINSTALL PLUGIN": true, "INSTALL COMPONENT": true, "UNINSTALL COMPONENT": true,
	"CLONE": true, "FLUSH": true, "FLUSH PRIVILEGES": true, "KILL": true, "CACHE INDEX": true,
	"LOAD INDEX INTO CACHE": true, "BINLOG": true, "RESTART": true, "SHUTDOWN": true,
	"CREATE RESOURCE GROUP": true, "ALTER RESOURCE GROUP": true, "DROP RESOURCE GROUP": true,
	"LOCK TABLES": true, "UNLOCK TABLES": true, "LOCK INSTANCE FOR BACKUP": true, "UNLOCK INSTANCE": true,
	"PREPARE": true, "EXECUTE": true, "HANDLER OPEN": true, "HANDLER READ": true,
	"LOAD DATA": true, "LOAD XML": true, "IMPORT TABLE": true, "CALL": true, "SELECT INTO DUMPFILE": true,
	// account/server-admin SET forms and data/credential/topology SHOWs — utility-gated, guarded against
	// regression to bare passthrough.
	"SET PASSWORD": true, "SET ROLE": true, "SET DEFAULT ROLE": true, "SET GLOBAL var": true,
	"SET PERSIST var": true, "SET PERSIST_ONLY var": true, "SET sql_log_bin": true,
	"SHOW PROCESSLIST": true, "SHOW GRANTS": true, "SHOW CREATE USER": true, "SHOW ENGINE INNODB STATUS": true,
	"SHOW BINLOG EVENTS": true, "SHOW RELAYLOG EVENTS": true, "SHOW REPLICA STATUS": true, "SHOW SLAVE STATUS": true,
	"SHOW BINARY LOGS": true, "SHOW MASTER STATUS": true, "SHOW REPLICAS": true, "SHOW SLAVE HOSTS": true,
}

// knownConnectOnlyGaps are privileged kinds that today DO resolve to a bare connect-only passthrough — real
// under-gating the analyzer does not yet close. Listing them keeps this test green while making each gap
// explicit; a NEW privileged kind that slips through is not on the list and fails the test. They are
// documented as an open boundary in docs/system-classification.md and are closed by the statement-typing
// redesign (docs/statement-typing.md), which removes the benign catch-all passthrough they fall into.
//
//	SET sql_log_bin                     — restricted SESSION variable; SET is gated by scope/PASSWORD only.
//	SHOW MASTER STATUS / SHOW BINARY LOGS / SHOW REPLICAS / SHOW SLAVE HOSTS
//	                                    — replication topology/binlog reads the analyzer emits no utility for.
var knownConnectOnlyGaps = map[string]bool{
	"SET sql_log_bin":    true,
	"SHOW MASTER STATUS": true,
	"SHOW BINARY LOGS":   true,
	"SHOW REPLICAS":      true,
	"SHOW SLAVE HOSTS":   true,
}

// gatedBareKinds are privileged kinds whose bare stmt.kind.<k> term IS the gate, not an under-gating.
// Account management (CREATE/ALTER/DROP USER|ROLE) touches no data, so it emits no utility grant and no
// lineage — a lone stmt.kind.<k>. But the CP schema maps these kinds into stmt.cat.admin.account, a
// deny-by-default category with no benign passthrough, so a bare admin-category term denies unless an
// admin grant is present. This is the opposite of knownConnectOnlyGaps, which are genuinely under-gated
// (a benign category). The map key is the resolve() output.
var gatedBareKinds = map[string]bool{
	"stmt.kind.create_user":      true,
	"stmt.kind.alter_user":       true,
	"stmt.kind.drop_user":        true,
	"stmt.kind.create_role":      true,
	"stmt.kind.drop_role":        true,
	"stmt.kind.show_grants":      true,
	"stmt.kind.show_processlist": true,
}

// TestPrivilegedStatementsAreGated is the security invariant: every privileged or data-exposing MySQL
// statement must be gated — a datasource verb, a utility grant, a gated-category kind, or a fail-closed
// deny — never a bare connect-only passthrough. The known gaps are enumerated, so this stays green today
// AND fails the moment a new privileged kind falls through the analyzer's dispatch to a bare stmt.kind
// passthrough.
func TestPrivilegedStatementsAreGated(t *testing.T) {
	for _, s := range mysqlStatements {
		if !privilegedNeedingGate[s.name] {
			continue
		}
		got := resolve(t, s.sql)
		// A bare connect-only passthrough now shows as a lone stmt.kind.<k> term (or the zero-grant
		// sentinel): resolved, asking nothing beyond the kind — no utility grant, no result.read, and not
		// a fail-closed deny. A privileged statement landing there is authorized by its benign-category
		// kind alone, the same under-gating the METADATA/SESSION passthrough classes used to represent —
		// UNLESS the kind's own category gates it (gatedBareKinds), which the account-mgmt kinds do.
		bareKind := strings.HasPrefix(got, "stmt.kind.") && !strings.Contains(got, " + ")
		connectOnly := (bareKind && !gatedBareKinds[got]) || got == "allow(connect-only)"
		if connectOnly && !knownConnectOnlyGaps[s.name] {
			t.Errorf("%s is privileged but resolves connect-only (%s) — it must be gated; verify %q", s.name, got, s.sql)
		}
		if !connectOnly && knownConnectOnlyGaps[s.name] {
			t.Errorf("%s no longer resolves connect-only (%s) — the gap is fixed; drop it from knownConnectOnlyGaps", s.name, got)
		}
	}
}
