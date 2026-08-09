package probe

import (
	"sort"
	"strings"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// resolve runs one statement through the real analyzer and reduces its emitted facts to the requirement
// fingerprint for the WIRE data-plane path — the grants decideQuery would require and the fail-closed bucket
// it would hit, named in the terms an operator reasons in. It is the analyzer's actual output, reduced; it
// is deliberately NOT a full decideQuery replica. It models decideQuery's short-circuit ORDER (INADMISSIBLE
// deny, then the datasource-grant loop, then the unanalyzable gate) but not: the channel (a bare `session`
// is passthrough only on WIRE/EDITOR — MCP and workflow channels DENY it), the Cedar verdict (it reports
// what is REQUIRED, never ALLOW/DENY), or that a datasource holding `sql.unanalyzable` can relay the
// unanalyzable gate. For those, read Query.kt.
//
// The vocabulary:
//
//	sql.select|insert|update|delete|ddl  — an ANALYZED statement's datasource grant (Query.kt grantAction()).
//	                                        Several joined by '+' when a statement needs more than one.
//	DENY(unspecified)                    — a datasource grant of UNSPECIFIED. grantAction() maps it to null
//	                                        and the datasource loop (Query.kt:478) denies THERE — before the
//	                                        unanalyzable gate — so it short-circuits any relay below it.
//	unanalyzable→sql.unanalyzable        — not resolved, UNANALYZABLE: routed to the deny-by-default gate a
//	                                        dev datasource can override.
//	INADMISSIBLE                         — not resolved, INADMISSIBLE: hard deny, no gate.
//	metadata                             — METADATA passthrough (SHOW TABLES, DESCRIBE): only connect is asked.
//	session                              — SESSION passthrough (SET, transaction control): only connect is
//	                                        asked ON WIRE/EDITOR (MCP/workflow deny — see above).
//	result.read                          — an ANALYZED statement touched a column/table/function: result.read.*
//	                                        is authorized per resource (joined with the datasource verb).
//	utility:<CMD>                        — carries a Utility grant; authorized as result.read.* on that
//	                                        utility, which the shipped forbids deny for the dangerous ones.
//	allow(connect-only)                  — resolved, ANALYZED, zero grants: nothing asked beyond connect.
func resolve(t *testing.T, sql string) string {
	t.Helper()
	f := mysqlFacts(t, sql)

	// INADMISSIBLE is a structural hard deny before any grant is considered (Query.kt ~357); it dominates.
	if !f.Resolved && f.FailureClass == pb.FailureClass_FAILURE_CLASS_INADMISSIBLE {
		return "INADMISSIBLE-deny"
	}

	var parts []string
	dsVerbs := map[string]bool{}
	utilities := map[string]bool{}
	touchesData := false
	for _, g := range f.RequiredGrants {
		switch {
		case g.GetDatasource():
			dsVerbs[sqlVerb(g.Action)] = true
		case g.GetUtility() != nil:
			utilities["utility:"+g.GetUtility().Command] = true
		case g.GetColumn() != nil || g.GetTable() != nil || g.GetFunction() != nil:
			touchesData = true
		}
	}
	parts = append(parts, mapKeys(utilities)...)
	parts = append(parts, mapKeys(dsVerbs)...)

	// A statement can carry a real datasource verb AND be unresolved (ALTER: sql.ddl + the sql.unanalyzable
	// gate) — both are required, so both surface. But an UNSPECIFIED verb DENIES at the datasource loop
	// before the unanalyzable gate is reached, so the relay is unreachable and must not be surfaced.
	switch {
	case dsVerbs["DENY(unspecified)"]:
		// hard-denied at the datasource loop; nothing downstream runs.
	case !f.Resolved && f.FailureClass == pb.FailureClass_FAILURE_CLASS_UNANALYZABLE:
		parts = append(parts, "unanalyzable→sql.unanalyzable")
	case !f.Resolved:
		parts = append(parts, "UNRESOLVED("+f.FailureClass.String()+")")
	default:
		switch f.StatementClass {
		case pb.StatementClass_STATEMENT_CLASS_METADATA:
			parts = append(parts, "metadata")
		case pb.StatementClass_STATEMENT_CLASS_SESSION:
			parts = append(parts, "session")
		case pb.StatementClass_STATEMENT_CLASS_UNSPECIFIED:
			parts = append(parts, "class-unspecified-deny")
		case pb.StatementClass_STATEMENT_CLASS_ANALYZED:
			if touchesData {
				parts = append(parts, "result.read")
			}
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

func sqlVerb(a pb.GrantAction) string {
	switch a {
	case pb.GrantAction_GRANT_ACTION_SQL_SELECT:
		return "sql.select"
	case pb.GrantAction_GRANT_ACTION_SQL_INSERT:
		return "sql.insert"
	case pb.GrantAction_GRANT_ACTION_SQL_UPDATE:
		return "sql.update"
	case pb.GrantAction_GRANT_ACTION_SQL_DELETE:
		return "sql.delete"
	case pb.GrantAction_GRANT_ACTION_SQL_DDL:
		return "sql.ddl"
	case pb.GrantAction_GRANT_ACTION_UNSPECIFIED:
		return "DENY(unspecified)"
	default:
		return "?(" + a.String() + ")"
	}
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
// data-exposing kind must be fail-closed (a datasource verb the operator must grant, a utility the shipped
// forbids deny, `unanalyzable→sql.unanalyzable`, or an outright deny), and no kind may resolve to
// `allow(connect-only)` unless it genuinely exposes nothing. Where a kind is under-gated today, its `want`
// records that and it is enumerated in knownConnectOnlyGaps below — the audit documents the gap rather than
// hiding it.
var mysqlStatements = []mysqlStatement{
	// ---- DML (§15.2) ----
	{"SELECT", "SELECT id FROM users", "result.read + sql.select", pb.StatementKind_STATEMENT_KIND_SELECT},
	{"SELECT (no table)", "SELECT 1", "metadata", pb.StatementKind_STATEMENT_KIND_SELECT},
	{"SELECT INTO OUTFILE", "SELECT id INTO OUTFILE 'f' FROM users", "result.read + sql.ddl", pb.StatementKind_STATEMENT_KIND_SELECT_INTO_OUTFILE},
	{"SELECT INTO DUMPFILE", "SELECT id INTO DUMPFILE 'f' FROM users", "result.read + sql.ddl", pb.StatementKind_STATEMENT_KIND_SELECT_INTO_DUMPFILE},
	{"UNION", "SELECT id FROM users UNION SELECT id FROM users", "result.read + sql.select", pb.StatementKind_STATEMENT_KIND_SET_OP},
	{"INTERSECT", "SELECT id FROM users INTERSECT SELECT id FROM users", "result.read + sql.select", pb.StatementKind_STATEMENT_KIND_SET_OP},
	{"EXCEPT", "SELECT id FROM users EXCEPT SELECT id FROM users", "result.read + sql.select", pb.StatementKind_STATEMENT_KIND_SET_OP},
	{"TABLE", "TABLE users", "result.read + sql.select", pb.StatementKind_STATEMENT_KIND_SELECT}, // v0.22: parses as SELECT * FROM users, indistinguishable from SELECT
	{"VALUES", "VALUES ROW(1)", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_VALUES},
	{"WITH (CTE)", "WITH c AS (SELECT id FROM users) SELECT id FROM c", "result.read + sql.select", pb.StatementKind_STATEMENT_KIND_WITH_SELECT},
	{"INSERT", "INSERT INTO users (id) VALUES (1)", "sql.insert", pb.StatementKind_STATEMENT_KIND_INSERT},
	{"INSERT SELECT", "INSERT INTO users (id) SELECT id FROM users", "result.read + sql.insert", pb.StatementKind_STATEMENT_KIND_INSERT_SELECT},
	{"INSERT ODKU", "INSERT INTO users (id) VALUES (1) ON DUPLICATE KEY UPDATE id=id", "result.read + sql.insert + sql.update", pb.StatementKind_STATEMENT_KIND_INSERT_ON_DUP},
	{"REPLACE", "REPLACE INTO users (id) VALUES (1)", "DENY(unspecified)", pb.StatementKind_STATEMENT_KIND_REPLACE},
	{"UPDATE", "UPDATE users SET email='x'", "sql.update", pb.StatementKind_STATEMENT_KIND_UPDATE},
	{"DELETE", "DELETE FROM users", "sql.delete", pb.StatementKind_STATEMENT_KIND_DELETE},
	{"DO", "DO 1", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},                                         // parse error
	{"CALL", "CALL p()", "DENY(unspecified)", pb.StatementKind_STATEMENT_KIND_CALL},                                                       // denied at the datasource loop before the unanalyzable gate
	{"HANDLER OPEN", "HANDLER users OPEN", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},                 // parse error
	{"HANDLER READ", "HANDLER users READ FIRST", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},           // parse error
	{"HANDLER CLOSE", "HANDLER users CLOSE", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},               // parse error
	{"LOAD DATA", "LOAD DATA INFILE 'f' INTO TABLE users", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error
	{"LOAD XML", "LOAD XML INFILE 'f' INTO TABLE users", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"IMPORT TABLE", "IMPORT TABLE FROM 'users.sdi'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error

	// ---- DDL (§15.1) ----
	// Table/index/view/schema DDL that sqlglot models structurally (Create / Alter / Drop / TruncateTable)
	// is catalog-changing: fully determined, reads no column values, gated by sql.ddl alone. Forms sqlglot
	// leaves as a Command (routines, events, servers, tablespaces, SRS, RENAME TABLE) stay unresolved and
	// route to the sql.unanalyzable gate — an over-deny, not a leak.
	{"CREATE TABLE", "CREATE TABLE t (id INT)", "sql.ddl", pb.StatementKind_STATEMENT_KIND_CREATE_TABLE},
	{"CREATE TABLE AS SELECT", "CREATE TABLE t AS SELECT id FROM users", "result.read + sql.ddl", pb.StatementKind_STATEMENT_KIND_CREATE_TABLE},
	{"CREATE TABLE LIKE", "CREATE TABLE t LIKE users", "sql.ddl", pb.StatementKind_STATEMENT_KIND_CREATE_TABLE},
	{"CREATE INDEX", "CREATE INDEX i ON users (id)", "sql.ddl", pb.StatementKind_STATEMENT_KIND_CREATE_INDEX},
	{"CREATE VIEW", "CREATE VIEW v AS SELECT 1", "sql.ddl", pb.StatementKind_STATEMENT_KIND_CREATE_VIEW},
	{"CREATE DATABASE", "CREATE DATABASE d", "sql.ddl", pb.StatementKind_STATEMENT_KIND_CREATE_DATABASE},
	{"CREATE TRIGGER", "CREATE TRIGGER trg BEFORE INSERT ON users FOR EACH ROW SET @a = 1", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"CREATE PROCEDURE", "CREATE PROCEDURE p() SELECT 1", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"CREATE FUNCTION (stored)", "CREATE FUNCTION f() RETURNS INT RETURN 1", "sql.ddl", pb.StatementKind_STATEMENT_KIND_CREATE_FUNCTION},
	// A routine body carrying a query (RETURN (SELECT …)) is not a CTAS: the read happens at invocation,
	// not at CREATE. Lineage cannot analyze the routine body, so it over-denies (unresolved) rather than
	// resolving catalog-changing like the bare form above — a fail-closed asymmetry, not a leak.
	{"CREATE FUNCTION (stored, query body)", "CREATE FUNCTION f() RETURNS INT RETURN (SELECT id FROM users)", "sql.ddl + unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_CREATE_FUNCTION},
	{"CREATE FUNCTION (UDF)", "CREATE FUNCTION f RETURNS INTEGER SONAME 'f.so'", "sql.ddl", pb.StatementKind_STATEMENT_KIND_CREATE_FUNCTION},
	{"CREATE EVENT", "CREATE EVENT e ON SCHEDULE AT NOW() DO SET @a = 1", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"CREATE SERVER", "CREATE SERVER s FOREIGN DATA WRAPPER mysql OPTIONS (USER 'u')", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"CREATE TABLESPACE", "CREATE TABLESPACE ts ADD DATAFILE 'ts.ibd'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"CREATE SRS", "CREATE SPATIAL REFERENCE SYSTEM 4000 NAME 'x' DEFINITION 'y'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"ALTER TABLE", "ALTER TABLE users ADD COLUMN x INT", "sql.ddl", pb.StatementKind_STATEMENT_KIND_ALTER_TABLE},
	{"ALTER DATABASE", "ALTER DATABASE d CHARACTER SET utf8mb4", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"ALTER VIEW", "ALTER VIEW v AS SELECT 1", "sql.ddl", pb.StatementKind_STATEMENT_KIND_ALTER_VIEW},
	{"ALTER EVENT", "ALTER EVENT e DISABLE", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"ALTER PROCEDURE", "ALTER PROCEDURE p COMMENT 'x'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"ALTER FUNCTION", "ALTER FUNCTION f COMMENT 'x'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"ALTER SERVER", "ALTER SERVER s OPTIONS (USER 'u')", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"ALTER TABLESPACE", "ALTER TABLESPACE ts RENAME TO ts2", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"ALTER INSTANCE", "ALTER INSTANCE ROTATE INNODB MASTER KEY", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"DROP TABLE", "DROP TABLE users", "sql.ddl", pb.StatementKind_STATEMENT_KIND_DROP_TABLE},
	{"DROP INDEX", "DROP INDEX i ON users", "sql.ddl", pb.StatementKind_STATEMENT_KIND_DROP_INDEX}, // sqlglot-go v0.22.0 models this as a structured Drop, unlike RENAME TABLE
	{"DROP VIEW", "DROP VIEW v", "sql.ddl", pb.StatementKind_STATEMENT_KIND_DROP_VIEW},
	{"DROP DATABASE", "DROP DATABASE d", "sql.ddl", pb.StatementKind_STATEMENT_KIND_DROP_DATABASE},
	{"DROP TRIGGER", "DROP TRIGGER trg", "sql.ddl", pb.StatementKind_STATEMENT_KIND_DROP_TRIGGER},
	{"DROP PROCEDURE", "DROP PROCEDURE p", "sql.ddl", pb.StatementKind_STATEMENT_KIND_DROP_PROCEDURE},
	{"DROP FUNCTION", "DROP FUNCTION f", "sql.ddl", pb.StatementKind_STATEMENT_KIND_DROP_FUNCTION},
	{"DROP EVENT", "DROP EVENT e", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"DROP SERVER", "DROP SERVER s", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"DROP TABLESPACE", "DROP TABLESPACE ts", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"DROP SRS", "DROP SPATIAL REFERENCE SYSTEM 4000", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"TRUNCATE TABLE", "TRUNCATE TABLE users", "sql.ddl", pb.StatementKind_STATEMENT_KIND_TRUNCATE_TABLE},
	{"RENAME TABLE", "RENAME TABLE users TO u2", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},

	// ---- Transaction / locking (§15.3) ----
	{"START TRANSACTION", "START TRANSACTION", "session", pb.StatementKind_STATEMENT_KIND_START_TRANSACTION},
	{"BEGIN", "BEGIN", "session", pb.StatementKind_STATEMENT_KIND_START_TRANSACTION},
	{"COMMIT", "COMMIT", "session", pb.StatementKind_STATEMENT_KIND_COMMIT},
	{"ROLLBACK", "ROLLBACK", "session", pb.StatementKind_STATEMENT_KIND_ROLLBACK},
	{"SAVEPOINT", "SAVEPOINT s", "session", pb.StatementKind_STATEMENT_KIND_SAVEPOINT},
	{"ROLLBACK TO SAVEPOINT", "ROLLBACK TO SAVEPOINT s", "session", pb.StatementKind_STATEMENT_KIND_ROLLBACK},
	{"RELEASE SAVEPOINT", "RELEASE SAVEPOINT s", "session", pb.StatementKind_STATEMENT_KIND_SAVEPOINT},
	{"SET TRANSACTION", "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE", "session", pb.StatementKind_STATEMENT_KIND_SET_TRANSACTION},
	{"SET autocommit", "SET autocommit=0", "session", pb.StatementKind_STATEMENT_KIND_SET_SESSION_VAR},
	{"LOCK TABLES", "LOCK TABLES users READ", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_LOCK_TABLES},
	{"UNLOCK TABLES", "UNLOCK TABLES", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_UNLOCK_TABLES},
	{"LOCK INSTANCE FOR BACKUP", "LOCK INSTANCE FOR BACKUP", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error
	{"UNLOCK INSTANCE", "UNLOCK INSTANCE", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"XA START", "XA START 'x'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_XA},
	{"XA END", "XA END 'x'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_XA},
	{"XA PREPARE", "XA PREPARE 'x'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_XA},
	{"XA COMMIT", "XA COMMIT 'x'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_XA},
	{"XA ROLLBACK", "XA ROLLBACK 'x'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_XA},
	{"XA RECOVER", "XA RECOVER", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_XA},

	// ---- Prepared statements (§15.5) — SQL-injection surface, must fail closed ----
	{"PREPARE", "PREPARE s FROM 'SELECT 1'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_PREPARE},
	{"EXECUTE", "EXECUTE s", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_EXECUTE},
	{"DEALLOCATE PREPARE", "DEALLOCATE PREPARE s", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error

	// ---- Replication (§15.4) — privileged, must fail closed ----
	{"CHANGE REPLICATION SOURCE TO", "CHANGE REPLICATION SOURCE TO SOURCE_HOST='h'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},  // parse error
	{"CHANGE MASTER TO", "CHANGE MASTER TO MASTER_HOST='h'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},                          // parse error
	{"CHANGE REPLICATION FILTER", "CHANGE REPLICATION FILTER REPLICATE_DO_DB = (d1)", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error
	{"START REPLICA", "START REPLICA", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"START SLAVE", "START SLAVE", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"STOP REPLICA", "STOP REPLICA", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"STOP SLAVE", "STOP SLAVE", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"RESET REPLICA", "RESET REPLICA", "INADMISSIBLE-deny", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"RESET SLAVE", "RESET SLAVE", "INADMISSIBLE-deny", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"START GROUP_REPLICATION", "START GROUP_REPLICATION", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"STOP GROUP_REPLICATION", "STOP GROUP_REPLICATION", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"PURGE BINARY LOGS", "PURGE BINARY LOGS BEFORE '2020-01-01'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error
	{"RESET MASTER", "RESET MASTER", "INADMISSIBLE-deny", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"RESET BINARY LOGS AND GTIDS", "RESET BINARY LOGS AND GTIDS", "INADMISSIBLE-deny", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // 8.4 replacement for RESET MASTER

	// ---- Account management (§15.7.1) — privileged, must fail closed ----
	{"CREATE USER", "CREATE USER 'u'@'h'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"ALTER USER", "ALTER USER 'u'@'h' IDENTIFIED BY 'p'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"DROP USER", "DROP USER 'u'@'h'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"RENAME USER", "RENAME USER 'u'@'h' TO 'v'@'h'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"CREATE ROLE", "CREATE ROLE 'r'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"DROP ROLE", "DROP ROLE 'r'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"GRANT (priv)", "GRANT SELECT ON *.* TO 'u'@'h'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_GRANT_PRIV},
	{"GRANT (role)", "GRANT 'r' TO 'u'@'h'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_GRANT_PRIV},
	{"REVOKE (priv)", "REVOKE SELECT ON *.* FROM 'u'@'h'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_REVOKE_PRIV},
	{"REVOKE (role)", "REVOKE 'r' FROM 'u'@'h'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_REVOKE_PRIV},
	{"SET PASSWORD", "SET PASSWORD FOR 'u'@'h' = 'p'", "session + utility:SET_PASSWORD", pb.StatementKind_STATEMENT_KIND_SET_PASSWORD},
	{"SET ROLE", "SET ROLE 'r'", "session + utility:SET_ROLE", pb.StatementKind_STATEMENT_KIND_SET_ROLE},
	{"SET DEFAULT ROLE", "SET DEFAULT ROLE 'r' TO 'u'@'h'", "session + utility:SET_DEFAULT_ROLE", pb.StatementKind_STATEMENT_KIND_SET_DEFAULT_ROLE},

	// ---- Table maintenance (§15.7.3) ----
	// GAP: ANALYZE is in the session-passthrough set (facts.go), so it is connect-only; CHECK/OPTIMIZE/REPAIR fail closed.
	{"ANALYZE TABLE", "ANALYZE TABLE users", "session", pb.StatementKind_STATEMENT_KIND_ANALYZE_TABLE},
	{"CHECK TABLE", "CHECK TABLE users", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},       // parse error
	{"CHECKSUM TABLE", "CHECKSUM TABLE users", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error
	{"OPTIMIZE TABLE", "OPTIMIZE TABLE users", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_OPTIMIZE_TABLE},
	{"REPAIR TABLE", "REPAIR TABLE users", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error

	// ---- Other server administration (§15.7) — privileged, must fail closed ----
	{"INSTALL PLUGIN", "INSTALL PLUGIN p SONAME 'p.so'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},      // parse error
	{"UNINSTALL PLUGIN", "UNINSTALL PLUGIN p", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},                // parse error
	{"INSTALL COMPONENT", "INSTALL COMPONENT 'file://c'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},     // parse error
	{"UNINSTALL COMPONENT", "UNINSTALL COMPONENT 'file://c'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error
	{"CLONE", "CLONE LOCAL DATA DIRECTORY = '/tmp/c'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},        // parse error
	{"FLUSH", "FLUSH TABLES", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_FLUSH},
	{"FLUSH PRIVILEGES", "FLUSH PRIVILEGES", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_FLUSH},
	{"KILL", "KILL 1", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_KILL},
	{"CACHE INDEX", "CACHE INDEX users IN c", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error
	{"LOAD INDEX INTO CACHE", "LOAD INDEX INTO CACHE users", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"BINLOG", "BINLOG 'x'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_BINLOG},
	{"RESET PERSIST", "RESET PERSIST", "INADMISSIBLE-deny", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"RESTART", "RESTART", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_RESTART},
	{"SHUTDOWN", "SHUTDOWN", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_SHUTDOWN},
	{"SET RESOURCE GROUP", "SET RESOURCE GROUP grp", "INADMISSIBLE-deny", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"CREATE RESOURCE GROUP", "CREATE RESOURCE GROUP grp TYPE = USER", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"ALTER RESOURCE GROUP", "ALTER RESOURCE GROUP grp VCPU = 0", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	{"DROP RESOURCE GROUP", "DROP RESOURCE GROUP grp", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},

	// ---- SET forms (§15.7.6) ----
	{"SET user var", "SET @x = 1", "session", pb.StatementKind_STATEMENT_KIND_SET_SESSION_VAR},
	{"SET GLOBAL var", "SET GLOBAL max_connections = 100", "session + utility:SET_GLOBAL", pb.StatementKind_STATEMENT_KIND_SET_GLOBAL},
	{"SET PERSIST var", "SET PERSIST max_connections = 100", "session + utility:SET_PERSIST", pb.StatementKind_STATEMENT_KIND_SET_PERSIST},
	{"SET PERSIST_ONLY var", "SET PERSIST_ONLY max_connections = 100", "session + utility:SET_PERSIST_ONLY", pb.StatementKind_STATEMENT_KIND_SET_PERSIST_ONLY},
	{"SET NAMES", "SET NAMES utf8mb4", "session", pb.StatementKind_STATEMENT_KIND_SET_SESSION_VAR},
	{"SET CHARACTER SET", "SET CHARACTER SET utf8mb4", "session", pb.StatementKind_STATEMENT_KIND_SET_SESSION_VAR},
	// GAP: sql_log_bin is a restricted SESSION variable (needs SESSION_VARIABLES_ADMIN); disabling it drops
	// the session's writes from the binlog/GTID stream. The analyzer gates SET by scope (GLOBAL/PERSIST) and
	// PASSWORD only, so a session-scoped assignment is a bare passthrough. See knownConnectOnlyGaps.
	{"SET sql_log_bin", "SET SESSION sql_log_bin = 0", "session", pb.StatementKind_STATEMENT_KIND_SET_SQL_LOG_BIN},

	// ---- SHOW: benign metadata (§15.7.7) ----
	{"SHOW DATABASES", "SHOW DATABASES", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW TABLES", "SHOW TABLES", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW COLUMNS", "SHOW COLUMNS FROM users", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW INDEX", "SHOW INDEX FROM users", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW CREATE TABLE", "SHOW CREATE TABLE users", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW CREATE DATABASE", "SHOW CREATE DATABASE d", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW CREATE VIEW", "SHOW CREATE VIEW v", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW CREATE PROCEDURE", "SHOW CREATE PROCEDURE p", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW CREATE FUNCTION", "SHOW CREATE FUNCTION f", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW CREATE TRIGGER", "SHOW CREATE TRIGGER trg", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW CREATE EVENT", "SHOW CREATE EVENT e", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW ENGINES", "SHOW ENGINES", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW STATUS", "SHOW STATUS", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW VARIABLES", "SHOW VARIABLES", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW WARNINGS", "SHOW WARNINGS", "metadata + utility:SHOW_WARNINGS", pb.StatementKind_STATEMENT_KIND_SHOW_WARNINGS},
	{"SHOW ERRORS", "SHOW ERRORS", "metadata + utility:SHOW_ERRORS", pb.StatementKind_STATEMENT_KIND_SHOW_ERRORS},
	{"SHOW CHARACTER SET", "SHOW CHARACTER SET", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW COLLATION", "SHOW COLLATION", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW PRIVILEGES", "SHOW PRIVILEGES", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW PLUGINS", "SHOW PLUGINS", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW TABLE STATUS", "SHOW TABLE STATUS", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW OPEN TABLES", "SHOW OPEN TABLES", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW TRIGGERS", "SHOW TRIGGERS", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW EVENTS", "SHOW EVENTS", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW PROCEDURE STATUS", "SHOW PROCEDURE STATUS", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
	{"SHOW FUNCTION STATUS", "SHOW FUNCTION STATUS", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},

	// ---- SHOW: data/credential/topology-exposing — must be a utility or fail closed ----
	// The `metadata`-only rows here are UNDER-GATED today (see knownConnectOnlyGaps): the analyzer emits no
	// utility for them, so they relay connect-only on wire. The statement-typing redesign closes them.
	{"SHOW PROCESSLIST", "SHOW PROCESSLIST", "metadata + utility:SHOW_PROCESSLIST", pb.StatementKind_STATEMENT_KIND_SHOW_PROCESSLIST},
	{"SHOW GRANTS", "SHOW GRANTS", "metadata + utility:SHOW_GRANTS", pb.StatementKind_STATEMENT_KIND_SHOW_GRANTS},
	{"SHOW CREATE USER", "SHOW CREATE USER CURRENT_USER", "metadata + utility:SHOW_CREATE_USER", pb.StatementKind_STATEMENT_KIND_SHOW_CREATE_USER},
	{"SHOW ENGINE INNODB STATUS", "SHOW ENGINE INNODB STATUS", "metadata + utility:SHOW_ENGINE_STATUS", pb.StatementKind_STATEMENT_KIND_SHOW_ENGINE_STATUS},
	{"SHOW BINLOG EVENTS", "SHOW BINLOG EVENTS", "metadata + utility:SHOW_BINLOG_EVENTS", pb.StatementKind_STATEMENT_KIND_SHOW_BINLOG_EVENTS},
	{"SHOW RELAYLOG EVENTS", "SHOW RELAYLOG EVENTS", "metadata + utility:SHOW_RELAYLOG_EVENTS", pb.StatementKind_STATEMENT_KIND_SHOW_RELAYLOG_EVENTS},
	{"SHOW BINARY LOGS", "SHOW BINARY LOGS", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_BINARY_LOGS},                                        // GAP: needs REPLICATION CLIENT
	{"SHOW MASTER STATUS", "SHOW MASTER STATUS", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_MASTER_STATUS},                                  // GAP: needs REPLICATION CLIENT
	{"SHOW BINARY LOG STATUS", "SHOW BINARY LOG STATUS", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // 8.4 rename; degrades to Command, fails closed (unlike SHOW MASTER STATUS)
	{"SHOW REPLICA STATUS", "SHOW REPLICA STATUS", "metadata + utility:SHOW_REPLICA_STATUS", pb.StatementKind_STATEMENT_KIND_SHOW_REPLICA_STATUS},
	{"SHOW SLAVE STATUS", "SHOW SLAVE STATUS", "metadata + utility:SHOW_REPLICA_STATUS", pb.StatementKind_STATEMENT_KIND_SHOW_REPLICA_STATUS},
	{"SHOW REPLICAS", "SHOW REPLICAS", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_REPLICAS},       // GAP: needs REPLICATION SLAVE
	{"SHOW SLAVE HOSTS", "SHOW SLAVE HOSTS", "metadata", pb.StatementKind_STATEMENT_KIND_SHOW_REPLICAS}, // GAP: alias of SHOW REPLICAS
	{"SHOW WHERE subquery", "SHOW TABLES WHERE Tables_in_db IN (SELECT ssn FROM users)", "metadata + utility:SHOW_SUBQUERY", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},

	// ---- Utility (§15.8) ----
	{"DESCRIBE", "DESCRIBE users", "metadata", pb.StatementKind_STATEMENT_KIND_DESCRIBE},
	{"DESC", "DESC users", "metadata", pb.StatementKind_STATEMENT_KIND_DESCRIBE},
	{"EXPLAIN (query)", "EXPLAIN SELECT id FROM users", "result.read + sql.select", pb.StatementKind_STATEMENT_KIND_SELECT},
	{"EXPLAIN ANALYZE", "EXPLAIN ANALYZE SELECT id FROM users", "result.read + sql.select", pb.StatementKind_STATEMENT_KIND_SELECT},
	{"EXPLAIN (table)", "EXPLAIN users", "metadata", pb.StatementKind_STATEMENT_KIND_DESCRIBE}, // EXPLAIN <table> is AST-identical to DESCRIBE <table>
	{"HELP", "HELP 'contents'", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_HELP},
	{"USE", "USE acme", "session", pb.StatementKind_STATEMENT_KIND_USE},

	// ---- Compound (§15.6) ----
	// Compound BEGIN...END blocks are valid only inside a stored program; a client reaches them via CALL
	// (above), never as a standalone statement. Sent standalone it is a parse error → fail-closed.
	{"BEGIN...END (standalone)", "BEGIN SELECT 1; END", "unanalyzable→sql.unanalyzable", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN}, // parse error
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
		got := mysqlFacts(t, s.sql).GetStatementKind()
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
// bare connect-only passthrough (`session` or `metadata` with no utility gate). The utility-gated kinds
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
	"CREATE USER": true, "ALTER USER": true, "DROP USER": true, "RENAME USER": true, "CREATE ROLE": true,
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
//	ANALYZE TABLE                       — in the analyzer's SESSION passthrough set (facts.go).
//	SET sql_log_bin                     — restricted SESSION variable; SET is gated by scope/PASSWORD only.
//	SHOW MASTER STATUS / SHOW BINARY LOGS / SHOW REPLICAS / SHOW SLAVE HOSTS
//	                                    — replication topology/binlog reads the analyzer emits no utility for.
var knownConnectOnlyGaps = map[string]bool{
	"ANALYZE TABLE":      true,
	"SET sql_log_bin":    true,
	"SHOW MASTER STATUS": true,
	"SHOW BINARY LOGS":   true,
	"SHOW REPLICAS":      true,
	"SHOW SLAVE HOSTS":   true,
}

// TestPrivilegedStatementsAreGated is the security invariant: every privileged or data-exposing MySQL
// statement must be gated — a datasource verb, a utility grant, or a fail-closed deny — never a bare
// connect-only passthrough. The known gaps are enumerated, so this stays green today AND fails the moment a
// new privileged kind falls through the analyzer's dispatch to `session`/`metadata`.
func TestPrivilegedStatementsAreGated(t *testing.T) {
	for _, s := range mysqlStatements {
		if !privilegedNeedingGate[s.name] {
			continue
		}
		got := resolve(t, s.sql)
		connectOnly := got == "session" || got == "metadata" || got == "allow(connect-only)"
		if connectOnly && !knownConnectOnlyGaps[s.name] {
			t.Errorf("%s is privileged but resolves connect-only (%s) — it must be gated; verify %q", s.name, got, s.sql)
		}
		if !connectOnly && knownConnectOnlyGaps[s.name] {
			t.Errorf("%s no longer resolves connect-only (%s) — the gap is fixed; drop it from knownConnectOnlyGaps", s.name, got)
		}
	}
}
