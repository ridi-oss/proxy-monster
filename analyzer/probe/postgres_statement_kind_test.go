package probe

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// pgFacts runs one statement through the real analyzer under the PostgreSQL dialect.
func pgFacts(t *testing.T, sql string) *pb.StatementFacts {
	t.Helper()
	return analyzeProto(t, &pb.AnalyzeRequest{
		Sql:          sql,
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
		Namespace:    &pb.Namespace{Catalog: "def", SearchPath: []string{"public"}},
		Catalog: []*pb.ColumnSpec{
			columnSpec("def", "public", "users", "id", "BIGINT"),
			columnSpec("def", "public", "users", "ssn", "VARCHAR"),
		},
	})
}

// TestPostgresStatementKind is the PostgreSQL parallel of mysql_statement_coverage_test.go's kind pinning.
// MySQL is the correctness bar (its coverage is exhaustive and build-enforced); this pins the kind the probe
// emits across PostgreSQL's SQL-command surface — enumerated from the command reference, not sampled.
//
// It is a LIVING LEDGER, and the ledger is currently sparse: roughly half of PostgreSQL's statements land on
// STMT_UNKNOWN, because sqlglot-go parses them as a Command (or a node the classifier does not map) and the
// port structures far less PostgreSQL DDL/admin than MySQL. Every STMT_UNKNOWN is FAIL-SAFE: it routes to the
// deny-by-default sql.unanalyzable exception (prod denies, a dev datasource may relay), so an unclassified
// PostgreSQL statement is denied, never silently allowed. As sqlglot-go structures more and the classifier
// maps more, these flip to real kinds — a diff on this table is the record of that progress.
//
// A few PostgreSQL-specific results worth knowing (verified here, not assumed):
//   - EXPLAIN [ANALYZE] <query> unwraps to the inner query's kind (SELECT), and the control-plane's
//     explainOfQuery guard handles the plan-vs-rows distinction.
//   - SELECT … INTO <newtable> classifies as SELECT (read), NOT create_table — it is CTAS-equivalent, so the
//     read-side lineage/masking is what must cover it; the write side is not modelled as DDL here.
//   - MERGE, and privilege GRANT/REVOKE ON <object>, are STMT_UNKNOWN (only GRANT <role> TO <user>, a bare
//     Command, resolves to grant_priv). PostgreSQL trigger/function DROP structure where MySQL's do not.
func TestPostgresStatementKind(t *testing.T) {
	cases := []struct {
		sql  string
		want pb.StatementKind
	}{
		// --- read ---
		{"SELECT ssn FROM users", pb.StatementKind_STATEMENT_KIND_SELECT},
		{"SELECT 1", pb.StatementKind_STATEMENT_KIND_SELECT},
		{"WITH c AS (SELECT id FROM users) SELECT * FROM c", pb.StatementKind_STATEMENT_KIND_WITH_SELECT},
		{"SELECT 1 UNION SELECT 2", pb.StatementKind_STATEMENT_KIND_SET_OP},
		{"SELECT 1 INTERSECT SELECT 2", pb.StatementKind_STATEMENT_KIND_SET_OP},
		{"SELECT 1 EXCEPT SELECT 2", pb.StatementKind_STATEMENT_KIND_SET_OP},
		{"VALUES (1), (2)", pb.StatementKind_STATEMENT_KIND_VALUES},
		{"SELECT ssn FROM users FOR UPDATE", pb.StatementKind_STATEMENT_KIND_SELECT},
		// SELECT … INTO is CTAS-equivalent but classifies as a read; EXPLAIN unwraps to its inner query.
		{"SELECT id INTO newtab FROM users", pb.StatementKind_STATEMENT_KIND_SELECT_INTO},
		{"EXPLAIN SELECT ssn FROM users", pb.StatementKind_STATEMENT_KIND_SELECT},
		{"EXPLAIN ANALYZE SELECT ssn FROM users", pb.StatementKind_STATEMENT_KIND_SELECT},
		// TABLE <name> (a PostgreSQL SELECT shorthand) is not structured as a query.
		{"TABLE users", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},

		// --- write ---
		{"INSERT INTO users (id) VALUES (1)", pb.StatementKind_STATEMENT_KIND_INSERT},
		{"INSERT INTO users (id) SELECT id FROM users", pb.StatementKind_STATEMENT_KIND_INSERT_SELECT},
		{"INSERT INTO users (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET id = 1", pb.StatementKind_STATEMENT_KIND_INSERT_ON_DUP},
		{"INSERT INTO users (id) VALUES (1) ON CONFLICT (id) DO NOTHING", pb.StatementKind_STATEMENT_KIND_INSERT},
		{"UPDATE users SET id = 1", pb.StatementKind_STATEMENT_KIND_UPDATE},
		{"DELETE FROM users", pb.StatementKind_STATEMENT_KIND_DELETE},
		{"TRUNCATE users", pb.StatementKind_STATEMENT_KIND_TRUNCATE_TABLE},
		{"TRUNCATE TABLE users", pb.StatementKind_STATEMENT_KIND_TRUNCATE_TABLE},
		// MERGE (PG 15+) is a data-modifying statement the classifier does not map yet.
		{"MERGE INTO users u USING users s ON u.id = s.id WHEN MATCHED THEN UPDATE SET id = s.id", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},

		// --- transaction / session ---
		{"BEGIN", pb.StatementKind_STATEMENT_KIND_START_TRANSACTION},
		{"START TRANSACTION", pb.StatementKind_STATEMENT_KIND_START_TRANSACTION},
		{"COMMIT", pb.StatementKind_STATEMENT_KIND_COMMIT},
		{"END", pb.StatementKind_STATEMENT_KIND_COMMIT},
		{"ROLLBACK", pb.StatementKind_STATEMENT_KIND_ROLLBACK},
		{"SAVEPOINT s", pb.StatementKind_STATEMENT_KIND_SAVEPOINT},
		{"RELEASE SAVEPOINT s", pb.StatementKind_STATEMENT_KIND_SAVEPOINT},
		{"ROLLBACK TO SAVEPOINT s", pb.StatementKind_STATEMENT_KIND_ROLLBACK},
		{"SET search_path TO public", pb.StatementKind_STATEMENT_KIND_SET_SESSION_VAR},
		{"SET LOCAL search_path TO public", pb.StatementKind_STATEMENT_KIND_SET_SESSION_VAR},
		{"SET ROLE analyst", pb.StatementKind_STATEMENT_KIND_SET_ROLE},
		{"SET SESSION AUTHORIZATION analyst", pb.StatementKind_STATEMENT_KIND_SET_SESSION_AUTHORIZATION},
		{"SET TRANSACTION ISOLATION LEVEL SERIALIZABLE", pb.StatementKind_STATEMENT_KIND_SET_TRANSACTION},
		{"SET CONSTRAINTS ALL DEFERRED", pb.StatementKind_STATEMENT_KIND_SET_SESSION_VAR},
		{"RESET search_path", pb.StatementKind_STATEMENT_KIND_SET_SESSION_VAR},
		{"RESET ALL", pb.StatementKind_STATEMENT_KIND_SET_SESSION_VAR},
		{"SHOW search_path", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
		{"SHOW ALL", pb.StatementKind_STATEMENT_KIND_SHOW_METADATA},
		// PREPARE TRANSACTION is a bare Command keyed only on the leading keyword PREPARE.
		{"PREPARE TRANSACTION 'gid'", pb.StatementKind_STATEMENT_KIND_PREPARE},
		{"ABORT", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"DISCARD ALL", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"COMMIT PREPARED 'gid'", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"ROLLBACK PREPARED 'gid'", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"LOAD 'plugin'", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},

		// --- DDL that sqlglot structures (PostgreSQL structures trigger/function DDL MySQL leaves as Commands) ---
		{"CREATE TABLE t (id INT)", pb.StatementKind_STATEMENT_KIND_CREATE_TABLE},
		{"CREATE TABLE t AS SELECT id FROM users", pb.StatementKind_STATEMENT_KIND_CREATE_TABLE},
		{"CREATE TEMP TABLE t (id INT)", pb.StatementKind_STATEMENT_KIND_CREATE_TABLE},
		{"CREATE VIEW v AS SELECT 1", pb.StatementKind_STATEMENT_KIND_CREATE_VIEW},
		{"CREATE MATERIALIZED VIEW mv AS SELECT 1", pb.StatementKind_STATEMENT_KIND_CREATE_VIEW},
		{"CREATE INDEX i ON users (id)", pb.StatementKind_STATEMENT_KIND_CREATE_INDEX},
		{"CREATE UNIQUE INDEX i ON users (id)", pb.StatementKind_STATEMENT_KIND_CREATE_INDEX},
		{"CREATE SCHEMA s", pb.StatementKind_STATEMENT_KIND_CREATE_DATABASE},
		{"CREATE TRIGGER trg BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION f()", pb.StatementKind_STATEMENT_KIND_CREATE_TRIGGER},
		{"ALTER TABLE users ADD COLUMN c INT", pb.StatementKind_STATEMENT_KIND_ALTER_TABLE},
		{"ALTER TABLE users RENAME TO users2", pb.StatementKind_STATEMENT_KIND_ALTER_TABLE},
		{"ALTER VIEW v RENAME TO v2", pb.StatementKind_STATEMENT_KIND_ALTER_VIEW},
		{"DROP TABLE users", pb.StatementKind_STATEMENT_KIND_DROP_TABLE},
		{"DROP TABLE IF EXISTS users CASCADE", pb.StatementKind_STATEMENT_KIND_DROP_TABLE},
		{"DROP VIEW v", pb.StatementKind_STATEMENT_KIND_DROP_VIEW},
		{"DROP MATERIALIZED VIEW mv", pb.StatementKind_STATEMENT_KIND_DROP_VIEW},
		{"DROP INDEX i", pb.StatementKind_STATEMENT_KIND_DROP_INDEX},
		{"DROP SCHEMA s", pb.StatementKind_STATEMENT_KIND_DROP_DATABASE},
		{"DROP FUNCTION f()", pb.StatementKind_STATEMENT_KIND_DROP_FUNCTION},
		{"DROP TRIGGER trg ON users", pb.StatementKind_STATEMENT_KIND_DROP_TRIGGER},

		// --- DDL the classifier does not map yet (parses as a Command / unmapped node) ---
		{"CREATE SEQUENCE seq", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"CREATE TYPE ty AS ENUM ('a', 'b')", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"CREATE DOMAIN dom AS INT", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"CREATE EXTENSION ext", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"CREATE FUNCTION f() RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"CREATE PROCEDURE p() AS $$ BEGIN END $$ LANGUAGE plpgsql", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"CREATE RULE r AS ON INSERT TO users DO NOTHING", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"CREATE POLICY pol ON users USING (true)", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"CREATE FOREIGN TABLE ft (id INT) SERVER srv", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"CREATE SERVER srv FOREIGN DATA WRAPPER fdw", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"CREATE PUBLICATION pub FOR ALL TABLES", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"CREATE SUBSCRIPTION sub CONNECTION 'x' PUBLICATION pub", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"CREATE STATISTICS st ON id FROM users", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"CREATE EVENT TRIGGER et ON ddl_command_start EXECUTE FUNCTION f()", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"ALTER INDEX i RENAME TO i2", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"ALTER SEQUENCE seq RESTART", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"ALTER TYPE ty ADD VALUE 'c'", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"ALTER SCHEMA s RENAME TO s2", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"ALTER SYSTEM SET work_mem = '4MB'", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO analyst", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"DROP SEQUENCE seq", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"DROP TYPE ty", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"DROP DOMAIN dom", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"DROP EXTENSION ext", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"COMMENT ON TABLE users IS 'x'", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"SECURITY LABEL ON TABLE users IS 'label'", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},

		// --- account / privilege (mostly unmapped; only a bare-Command GRANT <role> resolves) ---
		{"GRANT analyst TO u", pb.StatementKind_STATEMENT_KIND_GRANT_PRIV},
		{"CREATE ROLE r", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"CREATE USER u", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"CREATE GROUP g", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"ALTER ROLE r WITH LOGIN", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"ALTER USER u WITH PASSWORD 'p'", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"DROP ROLE r", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"DROP USER u", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"GRANT SELECT ON users TO analyst", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"REVOKE SELECT ON users FROM analyst", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"REASSIGN OWNED BY r TO analyst", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"DROP OWNED BY analyst", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},

		// --- maintenance / admin ---
		{"ANALYZE users", pb.StatementKind_STATEMENT_KIND_ANALYZE_TABLE},
		{"VACUUM users", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"VACUUM FULL users", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"REINDEX INDEX i", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"REINDEX TABLE users", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"CLUSTER users USING i", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"CHECKPOINT", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"REFRESH MATERIALIZED VIEW mv", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"LOCK TABLE users", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},

		// --- dynamic execution (bare Commands keyed on the leading keyword) ---
		{"CALL proc(1)", pb.StatementKind_STATEMENT_KIND_CALL},
		{"DO $$ BEGIN PERFORM 1; END $$", pb.StatementKind_STATEMENT_KIND_DO},
		{"PREPARE pl AS SELECT ssn FROM users", pb.StatementKind_STATEMENT_KIND_PREPARE},
		{"EXECUTE pl", pb.StatementKind_STATEMENT_KIND_EXECUTE},
		{"DEALLOCATE pl", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},

		// --- cursors ---
		{"DECLARE cur CURSOR FOR SELECT ssn FROM users", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"FETCH cur", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"MOVE cur", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"CLOSE cur", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},

		// --- async notification ---
		{"LISTEN ch", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"NOTIFY ch", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
		{"UNLISTEN ch", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},

		// --- copy / import ---
		{"COPY users TO '/tmp/x'", pb.StatementKind_STATEMENT_KIND_COPY},
		{"COPY users FROM '/tmp/x'", pb.StatementKind_STATEMENT_KIND_COPY},
		{"COPY (SELECT ssn FROM users) TO '/tmp/x'", pb.StatementKind_STATEMENT_KIND_COPY},
		{"IMPORT FOREIGN SCHEMA remote LIMIT TO (users) FROM SERVER srv INTO local", pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN},
	}
	for _, c := range cases {
		if got := factsKind(pgFacts(t, c.sql)); got != c.want {
			t.Errorf("kind(%q) = %v, want %v", c.sql, got, c.want)
		}
	}
}

// TestPostgresStatementKindNoUnspecified guards the invariant the MySQL suite also holds: every statement
// leaves a real kind or STMT_UNKNOWN, never the invalid zero value STATEMENT_KIND_UNSPECIFIED.
func TestPostgresStatementKindNoUnspecified(t *testing.T) {
	for _, sql := range []string{
		"SELECT 1", "VACUUM users", "CREATE SEQUENCE s", "COPY users TO '/tmp/x'",
		"DO $$ BEGIN END $$", "GRANT SELECT ON users TO r", "LISTEN ch", "MERGE INTO users u USING users s ON u.id = s.id WHEN MATCHED THEN DO NOTHING",
	} {
		if got := factsKind(pgFacts(t, sql)); got == pb.StatementKind_STATEMENT_KIND_UNSPECIFIED {
			t.Errorf("%q left StatementKind UNSPECIFIED — must be a real kind or STMT_UNKNOWN", sql)
		}
	}
}
