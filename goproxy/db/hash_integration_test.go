package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

const hashTestTimeout = 30 * time.Second

var hashFixtureCounter atomic.Uint64

func uniqueFixtureName(prefix string) string {
	return fmt.Sprintf("%s_%d_%d", prefix, os.Getpid(), hashFixtureCounter.Add(1))
}

func TestMySqlSchemaHashIntegration(t *testing.T) {
	database := dbtest.OpenMySQL(t, "")
	conn, err := database.Conn(context.Background())
	if err != nil {
		t.Fatalf("pin MySQL connection: %v", err)
	}
	defer conn.Close()

	db := MySqlDb{}
	lowerCaseTableNames := 0
	if rows, err := queryStrings(conn, db.LowerCaseTableNamesProbeSQL(), 1); err == nil && len(rows) == 1 && len(rows[0]) == 1 && rows[0][0] != nil {
		if mode, err := strconv.Atoi(*rows[0][0]); err == nil {
			lowerCaseTableNames = mode
		}
	}
	quote := func(identifier string) string { return "`" + strings.ReplaceAll(identifier, "`", "``") + "`" }
	exec := func(statement string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), hashTestTimeout)
		defer cancel()
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			t.Fatalf("MySQL exec %q: %v", statement, err)
		}
	}
	cleanupExec := func(statement string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), hashTestTimeout)
		defer cancel()
		_, _ = database.ExecContext(ctx, statement)
	}
	var backendID string
	if err := conn.QueryRowContext(context.Background(), "SELECT @@server_uuid").Scan(&backendID); err != nil {
		t.Fatalf("read MySQL server UUID: %v", err)
	}
	observe := func(schema string) engine.HashObservation {
		t.Helper()
		sqlText, columns, err := db.SchemaHashSQL(schema, nil)
		if err != nil {
			t.Fatalf("SchemaHashSQL(%q): %v", schema, err)
		}
		rows, err := queryStrings(conn, sqlText, columns)
		if err != nil {
			t.Fatalf("hash query for %q: %v\n%s", schema, err, sqlText)
		}
		observation, err := db.SchemaHashFromRows(rows)
		if err != nil {
			t.Fatalf("SchemaHashFromRows(%q): %v", schema, err)
		}
		if !observation.Trusted {
			t.Fatalf("hash for %q is untrusted: %#v", schema, rows)
		}
		assertSaneHashMetadata(t, observation, backendID)
		return observation
	}
	hash := func(schema string) []byte { return observe(schema).Hash }
	fragments := func(schema string) []*pb.Column {
		t.Helper()
		rows, err := queryStrings(conn, db.SchemaColumnsSQL(schema), 6)
		if err != nil {
			t.Fatalf("fragment query for %q: %v", schema, err)
		}
		columns, err := engine.FragmentColumnsFromRows(db, lowerCaseTableNames, schema, rows)
		if err != nil {
			t.Fatalf("FragmentColumnsFromRows(%q): %v", schema, err)
		}
		return columns
	}

	schema := uniqueFixtureName("pm_hash_mysql_fields")
	exec("DROP DATABASE IF EXISTS " + quote(schema))
	exec("CREATE DATABASE " + quote(schema))
	t.Cleanup(func() { cleanupExec("DROP DATABASE IF EXISTS " + quote(schema)) })
	exec("CREATE TABLE " + quote(schema) + ".base (a INT NOT NULL)")

	t.Run("grouped hash agrees with per-schema hash", func(t *testing.T) {
		sqlText, columns, err := db.ServerHashSQL(nil)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := queryStrings(conn, sqlText, columns)
		if err != nil {
			t.Fatalf("grouped hash query: %v\n%s", err, sqlText)
		}
		observations, err := db.ServerHashFromRows(rows)
		if err != nil {
			t.Fatal(err)
		}
		grouped := findObservation(t, observations, schema)
		perSchema := observe(schema)
		if !reflect.DeepEqual(grouped.Hash, perSchema.Hash) {
			t.Fatalf("grouped hash %x != per-schema hash %x", grouped.Hash, perSchema.Hash)
		}
		assertSaneHashMetadata(t, grouped.HashObservation, backendID)
		empty := uniqueFixtureName("pm_hash_mysql_empty")
		exec("CREATE DATABASE " + quote(empty))
		t.Cleanup(func() { cleanupExec("DROP DATABASE IF EXISTS " + quote(empty)) })
		rows, err = queryStrings(conn, sqlText, columns)
		if err != nil {
			t.Fatal(err)
		}
		observations, err = db.ServerHashFromRows(rows)
		if err != nil {
			t.Fatal(err)
		}
		assertObservationAbsent(t, observations, empty)
	})

	t.Run("schema field changes the hash", func(t *testing.T) {
		firstSchema := uniqueFixtureName("pm_hash_mysql_schema_a")
		secondSchema := uniqueFixtureName("pm_hash_mysql_schema_b")
		for _, fixture := range []string{firstSchema, secondSchema} {
			exec("DROP DATABASE IF EXISTS " + quote(fixture))
			exec("CREATE DATABASE " + quote(fixture))
			t.Cleanup(func() { cleanupExec("DROP DATABASE IF EXISTS " + quote(fixture)) })
			exec("CREATE TABLE " + quote(fixture) + ".same_table (id INT NOT NULL, note TEXT NULL)")
		}
		first, second := hash(firstSchema), hash(secondSchema)
		if reflect.DeepEqual(first, second) {
			t.Fatalf("byte-identical tables in distinct MySQL schemas collided: %x", first)
		}
	})

	previous := hash(schema)
	if again := hash(schema); !reflect.DeepEqual(again, previous) {
		t.Fatalf("same MySQL schema hashed nondeterministically: %x != %x", previous, again)
	}
	mutate := func(name, statement string) {
		t.Helper()
		exec(statement)
		next := hash(schema)
		if reflect.DeepEqual(next, previous) {
			t.Fatalf("%s did not change schema hash: %x", name, next)
		}
		previous = next
	}
	mutate("add column", "ALTER TABLE "+quote(schema)+".base ADD COLUMN b VARCHAR(20) NULL")
	mutate("rename column", "ALTER TABLE "+quote(schema)+".base RENAME COLUMN b TO renamed")
	mutate("change data type", "ALTER TABLE "+quote(schema)+".base MODIFY COLUMN renamed TEXT NULL")
	mutate("change ordinal", "ALTER TABLE "+quote(schema)+".base MODIFY COLUMN renamed TEXT NULL FIRST")
	mutate("change nullability", "ALTER TABLE "+quote(schema)+".base MODIFY COLUMN renamed TEXT NOT NULL FIRST")
	mutate("rename table", "RENAME TABLE "+quote(schema)+".base TO "+quote(schema)+".renamed_table")
	mutate("drop table", "DROP TABLE "+quote(schema)+".renamed_table")

	t.Run("length-prefix removes concatenation ambiguity", func(t *testing.T) {
		ambiguity := uniqueFixtureName("pm_hash_mysql_ambiguity")
		exec("DROP DATABASE IF EXISTS " + quote(ambiguity))
		exec("CREATE DATABASE " + quote(ambiguity))
		t.Cleanup(func() { cleanupExec("DROP DATABASE IF EXISTS " + quote(ambiguity)) })
		exec("CREATE TABLE " + quote(ambiguity) + ".ab (c INT)")
		first := hash(ambiguity)
		exec("DROP TABLE " + quote(ambiguity) + ".ab")
		exec("CREATE TABLE " + quote(ambiguity) + ".a (bc INT)")
		second := hash(ambiguity)
		if reflect.DeepEqual(first, second) {
			t.Fatalf("ambiguous field split collided: %x", first)
		}
	})

	t.Run("large aggregate is trusted without session mutation", func(t *testing.T) {
		large := uniqueFixtureName("pm_hash_mysql_large")
		exec("DROP DATABASE IF EXISTS " + quote(large))
		exec("CREATE DATABASE " + quote(large))
		t.Cleanup(func() { cleanupExec("DROP DATABASE IF EXISTS " + quote(large)) })
		var definitions []string
		for i := 0; i < 24; i++ {
			definitions = append(definitions, fmt.Sprintf("column_%02d VARCHAR(255)", i))
		}
		exec("CREATE TABLE " + quote(large) + ".wide (" + strings.Join(definitions, ",") + ")")
		exec("SET SESSION group_concat_max_len = 1024")
		var before, after uint64
		if err := conn.QueryRowContext(context.Background(), "SELECT @@session.group_concat_max_len").Scan(&before); err != nil {
			t.Fatalf("read group_concat_max_len before: %v", err)
		}
		_ = hash(large)
		if err := conn.QueryRowContext(context.Background(), "SELECT @@session.group_concat_max_len").Scan(&after); err != nil {
			t.Fatalf("read group_concat_max_len after: %v", err)
		}
		if before != 1024 || after != before {
			t.Fatalf("group_concat_max_len changed: before=%d after=%d", before, after)
		}
	})

	t.Run("hostile and empty schemas", func(t *testing.T) {
		hostile := uniqueFixtureName("pm_hash_mysql_hostile") + "_'quote\\slash"
		exec("DROP DATABASE IF EXISTS " + quote(hostile))
		exec("CREATE DATABASE " + quote(hostile))
		t.Cleanup(func() { cleanupExec("DROP DATABASE IF EXISTS " + quote(hostile)) })
		exec("CREATE TABLE " + quote(hostile) + ".t (id INT NOT NULL)")
		_ = hash(hostile)
		want := []*pb.Column{{Schema: hostile, Table: "t", Column: "id", DataType: "int", Ordinal: 1}}
		if got := fragments(hostile); !reflect.DeepEqual(got, want) {
			t.Fatalf("hostile schema fragment = %+v, want %+v", got, want)
		}
		missing := uniqueFixtureName("pm_hash_mysql_missing")
		empty1, empty2 := hash(missing), hash(missing)
		if !reflect.DeepEqual(empty1, empty2) || len(fragments(missing)) != 0 {
			t.Fatalf("empty schema is not deterministic/empty: %x %x", empty1, empty2)
		}
	})

	t.Run("exact fragments include system schema", func(t *testing.T) {
		fragmentSchema := uniqueFixtureName("pm_hash_mysql_fragment")
		exec("DROP DATABASE IF EXISTS " + quote(fragmentSchema))
		exec("CREATE DATABASE " + quote(fragmentSchema))
		t.Cleanup(func() { cleanupExec("DROP DATABASE IF EXISTS " + quote(fragmentSchema)) })
		exec("CREATE TABLE " + quote(fragmentSchema) + ".sample (id INT NOT NULL, note VARCHAR(20) NULL)")
		want := []*pb.Column{
			{Schema: fragmentSchema, Table: "sample", Column: "id", DataType: "int", Ordinal: 1},
			{Schema: fragmentSchema, Table: "sample", Column: "note", DataType: "varchar", Ordinal: 2, Nullable: true},
		}
		if got := fragments(fragmentSchema); !reflect.DeepEqual(got, want) {
			t.Fatalf("fragment = %+v, want %+v", got, want)
		}
		if got := fragments("information_schema"); len(got) == 0 {
			t.Fatal("information_schema fragment is empty; system schemas must not be excluded")
		}
	})
}

// TestMySqlHashClockIsNotClientSettable proves the version clock cannot be moved by the session the
// hash probe runs on — which is the client's own backend connection, so `SET timestamp` is theirs to
// call. A future reading would freeze the manager's strictly-newer ordering rule on the poisoned
// version and reject every later genuine observation.
//
// Both server configurations are exercised because they fail differently and only one is visible in
// SQL text: on a default server SYSDATE(6) ignores `SET timestamp` and the clock must stay real; on a
// server started with --sysdate-is-now, SYSDATE is ALIASED to NOW and the reading becomes settable
// again, so the statement's own guard must report the clock unavailable instead. MySQL exposes no
// variable naming that option, so a live server is the only way to observe it.
func TestMySqlHashClockIsNotClientSettable(t *testing.T) {
	const poisonedEpoch = 2147483647
	for _, tc := range []struct {
		name          string
		backend       dbtest.Backend
		wantClockReal bool
	}{
		{"default server", dbtest.MySQL(t), true},
		{"server started with --sysdate-is-now", dbtest.MySQLSysdateIsNow(t), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := open(t, tc.backend)
			conn, err := database.Conn(context.Background())
			if err != nil {
				t.Fatalf("pin MySQL connection: %v", err)
			}
			defer conn.Close()

			ctx, cancel := context.WithTimeout(context.Background(), hashTestTimeout)
			defer cancel()
			if _, err := conn.ExecContext(ctx, fmt.Sprintf("SET timestamp = %d", poisonedEpoch)); err != nil {
				t.Fatalf("poison session clock: %v", err)
			}

			db := MySqlDb{}
			statement, width, err := db.SchemaHashSQL("information_schema", nil)
			if err != nil {
				t.Fatalf("SchemaHashSQL: %v", err)
			}
			rows, err := queryStrings(conn, statement, width)
			if err != nil {
				t.Fatalf("hash query: %v\n%s", err, statement)
			}
			observation, err := db.SchemaHashFromRows(rows)
			if err != nil {
				t.Fatalf("SchemaHashFromRows: %v", err)
			}
			// The hash itself must survive either way: an unusable clock costs recency, never content.
			if !observation.Trusted || len(observation.Hash) == 0 {
				t.Fatalf("observation = %+v, want a trusted non-empty hash", observation)
			}
			if observation.DbClockMicros == poisonedEpoch*int64(1000000) {
				t.Fatalf("session `SET timestamp = %d` moved the version clock to %d", poisonedEpoch, observation.DbClockMicros)
			}
			if !tc.wantClockReal {
				if observation.DbClockMicros != 0 {
					t.Fatalf("DbClockMicros = %d, want 0 (unavailable) when SYSDATE is aliased to NOW", observation.DbClockMicros)
				}
				return
			}
			if observation.DbClockMicros <= 0 {
				t.Fatalf("DbClockMicros = %d, want the real server clock", observation.DbClockMicros)
			}
			if delta := time.Since(time.UnixMicro(observation.DbClockMicros)); delta < -time.Minute || delta > 5*time.Minute {
				t.Fatalf("DbClockMicros = %d, want near wall clock (delta %s)", observation.DbClockMicros, delta)
			}
		})
	}
}

func open(t *testing.T, backend dbtest.Backend) *sql.DB {
	t.Helper()
	return openAs(t, backend, backend.User, backend.Password)
}

func openAs(t *testing.T, backend dbtest.Backend, user, password string) *sql.DB {
	t.Helper()
	as := backend
	as.User, as.Password = user, password
	database, err := sql.Open("mysql", as.MySQLDSN(""))
	if err != nil {
		t.Fatalf("open MySQL backend as %q: %v", user, err)
	}
	if err := database.Ping(); err != nil {
		database.Close()
		t.Fatalf("ping MySQL backend as %q: %v", user, err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

// TestMySqlCatalogVisibilityTracksTheReader proves the completeness claim answers the question it is
// asked — "will a whole-server scan on THIS connection enumerate every schema?" — rather than the
// easier "does this account's own grant list mention SELECT". A wrong yes hands the manager a license
// to delete every schema the account cannot see, so each case pairs the probe's answer with what the
// account actually reads out of information_schema.COLUMNS: an assertion the probe agreed with the
// live catalog, not merely that it returned something.
//
// Two shapes make the naive lookup wrong in opposite directions, and neither is visible in SQL text:
// a partial revoke leaves the global grant row intact while hiding a schema (wrong yes), and a service
// account that inherits global SELECT from a role holds no such row at all (wrong no, which
// permanently suppresses dropped-schema reconciliation for the deployment shape most installs use).
func TestMySqlCatalogVisibilityTracksTheReader(t *testing.T) {
	probe := func(t *testing.T, database *sql.DB) (complete bool, visibleSchemas map[string]struct{}) {
		t.Helper()
		conn, err := database.Conn(context.Background())
		if err != nil {
			t.Fatalf("pin connection: %v", err)
		}
		defer conn.Close()
		rows, err := queryStrings(conn, MySqlDb{}.CatalogVisibilitySQL(), 1)
		if err != nil {
			t.Fatalf("catalog visibility probe: %v", err)
		}
		if len(rows) != 1 || rows[0][0] == nil {
			t.Fatalf("catalog visibility probe returned %#v, want one non-NULL row", rows)
		}
		seen, err := queryStrings(conn, "SELECT DISTINCT TABLE_SCHEMA FROM information_schema.COLUMNS", 1)
		if err != nil {
			t.Fatalf("read visible schemas: %v", err)
		}
		visibleSchemas = make(map[string]struct{}, len(seen))
		for _, row := range seen {
			if row[0] != nil {
				visibleSchemas[*row[0]] = struct{}{}
			}
		}
		return *rows[0][0] == "1", visibleSchemas
	}

	t.Run("partial revoke hides a schema while global SELECT survives", func(t *testing.T) {
		backend := dbtest.MySQLPartialRevokes(t)
		admin := open(t, backend)
		hidden := uniqueFixtureName("pm_vis_hidden")
		user := uniqueFixtureName("pm_vis_pr")
		for _, statement := range []string{
			"CREATE DATABASE `" + hidden + "`",
			"CREATE TABLE `" + hidden + "`.secret (id INT PRIMARY KEY)",
			"CREATE USER '" + user + "'@'%' IDENTIFIED BY 'probe'",
			"GRANT SELECT ON *.* TO '" + user + "'@'%'",
			"REVOKE SELECT ON `" + hidden + "`.* FROM '" + user + "'@'%'",
		} {
			if _, err := admin.Exec(statement); err != nil {
				t.Fatalf("fixture %q: %v", statement, err)
			}
		}
		t.Cleanup(func() {
			_, _ = admin.Exec("DROP USER IF EXISTS '" + user + "'@'%'")
			_, _ = admin.Exec("DROP DATABASE IF EXISTS `" + hidden + "`")
		})

		complete, visible := probe(t, openAs(t, backend, user, "probe"))
		if _, sees := visible[hidden]; sees {
			t.Fatalf("the restricted account still reads %q, so this fixture proves nothing", hidden)
		}
		if complete {
			t.Fatalf("catalog visibility = complete while %q is hidden by a partial revoke; the manager would delete it", hidden)
		}
	})

	// The ordinary deployment shape: a service account holding nothing directly, with global SELECT
	// reached through a role — and, in the nested case, through a role that role holds. Both must claim
	// completeness, since both genuinely read every schema.
	t.Run("global SELECT inherited through a role claims completeness", func(t *testing.T) {
		backend := dbtest.MySQL(t)
		admin := open(t, backend)
		inner := uniqueFixtureName("pm_vis_role_inner")
		outer := uniqueFixtureName("pm_vis_role_outer")
		direct := uniqueFixtureName("pm_vis_direct")
		nested := uniqueFixtureName("pm_vis_nested")
		dormant := uniqueFixtureName("pm_vis_dormant")
		scoped := uniqueFixtureName("pm_vis_scoped")
		for _, statement := range []string{
			"CREATE ROLE '" + inner + "'", "GRANT SELECT ON *.* TO '" + inner + "'",
			"CREATE ROLE '" + outer + "'", "GRANT '" + inner + "' TO '" + outer + "'",
			"CREATE USER '" + direct + "'@'%' IDENTIFIED BY 'probe'",
			"GRANT '" + inner + "' TO '" + direct + "'@'%'", "SET DEFAULT ROLE ALL TO '" + direct + "'@'%'",
			"CREATE USER '" + nested + "'@'%' IDENTIFIED BY 'probe'",
			"GRANT '" + outer + "' TO '" + nested + "'@'%'", "SET DEFAULT ROLE ALL TO '" + nested + "'@'%'",
			// Granted the same global-SELECT role but never activating it: it confers nothing, so the
			// probe must not count it. The per-schema grant on the connect database is what lets these two
			// accounts open a session at all; it is also the grant shape that must NOT read as complete.
			"CREATE USER '" + dormant + "'@'%' IDENTIFIED BY 'probe'",
			"GRANT '" + inner + "' TO '" + dormant + "'@'%'", "SET DEFAULT ROLE NONE TO '" + dormant + "'@'%'",
			"GRANT SELECT ON `" + backend.DB + "`.* TO '" + dormant + "'@'%'",
			"CREATE USER '" + scoped + "'@'%' IDENTIFIED BY 'probe'",
			"GRANT SELECT ON `" + backend.DB + "`.* TO '" + scoped + "'@'%'",
		} {
			if _, err := admin.Exec(statement); err != nil {
				t.Fatalf("fixture %q: %v", statement, err)
			}
		}
		t.Cleanup(func() {
			for _, name := range []string{direct, nested, dormant, scoped} {
				_, _ = admin.Exec("DROP USER IF EXISTS '" + name + "'@'%'")
			}
			for _, name := range []string{outer, inner} {
				_, _ = admin.Exec("DROP ROLE IF EXISTS '" + name + "'")
			}
		})

		_, everySchema := probe(t, admin)
		for _, tc := range []struct {
			name         string
			user         string
			wantComplete bool
		}{
			{"role granting global SELECT", direct, true},
			{"role reached through another role", nested, true},
			{"role granted but not activated", dormant, false},
			{"per-schema grant only", scoped, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				complete, visible := probe(t, openAs(t, backend, tc.user, "probe"))
				// What the claim asserts: this account reads the same schema set the privileged one does.
				sameView := len(visible) == len(everySchema)
				for schema := range everySchema {
					if _, sees := visible[schema]; !sees {
						sameView = false
					}
				}
				if sameView != tc.wantComplete {
					t.Fatalf("%s reads %d of %d schemas; the fixture no longer models %v completeness",
						tc.user, len(visible), len(everySchema), tc.wantComplete)
				}
				if complete != tc.wantComplete {
					t.Fatalf("catalog visibility = %v, want %v (account reads %d of %d schemas)",
						complete, tc.wantComplete, len(visible), len(everySchema))
				}
			})
		}
	})
}

func TestPostgresSchemaHashIntegration(t *testing.T) {
	backend := dbtest.Postgres(t)
	admin := dbtest.OpenPostgres(t, "")

	createDatabase := func(t *testing.T, name string) *sql.DB {
		t.Helper()
		if _, err := admin.Exec(`DROP DATABASE IF EXISTS "` + name + `" WITH (FORCE)`); err != nil {
			t.Fatalf("drop database %s: %v", name, err)
		}
		if _, err := admin.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
			t.Fatalf("create database %s: %v", name, err)
		}
		t.Cleanup(func() {
			_, _ = admin.Exec(`DROP DATABASE IF EXISTS "` + name + `" WITH (FORCE)`)
		})
		return openPostgresDatabase(t, backend, name)
	}

	t.Run("pgcrypto in public", func(t *testing.T) {
		database := createDatabase(t, uniqueFixtureName("pm_hash_pg_crypto"))
		if _, err := database.Exec("CREATE EXTENSION pgcrypto"); err != nil {
			t.Fatalf("CREATE EXTENSION pgcrypto: %v", err)
		}
		verifyPostgresHashAndFragment(t, database, true)
	})

	t.Run("pgcrypto in non-public schema", func(t *testing.T) {
		database := createDatabase(t, uniqueFixtureName("pm_hash_pg_nonpublic"))
		if _, err := database.Exec(`CREATE SCHEMA crypto_ext; CREATE EXTENSION pgcrypto WITH SCHEMA crypto_ext`); err != nil {
			t.Fatalf("install pgcrypto in crypto_ext: %v", err)
		}
		verifyPostgresHashAndFragment(t, database, true)
	})

	t.Run("md5 fallback without pgcrypto", func(t *testing.T) {
		database := createDatabase(t, uniqueFixtureName("pm_hash_pg_md5"))
		verifyPostgresHashAndFragment(t, database, false)
	})

	// A cluster that revoked pg_control_system() from PUBLIC — the hardened posture — must still yield a
	// trusted hash, degrading only the backend id. This runs against a real revocation because the
	// failure mode is invisible to SQL-text assertions: PostgreSQL resolves function EXECUTE at PLAN
	// time, so an inline privilege guard aborts the whole statement instead of taking its false branch,
	// and every schema hash is lost rather than one field.
	t.Run("identity unreadable degrades the id, never the hash", func(t *testing.T) {
		name := uniqueFixtureName("pm_hash_pg_hardened")
		database := createDatabase(t, name)
		role := uniqueFixtureName("pm_hash_pg_role")
		schema := uniqueFixtureName("pm_hash_pg_hardened_schema")
		for _, statement := range []string{
			`CREATE SCHEMA "` + schema + `"`,
			`CREATE TABLE "` + schema + `".sample (id INTEGER NOT NULL, note TEXT NULL)`,
			`CREATE ROLE "` + role + `" LOGIN PASSWORD 'probe'`,
			`GRANT CONNECT ON DATABASE "` + name + `" TO "` + role + `"`,
			`GRANT USAGE ON SCHEMA "` + schema + `" TO "` + role + `"`,
			`GRANT SELECT ON "` + schema + `".sample TO "` + role + `"`,
			`REVOKE EXECUTE ON FUNCTION pg_catalog.pg_control_system() FROM PUBLIC`,
		} {
			if _, err := database.Exec(statement); err != nil {
				t.Fatalf("hardened fixture %q: %v", statement, err)
			}
		}
		t.Cleanup(func() {
			_, _ = database.Exec(`GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO PUBLIC`)
			_, _ = database.Exec(`REASSIGN OWNED BY "` + role + `" TO CURRENT_USER`)
			_, _ = database.Exec(`DROP OWNED BY "` + role + `"`)
			_, _ = admin.Exec(`DROP ROLE IF EXISTS "` + role + `"`)
		})

		restricted := openPostgresDatabaseAs(t, backend, name, role, "probe")
		conn, err := restricted.Conn(context.Background())
		if err != nil {
			t.Fatalf("pin restricted Postgres connection: %v", err)
		}
		defer conn.Close()

		db := PgDb{}
		setupRows, err := queryStrings(conn, db.HashSetupProbeSQL(), db.HashSetupColumns())
		if err != nil {
			t.Fatalf("setup probe as restricted role: %v", err)
		}
		if privilege := pgSetupCell(setupRows, 1); privilege == nil || *privilege != "0" {
			t.Fatalf("identity privilege cell = %v, want 0 after REVOKE", privilege)
		}
		for _, tc := range []struct {
			name    string
			observe func() (engine.HashObservation, error)
		}{
			{"SchemaHashSQL", func() (engine.HashObservation, error) {
				statement, width, err := db.SchemaHashSQL(schema, setupRows)
				if err != nil {
					return engine.HashObservation{}, err
				}
				rows, err := queryStrings(conn, statement, width)
				if err != nil {
					return engine.HashObservation{}, err
				}
				return db.SchemaHashFromRows(rows)
			}},
			{"ServerHashSQL", func() (engine.HashObservation, error) {
				statement, width, err := db.ServerHashSQL(setupRows)
				if err != nil {
					return engine.HashObservation{}, err
				}
				rows, err := queryStrings(conn, statement, width)
				if err != nil {
					return engine.HashObservation{}, err
				}
				observations, err := db.ServerHashFromRows(rows)
				if err != nil {
					return engine.HashObservation{}, err
				}
				return findObservation(t, observations, schema).HashObservation, nil
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				observation, err := tc.observe()
				if err != nil {
					t.Fatalf("measurement failed on a cluster with pg_control_system revoked: %v", err)
				}
				if !observation.Trusted || len(observation.Hash) == 0 {
					t.Fatalf("observation = %+v, want a trusted non-empty hash", observation)
				}
				if observation.BackendID != "" {
					t.Fatalf("BackendID = %q, want empty when the identity is unreadable", observation.BackendID)
				}
				if observation.DbClockMicros <= 0 {
					t.Fatalf("DbClockMicros = %d, want the clock to survive an unreadable identity", observation.DbClockMicros)
				}
			})
		}

		// The same role must also decline to claim it saw every schema: it reads a privilege-filtered
		// information_schema, and a subset pushed as a whole-server scan reads as mass deletion.
		visibility, err := queryStrings(conn, db.CatalogVisibilitySQL(), 1)
		if err != nil {
			t.Fatalf("catalog visibility probe as restricted role: %v", err)
		}
		if len(visibility) != 1 || visibility[0][0] == nil || *visibility[0][0] != "0" {
			t.Fatalf("restricted role catalog visibility = %#v, want 0", visibility)
		}
	})
}

func verifyPostgresHashAndFragment(t *testing.T, database *sql.DB, wantCrypto bool) {
	t.Helper()
	conn, err := database.Conn(context.Background())
	if err != nil {
		t.Fatalf("pin Postgres connection: %v", err)
	}
	defer conn.Close()
	db := PgDb{}
	setupRows, err := queryStrings(conn, db.HashSetupProbeSQL(), db.HashSetupColumns())
	if err != nil {
		t.Fatalf("pgcrypto setup probe: %v", err)
	}
	// The probe answers two questions in one row, so pgcrypto's presence is the CELL being non-empty,
	// not the row existing — the row is always there to carry the identity privilege.
	cryptoSchema := pgSetupCell(setupRows, 0)
	if got := cryptoSchema != nil && *cryptoSchema != ""; got != wantCrypto {
		t.Fatalf("pgcrypto setup rows = %#v, wantCrypto=%v", setupRows, wantCrypto)
	}
	if privilege := pgSetupCell(setupRows, 1); privilege == nil || *privilege != "1" {
		t.Fatalf("identity privilege cell = %v, want 1 for the privileged test role", privilege)
	}
	quote := func(identifier string) string { return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"` }
	exec := func(statement string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), hashTestTimeout)
		defer cancel()
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			t.Fatalf("Postgres exec %q: %v", statement, err)
		}
	}
	var backendID string
	if err := conn.QueryRowContext(context.Background(), "SELECT system_identifier::text FROM pg_catalog.pg_control_system()").Scan(&backendID); err != nil {
		t.Fatalf("read Postgres system identifier: %v", err)
	}
	observe := func(schema string) engine.HashObservation {
		t.Helper()
		hashSQL, columns, err := db.SchemaHashSQL(schema, setupRows)
		if err != nil {
			t.Fatalf("SchemaHashSQL(%q): %v", schema, err)
		}
		if wantCrypto && !strings.Contains(hashSQL, ".digest(") {
			t.Fatalf("pgcrypto hash SQL did not resolve digest schema: %s", hashSQL)
		}
		if !wantCrypto && !strings.Contains(hashSQL, "pg_catalog.md5(") {
			t.Fatalf("fallback hash SQL does not use pg_catalog.md5: %s", hashSQL)
		}
		rows, err := queryStrings(conn, hashSQL, columns)
		if err != nil {
			t.Fatalf("Postgres hash query for %q: %v\n%s", schema, err, hashSQL)
		}
		observation, err := db.SchemaHashFromRows(rows)
		if err != nil || !observation.Trusted {
			t.Fatalf("Postgres hash decode for %q = %+v, err=%v, rows=%#v", schema, observation, err, rows)
		}
		assertSaneHashMetadata(t, observation, backendID)
		return observation
	}
	measure := func(schema string) []byte { return observe(schema).Hash }

	schema := uniqueFixtureName("pm_hash_pg_fragment")
	exec("CREATE SCHEMA " + quote(schema))
	exec("CREATE TABLE " + quote(schema) + ".sample (id INTEGER NOT NULL, note TEXT NULL)")

	t.Run("clock advances inside a transaction", func(t *testing.T) {
		exec("BEGIN")
		first := observe(schema)
		exec("SELECT pg_catalog.pg_sleep(0.01)")
		second := observe(schema)
		exec("ROLLBACK")
		if second.DbClockMicros <= first.DbClockMicros {
			t.Fatalf("clock did not advance inside transaction: %d <= %d", second.DbClockMicros, first.DbClockMicros)
		}
	})

	t.Run("grouped hash agrees with per-schema hash", func(t *testing.T) {
		sqlText, columns, err := db.ServerHashSQL(setupRows)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := queryStrings(conn, sqlText, columns)
		if err != nil {
			t.Fatalf("grouped hash query: %v\n%s", err, sqlText)
		}
		observations, err := db.ServerHashFromRows(rows)
		if err != nil {
			t.Fatal(err)
		}
		grouped := findObservation(t, observations, schema)
		perSchema := observe(schema)
		if !reflect.DeepEqual(grouped.Hash, perSchema.Hash) {
			t.Fatalf("grouped hash %x != per-schema hash %x", grouped.Hash, perSchema.Hash)
		}
		assertSaneHashMetadata(t, grouped.HashObservation, backendID)
		empty := uniqueFixtureName("pm_hash_pg_empty")
		exec("CREATE SCHEMA " + quote(empty))
		rows, err = queryStrings(conn, sqlText, columns)
		if err != nil {
			t.Fatal(err)
		}
		observations, err = db.ServerHashFromRows(rows)
		if err != nil {
			t.Fatal(err)
		}
		assertObservationAbsent(t, observations, empty)
	})

	first := measure(schema)
	if second := measure(schema); !reflect.DeepEqual(first, second) {
		t.Fatalf("Postgres hash nondeterministic: %x != %x", first, second)
	}
	if wantCrypto && len(first) != 32 {
		t.Fatalf("pgcrypto hash length = %d, want 32", len(first))
	}
	if !wantCrypto && len(first) != 16 {
		t.Fatalf("md5 hash length = %d, want 16", len(first))
	}
	rows, err := queryStrings(conn, db.SchemaColumnsSQL(schema), 6)
	if err != nil {
		t.Fatalf("Postgres fragment query: %v", err)
	}
	fragment, err := engine.FragmentColumnsFromRows(db, 0, schema, rows)
	if err != nil {
		t.Fatalf("Postgres fragment mapping: %v", err)
	}
	want := []*pb.Column{
		{Schema: schema, Table: "sample", Column: "id", DataType: "integer", Ordinal: 1},
		{Schema: schema, Table: "sample", Column: "note", DataType: "text", Ordinal: 2, Nullable: true},
	}
	if !reflect.DeepEqual(fragment, want) {
		t.Fatalf("Postgres fragment = %+v, want %+v", fragment, want)
	}

	t.Run("schema field changes the hash", func(t *testing.T) {
		firstSchema := uniqueFixtureName("pm_hash_pg_schema_a")
		secondSchema := uniqueFixtureName("pm_hash_pg_schema_b")
		for _, fixture := range []string{firstSchema, secondSchema} {
			exec("CREATE SCHEMA " + quote(fixture))
			exec("CREATE TABLE " + quote(fixture) + ".same_table (id INTEGER NOT NULL, note TEXT NULL)")
		}
		firstHash, secondHash := measure(firstSchema), measure(secondSchema)
		if reflect.DeepEqual(firstHash, secondHash) {
			t.Fatalf("byte-identical tables in distinct Postgres schemas collided: %x", firstHash)
		}
	})

	matrixSchema := uniqueFixtureName("pm_hash_pg_fields")
	exec("CREATE SCHEMA " + quote(matrixSchema))
	exec("CREATE TABLE " + quote(matrixSchema) + ".base (a INTEGER NOT NULL)")
	previous := measure(matrixSchema)
	mutate := func(name, statement string) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			exec(statement)
			next := measure(matrixSchema)
			if reflect.DeepEqual(next, previous) {
				t.Fatalf("%s did not change schema hash: %x", name, next)
			}
			previous = next
		})
	}
	mutate("add column", "ALTER TABLE "+quote(matrixSchema)+".base ADD COLUMN b CHARACTER VARYING(20) NULL")
	mutate("rename column", "ALTER TABLE "+quote(matrixSchema)+".base RENAME COLUMN b TO renamed")
	mutate("change data type", "ALTER TABLE "+quote(matrixSchema)+".base ALTER COLUMN renamed TYPE TEXT")
	mutate("set not null", "ALTER TABLE "+quote(matrixSchema)+".base ALTER COLUMN renamed SET NOT NULL")
	mutate("drop not null", "ALTER TABLE "+quote(matrixSchema)+".base ALTER COLUMN renamed DROP NOT NULL")
	mutate("change ordinal", "ALTER TABLE "+quote(matrixSchema)+".base DROP COLUMN a, ADD COLUMN a INTEGER NOT NULL")
	mutate("rename table", "ALTER TABLE "+quote(matrixSchema)+".base RENAME TO renamed_table")
	mutate("drop table", "DROP TABLE "+quote(matrixSchema)+".renamed_table")
}

func assertSaneHashMetadata(t *testing.T, observation engine.HashObservation, backendID string) {
	t.Helper()
	if observation.BackendID != backendID || observation.BackendID == "" {
		t.Fatalf("backend ID = %q, want %q", observation.BackendID, backendID)
	}
	nowMicros := time.Now().UnixMicro()
	if observation.DbClockMicros <= 0 || observation.DbClockMicros < nowMicros-int64(time.Hour/time.Microsecond) || observation.DbClockMicros > nowMicros+int64(time.Hour/time.Microsecond) {
		t.Fatalf("database clock %d is not within an hour of wall clock %d", observation.DbClockMicros, nowMicros)
	}
}

func findObservation(t *testing.T, observations []engine.SchemaHashObservation, schema string) engine.SchemaHashObservation {
	t.Helper()
	for _, observation := range observations {
		if observation.Schema == schema {
			if !observation.Trusted {
				t.Fatalf("grouped observation for %q is untrusted: %+v", schema, observation)
			}
			return observation
		}
	}
	t.Fatalf("grouped observation for %q not found", schema)
	return engine.SchemaHashObservation{}
}

func assertObservationAbsent(t *testing.T, observations []engine.SchemaHashObservation, schema string) {
	t.Helper()
	for _, observation := range observations {
		if observation.Schema == schema {
			t.Fatalf("zero-column schema %q unexpectedly produced a grouped row", schema)
		}
	}
}

func openPostgresDatabase(t *testing.T, backend dbtest.Backend, name string) *sql.DB {
	t.Helper()
	return openPostgresDatabaseAs(t, backend, name, backend.User, backend.Password)
}

func openPostgresDatabaseAs(t *testing.T, backend dbtest.Backend, name, user, password string) *sql.DB {
	t.Helper()
	as := backend
	as.User, as.Password = user, password
	database, err := sql.Open("pgx", as.PostgresDSN(name))
	if err != nil {
		t.Fatalf("open Postgres database %s: %v", name, err)
	}
	if err := database.Ping(); err != nil {
		database.Close()
		t.Fatalf("ping Postgres database %s: %v", name, err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

func queryStrings(conn *sql.Conn, statement string, expectedColumns int) ([][]*string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hashTestTimeout)
	defer cancel()
	rows, err := conn.QueryContext(ctx, statement)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columnNames, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	if len(columnNames) != expectedColumns {
		return nil, fmt.Errorf("query returned %d columns, want %d", len(columnNames), expectedColumns)
	}
	var result [][]*string
	for rows.Next() {
		values := make([]sql.NullString, expectedColumns)
		destinations := make([]any, expectedColumns)
		for i := range values {
			destinations[i] = &values[i]
		}
		if err := rows.Scan(destinations...); err != nil {
			return nil, err
		}
		row := make([]*string, expectedColumns)
		for i := range values {
			if values[i].Valid {
				value := values[i].String
				row[i] = &value
			}
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
