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
	hash := func(schema string) []byte {
		t.Helper()
		sqlText, columns, err := db.SchemaHashSQL(schema, nil)
		if err != nil {
			t.Fatalf("SchemaHashSQL(%q): %v", schema, err)
		}
		rows, err := queryStrings(conn, sqlText, columns)
		if err != nil {
			t.Fatalf("hash query for %q: %v\n%s", schema, err, sqlText)
		}
		value, trusted, err := db.SchemaHashFromRows(rows)
		if err != nil {
			t.Fatalf("SchemaHashFromRows(%q): %v", schema, err)
		}
		if !trusted {
			t.Fatalf("hash for %q is untrusted: %#v", schema, rows)
		}
		return value
	}
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

func TestPostgresSchemaHashIntegration(t *testing.T) {
	targetDb := dbtest.Postgres(t)
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
		return openPostgresDatabase(t, targetDb, name)
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
	if got := len(setupRows) == 1; got != wantCrypto {
		t.Fatalf("pgcrypto setup rows = %#v, wantCrypto=%v", setupRows, wantCrypto)
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
	measure := func(schema string) []byte {
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
		hash, trusted, err := db.SchemaHashFromRows(rows)
		if err != nil || !trusted {
			t.Fatalf("Postgres hash decode for %q = %x, trusted=%v, err=%v, rows=%#v", schema, hash, trusted, err, rows)
		}
		return hash
	}

	schema := uniqueFixtureName("pm_hash_pg_fragment")
	exec("CREATE SCHEMA " + quote(schema))
	exec("CREATE TABLE " + quote(schema) + ".sample (id INTEGER NOT NULL, note TEXT NULL)")
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

func openPostgresDatabase(t *testing.T, targetDb dbtest.TargetDb, name string) *sql.DB {
	t.Helper()
	database, err := sql.Open("pgx", targetDb.PostgresDSN(name))
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
