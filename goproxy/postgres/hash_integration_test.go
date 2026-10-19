package postgres

import (
	"context"
	"database/sql"
	"reflect"
	"strings"
	"testing"

	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/targettest"
	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"
)

func TestPostgresSchemaHashIntegration(t *testing.T) {
	targetConfig := dbtest.Postgres(t)
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
		return openPostgresDatabase(t, targetConfig, name)
	}

	t.Run("pgcrypto in public", func(t *testing.T) {
		database := createDatabase(t, targettest.UniqueFixtureName("pm_hash_pg_crypto"))
		if _, err := database.Exec("CREATE EXTENSION pgcrypto"); err != nil {
			t.Fatalf("CREATE EXTENSION pgcrypto: %v", err)
		}
		verifyPostgresHashAndFragment(t, database, true)
	})

	t.Run("pgcrypto in non-public schema", func(t *testing.T) {
		database := createDatabase(t, targettest.UniqueFixtureName("pm_hash_pg_nonpublic"))
		if _, err := database.Exec(`CREATE SCHEMA crypto_ext; CREATE EXTENSION pgcrypto WITH SCHEMA crypto_ext`); err != nil {
			t.Fatalf("install pgcrypto in crypto_ext: %v", err)
		}
		verifyPostgresHashAndFragment(t, database, true)
	})

	t.Run("md5 fallback without pgcrypto", func(t *testing.T) {
		database := createDatabase(t, targettest.UniqueFixtureName("pm_hash_pg_md5"))
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
	queries := TargetSQL{}
	setupRows, err := targettest.QueryStrings(conn, queries.HashSetupProbeSQL(), queries.HashSetupColumns())
	if err != nil {
		t.Fatalf("pgcrypto setup probe: %v", err)
	}
	if got := len(setupRows) == 1; got != wantCrypto {
		t.Fatalf("pgcrypto setup rows = %#v, wantCrypto=%v", setupRows, wantCrypto)
	}
	quote := func(identifier string) string { return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"` }
	exec := func(statement string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), targettest.HashTestTimeout)
		defer cancel()
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			t.Fatalf("Postgres exec %q: %v", statement, err)
		}
	}
	measure := func(schema string) []byte {
		t.Helper()
		hashSQL, columns, err := queries.SchemaHashSQL(schema, setupRows)
		if err != nil {
			t.Fatalf("SchemaHashSQL(%q): %v", schema, err)
		}
		if wantCrypto && !strings.Contains(hashSQL, ".digest(") {
			t.Fatalf("pgcrypto hash SQL did not resolve digest schema: %s", hashSQL)
		}
		if !wantCrypto && !strings.Contains(hashSQL, "pg_catalog.md5(") {
			t.Fatalf("fallback hash SQL does not use pg_catalog.md5: %s", hashSQL)
		}
		rows, err := targettest.QueryStrings(conn, hashSQL, columns)
		if err != nil {
			t.Fatalf("Postgres hash query for %q: %v\n%s", schema, err, hashSQL)
		}
		hash, trusted, err := queries.SchemaHashFromRows(rows)
		if err != nil || !trusted {
			t.Fatalf("Postgres hash decode for %q = %x, trusted=%v, err=%v, rows=%#v", schema, hash, trusted, err, rows)
		}
		return hash
	}

	schema := targettest.UniqueFixtureName("pm_hash_pg_fragment")
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
	rows, err := targettest.QueryStrings(conn, queries.SchemaColumnsSQL(schema), 7)
	if err != nil {
		t.Fatalf("Postgres fragment query: %v", err)
	}
	fragment, err := sqldb.FragmentColumnsFromRows(queries, 0, schema, rows)
	if err != nil {
		t.Fatalf("Postgres fragment mapping: %v", err)
	}
	catalog, err := sqldb.ReadPostgresCatalog(context.Background(), conn)
	if err != nil {
		t.Fatalf("Postgres catalog probe: %v", err)
	}
	want := targettest.InCatalog(catalog, []*analyzerpb.Column{
		{Schema: schema, Table: "sample", Column: "id", DataType: "integer", Ordinal: 1},
		{Schema: schema, Table: "sample", Column: "note", DataType: "text", Ordinal: 2, Nullable: true},
	})
	if !targettest.EqualColumns(fragment, want) {
		t.Fatalf("Postgres fragment = %+v, want %+v", fragment, want)
	}

	t.Run("schema field changes the hash", func(t *testing.T) {
		firstSchema := targettest.UniqueFixtureName("pm_hash_pg_schema_a")
		secondSchema := targettest.UniqueFixtureName("pm_hash_pg_schema_b")
		for _, fixture := range []string{firstSchema, secondSchema} {
			exec("CREATE SCHEMA " + quote(fixture))
			exec("CREATE TABLE " + quote(fixture) + ".same_table (id INTEGER NOT NULL, note TEXT NULL)")
		}
		firstHash, secondHash := measure(firstSchema), measure(secondSchema)
		if reflect.DeepEqual(firstHash, secondHash) {
			t.Fatalf("byte-identical tables in distinct Postgres schemas collided: %x", firstHash)
		}
	})

	matrixSchema := targettest.UniqueFixtureName("pm_hash_pg_fields")
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

func openPostgresDatabase(t *testing.T, targetConfig dbtest.TargetDb, name string) *sql.DB {
	t.Helper()
	database, err := sql.Open("pgx", targetConfig.PostgresDSN(name))
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
