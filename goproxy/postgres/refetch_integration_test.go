package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"strings"
	"testing"

	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/targettest"
)

func TestPostgresRefetcherIntegration(t *testing.T) {
	targetConfig := dbtest.Postgres(t)
	admin := dbtest.OpenPostgres(t, "")

	modes := []struct {
		name   string
		crypto bool
	}{
		{name: "pgcrypto", crypto: true},
		{name: "md5 fallback", crypto: false},
	}
	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			databaseName := targettest.UniqueFixtureName("pm_refetch_pg")
			database := createPostgresRefetchDatabase(t, admin, targetConfig, databaseName)
			if mode.crypto {
				if _, err := database.Exec("CREATE EXTENSION pgcrypto"); err != nil {
					t.Fatalf("CREATE EXTENSION pgcrypto: %v", err)
				}
			}
			conn, err := database.Conn(context.Background())
			if err != nil {
				t.Fatalf("pin Postgres connection: %v", err)
			}
			defer conn.Close()

			quote := func(identifier string) string { return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"` }
			schema := targettest.UniqueFixtureName("pm_refetch_pg_fields")
			targettest.ExecRefetchSQL(t, conn, "CREATE SCHEMA "+quote(schema))
			targettest.ExecRefetchSQL(t, conn, "CREATE TABLE "+quote(schema)+".base (a INTEGER NOT NULL)")

			queries := Queries
			previous := targettest.TrustedRefetchHash(t, queries, conn, schema)
			wantHashLength := 16
			if mode.crypto {
				wantHashLength = 32
			}
			if len(previous) != wantHashLength {
				t.Fatalf("initial hash length = %d, want %d", len(previous), wantHashLength)
			}
			t.Run("unchanged", func(t *testing.T) {
				push := targettest.RunRefetchIntegration(t, queries, conn, databaseName, schema, previous)
				if !push.Unchanged || len(push.Columns) != 0 || !bytes.Equal(push.ContentHash, previous) {
					t.Fatalf("unchanged push = %+v, want hash-only unchanged push", push)
				}
			})
			t.Run("schema field", func(t *testing.T) {
				otherSchema := targettest.UniqueFixtureName("pm_refetch_pg_schema")
				targettest.ExecRefetchSQL(t, conn, "CREATE SCHEMA "+quote(otherSchema))
				targettest.ExecRefetchSQL(t, conn, "CREATE TABLE "+quote(otherSchema)+".base (a INTEGER NOT NULL)")
				current := targettest.TrustedRefetchHash(t, queries, conn, otherSchema)
				if len(current) != wantHashLength {
					t.Fatalf("schema-field hash length = %d, want %d", len(current), wantHashLength)
				}
				if bytes.Equal(current, previous) {
					t.Fatalf("byte-identical tables in distinct schemas collided: %x", current)
				}
				push := targettest.RunRefetchIntegration(t, queries, conn, databaseName, otherSchema, previous)
				targettest.AssertFullRefetch(t, push, current, databaseName, []*analyzerpb.Column{
					{Schema: otherSchema, Table: "base", Column: "a", DataType: "integer", Ordinal: 1},
				}, nil)
			})

			steps := []struct {
				name      string
				before    string
				statement string
				columns   []*analyzerpb.Column
				routines  []string
			}{
				{
					name:      "add column",
					statement: "ALTER TABLE " + quote(schema) + ".base ADD COLUMN b CHARACTER VARYING(20) NULL",
					columns: []*analyzerpb.Column{
						{Schema: schema, Table: "base", Column: "a", DataType: "integer", Ordinal: 1},
						{Schema: schema, Table: "base", Column: "b", DataType: "character varying", Ordinal: 2, Nullable: true},
					},
				},
				{
					name:      "rename column",
					statement: "ALTER TABLE " + quote(schema) + ".base RENAME COLUMN b TO renamed",
					columns: []*analyzerpb.Column{
						{Schema: schema, Table: "base", Column: "a", DataType: "integer", Ordinal: 1},
						{Schema: schema, Table: "base", Column: "renamed", DataType: "character varying", Ordinal: 2, Nullable: true},
					},
				},
				{
					name:      "change data type",
					statement: "ALTER TABLE " + quote(schema) + ".base ALTER COLUMN renamed TYPE TEXT",
					columns: []*analyzerpb.Column{
						{Schema: schema, Table: "base", Column: "a", DataType: "integer", Ordinal: 1},
						{Schema: schema, Table: "base", Column: "renamed", DataType: "text", Ordinal: 2, Nullable: true},
					},
				},
				{
					name:      "set not null",
					statement: "ALTER TABLE " + quote(schema) + ".base ALTER COLUMN renamed SET NOT NULL",
					columns: []*analyzerpb.Column{
						{Schema: schema, Table: "base", Column: "a", DataType: "integer", Ordinal: 1},
						{Schema: schema, Table: "base", Column: "renamed", DataType: "text", Ordinal: 2},
					},
				},
				{
					name:      "drop not null",
					statement: "ALTER TABLE " + quote(schema) + ".base ALTER COLUMN renamed DROP NOT NULL",
					columns: []*analyzerpb.Column{
						{Schema: schema, Table: "base", Column: "a", DataType: "integer", Ordinal: 1},
						{Schema: schema, Table: "base", Column: "renamed", DataType: "text", Ordinal: 2, Nullable: true},
					},
				},
				{
					name:      "change ordinal",
					statement: "ALTER TABLE " + quote(schema) + ".base DROP COLUMN a, ADD COLUMN a INTEGER NOT NULL",
					columns: []*analyzerpb.Column{
						{Schema: schema, Table: "base", Column: "renamed", DataType: "text", Ordinal: 2, Nullable: true},
						{Schema: schema, Table: "base", Column: "a", DataType: "integer", Ordinal: 3},
					},
				},
				{
					name:      "rename table",
					statement: "ALTER TABLE " + quote(schema) + ".base RENAME TO renamed_table",
					columns: []*analyzerpb.Column{
						{Schema: schema, Table: "renamed_table", Column: "renamed", DataType: "text", Ordinal: 2, Nullable: true},
						{Schema: schema, Table: "renamed_table", Column: "a", DataType: "integer", Ordinal: 3},
					},
				},
				{
					name:      "create function inside an open transaction",
					statement: "CREATE FUNCTION " + quote(schema) + ".AddTax(integer) RETURNS integer LANGUAGE sql IMMUTABLE AS 'select $1 * 11 / 10'",
					before:    "BEGIN",
					columns: []*analyzerpb.Column{
						{Schema: schema, Table: "renamed_table", Column: "renamed", DataType: "text", Ordinal: 2, Nullable: true},
						{Schema: schema, Table: "renamed_table", Column: "a", DataType: "integer", Ordinal: 3},
					},
					routines: []string{"addtax"},
				},
				{
					name:      "roll the function back",
					statement: "ROLLBACK",
					columns: []*analyzerpb.Column{
						{Schema: schema, Table: "renamed_table", Column: "renamed", DataType: "text", Ordinal: 2, Nullable: true},
						{Schema: schema, Table: "renamed_table", Column: "a", DataType: "integer", Ordinal: 3},
					},
				},
				{
					name:      "drop table",
					statement: "DROP TABLE " + quote(schema) + ".renamed_table",
					columns:   []*analyzerpb.Column{},
				},
			}
			for _, step := range steps {
				t.Run(step.name, func(t *testing.T) {
					if step.before != "" {
						targettest.ExecRefetchSQL(t, conn, step.before)
					}
					targettest.ExecRefetchSQL(t, conn, step.statement)
					current := targettest.TrustedRefetchHash(t, queries, conn, schema)
					if len(current) != wantHashLength {
						t.Fatalf("mutated hash length = %d, want %d", len(current), wantHashLength)
					}
					if bytes.Equal(current, previous) {
						t.Fatalf("mutation did not change trusted hash: %x", current)
					}
					push := targettest.RunRefetchIntegration(t, queries, conn, databaseName, schema, previous)
					targettest.AssertFullRefetch(t, push, current, databaseName, step.columns, step.routines)
					previous = current
				})
			}
		})
	}
}

func createPostgresRefetchDatabase(t *testing.T, admin *sql.DB, targetConfig dbtest.TargetDb, name string) *sql.DB {
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
