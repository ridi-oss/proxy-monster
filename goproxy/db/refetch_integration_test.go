package db

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

func TestMySqlRefetcherIntegration(t *testing.T) {
	database := dbtest.OpenMySQL(t, "")
	conn, err := database.Conn(context.Background())
	if err != nil {
		t.Fatalf("pin MySQL connection: %v", err)
	}
	defer conn.Close()

	quote := func(identifier string) string { return "`" + strings.ReplaceAll(identifier, "`", "``") + "`" }
	schema := uniqueFixtureName("pm_refetch_mysql_fields")
	execRefetchSQL(t, conn, "DROP DATABASE IF EXISTS "+quote(schema))
	execRefetchSQL(t, conn, "CREATE DATABASE "+quote(schema))
	t.Cleanup(func() {
		_, _ = database.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+quote(schema))
	})
	execRefetchSQL(t, conn, "CREATE TABLE "+quote(schema)+".base (a INT NOT NULL)")

	adapter := MySqlDb{}
	previous := trustedRefetchHash(t, adapter, conn, schema)
	t.Run("unchanged", func(t *testing.T) {
		push := runRefetchIntegration(t, adapter, conn, schema, previous)
		if !push.Unchanged || !push.HashTrusted || len(push.Columns) != 0 || !bytes.Equal(push.ContentHash, previous) {
			t.Fatalf("unchanged push = %+v, want hash-only unchanged push", push)
		}
	})
	t.Run("schema field", func(t *testing.T) {
		otherSchema := uniqueFixtureName("pm_refetch_mysql_schema")
		execRefetchSQL(t, conn, "DROP DATABASE IF EXISTS "+quote(otherSchema))
		execRefetchSQL(t, conn, "CREATE DATABASE "+quote(otherSchema))
		t.Cleanup(func() {
			_, _ = database.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+quote(otherSchema))
		})
		execRefetchSQL(t, conn, "CREATE TABLE "+quote(otherSchema)+".base (a INT NOT NULL)")
		current := trustedRefetchHash(t, adapter, conn, otherSchema)
		if bytes.Equal(current, previous) {
			t.Fatalf("byte-identical tables in distinct schemas collided: %x", current)
		}
		push := runRefetchIntegration(t, adapter, conn, otherSchema, previous)
		assertFullRefetch(t, push, current, []*pb.Column{
			{Schema: otherSchema, Table: "base", Column: "a", DataType: "int", Ordinal: 1},
		})
	})

	steps := []struct {
		name      string
		statement string
		columns   []*pb.Column
	}{
		{
			name:      "add column",
			statement: "ALTER TABLE " + quote(schema) + ".base ADD COLUMN b VARCHAR(20) NULL",
			columns: []*pb.Column{
				{Schema: schema, Table: "base", Column: "a", DataType: "int", Ordinal: 1},
				{Schema: schema, Table: "base", Column: "b", DataType: "varchar", Ordinal: 2, Nullable: true},
			},
		},
		{
			name:      "rename column",
			statement: "ALTER TABLE " + quote(schema) + ".base RENAME COLUMN b TO renamed",
			columns: []*pb.Column{
				{Schema: schema, Table: "base", Column: "a", DataType: "int", Ordinal: 1},
				{Schema: schema, Table: "base", Column: "renamed", DataType: "varchar", Ordinal: 2, Nullable: true},
			},
		},
		{
			name:      "change data type",
			statement: "ALTER TABLE " + quote(schema) + ".base MODIFY COLUMN renamed TEXT NULL",
			columns: []*pb.Column{
				{Schema: schema, Table: "base", Column: "a", DataType: "int", Ordinal: 1},
				{Schema: schema, Table: "base", Column: "renamed", DataType: "text", Ordinal: 2, Nullable: true},
			},
		},
		{
			name:      "change ordinal",
			statement: "ALTER TABLE " + quote(schema) + ".base MODIFY COLUMN renamed TEXT NULL FIRST",
			columns: []*pb.Column{
				{Schema: schema, Table: "base", Column: "renamed", DataType: "text", Ordinal: 1, Nullable: true},
				{Schema: schema, Table: "base", Column: "a", DataType: "int", Ordinal: 2},
			},
		},
		{
			name:      "change nullability",
			statement: "ALTER TABLE " + quote(schema) + ".base MODIFY COLUMN renamed TEXT NOT NULL FIRST",
			columns: []*pb.Column{
				{Schema: schema, Table: "base", Column: "renamed", DataType: "text", Ordinal: 1},
				{Schema: schema, Table: "base", Column: "a", DataType: "int", Ordinal: 2},
			},
		},
		{
			name:      "rename table",
			statement: "RENAME TABLE " + quote(schema) + ".base TO " + quote(schema) + ".renamed_table",
			columns: []*pb.Column{
				{Schema: schema, Table: "renamed_table", Column: "renamed", DataType: "text", Ordinal: 1},
				{Schema: schema, Table: "renamed_table", Column: "a", DataType: "int", Ordinal: 2},
			},
		},
		{
			name:      "drop table",
			statement: "DROP TABLE " + quote(schema) + ".renamed_table",
			columns:   []*pb.Column{},
		},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			execRefetchSQL(t, conn, step.statement)
			current := trustedRefetchHash(t, adapter, conn, schema)
			if bytes.Equal(current, previous) {
				t.Fatalf("mutation did not change trusted hash: %x", current)
			}
			push := runRefetchIntegration(t, adapter, conn, schema, previous)
			assertFullRefetch(t, push, current, step.columns)
			previous = current
		})
	}
}

func TestPostgresRefetcherIntegration(t *testing.T) {
	backend := dbtest.Postgres(t)
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
			databaseName := uniqueFixtureName("pm_refetch_pg")
			database := createPostgresRefetchDatabase(t, admin, backend, databaseName)
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
			schema := uniqueFixtureName("pm_refetch_pg_fields")
			execRefetchSQL(t, conn, "CREATE SCHEMA "+quote(schema))
			execRefetchSQL(t, conn, "CREATE TABLE "+quote(schema)+".base (a INTEGER NOT NULL)")

			adapter := PgDb{}
			previous := trustedRefetchHash(t, adapter, conn, schema)
			wantHashLength := 16
			if mode.crypto {
				wantHashLength = 32
			}
			if len(previous) != wantHashLength {
				t.Fatalf("initial hash length = %d, want %d", len(previous), wantHashLength)
			}
			t.Run("unchanged", func(t *testing.T) {
				push := runRefetchIntegration(t, adapter, conn, schema, previous)
				if !push.Unchanged || !push.HashTrusted || len(push.Columns) != 0 || !bytes.Equal(push.ContentHash, previous) {
					t.Fatalf("unchanged push = %+v, want hash-only unchanged push", push)
				}
			})
			t.Run("schema field", func(t *testing.T) {
				otherSchema := uniqueFixtureName("pm_refetch_pg_schema")
				execRefetchSQL(t, conn, "CREATE SCHEMA "+quote(otherSchema))
				execRefetchSQL(t, conn, "CREATE TABLE "+quote(otherSchema)+".base (a INTEGER NOT NULL)")
				current := trustedRefetchHash(t, adapter, conn, otherSchema)
				if len(current) != wantHashLength {
					t.Fatalf("schema-field hash length = %d, want %d", len(current), wantHashLength)
				}
				if bytes.Equal(current, previous) {
					t.Fatalf("byte-identical tables in distinct schemas collided: %x", current)
				}
				push := runRefetchIntegration(t, adapter, conn, otherSchema, previous)
				assertFullRefetch(t, push, current, []*pb.Column{
					{Schema: otherSchema, Table: "base", Column: "a", DataType: "integer", Ordinal: 1},
				})
			})

			steps := []struct {
				name      string
				statement string
				columns   []*pb.Column
			}{
				{
					name:      "add column",
					statement: "ALTER TABLE " + quote(schema) + ".base ADD COLUMN b CHARACTER VARYING(20) NULL",
					columns: []*pb.Column{
						{Schema: schema, Table: "base", Column: "a", DataType: "integer", Ordinal: 1},
						{Schema: schema, Table: "base", Column: "b", DataType: "character varying", Ordinal: 2, Nullable: true},
					},
				},
				{
					name:      "rename column",
					statement: "ALTER TABLE " + quote(schema) + ".base RENAME COLUMN b TO renamed",
					columns: []*pb.Column{
						{Schema: schema, Table: "base", Column: "a", DataType: "integer", Ordinal: 1},
						{Schema: schema, Table: "base", Column: "renamed", DataType: "character varying", Ordinal: 2, Nullable: true},
					},
				},
				{
					name:      "change data type",
					statement: "ALTER TABLE " + quote(schema) + ".base ALTER COLUMN renamed TYPE TEXT",
					columns: []*pb.Column{
						{Schema: schema, Table: "base", Column: "a", DataType: "integer", Ordinal: 1},
						{Schema: schema, Table: "base", Column: "renamed", DataType: "text", Ordinal: 2, Nullable: true},
					},
				},
				{
					name:      "set not null",
					statement: "ALTER TABLE " + quote(schema) + ".base ALTER COLUMN renamed SET NOT NULL",
					columns: []*pb.Column{
						{Schema: schema, Table: "base", Column: "a", DataType: "integer", Ordinal: 1},
						{Schema: schema, Table: "base", Column: "renamed", DataType: "text", Ordinal: 2},
					},
				},
				{
					name:      "drop not null",
					statement: "ALTER TABLE " + quote(schema) + ".base ALTER COLUMN renamed DROP NOT NULL",
					columns: []*pb.Column{
						{Schema: schema, Table: "base", Column: "a", DataType: "integer", Ordinal: 1},
						{Schema: schema, Table: "base", Column: "renamed", DataType: "text", Ordinal: 2, Nullable: true},
					},
				},
				{
					name:      "change ordinal",
					statement: "ALTER TABLE " + quote(schema) + ".base DROP COLUMN a, ADD COLUMN a INTEGER NOT NULL",
					columns: []*pb.Column{
						{Schema: schema, Table: "base", Column: "renamed", DataType: "text", Ordinal: 2, Nullable: true},
						{Schema: schema, Table: "base", Column: "a", DataType: "integer", Ordinal: 3},
					},
				},
				{
					name:      "rename table",
					statement: "ALTER TABLE " + quote(schema) + ".base RENAME TO renamed_table",
					columns: []*pb.Column{
						{Schema: schema, Table: "renamed_table", Column: "renamed", DataType: "text", Ordinal: 2, Nullable: true},
						{Schema: schema, Table: "renamed_table", Column: "a", DataType: "integer", Ordinal: 3},
					},
				},
				{
					name:      "drop table",
					statement: "DROP TABLE " + quote(schema) + ".renamed_table",
					columns:   []*pb.Column{},
				},
			}
			for _, step := range steps {
				t.Run(step.name, func(t *testing.T) {
					execRefetchSQL(t, conn, step.statement)
					current := trustedRefetchHash(t, adapter, conn, schema)
					if len(current) != wantHashLength {
						t.Fatalf("mutated hash length = %d, want %d", len(current), wantHashLength)
					}
					if bytes.Equal(current, previous) {
						t.Fatalf("mutation did not change trusted hash: %x", current)
					}
					push := runRefetchIntegration(t, adapter, conn, schema, previous)
					assertFullRefetch(t, push, current, step.columns)
					previous = current
				})
			}
		})
	}
}

func TestMySqlRefetcherTruncationFallsBackToFullFetch(t *testing.T) {
	database := dbtest.OpenMySQL(t, "")
	conn, err := database.Conn(context.Background())
	if err != nil {
		t.Fatalf("pin MySQL connection: %v", err)
	}
	defer conn.Close()

	quote := func(identifier string) string { return "`" + strings.ReplaceAll(identifier, "`", "``") + "`" }
	schema := uniqueFixtureName("pm_refetch_mysql_truncated")
	execRefetchSQL(t, conn, "DROP DATABASE IF EXISTS "+quote(schema))
	execRefetchSQL(t, conn, "CREATE DATABASE "+quote(schema))
	t.Cleanup(func() {
		_, _ = database.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+quote(schema))
	})
	definitions := make([]string, 0, 24)
	wantColumns := make([]*pb.Column, 0, 24)
	for i := 0; i < 24; i++ {
		column := fmt.Sprintf("column_%02d", i)
		definitions = append(definitions, column+" VARCHAR(255)")
		wantColumns = append(wantColumns, &pb.Column{
			Schema: schema, Table: "wide", Column: column, DataType: "varchar", Ordinal: int32(i + 1), Nullable: true,
		})
	}
	execRefetchSQL(t, conn, "CREATE TABLE "+quote(schema)+".wide ("+strings.Join(definitions, ",")+")")

	adapter := narrowMySqlHashDb{MySqlDb: MySqlDb{}}
	hashSQL, hashColumns, err := adapter.SchemaHashSQL(schema, nil)
	if err != nil {
		t.Fatalf("narrow SchemaHashSQL: %v", err)
	}
	rows, err := queryStrings(conn, hashSQL, hashColumns)
	if err != nil {
		t.Fatalf("narrow hash query: %v\n%s", err, hashSQL)
	}
	if len(rows) != 1 || len(rows[0]) != 5 || rows[0][0] == nil || rows[0][1] == nil || rows[0][2] == nil || rows[0][3] == nil || rows[0][4] == nil {
		t.Fatalf("narrow hash rows = %#v, want one complete five-column row", rows)
	}
	if *rows[0][1] != "1024" || *rows[0][2] != "24" {
		t.Fatalf("real GROUP_CONCAT result length/count = %s/%s, want 1024/24", *rows[0][1], *rows[0][2])
	}
	truncatedHash := decodeHash(*rows[0][0], 64)
	if truncatedHash == nil {
		t.Fatalf("truncated hash %q is not a decodable digest", *rows[0][0])
	}
	observation, err := adapter.SchemaHashFromRows(rows)
	if err != nil || observation.Trusted || !bytes.Equal(observation.Hash, truncatedHash) {
		t.Fatalf("truncated hash observation = %+v, err=%v; want genuine untrusted hash %x", observation, err, truncatedHash)
	}

	pushes := make([]*pb.SchemaFragmentPush, 0, 2)
	for i := 0; i < 2; i++ {
		push := runRefetchIntegration(t, adapter, conn, schema, truncatedHash)
		if push.Unchanged {
			t.Fatalf("run %d emitted Unchanged=true for matching truncated hash", i+1)
		}
		if !reflect.DeepEqual(push.Columns, wantColumns) {
			t.Fatalf("run %d columns = %+v, want complete %+v", i+1, push.Columns, wantColumns)
		}
		if push.HashTrusted || !bytes.Equal(push.ContentHash, truncatedHash) {
			t.Fatalf("run %d hash = %x trusted=%v, want genuine untrusted hash %x", i+1, push.ContentHash, push.HashTrusted, truncatedHash)
		}
		pushes = append(pushes, push)
	}
	if !bytes.Equal(pushes[0].ContentHash, pushes[1].ContentHash) {
		t.Fatalf("repeated untrusted refetch hashes differ: %x vs %x", pushes[0].ContentHash, pushes[1].ContentHash)
	}
}

// narrowMySqlHashDb narrows only the production query's SET_VAR numeric bound. The serialization,
// result decoder, and Refetcher behavior remain the production implementations under test.
type narrowMySqlHashDb struct {
	MySqlDb
}

func (db narrowMySqlHashDb) SchemaHashSQL(schema string, setupRows [][]*string) (string, int, error) {
	sqlText, columns, err := db.MySqlDb.SchemaHashSQL(schema, setupRows)
	if err != nil {
		return "", 0, err
	}
	if strings.Count(sqlText, "33554432") != 1 {
		return "", 0, fmt.Errorf("production MySQL hash SQL has unexpected SET_VAR bound")
	}
	return strings.Replace(sqlText, "33554432", "1024", 1), columns, nil
}

func trustedRefetchHash(t *testing.T, adapter engine.Db, conn *sql.Conn, schema string) []byte {
	t.Helper()
	var setupRows [][]*string
	if setupSQL := adapter.HashSetupProbeSQL(); setupSQL != "" {
		rows, err := queryStrings(conn, setupSQL, adapter.HashSetupColumns())
		if err != nil {
			t.Fatalf("hash setup probe: %v", err)
		}
		setupRows = rows
	}
	hashSQL, columns, err := adapter.SchemaHashSQL(schema, setupRows)
	if err != nil {
		t.Fatalf("SchemaHashSQL(%q): %v", schema, err)
	}
	rows, err := queryStrings(conn, hashSQL, columns)
	if err != nil {
		t.Fatalf("hash query for %q: %v\n%s", schema, err, hashSQL)
	}
	observation, err := adapter.SchemaHashFromRows(rows)
	if err != nil || !observation.Trusted {
		t.Fatalf("hash for %q = %+v, err=%v, rows=%#v", schema, observation, err, rows)
	}
	if observation.DbClockMicros == 0 || observation.BackendID == "" {
		t.Fatalf("hash for %q lacks clock/backend identity: %+v", schema, observation)
	}
	return observation.Hash
}

func runRefetchIntegration(t *testing.T, adapter engine.Db, conn *sql.Conn, schema string, ifHashDiffers []byte) *pb.SchemaFragmentPush {
	t.Helper()
	connectionID := []byte("refetch-test-connection")
	const generation = uint64(41)
	var pushes []*pb.SchemaFragmentPush
	refetcher := engine.Refetcher{
		Db:                adapter,
		ConnectionID:      connectionID,
		BackendGeneration: generation,
		Probe: func(statement string, expectedColumns int) ([][]*string, error) {
			return queryStrings(conn, statement, expectedColumns)
		},
		Push: func(push *pb.SchemaFragmentPush) (uint64, error) {
			pushes = append(pushes, push)
			return uint64(len(pushes)), nil
		},
	}
	if err := refetcher.Run(&pb.Refetch{Schema: schema, IfHashDiffers: ifHashDiffers}); err != nil {
		t.Fatalf("Refetcher.Run(%q): %v", schema, err)
	}
	if len(pushes) != 1 {
		t.Fatalf("push count = %d, want exactly 1", len(pushes))
	}
	push := pushes[0]
	if !bytes.Equal(push.ConnectionId, connectionID) || push.Schema != schema || push.BackendGeneration != generation {
		t.Fatalf("push identity = %+v, want connection/schema/generation preserved", push)
	}
	if push.DbClockMicros == 0 || push.BackendId == "" {
		t.Fatalf("push observation lacks clock/backend identity: %+v", push)
	}
	if push.MeasuredInTransaction {
		t.Fatalf("integration refetch unexpectedly measured in transaction: %+v", push)
	}
	return push
}

func assertFullRefetch(t *testing.T, push *pb.SchemaFragmentPush, currentHash []byte, wantColumns []*pb.Column) {
	t.Helper()
	if push.Unchanged {
		t.Fatalf("push = %+v, want full fetch", push)
	}
	if !bytes.Equal(push.ContentHash, currentHash) || !push.HashTrusted {
		t.Fatalf("push hash = %x trusted=%v, want new trusted hash %x", push.ContentHash, push.HashTrusted, currentHash)
	}
	if !reflect.DeepEqual(push.Columns, wantColumns) {
		t.Fatalf("push columns = %+v, want %+v", push.Columns, wantColumns)
	}
}

func execRefetchSQL(t *testing.T, conn *sql.Conn, statement string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), hashTestTimeout)
	defer cancel()
	if _, err := conn.ExecContext(ctx, statement); err != nil {
		t.Fatalf("exec %q: %v", statement, err)
	}
}

func createPostgresRefetchDatabase(t *testing.T, admin *sql.DB, backend dbtest.Backend, name string) *sql.DB {
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
