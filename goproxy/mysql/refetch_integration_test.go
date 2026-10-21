package mysql

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/targettest"
	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"
)

func TestMySqlRefetcherIntegration(t *testing.T) {
	database := dbtest.OpenMySQL(t, "")
	conn, err := database.Conn(context.Background())
	if err != nil {
		t.Fatalf("pin MySQL connection: %v", err)
	}
	defer conn.Close()

	quote := func(identifier string) string { return "`" + strings.ReplaceAll(identifier, "`", "``") + "`" }
	schema := targettest.UniqueFixtureName("pm_refetch_mysql_fields")
	targettest.ExecRefetchSQL(t, conn, "DROP DATABASE IF EXISTS "+quote(schema))
	targettest.ExecRefetchSQL(t, conn, "CREATE DATABASE "+quote(schema))
	t.Cleanup(func() {
		_, _ = database.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+quote(schema))
	})
	targettest.ExecRefetchSQL(t, conn, "CREATE TABLE "+quote(schema)+".base (a INT NOT NULL)")

	queries := Queries
	previous := targettest.TrustedRefetchHash(t, queries, conn, schema)
	t.Run("unchanged", func(t *testing.T) {
		push := targettest.RunRefetchIntegration(t, queries, conn, "def", schema, previous)
		if !push.Unchanged || len(push.Columns) != 0 || !bytes.Equal(push.ContentHash, previous) {
			t.Fatalf("unchanged push = %+v, want hash-only unchanged push", push)
		}
	})
	t.Run("schema field", func(t *testing.T) {
		otherSchema := targettest.UniqueFixtureName("pm_refetch_mysql_schema")
		targettest.ExecRefetchSQL(t, conn, "DROP DATABASE IF EXISTS "+quote(otherSchema))
		targettest.ExecRefetchSQL(t, conn, "CREATE DATABASE "+quote(otherSchema))
		t.Cleanup(func() {
			_, _ = database.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+quote(otherSchema))
		})
		targettest.ExecRefetchSQL(t, conn, "CREATE TABLE "+quote(otherSchema)+".base (a INT NOT NULL)")
		current := targettest.TrustedRefetchHash(t, queries, conn, otherSchema)
		if bytes.Equal(current, previous) {
			t.Fatalf("byte-identical tables in distinct schemas collided: %x", current)
		}
		push := targettest.RunRefetchIntegration(t, queries, conn, "def", otherSchema, previous)
		targettest.AssertFullRefetch(t, push, current, "def", []*analyzerpb.Column{
			{Schema: otherSchema, Table: "base", Column: "a", DataType: "int", Ordinal: 1},
		}, nil)
	})

	steps := []struct {
		name      string
		statement string
		columns   []*analyzerpb.Column
		routines  []string
	}{
		{
			name:      "add column",
			statement: "ALTER TABLE " + quote(schema) + ".base ADD COLUMN b VARCHAR(20) NULL",
			columns: []*analyzerpb.Column{
				{Schema: schema, Table: "base", Column: "a", DataType: "int", Ordinal: 1},
				{Schema: schema, Table: "base", Column: "b", DataType: "varchar", Ordinal: 2, Nullable: true},
			},
		},
		{
			name:      "rename column",
			statement: "ALTER TABLE " + quote(schema) + ".base RENAME COLUMN b TO renamed",
			columns: []*analyzerpb.Column{
				{Schema: schema, Table: "base", Column: "a", DataType: "int", Ordinal: 1},
				{Schema: schema, Table: "base", Column: "renamed", DataType: "varchar", Ordinal: 2, Nullable: true},
			},
		},
		{
			name:      "change data type",
			statement: "ALTER TABLE " + quote(schema) + ".base MODIFY COLUMN renamed TEXT NULL",
			columns: []*analyzerpb.Column{
				{Schema: schema, Table: "base", Column: "a", DataType: "int", Ordinal: 1},
				{Schema: schema, Table: "base", Column: "renamed", DataType: "text", Ordinal: 2, Nullable: true},
			},
		},
		{
			name:      "change ordinal",
			statement: "ALTER TABLE " + quote(schema) + ".base MODIFY COLUMN renamed TEXT NULL FIRST",
			columns: []*analyzerpb.Column{
				{Schema: schema, Table: "base", Column: "renamed", DataType: "text", Ordinal: 1, Nullable: true},
				{Schema: schema, Table: "base", Column: "a", DataType: "int", Ordinal: 2},
			},
		},
		{
			name:      "change nullability",
			statement: "ALTER TABLE " + quote(schema) + ".base MODIFY COLUMN renamed TEXT NOT NULL FIRST",
			columns: []*analyzerpb.Column{
				{Schema: schema, Table: "base", Column: "renamed", DataType: "text", Ordinal: 1},
				{Schema: schema, Table: "base", Column: "a", DataType: "int", Ordinal: 2},
			},
		},
		{
			name:      "rename table",
			statement: "RENAME TABLE " + quote(schema) + ".base TO " + quote(schema) + ".renamed_table",
			columns: []*analyzerpb.Column{
				{Schema: schema, Table: "renamed_table", Column: "renamed", DataType: "text", Ordinal: 1},
				{Schema: schema, Table: "renamed_table", Column: "a", DataType: "int", Ordinal: 2},
			},
		},
		{
			name:      "create function",
			statement: "CREATE FUNCTION " + quote(schema) + ".AddTax(amount INT) RETURNS INT DETERMINISTIC RETURN amount * 11 / 10",
			columns: []*analyzerpb.Column{
				{Schema: schema, Table: "renamed_table", Column: "renamed", DataType: "text", Ordinal: 1},
				{Schema: schema, Table: "renamed_table", Column: "a", DataType: "int", Ordinal: 2},
			},
			routines: []string{"addtax"},
		},
		{
			name:      "drop function",
			statement: "DROP FUNCTION " + quote(schema) + ".AddTax",
			columns: []*analyzerpb.Column{
				{Schema: schema, Table: "renamed_table", Column: "renamed", DataType: "text", Ordinal: 1},
				{Schema: schema, Table: "renamed_table", Column: "a", DataType: "int", Ordinal: 2},
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
			targettest.ExecRefetchSQL(t, conn, step.statement)
			current := targettest.TrustedRefetchHash(t, queries, conn, schema)
			if bytes.Equal(current, previous) {
				t.Fatalf("mutation did not change trusted hash: %x", current)
			}
			push := targettest.RunRefetchIntegration(t, queries, conn, "def", schema, previous)
			targettest.AssertFullRefetch(t, push, current, "def", step.columns, step.routines)
			previous = current
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
	schema := targettest.UniqueFixtureName("pm_refetch_mysql_truncated")
	targettest.ExecRefetchSQL(t, conn, "DROP DATABASE IF EXISTS "+quote(schema))
	targettest.ExecRefetchSQL(t, conn, "CREATE DATABASE "+quote(schema))
	t.Cleanup(func() {
		_, _ = database.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+quote(schema))
	})
	definitions := make([]string, 0, 24)
	wantColumns := make([]*analyzerpb.Column, 0, 24)
	for i := 0; i < 24; i++ {
		column := fmt.Sprintf("column_%02d", i)
		definitions = append(definitions, column+" VARCHAR(255)")
		wantColumns = append(wantColumns, &analyzerpb.Column{
			Schema: schema, Table: "wide", Column: column, DataType: "varchar", Ordinal: int32(i + 1), Nullable: true,
		})
	}
	targettest.ExecRefetchSQL(t, conn, "CREATE TABLE "+quote(schema)+".wide ("+strings.Join(definitions, ",")+")")

	queries := narrowHashQueries()
	hashSQL, hashColumns, err := queries.SchemaHash(schema, nil)
	if err != nil {
		t.Fatalf("narrow SchemaHashSQL: %v", err)
	}
	rows, err := targettest.QueryStrings(conn, hashSQL, hashColumns)
	if err != nil {
		t.Fatalf("narrow hash query: %v\n%s", err, hashSQL)
	}
	if len(rows) != 1 || len(rows[0]) != 3 || rows[0][0] == nil || rows[0][1] == nil || rows[0][2] == nil {
		t.Fatalf("narrow hash rows = %#v, want one complete row", rows)
	}
	if *rows[0][1] != "1024" || *rows[0][2] != "24" {
		t.Fatalf("real GROUP_CONCAT result length/count = %s/%s, want 1024/24", *rows[0][1], *rows[0][2])
	}
	truncatedHash, err := decodeHash(*rows[0][0], 64)
	if err != nil {
		t.Fatalf("decode truncated hash bytes: %v", err)
	}
	if decoded, trusted, err := queries.SchemaHashFromRows(rows); err != nil || trusted || decoded != nil {
		t.Fatalf("truncated hash decode = %x, trusted=%v, err=%v; want untrusted", decoded, trusted, err)
	}

	pushes := make([]*pb.SchemaFragmentPush, 0, 2)
	for i := 0; i < 2; i++ {
		push := targettest.RunRefetchIntegration(t, queries, conn, "def", schema, truncatedHash)
		if push.Unchanged {
			t.Fatalf("run %d emitted Unchanged=true for matching truncated hash", i+1)
		}
		if want := targettest.InCatalog("def", wantColumns); !targettest.EqualColumns(push.Columns, want) {
			t.Fatalf("run %d columns = %+v, want complete %+v", i+1, push.Columns, want)
		}
		if len(push.ContentHash) != 32 {
			t.Fatalf("run %d nonce length = %d, want 32", i+1, len(push.ContentHash))
		}
		pushes = append(pushes, push)
	}
	if bytes.Equal(pushes[0].ContentHash, pushes[1].ContentHash) {
		t.Fatalf("untrusted refetch nonce repeated across runs: %x", pushes[0].ContentHash)
	}
}

// narrowHashQueries narrows only the production query's SET_VAR numeric bound. The serialization,
// result decoder, and Refetcher behavior remain the production implementations under test.
func narrowHashQueries() sqldb.Queries {
	queries := Queries
	queries.SchemaHash = func(schema string, setupRows [][]*string) (string, int, error) {
		sqlText, columns, err := Queries.SchemaHash(schema, setupRows)
		if err != nil {
			return "", 0, err
		}
		if strings.Count(sqlText, "33554432") != 1 {
			return "", 0, fmt.Errorf("production MySQL hash SQL has unexpected SET_VAR bound")
		}
		return strings.Replace(sqlText, "33554432", "1024", 1), columns, nil
	}
	return queries
}
