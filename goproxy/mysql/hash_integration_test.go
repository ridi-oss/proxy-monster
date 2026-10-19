package mysql

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/targettest"
	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"
)

func TestMySqlSchemaHashIntegration(t *testing.T) {
	database := dbtest.OpenMySQL(t, "")
	conn, err := database.Conn(context.Background())
	if err != nil {
		t.Fatalf("pin MySQL connection: %v", err)
	}
	defer conn.Close()

	queries := TargetSQL{}
	lowerCaseTableNames := 0
	if rows, err := targettest.QueryStrings(conn, queries.LowerCaseTableNamesProbeSQL(), 1); err == nil && len(rows) == 1 && len(rows[0]) == 1 && rows[0][0] != nil {
		if mode, err := strconv.Atoi(*rows[0][0]); err == nil {
			lowerCaseTableNames = mode
		}
	}
	quote := func(identifier string) string { return "`" + strings.ReplaceAll(identifier, "`", "``") + "`" }
	exec := func(statement string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), targettest.HashTestTimeout)
		defer cancel()
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			t.Fatalf("MySQL exec %q: %v", statement, err)
		}
	}
	cleanupExec := func(statement string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), targettest.HashTestTimeout)
		defer cancel()
		_, _ = database.ExecContext(ctx, statement)
	}
	hash := func(schema string) []byte {
		t.Helper()
		sqlText, columns, err := queries.SchemaHashSQL(schema, nil)
		if err != nil {
			t.Fatalf("SchemaHashSQL(%q): %v", schema, err)
		}
		rows, err := targettest.QueryStrings(conn, sqlText, columns)
		if err != nil {
			t.Fatalf("hash query for %q: %v\n%s", schema, err, sqlText)
		}
		value, trusted, err := queries.SchemaHashFromRows(rows)
		if err != nil {
			t.Fatalf("SchemaHashFromRows(%q): %v", schema, err)
		}
		if !trusted {
			t.Fatalf("hash for %q is untrusted: %#v", schema, rows)
		}
		return value
	}
	fragments := func(schema string) []*analyzerpb.Column {
		t.Helper()
		rows, err := targettest.QueryStrings(conn, queries.SchemaColumnsSQL(schema), 7)
		if err != nil {
			t.Fatalf("fragment query for %q: %v", schema, err)
		}
		columns, err := sqldb.FragmentColumnsFromRows(queries, lowerCaseTableNames, schema, rows)
		if err != nil {
			t.Fatalf("FragmentColumnsFromRows(%q): %v", schema, err)
		}
		return columns
	}

	schema := targettest.UniqueFixtureName("pm_hash_mysql_fields")
	exec("DROP DATABASE IF EXISTS " + quote(schema))
	exec("CREATE DATABASE " + quote(schema))
	t.Cleanup(func() { cleanupExec("DROP DATABASE IF EXISTS " + quote(schema)) })
	exec("CREATE TABLE " + quote(schema) + ".base (a INT NOT NULL)")

	t.Run("schema field changes the hash", func(t *testing.T) {
		firstSchema := targettest.UniqueFixtureName("pm_hash_mysql_schema_a")
		secondSchema := targettest.UniqueFixtureName("pm_hash_mysql_schema_b")
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
		ambiguity := targettest.UniqueFixtureName("pm_hash_mysql_ambiguity")
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
		large := targettest.UniqueFixtureName("pm_hash_mysql_large")
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
		hostile := targettest.UniqueFixtureName("pm_hash_mysql_hostile") + "_'quote\\slash"
		exec("DROP DATABASE IF EXISTS " + quote(hostile))
		exec("CREATE DATABASE " + quote(hostile))
		t.Cleanup(func() { cleanupExec("DROP DATABASE IF EXISTS " + quote(hostile)) })
		exec("CREATE TABLE " + quote(hostile) + ".t (id INT NOT NULL)")
		_ = hash(hostile)
		want := targettest.InCatalog("def", []*analyzerpb.Column{{Schema: hostile, Table: "t", Column: "id", DataType: "int", Ordinal: 1}})
		if got := fragments(hostile); !targettest.EqualColumns(got, want) {
			t.Fatalf("hostile schema fragment = %+v, want %+v", got, want)
		}
		missing := targettest.UniqueFixtureName("pm_hash_mysql_missing")
		empty1, empty2 := hash(missing), hash(missing)
		if !reflect.DeepEqual(empty1, empty2) || len(fragments(missing)) != 0 {
			t.Fatalf("empty schema is not deterministic/empty: %x %x", empty1, empty2)
		}
	})

	t.Run("exact fragments include system schema", func(t *testing.T) {
		fragmentSchema := targettest.UniqueFixtureName("pm_hash_mysql_fragment")
		exec("DROP DATABASE IF EXISTS " + quote(fragmentSchema))
		exec("CREATE DATABASE " + quote(fragmentSchema))
		t.Cleanup(func() { cleanupExec("DROP DATABASE IF EXISTS " + quote(fragmentSchema)) })
		exec("CREATE TABLE " + quote(fragmentSchema) + ".sample (id INT NOT NULL, note VARCHAR(20) NULL)")
		want := targettest.InCatalog("def", []*analyzerpb.Column{
			{Schema: fragmentSchema, Table: "sample", Column: "id", DataType: "int", Ordinal: 1},
			{Schema: fragmentSchema, Table: "sample", Column: "note", DataType: "varchar", Ordinal: 2, Nullable: true},
		})
		if got := fragments(fragmentSchema); !targettest.EqualColumns(got, want) {
			t.Fatalf("fragment = %+v, want %+v", got, want)
		}
		if got := fragments("information_schema"); len(got) == 0 {
			t.Fatal("information_schema fragment is empty; system schemas must not be excluded")
		}
	})
}
