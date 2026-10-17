package dialects_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/dialects"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

func namesDetailDb(t *testing.T, e *engines.Engine, target dbtest.TargetDb) spi.Db {
	t.Helper()
	provider, err := dialects.For(e)
	if err != nil {
		t.Fatal(err)
	}
	targetDb, err := provider.NewDb(spi.TargetDb{Host: target.Host, Port: target.Port, Db: target.DB, User: target.User, Password: target.Password})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = targetDb.Close() })
	return targetDb
}

func namesExec(t *testing.T, database *sql.DB, statements ...string) {
	t.Helper()
	for _, statement := range statements {
		if _, err := database.Exec(statement); err != nil {
			t.Fatalf("exec %q: %v", statement, err)
		}
	}
}

// detailNames reads table detail and returns "schema.table" and its column names, or "" when not found.
func detailNames(t *testing.T, targetDb spi.Db, catalog, schema, table string) (string, []string) {
	t.Helper()
	detail, err := targetDb.ReadTableDetail(context.Background(), &enginepb.ObjectRef{Catalog: catalog, Schema: schema, Table: table})
	if err != nil {
		t.Fatalf("ReadTableDetail(%s.%s): %v", schema, table, err)
	}
	if detail == nil {
		return "", nil
	}
	var columns []string
	for _, column := range detail.Columns {
		columns = append(columns, column.Name)
	}
	return detail.Schema + "." + detail.Table, columns
}

func TestTableDetailMySQLLowerCase1FindsAnySpelling(t *testing.T) {
	target := dbtest.MySQLLowerCase1(t)
	admin := dbtest.OpenMySQLLowerCase1(t, "")
	mixed := fmt.Sprintf("PmNamesDetail_%d", os.Getpid())
	canonical := strings.ToLower(mixed)
	namesExec(t, admin,
		"DROP DATABASE IF EXISTS `"+mixed+"`",
		"CREATE DATABASE `"+mixed+"`",
		"CREATE TABLE `"+mixed+"`.`Users` (Id INT NOT NULL, EMail VARCHAR(64) NULL)",
	)
	t.Cleanup(func() { _, _ = admin.Exec("DROP DATABASE IF EXISTS `" + mixed + "`") })
	targetDb := namesDetailDb(t, engines.MySQL, target)

	if got, _ := detailNames(t, targetDb, "def", canonical, "users"); got != canonical+".users" {
		t.Fatalf("canonical request resolved to %q, want %s.users", got, canonical)
	}
	t.Run("mixed-case request", func(t *testing.T) {
		t.Skip("pending-name-fix: table detail compares the requested name byte-exact against the folded stored name")
		if got, _ := detailNames(t, targetDb, "def", mixed, "Users"); got != canonical+".users" {
			t.Fatalf("mixed-case request resolved to %q, want %s.users", got, canonical)
		}
	})
	t.Run("columns canonical", func(t *testing.T) {
		if _, columns := detailNames(t, targetDb, "def", canonical, "users"); !slices.Equal(columns, []string{"id", "email"}) {
			t.Fatalf("columns = %v, want [id email]", columns)
		}
	})
}

func TestTableDetailMySQLLowerCase0KeepsTablesDistinct(t *testing.T) {
	target := dbtest.MySQL(t)
	admin := dbtest.OpenMySQL(t, "")
	schema := fmt.Sprintf("PmNamesDetail_%d", os.Getpid())
	namesExec(t, admin,
		"DROP DATABASE IF EXISTS `"+schema+"`",
		"CREATE DATABASE `"+schema+"`",
		"CREATE TABLE `"+schema+"`.`Users` (Id INT NOT NULL, EMail VARCHAR(64) NULL)",
		"CREATE TABLE `"+schema+"`.`users` (id INT NOT NULL, note VARCHAR(64) NULL)",
	)
	t.Cleanup(func() { _, _ = admin.Exec("DROP DATABASE IF EXISTS `" + schema + "`") })
	targetDb := namesDetailDb(t, engines.MySQL, target)

	if got, _ := detailNames(t, targetDb, "def", schema, "Users"); got != schema+".Users" {
		t.Fatalf("Users resolved to %q", got)
	}
	if got, columns := detailNames(t, targetDb, "def", schema, "users"); got != schema+".users" || !slices.Equal(columns, []string{"id", "note"}) {
		t.Fatalf("users resolved to %q %v, want %s.users [id note]", got, columns, schema)
	}
	for _, miss := range [][2]string{{schema, "USERS"}, {strings.ToLower(schema), "Users"}} {
		if got, _ := detailNames(t, targetDb, "def", miss[0], miss[1]); got != "" {
			t.Fatalf("%s.%s resolved to %q, want not found", miss[0], miss[1], got)
		}
	}
	t.Run("columns canonical", func(t *testing.T) {
		if _, columns := detailNames(t, targetDb, "def", schema, "Users"); !slices.Equal(columns, []string{"id", "email"}) {
			t.Fatalf("columns = %v, want [id email]", columns)
		}
	})
}

func TestTableDetailPostgresQuotedAndUnquotedAreDistinct(t *testing.T) {
	target := dbtest.Postgres(t)
	admin := dbtest.OpenPostgres(t, "")
	upper := fmt.Sprintf("PmNamesDetail_%d", os.Getpid())
	lower := strings.ToLower(upper)
	namesExec(t, admin,
		`DROP SCHEMA IF EXISTS "`+upper+`" CASCADE`,
		`DROP SCHEMA IF EXISTS `+lower+` CASCADE`,
		`CREATE SCHEMA "`+upper+`"`,
		`CREATE SCHEMA `+lower,
		`CREATE TABLE "`+upper+`"."Users" (id INT NOT NULL, "Email" TEXT)`,
		`CREATE TABLE `+lower+`.users (id INT NOT NULL, email TEXT)`,
	)
	t.Cleanup(func() {
		_, _ = admin.Exec(`DROP SCHEMA IF EXISTS "` + upper + `" CASCADE`)
		_, _ = admin.Exec(`DROP SCHEMA IF EXISTS ` + lower + ` CASCADE`)
	})
	targetDb := namesDetailDb(t, engines.Postgres, target)

	if got, columns := detailNames(t, targetDb, target.DB, upper, "Users"); got != upper+".Users" || !slices.Equal(columns, []string{"id", "Email"}) {
		t.Fatalf(`quoted request resolved to %q %v, want %s.Users [id Email]`, got, columns, upper)
	}
	if got, columns := detailNames(t, targetDb, target.DB, lower, "users"); got != lower+".users" || !slices.Equal(columns, []string{"id", "email"}) {
		t.Fatalf(`unquoted request resolved to %q %v, want %s.users [id email]`, got, columns, lower)
	}
	for _, miss := range [][2]string{{lower, "Users"}, {upper, "users"}} {
		if got, _ := detailNames(t, targetDb, target.DB, miss[0], miss[1]); got != "" {
			t.Fatalf("%s.%s resolved to %q, want not found", miss[0], miss[1], got)
		}
	}
}
