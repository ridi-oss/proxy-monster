package dialects_test

import (
	"context"
	"testing"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

func TestMySQLQualifiedPublicSchemaIsLiteral(t *testing.T) {
	database := dbtest.MySQL(t)
	seed := dbtest.OpenMySQL(t, "")
	for _, schema := range []string{"app", "public"} {
		if _, err := seed.Exec("CREATE DATABASE IF NOT EXISTS `" + schema + "`"); err != nil {
			t.Fatal(err)
		}
		if _, err := seed.Exec("CREATE TABLE `" + schema + "`.users (`" + schema + "_id` INT PRIMARY KEY)"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := seed.Exec("DROP TABLE `" + schema + "`.users"); err != nil {
				t.Error(err)
			}
		})
	}
	target := openDb(t, engine.MySQL, spi.TargetDb{Host: database.Host, Port: database.Port, Db: "app", User: database.User, Password: database.Password})
	if _, err := target.ReadTableDetail(context.Background(), &enginepb.ObjectRef{Schema: "app", Table: "users"}); err == nil {
		t.Fatal("blank catalog was answered")
	}
	for _, test := range []struct {
		name, catalog, schema, wantSchema string
	}{
		{"qualified public", "def", "public", "public"},
		{"qualified app", "def", "app", "app"},
	} {
		t.Run(test.name, func(t *testing.T) {
			detail, err := target.ReadTableDetail(context.Background(), &enginepb.ObjectRef{Catalog: test.catalog, Schema: test.schema, Table: "users"})
			if err != nil {
				t.Fatal(err)
			}
			if detail == nil || detail.Catalog != "def" || detail.Schema != test.wantSchema || detail.Table != "users" {
				t.Fatalf("table detail = %+v, want def.%s.users", detail, test.wantSchema)
			}
			if len(detail.Columns) != 1 || detail.Columns[0].Name != test.wantSchema+"_id" {
				t.Fatalf("columns = %+v, want %s_id", detail.Columns, test.wantSchema)
			}
		})
	}
}

func TestMySQLTableDetailNamesAreCanonical(t *testing.T) {
	database := dbtest.MySQL(t)
	seed := dbtest.OpenMySQL(t, "")
	for _, statement := range []string{
		"CREATE DATABASE IF NOT EXISTS app",
		"CREATE TABLE app.Parent (ID INT PRIMARY KEY)",
		"CREATE TABLE app.Mixed (Email VARCHAR(64), ParentID INT, INDEX by_email (Email), FOREIGN KEY (ParentID) REFERENCES app.Parent (ID))",
	} {
		if _, err := seed.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, statement := range []string{"DROP TABLE app.Mixed", "DROP TABLE app.Parent"} {
			if _, err := seed.Exec(statement); err != nil {
				t.Error(err)
			}
		}
	})
	target := openDb(t, engine.MySQL, spi.TargetDb{Host: database.Host, Port: database.Port, Db: "app", User: database.User, Password: database.Password})
	detail, err := target.ReadTableDetail(context.Background(), &enginepb.ObjectRef{Catalog: "def", Schema: "app", Table: "Mixed"})
	if err != nil || detail == nil {
		t.Fatalf("detail: %v %v", detail, err)
	}
	if len(detail.Columns) != 2 || detail.Columns[0].Name != "email" || detail.Columns[1].Name != "parentid" {
		t.Fatalf("columns: %+v", detail.Columns)
	}
	if len(detail.ForeignKeys) != 1 || detail.ForeignKeys[0].SourceColumns[0] != "parentid" ||
		detail.ForeignKeys[0].TargetTable != "Parent" || detail.ForeignKeys[0].TargetColumns[0] != "id" {
		t.Fatalf("foreign keys: %+v", detail.ForeignKeys)
	}
	for _, index := range detail.Indexes {
		for _, column := range index.Columns {
			if column.Name != "email" && column.Name != "parentid" {
				t.Fatalf("index column %q is not canonical", column.Name)
			}
		}
	}
}
