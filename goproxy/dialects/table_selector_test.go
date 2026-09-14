package dialects_test

import (
	"context"
	"testing"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/goproxy/sqltarget"
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
	target := configuredTarget(t, "mysql", sqltarget.Config{Host: database.Host, Port: database.Port, Db: "app", User: database.User, Password: database.Password})
	for _, test := range []struct {
		name, catalog, schema, wantSchema string
	}{
		{"qualified public", "def", "public", "public"},
		{"qualified app", "def", "app", "app"},
		{"legacy public default", "", "public", "app"},
	} {
		t.Run(test.name, func(t *testing.T) {
			detail, err := target.ReadTableDetail(context.Background(), &enginepb.TableRef{Catalog: test.catalog, Schema: test.schema, Table: "users"})
			if err != nil {
				t.Fatal(err)
			}
			if detail == nil || detail.Catalog == nil || *detail.Catalog != "def" || detail.Schema != test.wantSchema || detail.Table != "users" {
				t.Fatalf("table detail = %+v, want def.%s.users", detail, test.wantSchema)
			}
			if len(detail.Columns) != 1 || detail.Columns[0].Name != test.wantSchema+"_id" {
				t.Fatalf("columns = %+v, want %s_id", detail.Columns, test.wantSchema)
			}
		})
	}
}
