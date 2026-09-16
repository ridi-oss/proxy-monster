package introspect

import (
	"testing"

	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/db"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"google.golang.org/protobuf/proto"
)

type routinesQueryDb struct {
	db.MySqlDb
	query string
}

func (d routinesQueryDb) RoutinesSQL() string { return d.query }

type routinesQueryOpener struct {
	mysqlTestOpener
	query string
}

func (o routinesQueryOpener) NewDb() engine.Db { return routinesQueryDb{query: o.query} }

func TestRoutinesObservation(t *testing.T) {
	targetDb := dbtest.MySQL(t)
	seed := dbtest.OpenMySQL(t, "")
	const schema = "it_routines_observation"
	for _, sql := range []string{
		"CREATE DATABASE IF NOT EXISTS " + schema,
		"CREATE TABLE IF NOT EXISTS " + schema + ".users (ssn VARCHAR(32))",
	} {
		if _, err := seed.Exec(sql); err != nil {
			t.Fatal(err)
		}
	}
	target := spi.TargetDb{Host: targetDb.Host, Port: targetDb.Port, Db: schema, User: targetDb.User, Password: targetDb.Password}
	t.Run("routines fold and group by schema", func(t *testing.T) {
		catalog, err := Run(routinesQueryOpener{query: "SELECT 'app', 'LOOKUP' UNION ALL SELECT 'app', 'lookup' UNION ALL SELECT 'mysql', 'PLUGIN_FN'"}, target)
		if err != nil {
			t.Fatal(err)
		}
		want := []*analyzerpb.SchemaFunctions{
			{Schema: "app", Names: []string{"lookup"}},
			{Schema: "mysql", Names: []string{"plugin_fn"}},
		}
		if len(catalog.GetCatalog().GetRoutines()) != len(want) {
			t.Fatalf("routines=%v, want %v", catalog.GetCatalog().GetRoutines(), want)
		}
		for i := range want {
			if !proto.Equal(catalog.GetCatalog().GetRoutines()[i], want[i]) {
				t.Fatalf("routines=%v, want %v", catalog.GetCatalog().GetRoutines(), want)
			}
		}
		if catalog.GetCatalog().GetFunctions() != nil {
			t.Fatalf("the proxy must not tier functions itself: %v", catalog.GetCatalog().GetFunctions())
		}
	})
	t.Run("an empty observation is an empty list", func(t *testing.T) {
		catalog, err := Run(routinesQueryOpener{query: "SELECT 'app', 'lookup' WHERE FALSE"}, target)
		if err != nil {
			t.Fatal(err)
		}
		if len(catalog.GetCatalog().GetRoutines()) != 0 {
			t.Fatalf("routines=%v, want none", catalog.GetCatalog().GetRoutines())
		}
	})
	for name, query := range map[string]string{
		"query":        "SELECT * FROM " + schema + ".missing_table",
		"column count": "SELECT 'one'",
	} {
		t.Run(name+" failure fails the whole catalog", func(t *testing.T) {
			if _, err := Run(routinesQueryOpener{query: query}, target); err == nil {
				t.Fatal("Run succeeded, want a routines failure")
			}
		})
	}
}
