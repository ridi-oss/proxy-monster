package sqldb_test

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/goproxy/mysql"
	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"

	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"google.golang.org/protobuf/proto"
)

func routinesQueries(query string) sqldb.Queries {
	queries := mysql.Queries
	queries.Routines = query
	return queries
}

func runRoutinesQuery(query string, config spi.TargetConfig) (*pb.CatalogRequest, error) {
	return runWith(mysql.OpenPool, routinesQueries(query), mysql.ProbeNamespace, config)
}

func TestRoutinesObservation(t *testing.T) {
	targetConfig := dbtest.MySQL(t)
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
	config := spi.TargetConfig{Host: targetConfig.Host, Port: targetConfig.Port, Db: schema, User: targetConfig.User, Password: targetConfig.Password}
	t.Run("routines fold and group by schema", func(t *testing.T) {
		catalog, err := runRoutinesQuery("SELECT 'app', 'LOOKUP' UNION ALL SELECT 'app', 'lookup' UNION ALL SELECT 'mysql', 'PLUGIN_FN'", config)
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
		catalog, err := runRoutinesQuery("SELECT 'app', 'lookup' WHERE FALSE", config)
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
			if _, err := runRoutinesQuery(query, config); err == nil {
				t.Fatal("sqldb.Introspect succeeded, want a routines failure")
			}
		})
	}
}
