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

type functionQueryDb struct {
	db.MySqlDb
	queries db.FunctionCatalogSQL
}

func (d functionQueryDb) FunctionCatalogSQL() db.FunctionCatalogSQL { return d.queries }

type functionQueryOpener struct {
	mysqlTestOpener
	queries db.FunctionCatalogSQL
}

func (o functionQueryOpener) NewDb() engine.Db { return functionQueryDb{queries: o.queries} }

func TestFunctionCatalogObservation(t *testing.T) {
	targetDb := dbtest.MySQL(t)
	seed := dbtest.OpenMySQL(t, "")
	const schema = "it_functions_observation"
	for _, sql := range []string{
		"CREATE DATABASE IF NOT EXISTS " + schema,
		"CREATE TABLE IF NOT EXISTS " + schema + ".users (ssn VARCHAR(32))",
	} {
		if _, err := seed.Exec(sql); err != nil {
			t.Fatal(err)
		}
	}
	target := spi.TargetDb{Host: targetDb.Host, Port: targetDb.Port, Db: schema, User: targetDb.User, Password: targetDb.Password}
	queries := db.FunctionCatalogSQL{
		BuiltinFunctions:      "SELECT 'LOWER'",
		SystemFunctionSchemas: "SELECT 'helpers', 'LOOKUP'",
		UdfSchemas:            "SELECT 'app', 'LOOKUP'",
		LoadableFunctions:     "SELECT 'PLUGIN_FN'",
	}
	t.Run("all tiers reach the existing catalog request", func(t *testing.T) {
		catalog, err := Run(functionQueryOpener{queries: queries}, target)
		if err != nil {
			t.Fatal(err)
		}
		want := &analyzerpb.FunctionCatalog{
			BuiltinFunctions:      []string{"lower"},
			SystemFunctionSchemas: []*analyzerpb.SchemaFunctions{{Schema: "helpers", Names: []string{"lookup"}}},
			UdfSchemas:            []*analyzerpb.SchemaFunctions{{Schema: "app", Names: []string{"lookup"}}},
			LoadableFunctions:     []string{"plugin_fn"},
		}
		if !proto.Equal(catalog.GetCatalog().GetFunctions(), want) {
			t.Fatalf("functions=%v, want %v", catalog.GetCatalog().GetFunctions(), want)
		}
	})
	t.Run("empty results remain present", func(t *testing.T) {
		empty := db.FunctionCatalogSQL{
			BuiltinFunctions:      queries.BuiltinFunctions + " WHERE FALSE",
			SystemFunctionSchemas: queries.SystemFunctionSchemas + " WHERE FALSE",
			UdfSchemas:            queries.UdfSchemas + " WHERE FALSE",
			LoadableFunctions:     queries.LoadableFunctions + " WHERE FALSE",
		}
		catalog, err := Run(functionQueryOpener{queries: empty}, target)
		if err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(catalog.GetCatalog().GetFunctions(), &analyzerpb.FunctionCatalog{}) {
			t.Fatalf("empty observation became absent or populated: %v", catalog.GetCatalog().GetFunctions())
		}
	})
	for _, tier := range []string{"builtin", "system", "udf", "loadable", "scan one", "scan two"} {
		t.Run(tier+" failure withholds all functions", func(t *testing.T) {
			failed := queries
			const invalid = "SELECT * FROM " + schema + ".missing_table"
			switch tier {
			case "builtin":
				failed.BuiltinFunctions = invalid
			case "system":
				failed.SystemFunctionSchemas = invalid
			case "udf":
				failed.UdfSchemas = invalid
			case "loadable":
				failed.LoadableFunctions = invalid
			case "scan one":
				failed.BuiltinFunctions = "SELECT 'one', 'two'"
			case "scan two":
				failed.UdfSchemas = "SELECT 'one'"
			}
			catalog, err := Run(functionQueryOpener{queries: failed}, target)
			if err != nil {
				t.Fatal(err)
			}
			if catalog.GetCatalog().GetFunctions() != nil {
				t.Fatalf("failed tier yielded partial function observation: %v", catalog.GetCatalog().GetFunctions())
			}
			if !hasColumn(catalog.GetCatalog().GetColumns(), schema, "users", "ssn") {
				t.Fatal("function failure discarded the independent column catalog")
			}
		})
	}
}
