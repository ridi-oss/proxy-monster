package postgres

import (
	"bytes"
	"slices"
	"testing"

	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/targettest"
)

func TestPostgresQuotedNamesStayDistinct(t *testing.T) {
	targetConfig := dbtest.Postgres(t)
	admin := dbtest.OpenPostgres(t, "")
	name := targettest.UniqueFixtureName("pm_names_pg")
	database := createPostgresRefetchDatabase(t, admin, targetConfig, name)
	for _, statement := range []string{
		`CREATE SCHEMA "Sales"`,
		`CREATE SCHEMA sales`,
		`CREATE TABLE "Sales"."Users" (id INT NOT NULL, "Email" TEXT)`,
		`CREATE TABLE sales.users (id INT NOT NULL, email TEXT)`,
		`CREATE TABLE "Sales".users (id INT NOT NULL, "EMAIL" TEXT)`,
		`ALTER DATABASE ` + quotePgIdentifier(name) + ` SET search_path = "Sales", Public`,
	} {
		if _, err := database.Exec(statement); err != nil {
			t.Fatalf("seed %q: %v", statement, err)
		}
	}

	bulk := targettest.IntrospectTarget(t, OpenPool, Queries, ProbeNamespace, targetConfig, name)
	if got := bulk.GetDefaultSchemas(); !slices.Equal(got, []string{"pg_catalog", "Sales", "public"}) {
		t.Errorf("DefaultSchemas = %v, want [pg_catalog Sales public]", got)
	}
	cols := bulk.GetCatalog().GetColumns()
	if got, want := targettest.RelationKeys(cols, "Sales"), []targettest.RelationKey{
		{"Sales", "Users", "Email"}, {"Sales", "Users", "id"}, {"Sales", "users", "EMAIL"}, {"Sales", "users", "id"},
	}; !slices.Equal(got, want) {
		t.Errorf("pushed Sales columns = %v, want %v", got, want)
	}
	if got, want := targettest.RelationKeys(cols, "sales"), []targettest.RelationKey{{"sales", "users", "email"}, {"sales", "users", "id"}}; !slices.Equal(got, want) {
		t.Errorf("pushed sales columns = %v, want %v", got, want)
	}

	conn := targettest.PinConn(t, database)
	targettest.AssertFragmentMatchesBulk(t, Queries, conn, name, bulk, "Sales")
	targettest.AssertFragmentMatchesBulk(t, Queries, conn, name, bulk, "sales")
	if bytes.Equal(targettest.TrustedRefetchHash(t, Queries, conn, "Sales"), targettest.TrustedRefetchHash(t, Queries, conn, "sales")) {
		t.Fatal(`schemas "Sales" and sales hash identically`)
	}
}
