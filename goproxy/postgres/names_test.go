package postgres_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
)

func TestSearchPathKeepsQuotedCase(t *testing.T) {
	targetDb := dbtest.Postgres(t)
	seed := dbtest.OpenPostgres(t, "")
	for _, statement := range []string{
		`CREATE SCHEMA IF NOT EXISTS "PmNamesSales"`,
		`CREATE SCHEMA IF NOT EXISTS pmnamessales`,
		`CREATE TABLE IF NOT EXISTS "PmNamesSales"."Users" (id int)`,
		`CREATE TABLE IF NOT EXISTS pmnamessales.users (id int)`,
	} {
		if _, err := seed.Exec(statement); err != nil {
			t.Fatalf("seed %q: %v", statement, err)
		}
	}
	h := startBrokerForDB(t, targetDb, "app")
	conn, err := h.connect(t, validToken, true)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()
	for _, tc := range []struct {
		set  string
		want []string
	}{
		{`SET search_path = "PmNamesSales", public`, []string{"pg_catalog", "PmNamesSales", "public"}},
		{`SET search_path = PmNamesSales, public`, []string{"pg_catalog", "pmnamessales", "public"}},
		{`SET search_path = "pmnamessales", "PmNamesSales"`, []string{"pg_catalog", "pmnamessales", "PmNamesSales"}},
		{`SET search_path = "PmNamesSales", PG_CATALOG`, []string{"PmNamesSales", "pg_catalog"}},
	} {
		if _, err := conn.Exec(ctx, tc.set); err != nil {
			t.Fatalf("%s: %v", tc.set, err)
		}
		if _, err := conn.Exec(ctx, "SELECT 1"); err != nil {
			t.Fatalf("SELECT after %s: %v", tc.set, err)
		}
		requests := h.fake.requests()
		last := requests[len(requests)-1]
		if !strings.HasPrefix(last.GetSql(), "SELECT") || !reflect.DeepEqual(last.GetSearchPath(), tc.want) {
			t.Errorf("after %s: %q SearchPath = %v, want %v", tc.set, last.GetSql(), last.GetSearchPath(), tc.want)
		}
	}
}
