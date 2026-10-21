package me_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
)

func TestLocale(t *testing.T) {
	e := routetest.Setup(t)
	ctx := context.Background()
	if _, err := e.St.Pool.Exec(ctx, `INSERT INTO app_user (principal) VALUES ('alice@example.com')`); err != nil {
		t.Fatal(err)
	}
	c := e.St.WebSession(t, "alice@example.com", "k1", "dev-1")

	if status, _ := e.Do(t, http.MethodPut, "/api/me/locale", `{"locale":" KO "}`, c); status != http.StatusNoContent {
		t.Fatalf("status %d", status)
	}
	var locale string
	_ = e.St.Pool.QueryRow(ctx, `SELECT locale FROM app_user WHERE principal = 'alice@example.com'`).Scan(&locale)
	if locale != "ko" {
		t.Fatalf("locale %q", locale)
	}
	for _, body := range []string{`{"locale":"fr"}`, `not json`} {
		status, resp := e.Do(t, http.MethodPut, "/api/me/locale", body, c)
		if status != http.StatusBadRequest || resp != `{"code":"common.invalid_value","params":{"field":"locale"}}` {
			t.Fatalf("%s: %d %s", body, status, resp)
		}
	}
}

func TestQueryHistory(t *testing.T) {
	e := routetest.Setup(t)
	ctx := context.Background()
	c := e.St.WebSession(t, "alice@example.com", "k1", "dev-1")
	for _, row := range []struct {
		principal, sql string
		ds             any
		ago            string
	}{
		{"alice@example.com", "SELECT 1", int64(7), "3 minutes"},
		{"alice@example.com", "SELECT 2", nil, "2 minutes"},
		{"alice@example.com", "SELECT 1", int64(8), "1 minute"},
		{"bob@example.com", "SELECT secret", nil, "1 minute"},
	} {
		if _, err := e.St.Pool.Exec(ctx, `INSERT INTO query_history (principal, datasource_id, sql, created_at)
			VALUES ($1, $2, $3, now() - $4::interval)`, row.principal, row.ds, row.sql, row.ago); err != nil {
			t.Fatal(err)
		}
	}

	status, body := e.Do(t, http.MethodGet, "/api/query-history", "", c)
	if status != http.StatusOK {
		t.Fatalf("status %d %s", status, body)
	}
	var got []map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0]["sql"] != "SELECT 1" || got[0]["datasourceId"] != float64(8) || got[1]["sql"] != "SELECT 2" {
		t.Fatalf("history %s", body)
	}
	if _, present := got[1]["datasourceId"]; present {
		t.Fatalf("null datasourceId must be omitted: %s", body)
	}
	if _, err := time.Parse(time.RFC3339Nano, got[0]["ranAt"].(string)); err != nil {
		t.Fatalf("ranAt %v", got[0]["ranAt"])
	}

	if _, body := e.Do(t, http.MethodGet, "/api/query-history?limit=1", "", c); strings.Count(body, `"sql"`) != 1 {
		t.Fatalf("limit=1: %s", body)
	}

	if status, _ := e.Do(t, http.MethodDelete, "/api/query-history", "", c); status != http.StatusNoContent {
		t.Fatalf("delete status %d", status)
	}
	var left int
	_ = e.St.Pool.QueryRow(ctx, `SELECT count(*) FROM query_history`).Scan(&left)
	if left != 1 {
		t.Fatalf("%d rows left, want only bob's", left)
	}
}
