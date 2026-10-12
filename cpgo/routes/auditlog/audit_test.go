package auditlog_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
)

func TestAudit(t *testing.T) {
	e := routetest.Setup(t)
	ctx := context.Background()
	ids := map[string]int64{}
	for i, row := range []struct{ principal, statement string }{
		{"alice@example.com", "select a1"},
		{"bob@example.com", "select b1"},
		{"alice@example.com", "select a2"},
	} {
		id := int64(100 + i)
		ids[row.statement] = id
		if _, err := e.St.Pool.Exec(ctx, `INSERT INTO audit_event (id, ts, principal, datasource, statement, decision)
			VALUES ($1, now() - make_interval(mins => $2), $3, 'acme', $4, 'ALLOW')`, id, 10-i, row.principal, row.statement); err != nil {
			t.Fatal(err)
		}
	}
	alice := e.St.WebSession(t, "alice@example.com", "k-a", "dev-a")
	auditor := e.St.WebSession(t, "auditor@example.com", "k-x", "dev-x")
	e.Authz.Allow = map[string]bool{
		"auditor@example.com audit.read AuditLog:":                   true,
		"auditor@example.com audit.read AuditRecord:bob@example.com": true,
		"alice@example.com audit.read AuditRecord:alice@example.com": true,
	}

	statements := func(body string) []string {
		var got []struct{ Statement string }
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatalf("%v: %s", err, body)
		}
		out := []string{}
		for _, g := range got {
			out = append(out, g.Statement)
		}
		return out
	}

	_, body := e.Do(t, http.MethodGet, "/api/audit", "", alice)
	if got := statements(body); strings.Join(got, ",") != "select a2,select a1" {
		t.Fatalf("alice sees %v", got)
	}
	_, body = e.Do(t, http.MethodGet, "/api/audit?limit=2", "", auditor)
	if got := statements(body); strings.Join(got, ",") != "select a2,select b1" {
		t.Fatalf("auditor sees %v", got)
	}

	status, body := e.Do(t, http.MethodGet, "/api/audit/"+strconv.FormatInt(ids["select a1"], 10), "", alice)
	if status != http.StatusOK || !strings.Contains(body, `"statement":"select a1"`) || !strings.Contains(body, `"roles":[]`) || strings.Contains(body, "clientAddr") {
		t.Fatalf("own record: %d %s", status, body)
	}
	hiddenStatus, hidden := e.Do(t, http.MethodGet, "/api/audit/"+strconv.FormatInt(ids["select b1"], 10), "", alice)
	e.Authz.Asked = nil
	missingStatus, missing := e.Do(t, http.MethodGet, "/api/audit/999999", "", alice)
	if hiddenStatus != http.StatusNotFound || missingStatus != http.StatusNotFound || hidden != missing ||
		missing != `{"code":"common.not_found","params":{"resource":"audit record"}}` {
		t.Fatalf("hidden %d %s / missing %d %s", hiddenStatus, hidden, missingStatus, missing)
	}
	if len(e.Authz.Asked) != 0 {
		t.Fatalf("a missing record must not reach Cedar: %v", e.Authz.Asked)
	}
	if status, body := e.Do(t, http.MethodGet, "/api/audit/not-a-number", "", alice); status != http.StatusBadRequest ||
		body != `{"code":"common.bad_id","params":{}}` {
		t.Fatalf("bad id: %d %s", status, body)
	}
}

func TestAuditDecisionCarriesRequesterIP(t *testing.T) {
	e := routetest.Setup(t)
	alice := e.St.WebSession(t, "alice@example.com", "k-a", "dev-a")
	e.Do(t, http.MethodGet, "/api/audit", "", alice)
	if len(e.Authz.Asked) != 1 || e.Authz.Asked[0] != "alice@example.com audit.read AuditLog: @127.0.0.1" {
		t.Fatalf("asked %v", e.Authz.Asked)
	}

	e.Authz.Asked = nil
	if _, err := e.St.Pool.Exec(context.Background(), `UPDATE principal_session SET debug_requester_ip = '203.0.113.9' WHERE session_key = 'k-a'`); err != nil {
		t.Fatal(err)
	}
	e.Do(t, http.MethodGet, "/api/audit", "", alice)
	if len(e.Authz.Asked) != 1 || !strings.HasSuffix(e.Authz.Asked[0], "@203.0.113.9") {
		t.Fatalf("under auth debug the session's chosen address wins: %v", e.Authz.Asked)
	}
}
