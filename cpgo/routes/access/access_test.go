package access_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
)

func TestAccessLists(t *testing.T) {
	e := routetest.Setup(t)
	ctx := context.Background()
	var roleID, mine, theirs int64
	if err := e.St.Pool.QueryRow(ctx, `INSERT INTO app_role (name) VALUES ('zz-jit') RETURNING id`).Scan(&roleID); err != nil {
		t.Fatal(err)
	}
	for _, q := range []struct {
		principal, status string
		id                *int64
	}{{"alice@example.com", "PENDING", &mine}, {"bob@example.com", "APPROVED", &theirs}} {
		if err := e.St.Pool.QueryRow(ctx, `INSERT INTO access_request (principal, role_id, requested_duration_sec, status, creator_kind)
			VALUES ($1, $2, 3600, $3, 'WORKFLOW') RETURNING id`, q.principal, roleID, q.status).Scan(q.id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.St.Pool.Exec(ctx, `INSERT INTO access_grant (principal, role_id, granted_by, expires_at) VALUES
		('alice@example.com', $1, 'admin', now() + interval '1 hour'),
		('alice@example.com', $1, 'admin', now() - interval '1 hour'),
		('bob@example.com', $1, 'admin', NULL)`, roleID); err != nil {
		t.Fatal(err)
	}
	alice := e.St.WebSession(t, "alice@example.com", "k-a", "dev-a")
	// Stand-in for the shipped self-request / self-grant permits: a principal reads their own rows.
	e.Authz.Allow = map[string]bool{
		"alice@example.com task.read ApprovalRequest:alice@example.com": true,
		"alice@example.com task.read AccessGrant:alice@example.com":     true,
	}

	status, body := e.Do(t, http.MethodGet, "/api/access-requests", "", alice)
	want := fmt.Sprintf(`[{"id":%d,"principal":"alice@example.com","roleId":%d,"roleName":"zz-jit","requestedDurationSec":3600,"status":"PENDING",`, mine, roleID)
	if status != http.StatusOK || !strings.HasPrefix(body, want) || strings.Contains(body, "bob@example.com") ||
		!strings.Contains(body, `"kind":"ROLE","statementCount":0,`) || !strings.Contains(body, `"executeAs":[]`) {
		t.Fatalf("requests: %d %s", status, body)
	}
	if e.Authz.Asked[len(e.Authz.Asked)-1] != "alice@example.com task.read ApprovalRequest:alice@example.com @" {
		t.Fatalf("request listings decide without a requester IP: %v", e.Authz.Asked)
	}
	last := e.Authz.Resources[len(e.Authz.Resources)-1]
	if last.Approver != nil || last.ExecutedBy != nil || last.DatasourceName != nil || last.RoleName == nil || *last.RoleName != "zz-jit" {
		t.Fatalf("request resource %+v", last)
	}
	if _, body = e.Do(t, http.MethodGet, "/api/access-requests?status=APPROVED", "", alice); body != "[]" {
		t.Fatalf("status filter: %s", body)
	}

	e.Authz.Resources = nil
	if _, body = e.Do(t, http.MethodGet, "/api/access-grants", "", alice); strings.Count(body, `"id"`) != 2 || strings.Contains(body, "bob@example.com") ||
		!strings.Contains(body, `"roleName":"zz-jit","grantedBy":"admin","grantedAt":"`) {
		t.Fatalf("grants: %s", body)
	}
	for _, r := range e.Authz.Resources {
		if r.Type != "AccessGrant" || r.ID == 0 || r.RoleName == nil || *r.RoleName != "zz-jit" || r.DatasourceName != nil {
			t.Fatalf("grant resource %+v", r)
		}
	}
	if _, body = e.Do(t, http.MethodGet, "/api/access-grants?active=TRUE", "", alice); strings.Count(body, `"id"`) != 1 {
		t.Fatalf("active grants: %s", body)
	}
	if _, body = e.Do(t, http.MethodGet, "/api/access-grants?principal=bob@example.com", "", alice); body != "[]" {
		t.Fatalf("naming another principal must not widen the listing: %s", body)
	}
}
