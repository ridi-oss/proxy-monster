package routes

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestIdentityWrites(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.st.WebSession(t, "admin@example.com", "k-admin", "dev-1")
	plain := e.st.WebSession(t, "plain@example.com", "k-plain", "dev-2")
	e.authz.allow = map[string]bool{"admin@example.com admin.identity System:": true}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := e.st.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := e.st.Pool.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	do := func(method, path, body string, c []*http.Cookie, wantStatus int) string {
		t.Helper()
		status, resp := e.do(t, method, path, body, c)
		if status != wantStatus {
			t.Fatalf("%s %s: %d %s, want %d", method, path, status, resp, wantStatus)
		}
		return resp
	}
	idOf := func(body string) int64 {
		t.Helper()
		var id int64
		if _, err := fmt.Sscanf(body, `{"id":%d`, &id); err != nil {
			t.Fatalf("no id in %s", body)
		}
		return id
	}
	// live counts what still lets principal in: unrevoked tokens and grants, open daemon and web sessions.
	live := func(principal string) int {
		t.Helper()
		return count(`SELECT (SELECT count(*) FROM proxy_token WHERE principal = $1 AND revoked_at IS NULL)
			+ (SELECT count(*) FROM access_grant WHERE principal = $1 AND revoked_at IS NULL)
			+ (SELECT count(*) FROM principal_session WHERE principal = $1 AND ((kind = 'WEB' AND ended_at IS NULL)
				OR (kind = 'DAEMON' AND absolute_expires_at > now())))`, principal)
	}
	credentials := func(principal string) {
		t.Helper()
		e.st.WebSession(t, principal, "k-"+principal, "dev-"+principal)
		exec(`INSERT INTO proxy_token (token_hash, principal, kind, expires_at) VALUES (md5($1), $1, 'USER', now() + interval '1 hour')`, principal)
		exec(`INSERT INTO access_grant (principal, role_id, granted_at, expires_at) SELECT $1, id, now(), now() + interval '1 hour' FROM app_role WHERE name = 'analyst'`, principal)
		exec(`INSERT INTO access_request (principal, kind, datasource_id, status, creator_kind) SELECT $1, 'QUERY', id, 'DRAFT', 'EDITOR' FROM datasource WHERE name = 'orders'`, principal)
		exec(`INSERT INTO principal_session (principal, handle, ttl_seconds, absolute_expires_at, liveness_status, renewal_token_hash, kind)
			VALUES ($1, md5($1 || 'h'), 3600, now() + interval '1 hour', 'ACTIVE', md5($1 || 'r'), 'DAEMON')`, principal)
		if n := live(principal); n != 4 {
			t.Fatalf("seeded %d live credentials for %s, want token, grant, web and daemon session", n, principal)
		}
	}
	exec(`INSERT INTO app_role (name) VALUES ('analyst')`)
	exec(`INSERT INTO datasource (name, host, port, db_name) VALUES ('orders', 'h', 1, 'd')`)

	do(http.MethodGet, "/api/users", "", plain, http.StatusForbidden)
	do(http.MethodPost, "/api/users", `{"principal":"x@example.com"}`, plain, http.StatusForbidden)
	if body := do(http.MethodPost, "/api/users", `{"principal":" "}`, admin, http.StatusBadRequest); body != `{"code":"common.field_required","params":{"fields":"principal"}}` {
		t.Fatalf("blank principal: %s", body)
	}
	created := do(http.MethodPost, "/api/users", `{"principal":"carol@example.com","displayName":"Carol"}`, admin, http.StatusCreated)
	carol := idOf(created)
	if !strings.HasPrefix(created, fmt.Sprintf(`{"id":%d,"principal":"carol@example.com","displayName":"Carol","source":"LOCAL","active":true,"createdAt":"`, carol)) || !strings.HasSuffix(created, `","groups":[]}`) {
		t.Fatalf("created %s", created)
	}
	if body := do(http.MethodPost, "/api/users", `{"principal":"carol@example.com"}`, admin, http.StatusBadRequest); body != `{"code":"common.already_exists","params":{"resource":"principal","name":"carol@example.com"}}` {
		t.Fatalf("duplicate: %s", body)
	}

	credentials("dave@example.com")
	do(http.MethodPost, "/api/users", `{"principal":"dave@example.com","active":false}`, admin, http.StatusCreated)
	if n := live("dave@example.com"); n != 0 {
		t.Fatalf("an inactive create left %d live credentials", n)
	}
	if n := count(`SELECT count(*) FROM access_request WHERE principal = 'dave@example.com'`); n != 0 {
		t.Fatalf("%d editor tasks survived", n)
	}

	credentials("carol@example.com")
	renamed := do(http.MethodPut, fmt.Sprintf("/api/users/%d", carol), `{"principal":"caroline@example.com"}`, admin, http.StatusOK)
	if !strings.Contains(renamed, `"principal":"caroline@example.com"`) || strings.Contains(renamed, `"displayName"`) {
		t.Fatalf("renamed %s", renamed)
	}
	if n := live("carol@example.com"); n != 0 {
		t.Fatalf("the retired principal kept %d live credentials", n)
	}
	if n := count(`SELECT count(*) FROM app_user WHERE principal = 'carol@example.com' AND source = 'SCIM' AND NOT active AND external_id IS NULL`); n != 1 {
		t.Fatalf("no tombstone for the retired principal")
	}
	created = do(http.MethodPost, "/api/users", `{"principal":"carol@example.com"}`, admin, http.StatusCreated)
	if n := count(`SELECT count(*) FROM app_user WHERE principal = 'carol@example.com'`); n != 1 || !strings.Contains(created, `"source":"LOCAL","active":true`) {
		t.Fatalf("re-creating a retired principal: %d rows, %s", n, created)
	}

	credentials("caroline@example.com")
	do(http.MethodDelete, fmt.Sprintf("/api/users/%d", carol), "", admin, http.StatusNoContent)
	do(http.MethodDelete, fmt.Sprintf("/api/users/%d", carol), "", admin, http.StatusNoContent)
	if n := live("caroline@example.com"); n != 0 || count(`SELECT count(*) FROM app_user WHERE id = $1 AND NOT active`, carol) != 1 {
		t.Fatalf("deprovision left %d live credentials", n)
	}
	credentials("erin@example.com")
	erin := idOf(do(http.MethodPost, "/api/users", `{"principal":"erin@example.com"}`, admin, http.StatusCreated))
	if n := live("erin@example.com"); n != 4 {
		t.Fatalf("an active create revoked credentials: %d live", n)
	}
	do(http.MethodPut, fmt.Sprintf("/api/users/%d", erin), `{"principal":"erin@example.com","active":false}`, admin, http.StatusOK)
	if n := live("erin@example.com"); n != 0 {
		t.Fatalf("deactivating kept %d live credentials", n)
	}
	credentials("frank@example.com")
	credentials("frances@example.com")
	frank := idOf(do(http.MethodPost, "/api/users", `{"principal":"frank@example.com"}`, admin, http.StatusCreated))
	do(http.MethodPut, fmt.Sprintf("/api/users/%d", frank), `{"principal":"frances@example.com","active":false}`, admin, http.StatusOK)
	if old, renamed := live("frank@example.com"), live("frances@example.com"); old != 0 || renamed != 0 {
		t.Fatalf("rename and deactivate kept %d old and %d new live credentials", old, renamed)
	}
	exec(`INSERT INTO principal_role (principal, role_id) SELECT 'frank@example.com', id FROM app_role WHERE name = 'analyst'`)
	do(http.MethodPost, "/api/users", `{"principal":"frank@example.com"}`, admin, http.StatusCreated)
	if n := count(`SELECT count(*) FROM principal_role WHERE principal = 'frank@example.com'`); n != 0 {
		t.Fatalf("reusing a retired principal kept %d of its role assignments", n)
	}
	do(http.MethodDelete, "/api/users/999999", "", admin, http.StatusNotFound)
	do(http.MethodPut, "/api/users/abc", `{"principal":"x"}`, admin, http.StatusBadRequest)
	if got := strings.Join(e.sessionsEnded, ","); got != "dave@example.com,carol@example.com,caroline@example.com,caroline@example.com,erin@example.com,frank@example.com,frances@example.com" {
		t.Fatalf("sessions ended %s", got)
	}

	group := do(http.MethodPost, "/api/groups", `{"name":"ops","description":"on call"}`, admin, http.StatusCreated)
	ops := idOf(group)
	if group != fmt.Sprintf(`{"id":%d,"name":"ops","description":"on call","source":"LOCAL","memberCount":0,"roles":[]}`, ops) {
		t.Fatalf("group %s", group)
	}
	do(http.MethodPost, "/api/groups", `{"name":"ops"}`, admin, http.StatusBadRequest)
	var system int64
	_ = e.st.Pool.QueryRow(ctx, `SELECT id FROM app_group WHERE source = 'SYSTEM' LIMIT 1`).Scan(&system)
	if body := do(http.MethodPut, fmt.Sprintf("/api/groups/%d", system), `{"name":"x"}`, admin, http.StatusConflict); body != `{"code":"group.system_immutable","params":{}}` {
		t.Fatalf("system group: %s", body)
	}
	do(http.MethodPost, fmt.Sprintf("/api/groups/%d/roles", system), `{"roleId":1}`, admin, http.StatusConflict)
	do(http.MethodPut, fmt.Sprintf("/api/groups/%d", ops), `{"name":"ops-2"}`, admin, http.StatusOK)

	var analyst int64
	_ = e.st.Pool.QueryRow(ctx, `SELECT id FROM app_role WHERE name = 'analyst'`).Scan(&analyst)
	member := do(http.MethodPost, fmt.Sprintf("/api/groups/%d/members", ops), fmt.Sprintf(`{"userId":%d}`, carol), admin, http.StatusCreated)
	if member != fmt.Sprintf(`{"userId":%d,"principal":"caroline@example.com"}`, carol) {
		t.Fatalf("member %s", member)
	}
	do(http.MethodPost, fmt.Sprintf("/api/groups/%d/members", ops), fmt.Sprintf(`{"userId":%d}`, carol), admin, http.StatusCreated)
	do(http.MethodPost, fmt.Sprintf("/api/groups/%d/members", ops), `{"userId":999999}`, admin, http.StatusNotFound)
	if role := do(http.MethodPost, fmt.Sprintf("/api/groups/%d/roles", ops), fmt.Sprintf(`{"roleId":%d}`, analyst), admin, http.StatusCreated); role != fmt.Sprintf(`{"roleId":%d,"roleName":"analyst"}`, analyst) {
		t.Fatalf("group role %s", role)
	}
	if got := do(http.MethodGet, "/api/groups", "", admin, http.StatusOK); !strings.Contains(got, fmt.Sprintf(`{"id":%d,"name":"ops-2","source":"LOCAL","memberCount":1,"roles":[{"id":%d,"name":"analyst"}]}`, ops, analyst)) {
		t.Fatalf("groups %s", got)
	}
	if got := do(http.MethodGet, "/api/users", "", admin, http.StatusOK); !strings.Contains(got, fmt.Sprintf(`"principal":"caroline@example.com","source":"LOCAL","active":false,`)) || !strings.Contains(got, fmt.Sprintf(`"groups":[{"id":%d,"name":"ops-2"}]`, ops)) {
		t.Fatalf("users %s", got)
	}
	if got := do(http.MethodGet, fmt.Sprintf("/api/groups/%d/members", ops), "", admin, http.StatusOK); got != "["+member+"]" {
		t.Fatalf("members %s", got)
	}
	do(http.MethodGet, "/api/groups/999999/roles", "", admin, http.StatusNotFound)
	do(http.MethodDelete, fmt.Sprintf("/api/groups/%d/roles/%d", ops, analyst), "", admin, http.StatusNoContent)
	if body := do(http.MethodDelete, fmt.Sprintf("/api/groups/%d/roles/%d", ops, analyst), "", admin, http.StatusNotFound); body != `{"code":"common.not_found","params":{"resource":"group role mapping"}}` {
		t.Fatalf("missing mapping: %s", body)
	}
	do(http.MethodDelete, fmt.Sprintf("/api/groups/%d/members/%d", ops, carol), "", admin, http.StatusNoContent)
	if body := do(http.MethodDelete, fmt.Sprintf("/api/groups/%d/members/%d", ops, carol), "", admin, http.StatusNotFound); body != `{"code":"common.not_found","params":{"resource":"group member"}}` {
		t.Fatalf("missing member: %s", body)
	}
	do(http.MethodDelete, fmt.Sprintf("/api/groups/%d", ops), "", admin, http.StatusNoContent)
	do(http.MethodDelete, fmt.Sprintf("/api/groups/%d", ops), "", admin, http.StatusNotFound)

	a := func(resource, summary string) string {
		return "admin|admin@example.com|admin.identity|" + resource + "|" + summary + "|127.0.0.1|console"
	}
	want := []string{
		a(`User::"carol@example.com"`, "create user 'carol@example.com'"),
		a(`User::"dave@example.com"`, "create user 'dave@example.com'"),
		a(`User::"caroline@example.com"`, "update user 'carol@example.com' -> 'caroline@example.com'"),
		a(`User::"carol@example.com"`, "create user 'carol@example.com'"),
		a(`User::"caroline@example.com"`, "deprovision user 'caroline@example.com'"),
		a(`User::"caroline@example.com"`, "deprovision user 'caroline@example.com'"),
		a(`User::"erin@example.com"`, "create user 'erin@example.com'"),
		a(`User::"erin@example.com"`, "update user 'erin@example.com'"),
		a(`User::"frank@example.com"`, "create user 'frank@example.com'"),
		a(`User::"frances@example.com"`, "update user 'frank@example.com' -> 'frances@example.com'"),
		a(`User::"frank@example.com"`, "create user 'frank@example.com'"),
		a(`Group::"ops"`, "create group 'ops'"),
		a(`Group::"ops-2"`, "update group 'ops' -> 'ops-2'"),
		a(`Group::"ops-2"`, "add 'caroline@example.com' to group 'ops-2'"),
		a(`Group::"ops-2"`, "add role 'analyst' to group 'ops-2'"),
		a(`Group::"ops-2"`, "remove role 'analyst' from group 'ops-2'"),
		a(`Group::"ops-2"`, "remove 'caroline@example.com' from group 'ops-2'"),
		a(`Group::"ops-2"`, "delete group 'ops-2'"),
	}
	if got := auditRows(t, e); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("audit rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	verifyChain(t, e)
}
