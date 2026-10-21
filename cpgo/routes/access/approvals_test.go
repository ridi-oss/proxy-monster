package access_test

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
)

type approvalEnv struct {
	threadEnv
	mysql int64
}

func setupApprovals(t *testing.T) approvalEnv {
	e := approvalEnv{threadEnv: threadEnv{routetest.Setup(t), t}}
	e.mysql = e.id(`INSERT INTO datasource (name, engine, host, port, db_name, engine_version, mysql_lower_case_table_names)
		VALUES ('shop-mysql', 'mysql', 'h', 3306, 'shop', '8.0.36', 0) RETURNING id`)
	return e
}

// allow grants principal each action on requester's requests.
func (e approvalEnv) allow(principal string, actions ...string) {
	if e.Authz.Allow == nil {
		e.Authz.Allow = map[string]bool{}
	}
	for _, a := range actions {
		e.Authz.Allow[principal+" "+a+" ApprovalRequest:"+requester] = true
	}
}

func (e approvalEnv) audit() []string {
	e.t.Helper()
	rows, err := e.St.Pool.Query(context.Background(), `SELECT kind || ' ' || coalesce(action, '') || ' ' || statement FROM audit_event
		WHERE kind IN ('admin', 'approval_lifecycle') ORDER BY id`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		out = append(out, s)
	}
	return out
}

func TestDecideApproval(t *testing.T) {
	e := setupApprovals(t)
	bob := e.St.WebSession(t, approver, "k-bob", "dev-2")
	e.allow(approver, "task.approve")
	id := e.queryRequest(requester, "PENDING", "WORKFLOW", "console", e.mysql, nil)
	path := fmt.Sprintf("/api/approvals/%d", id)

	if body := e.do(http.MethodPost, path+"/approve", `{"revision":2}`, bob, http.StatusConflict); body != `{"code":"approval.request_changed","params":{}}` {
		t.Fatalf("stale revision: %s", body)
	}
	if body := e.do(http.MethodPost, path+"/approve", `{"revision":1}`, bob, http.StatusOK); !strings.Contains(body, `"status":"APPROVED","decidedBy":"bob@example.com"`) {
		t.Fatalf("approve: %s", body)
	}
	if body := e.do(http.MethodPost, path+"/approve", `{"revision":1}`, bob, http.StatusConflict); body != `{"code":"approval.already_decided","params":{}}` {
		t.Fatalf("approve twice: %s", body)
	}
	if body := e.do(http.MethodPost, path+"/unapprove", "", bob, http.StatusOK); !strings.Contains(body, `"status":"PENDING"`) || strings.Contains(body, "decidedBy") {
		t.Fatalf("unapprove: %s", body)
	}
	if body := e.do(http.MethodPost, path+"/unapprove", "", bob, http.StatusConflict); body != `{"code":"approval.not_approved","params":{}}` {
		t.Fatalf("unapprove a pending request: %s", body)
	}
	e.do(http.MethodPost, path+"/approve", `{"revision":1}`, bob, http.StatusOK)
	if body := e.do(http.MethodPost, path+"/reject", `{"reason":" no "}`, bob, http.StatusOK); !strings.Contains(body, `"status":"REJECTED"`) || !strings.Contains(body, `"rejectionReason":"no"`) {
		t.Fatalf("reject an approved request: %s", body)
	}
	if got, want := e.kinds(id), []string{"approved:bob@example.com:", "unapproved:bob@example.com:", "approved:bob@example.com:", "rejected:bob@example.com:no"}; !slices.Equal(got, want) {
		t.Fatalf("timeline %v, want %v", got, want)
	}
	if got, want := e.Authz.Notified, []string{fmt.Sprintf("%d:decided", id), fmt.Sprintf("%d:reopened", id), fmt.Sprintf("%d:decided", id), fmt.Sprintf("%d:decided", id)}; !slices.Equal(got, want) {
		t.Fatalf("notified %v, want %v", got, want)
	}
	if got := e.audit(); len(got) != 4 || got[1] != fmt.Sprintf("admin task.approve withdraw the approval of query request #%d (unapproved by bob@example.com)", id) ||
		got[3] != fmt.Sprintf("admin task.approve reject query request #%d revision 1", id) {
		t.Fatalf("audit: %v", got)
	}
	for _, s := range e.Authz.Scopes {
		if s.Channel != "workflow-viewer" || s.Datasource == nil || *s.Datasource != "shop-mysql" {
			t.Fatalf("decided outside the workflow viewer: %+v", s)
		}
	}

	alice := e.St.WebSession(t, requester, "k-alice", "dev-1")
	if body := e.do(http.MethodPost, path+"/reject", `{"reason":"self"}`, alice, http.StatusConflict); body != `{"code":"approval.already_decided","params":{}}` {
		t.Fatalf("reject a rejected request: %s", body)
	}
	other := e.queryRequest(requester, "PENDING", "WORKFLOW", "console", e.mysql, nil)
	if body := e.do(http.MethodPost, fmt.Sprintf("/api/approvals/%d/approve", other), `{"revision":1}`, alice, http.StatusForbidden); body != `{"code":"approval.not_approver","params":{}}` {
		t.Fatalf("self-approve: %s", body)
	}
}

func TestApprovalDetailAndInbox(t *testing.T) {
	e := setupApprovals(t)
	bob := e.St.WebSession(t, approver, "k-bob", "dev-2")
	id := e.queryRequest(requester, "PENDING", "WORKFLOW", "console", e.mysql, nil)
	e.queryRequest(requester, "PENDING", "EDITOR", "console", e.mysql, nil)
	e.Exec(t, `UPDATE query_result SET row_count = 3, columns = '["email"]' WHERE task_id = $1`, id)
	notFound := `{"code":"common.not_found","params":{"resource":"query approval request"}}`
	if body := e.do(http.MethodGet, fmt.Sprintf("/api/approvals/%d", id), "", bob, http.StatusNotFound); body != notFound {
		t.Fatalf("no task.read: %s", body)
	}
	if body := e.do(http.MethodGet, "/api/approvals/inbox", "", bob, http.StatusOK); body != "[]" {
		t.Fatalf("inbox without task.approve: %s", body)
	}

	e.allow(approver, "task.read", "task.approve")
	body := e.do(http.MethodGet, fmt.Sprintf("/api/approvals/%d", id), "", bob, http.StatusOK)
	for _, want := range []string{`"canDecide":true,"canApproveAndRun":false,"canReject":true,"canUnapprove":false,"canClose":false`,
		`"result":{"taskId":` + fmt.Sprint(id) + `,"ordinal":0,"sql":"select email from users","executedAt":`, `"columns":[]}`} {
		if !strings.Contains(body, want) {
			t.Fatalf("detail without task.assume lacks %s:\n%s", want, body)
		}
	}
	e.allow(approver, "task.assume", "task.run")
	body = e.do(http.MethodGet, fmt.Sprintf("/api/approvals/%d", id), "", bob, http.StatusOK)
	if !strings.Contains(body, `"rowCount":3`) || !strings.Contains(body, `"columns":["email"]`) || !strings.Contains(body, `"canApproveAndRun":true`) {
		t.Fatalf("detail with task.assume: %s", body)
	}
	if body := e.do(http.MethodGet, "/api/approvals/inbox", "", bob, http.StatusOK); !strings.HasPrefix(body, fmt.Sprintf(`[{"id":%d,`, id)) || strings.Count(body, `"id":`) != 1 {
		t.Fatalf("inbox: %s", body)
	}
}
