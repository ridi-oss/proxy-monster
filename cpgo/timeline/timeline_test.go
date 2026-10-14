package timeline

import (
	"context"
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/dbtest"
)

func TestRecord(t *testing.T) {
	st := dbtest.Open(t)
	ctx := context.Background()
	insert := func(creator string) int64 {
		var id int64
		if err := st.Pool.QueryRow(ctx, `INSERT INTO access_request (principal, kind, requested_duration_sec, creator_kind)
			VALUES ('alice', 'RATE_RESET', 0, $1) RETURNING id`, creator).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	str := func(s string) *string { return &s }
	workflow, editor := insert("WORKFLOW"), insert("EDITOR")
	for _, ev := range []struct {
		id    int64
		kind  string
		actor *string
	}{
		{workflow, Requested, str("alice")},
		{workflow, Approved, str("system:auto-reviewer")},
		{workflow, Rejected, str("alice")},
		{workflow, Approved, str("bob")},
		{editor, Approved, str("bob")},
	} {
		if err := Record(ctx, st.Pool, ev.id, ev.kind, ev.actor, "console", nil); err != nil {
			t.Fatal(err)
		}
	}
	var events, editorEvents int
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM request_event WHERE request_id = $1`, workflow).Scan(&events)
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM request_event WHERE request_id = $1`, editor).Scan(&editorEvents)
	if events != 4 || editorEvents != 0 {
		t.Fatalf("events %d on the workflow request, %d on the editor task; want 4 and 0", events, editorEvents)
	}
	var approvers []string
	rows, err := st.Pool.Query(ctx, `SELECT principal FROM request_participant WHERE request_id = $1 AND kind = 'approver'`, workflow)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var p string
		_ = rows.Scan(&p)
		approvers = append(approvers, p)
	}
	if len(approvers) != 1 || approvers[0] != "bob" {
		t.Fatalf("approvers %v: a system: actor and the requester are never listed", approvers)
	}
}
