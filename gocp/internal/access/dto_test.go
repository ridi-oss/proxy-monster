package access

import (
	"encoding/json"
	"testing"
)

// The DTO half of the wire contract (06-query-decision.md §5), asserted as bytes: INV-A1-4's two
// rules — optional ⇒ ABSENT (never null), list ⇒ always an array — are discipline rather than a
// language feature, and one wrong tag is invisible until a console screen breaks.

func TestAccessRequestJSONContract(t *testing.T) {
	// The shape a ROLE request has right after creation: nothing decided, no child, no roles.
	got, err := json.Marshal(AccessRequest{
		ID: 1, Principal: "alice@example.com", RequestedDurationSec: 3600, Status: "PENDING",
		CreatedAt: "2026-08-01T03:04:05Z", Kind: DefaultKind,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"id":1,"principal":"alice@example.com","requestedDurationSec":3600,"status":"PENDING",` +
		`"createdAt":"2026-08-01T03:04:05Z","kind":"ROLE","executeAs":[]}`
	if string(got) != want {
		t.Errorf("fresh request =\n%s\nwant\n%s", got, want)
	}

	// A QUERY task carries the elevation role set and the child-derived columns.
	got, err = json.Marshal(AccessRequest{
		ID: 2, Principal: "alice@example.com", RoleID: ptrTo(int64(9)), RoleName: ptrTo("analyst"),
		DatasourceID: ptrTo(int64(3)), RequestedDurationSec: 3600, Status: "APPROVED",
		CreatedAt: "2026-08-01T03:04:05Z", Kind: "QUERY", SQL: ptrTo("select 1"),
		ExecuteAs: []string{"analyst"}, CreatorKind: ptrTo("WORKFLOW"),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want = `{"id":2,"principal":"alice@example.com","roleId":9,"roleName":"analyst","datasourceId":3,` +
		`"requestedDurationSec":3600,"status":"APPROVED","createdAt":"2026-08-01T03:04:05Z","kind":"QUERY",` +
		`"sql":"select 1","executeAs":["analyst"],"creatorKind":"WORKFLOW"}`
	if string(got) != want {
		t.Errorf("query task =\n%s\nwant\n%s", got, want)
	}
}

// `sql` is raw SQL, so HTML escaping would hit essentially every comparison predicate the product
// exists to inspect. AccessRequest.MarshalJSON encodes without it, matching kotlinx — the outer
// types.MarshalWire does the same, so the unescaped bytes survive to the response body.
func TestAccessRequestDoesNotHTMLEscapeSQL(t *testing.T) {
	got, err := AccessRequest{
		ID: 1, Principal: "a", RequestedDurationSec: 3600, Status: "PENDING",
		CreatedAt: "2026-08-01T03:04:05Z", Kind: "QUERY", SQL: ptrTo("select * from t where a < 5 and b > 3"),
	}.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if want := `"sql":"select * from t where a < 5 and b > 3"`; !contains(string(got), want) {
		t.Errorf("marshalled body escaped the SQL: %s", got)
	}
}

// AccessRequestInput's window default is 3600, not Go's zero — the column is the approver's ceiling on
// the ROLE path, and a silent 0 would mint a grant that expires immediately.
func TestAccessRequestInputDurationDefault(t *testing.T) {
	if got := (AccessRequestInput{RoleID: 1}).Duration(); got != DefaultRequestedDurationSec {
		t.Errorf("omitted duration = %d, want %d", got, DefaultRequestedDurationSec)
	}
	explicitZero := int64(0)
	if got := (AccessRequestInput{RoleID: 1, RequestedDurationSec: &explicitZero}).Duration(); got != 0 {
		t.Errorf("explicit 0 = %d, want 0 — a caller may still ask for it", got)
	}
	// The same rule on the query-approval path's input.
	if got := (CreateQueryRequestInput{}).duration(); got != DefaultRequestedDurationSec {
		t.Errorf("omitted query-task duration = %d, want %d", got, DefaultRequestedDurationSec)
	}
}

func ptrTo[T any](v T) *T { return &v }

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
