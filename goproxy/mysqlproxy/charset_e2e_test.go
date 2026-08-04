package mysqlproxy_test

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

// TestResultsCharsetPinAppliedFromControlPlane proves the wire path applies a control-plane rewrite on a
// session passthrough: when the CP pins `SET character_set_results = NULL` to utf8mb4 (its rewritten_sql),
// the proxy relays the pinned statement to the backend, so the SET succeeds and a following masked read
// still returns the mask. Authorization and audit still see the client's original statement. (The
// recognition — that the real analyzer emits this pin — is covered by the analyzer and control-plane tests.)
func TestResultsCharsetPinAppliedFromControlPlane(t *testing.T) {
	const setNULL = "SET character_set_results = NULL"
	const pinned = "SET character_set_results = utf8mb4"
	const maskedRead = "SELECT id, name, ssn FROM people ORDER BY id"

	h := startBroker(t)
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		switch req.GetSql() {
		case setNULL:
			// The control plane pins the results charset via rewritten_sql on the session passthrough.
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, RewrittenSql: proto.String(pinned)}), nil
		case maskedRead:
			return wireVerdict(&pb.Verdict{
				Decision: pb.EnfAction_MASK,
				Masks:    []*pb.ColumnMask{{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(2)}},
			}), nil
		default:
			return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
		}
	}
	client := openRawClient(t, h.addr, validToken)

	// The pinned SET reaches the backend as utf8mb4, so it succeeds instead of tripping the charset invariant.
	response := client.firstQueryPacket(t, setNULL)
	if len(response) == 0 || response[0] != 0x00 {
		t.Fatalf("SET character_set_results = NULL response = %x, want OK (pinned to utf8mb4)", response)
	}
	// Masking still works: had the original NULL reached the backend, the invariant would have closed the
	// session and this read would fail; instead ssn is masked and the NULL row is preserved.
	rows := client.textRows(t, maskedRead, 3)
	if len(rows) != 2 {
		t.Fatalf("masked read rows = %d, want 2", len(rows))
	}
	if rows[0][2] == nil || *rows[0][2] != "####" {
		t.Fatalf("row 0 ssn = %v, want masked \"####\"", rows[0][2])
	}
	if rows[1][2] != nil {
		t.Fatalf("row 1 ssn = %v, want NULL preserved", rows[1][2])
	}

	// Authorization and audit saw the client's original statement, not the pin.
	var sawOriginal bool
	for _, req := range h.fake.requests() {
		if req.GetSql() == setNULL {
			sawOriginal = true
		}
	}
	if !sawOriginal {
		t.Fatalf("no Decide request carried the original %q", setNULL)
	}
}

// TestResultsCharsetNonNullStillFailsClosed proves the wire session charset invariant is the fail-closed
// backstop: an explicit non-UTF-8 results charset the control plane does not pin still trips the invariant
// and closes the session.
func TestResultsCharsetNonNullStillFailsClosed(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = allowAllDecide
	client := openRawClient(t, h.addr, validToken)

	response := client.firstQueryPacket(t, "SET character_set_results = latin1")
	if len(response) == 0 || response[0] != 0xff {
		t.Fatalf("SET character_set_results = latin1 response = %x, want fail-closed ERR", response)
	}
	if got := mysqlwire.ErrString(response); !strings.Contains(got, "utf8mb4/utf8") {
		t.Fatalf("SET character_set_results = latin1 error = %q, want an unsafe-charset fail-closed", got)
	}
}
