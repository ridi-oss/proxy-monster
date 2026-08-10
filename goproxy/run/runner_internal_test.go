package run

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// TestAbandonedDuringOpen pins the post-completion re-check directly: a completed target-DB open must be failed
// (not served) when a RunClose is queued, the stream has closed, or the drain is set — and served otherwise.
// The runner's integration tests can only observe the aborted OUTCOME, which the outer abort path produces
// too, so this is where the success-branch re-check itself is proven.
func TestAbandonedDuringOpen(t *testing.T) {
	closeMsg := &pb.ControlRunMsg{Kind: &pb.ControlRunMsg_Close{Close: &pb.RunClose{}}}
	queryMsg := &pb.ControlRunMsg{Kind: &pb.ControlRunMsg_Query{Query: &pb.RunQuery{Sql: "SELECT 1"}}}

	t.Run("a queued RunClose abandons the open", func(t *testing.T) {
		messages := make(chan *pb.ControlRunMsg, 1)
		messages <- closeMsg
		if !abandonedDuringOpen(messages, nil) {
			t.Fatal("a queued RunClose must abandon a completed open")
		}
	})

	t.Run("a closed stream abandons the open", func(t *testing.T) {
		messages := make(chan *pb.ControlRunMsg)
		close(messages)
		if !abandonedDuringOpen(messages, nil) {
			t.Fatal("a closed inbound stream must abandon a completed open")
		}
	})

	t.Run("a set drain abandons the open", func(t *testing.T) {
		draining := make(chan struct{})
		close(draining)
		if !abandonedDuringOpen(make(chan *pb.ControlRunMsg), draining) {
			t.Fatal("a set drain must abandon a completed open")
		}
	})

	t.Run("no signal serves the open", func(t *testing.T) {
		if abandonedDuringOpen(make(chan *pb.ControlRunMsg), make(chan struct{})) {
			t.Fatal("a completed open with no close/drain must be served")
		}
		if abandonedDuringOpen(make(chan *pb.ControlRunMsg), nil) {
			t.Fatal("a nil drain with no pending message must be served")
		}
	})

	t.Run("a pre-serving non-close message does not abandon the open", func(t *testing.T) {
		messages := make(chan *pb.ControlRunMsg, 1)
		messages <- queryMsg
		if abandonedDuringOpen(messages, nil) {
			t.Fatal("a pre-serving Query (protocol violation) must not be treated as an abandon")
		}
	})

	// A set drain must win even when a non-close message is also ready — otherwise a single select over both
	// would, by Go's fairness, sometimes pick the message arm and serve onto a departing proxy.
	t.Run("a set drain wins over a ready non-close message", func(t *testing.T) {
		draining := make(chan struct{})
		close(draining)
		messages := make(chan *pb.ControlRunMsg, 1)
		messages <- queryMsg
		for i := 0; i < 100; i++ {
			if !abandonedDuringOpen(messages, draining) {
				t.Fatal("a set drain must abandon the open even when a non-close message is queued")
			}
		}
	})
}
