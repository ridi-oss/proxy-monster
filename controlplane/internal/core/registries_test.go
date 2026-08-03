package core

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
)

func sptr(s string) *string { return &s }

// TestRequesterIPRegistryPutAndSetHaveDifferentNullSemantics pins INV-A7-33, which is the invariant a
// Go port is most likely to collapse into one method.
//
// 🔒 Put(hash, nil) is a NO-OP — it is the mint-time write and must not plant an absent-key sentinel.
// Set(hash, nil) REMOVES — it is the per-decision refresh, and a persistent session queried from a
// network whose requester_ip cannot be resolved must not inherit the (possibly trusted) open-time IP.
// The attribute goes absent ⇒ fail-closed, never stale.
func TestRequesterIPRegistryPutAndSetHaveDifferentNullSemantics(t *testing.T) {
	r := NewRequesterIPRegistry()

	// Put with a nil ip on an absent key: still absent.
	r.Put("hash-a", nil)
	if got := r.Get("hash-a"); got != nil {
		t.Errorf("Put(nil) on an absent key stored %q; it must be a no-op", *got)
	}

	// Put establishes the entry.
	r.Put("hash-a", sptr("10.0.0.1"))
	if got := r.Get("hash-a"); got == nil || *got != "10.0.0.1" {
		t.Fatalf("Get after Put = %v, want 10.0.0.1", got)
	}

	// Put with nil must NOT clear an existing entry — that is Set's job, not Put's.
	r.Put("hash-a", nil)
	if got := r.Get("hash-a"); got == nil || *got != "10.0.0.1" {
		t.Errorf("Put(nil) cleared the entry; only Set(nil) may remove")
	}

	// Set refreshes.
	r.Set("hash-a", sptr("10.0.0.2"))
	if got := r.Get("hash-a"); got == nil || *got != "10.0.0.2" {
		t.Fatalf("Get after Set = %v, want 10.0.0.2", got)
	}

	// 🔒 Set(nil) REMOVES, so the decision that follows sees the attribute ABSENT rather than stale.
	r.Set("hash-a", nil)
	if got := r.Get("hash-a"); got != nil {
		t.Errorf("Set(nil) left %q behind; a stale trusted IP must never survive an unresolvable one", *got)
	}
}

// TestRunSessionIsClaimableExactlyOnce pins INV-A7-32 / INV-A10-32.
//
// 🔒 Attach removes-then-completes atomically, so an unknown id and a duplicate claim are
// INDISTINGUISHABLE BY DESIGN — the RPC answers NOT_FOUND to both. A claimed-twice stream could
// otherwise share another request's token and query.
func TestRunSessionIsClaimableExactlyOnce(t *testing.T) {
	r := NewRunChannelRegistry()
	pending := &PendingRunSession{SessionID: "s1", Ready: make(chan *Attached, 1)}
	if !r.Register(pending) {
		t.Fatal("Register on an empty registry reported a duplicate")
	}
	if r.Register(&PendingRunSession{SessionID: "s1", Ready: make(chan *Attached, 1)}) {
		t.Error("a duplicate session id was accepted; Register is putIfAbsent")
	}

	first := r.Attach("s1", make(chan *pb.ControlRunMsg, 1))
	if first == nil {
		t.Fatal("the first claim failed")
	}
	select {
	case got := <-pending.Ready:
		if got != first {
			t.Error("Ready was completed with a different Attached than Attach returned")
		}
	default:
		t.Error("Attach did not complete the pending session's Ready channel")
	}

	if second := r.Attach("s1", make(chan *pb.ControlRunMsg, 1)); second != nil {
		t.Error("the SAME session was claimed twice")
	}
	if unknown := r.Attach("never-registered", make(chan *pb.ControlRunMsg, 1)); unknown != nil {
		t.Error("an unknown session id was claimable")
	}

	// Remove after a successful Attach is a no-op — which is what makes the RunExec handler's
	// unconditional cleanup safe on the failed-claim path (INV-A10-34).
	if r.Remove("s1") != nil {
		t.Error("Remove found a pending entry Attach should already have removed")
	}
}

// TestEventSubscriberSendAfterCloseDoesNotPanic pins A12 INV-A12-14 as it lands in Go.
//
// 🔒 A send on a CLOSED Go channel PANICS rather than failing, so the hub must never close a
// subscriber's message channel out from under a producer. Close() closes a separate `done` channel and
// every Send selects on it first.
func TestEventSubscriberSendAfterCloseDoesNotPanic(t *testing.T) {
	hub := NewProxyEventsHub()
	sub := NewEventSubscriber()
	hub.Register("ds", sub)
	if !hub.Attached("ds") {
		t.Fatal("Attached = false after Register")
	}

	if n := hub.Publish("ds", &pb.ControlEvent{Kind: &pb.ControlEvent_RefreshCatalog{RefreshCatalog: &pb.RefreshCatalog{}}}); n != 1 {
		t.Errorf("Publish delivered to %d subscribers, want 1", n)
	}

	hub.Deregister("ds", sub)
	if hub.Attached("ds") {
		t.Error("Attached = true after Deregister; the liveness view would carry a ghost")
	}
	// The assertion is that this does not panic AND reports the drop.
	if n := hub.Publish("ds", &pb.ControlEvent{}); n != 0 {
		t.Errorf("Publish to a deregistered datasource delivered %d, want 0", n)
	}
	if sub.Send(&pb.ControlEvent{}) {
		t.Error("Send on a closed subscriber reported success")
	}
}
