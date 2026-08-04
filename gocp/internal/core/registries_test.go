package core

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
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
	if !hub.AttachedTo("ds") {
		t.Fatal("Attached = false after Register")
	}

	if n := hub.Publish("ds", &pb.ControlEvent{Kind: &pb.ControlEvent_RefreshCatalog{RefreshCatalog: &pb.RefreshCatalog{}}}); n != 1 {
		t.Errorf("Publish delivered to %d subscribers, want 1", n)
	}

	hub.Deregister("ds", sub)
	if hub.AttachedTo("ds") {
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

// TestRequestOpenRunDistinguishesNotAttachedFromWedged is the PRODUCER SIDE of 🔒 INV-A7-34, and it is
// where that invariant is actually decided: A7 turns DispatchNotAttached into ErrNoProxyAttached and
// DispatchWedged into ErrProxyStreamWedged, so if this function collapses the two the routes have nothing
// left to distinguish and both conditions answer the same 503 code.
//
// The operator answer differs, which is the whole reason to keep them apart: NOT_ATTACHED means no proxy
// is there and someone should go find out why; WEDGED means one IS registered and its stream will not
// take an event, so the fix is to wait for the proxy's own reconnect — the wedged stream has already been
// dropped here to make room for it.
func TestRequestOpenRunDistinguishesNotAttachedFromWedged(t *testing.T) {
	// KT: ProxyEventsHubTest.kt#a datasource with no stream is not attached
	t.Run("no subscriber at all is NOT_ATTACHED", func(t *testing.T) {
		h := NewProxyEventsHub()
		h.SetLogForTest(nil)
		if got := h.RequestOpenRun("ds", "s1", "tok", make([]byte, 16), nil); got != DispatchNotAttached {
			t.Errorf("RequestOpenRun with no subscriber = %s, want NOT_ATTACHED", got)
		}
	})

	// KT: ProxyEventsHubTest.kt#an open stream takes the event — the Kotlin only asserts the channel is non-empty; this also pins the OpenRunChannel payload
	t.Run("a draining subscriber is SENT and gets the event", func(t *testing.T) {
		h := NewProxyEventsHub()
		h.SetLogForTest(nil)
		sub := NewEventSubscriber()
		h.Register("ds", sub)

		refetch := []*pb.Refetch{{Schema: "public"}}
		if got := h.RequestOpenRun("ds", "s1", "tok-abc", []byte("0123456789abcdef"), refetch); got != DispatchSent {
			t.Fatalf("RequestOpenRun = %s, want SENT", got)
		}
		ev := <-sub.C()
		open := ev.GetOpenRunChannel()
		if open == nil {
			t.Fatalf("the event is %T, want an OpenRunChannel", ev.GetKind())
		}
		if open.GetSessionId() != "s1" || open.GetEphemeralToken() != "tok-abc" {
			t.Errorf("OpenRunChannel = %+v, want the session id and token verbatim", open)
		}
		if string(open.GetConnectionId()) != "0123456789abcdef" {
			t.Errorf("connection_id = %q", open.GetConnectionId())
		}
		// 🔒 The on-open Refetch list is wrapped in ProxyCommands, in order — it is the connection's
		// opening catalog handshake, and the proxy satisfies it before reporting ready.
		if cmds := open.GetOnOpen(); len(cmds) != 1 || cmds[0].GetRefetch().GetSchema() != "public" {
			t.Errorf("on_open = %+v, want one Refetch for public", cmds)
		}
	})

	// A full buffer is the Go shape of the Kotlin's `Channel(1)` overflow, and the eviction half is the
	// same claim its case 5 makes with a CLOSED channel (the closed-channel variant lives in
	// TestRequestOpenRunOnAClosedSubscriberIsWedgedNotNotAttached).
	// KT: ProxyEventsHubTest.kt#a full buffer is WEDGED too
	// KT: ProxyEventsHubTest.kt#a wedged stream is dropped so liveness stops claiming it
	t.Run("a full subscriber is WEDGED and is DROPPED", func(t *testing.T) {
		h := NewProxyEventsHub()
		h.SetLogForTest(nil)
		sub := NewEventSubscriber()
		h.Register("ds", sub)
		// Case 5 asserts the registration IS the liveness signal BEFORE the wedge, so that the empty
		// attached() below is an eviction rather than a registration that never took.
		if _, ok := h.Attached()["ds"]; !ok {
			t.Fatalf("attached() = %v after Register, want ds", h.Attached())
		}
		// Fill the queue without draining it, leaving EXACTLY ONE free slot — the Go shape of the
		// Kotlin's `Channel(1)`, which is empty at this point.
		for i := 0; i < eventBuffer-1; i++ {
			if !sub.Send(&pb.ControlEvent{Kind: &pb.ControlEvent_RefreshCatalog{RefreshCatalog: &pb.RefreshCatalog{}}}) {
				t.Fatalf("pre-fill send %d was refused; the queue is shallower than eventBuffer", i)
			}
		}
		// Case 4's FIRST assertion: the dispatch takes the last free slot and reports SENT. Without it
		// the WEDGED below could be a dispatch that never enqueues anything at all.
		if got := h.RequestOpenRun("ds", "s0", "tok", make([]byte, 16), nil); got != DispatchSent {
			t.Fatalf("RequestOpenRun onto a subscriber with one free slot = %s, want SENT", got)
		}
		if got := h.RequestOpenRun("ds", "s1", "tok", make([]byte, 16), nil); got != DispatchWedged {
			t.Fatalf("RequestOpenRun onto a full subscriber = %s, want WEDGED — the single slot is taken", got)
		}
		// 🔒 THE REFUSER IS DEREGISTERED, not left in place. Leaving it registered would make
		// `attached()` keep reporting a proxy that cannot be reached — a liveness view that lies until
		// the stream's own close handler eventually runs.
		if _, ok := h.Attached()["ds"]; ok {
			t.Error("the wedged subscriber is still registered; attached() would report an unreachable proxy")
		}
		// ...and the SECOND attempt therefore reports NOT_ATTACHED, because there is now genuinely
		// nothing there. The two answers are not interchangeable and this is the sequence that shows it.
		if got := h.RequestOpenRun("ds", "s2", "tok", make([]byte, 16), nil); got != DispatchNotAttached {
			t.Errorf("the second RequestOpenRun = %s, want NOT_ATTACHED after the wedged stream was dropped", got)
		}
	})

	// KT: ProxyEventsHubTest.kt#a live replica serves the request even when another is wedged
	t.Run("a wedged replica is skipped when a live one can take the event", func(t *testing.T) {
		// 🔒 EXACTLY ONE REPLICA GETS IT. Broadcasting would make every attached replica dial a run
		// stream and open a backend connection for the same one CP request.
		h := NewProxyEventsHub()
		h.SetLogForTest(nil)
		wedged, live := NewEventSubscriber(), NewEventSubscriber()
		h.Register("ds", wedged)
		h.Register("ds", live)
		for i := 0; i < eventBuffer+1; i++ {
			wedged.Send(&pb.ControlEvent{Kind: &pb.ControlEvent_RefreshCatalog{RefreshCatalog: &pb.RefreshCatalog{}}})
		}
		if got := h.RequestOpenRun("ds", "s1", "tok", make([]byte, 16), nil); got != DispatchSent {
			t.Fatalf("RequestOpenRun with one live replica = %s, want SENT", got)
		}
		// The live one received it, and only it.
		select {
		case ev := <-live.C():
			if ev.GetOpenRunChannel() == nil {
				t.Errorf("the live replica got %T, want the OpenRunChannel", ev.GetKind())
			}
		default:
			t.Error("the live replica received nothing, yet the dispatch reported SENT")
		}
		// And the wedged one was dropped on the way past, so liveness now reports only the live replica.
		if !h.AttachedTo("ds") {
			t.Error("the datasource reports no attached proxy, but a live replica is registered")
		}
		if _, ok := h.Attached()["ds"]; !ok {
			t.Errorf("attached() = %v, want ds — the live stream keeps the datasource attached", h.Attached())
		}
		// The Kotlin's last assertion: "the dead one is gone, not retried". A SECOND dispatch still
		// reports SENT, and it does so without paying another refusal, because the wedged replica was
		// evicted rather than left in the fan-out.
		if got := h.RequestOpenRun("ds", "s2", "tok", make([]byte, 16), nil); got != DispatchSent {
			t.Errorf("the second RequestOpenRun = %s, want SENT — the dead replica is gone, not retried", got)
		}
		select {
		case ev := <-live.C():
			if ev.GetOpenRunChannel() == nil || ev.GetOpenRunChannel().GetSessionId() != "s2" {
				t.Errorf("the live replica got %+v, want the s2 OpenRunChannel", ev.GetKind())
			}
		default:
			t.Error("the second dispatch reported SENT but the live replica received nothing")
		}
	})
}

// TestRequestRefreshDoesNotDropARefuser pins the ASYMMETRY with dispatch, which is the Kotlin's and is
// easy to "tidy" away into one shared helper.
//
// ⚠️ A missed catalog refresh is recoverable on the proxy's next stream rotation, so a refusal is NOT
// evidence the stream is dead. An open-run refusal is different: that request cannot be retried on the
// same stream, so the stream is dropped to let the proxy's reconnect replace it.
//
// KT: ProxyEventsHubTest.kt#a refresh push skips a wedged stream rather than counting it — the Kotlin wedges by CLOSING the channel and asserts only the 0; this also pins the non-eviction
func TestRequestRefreshDoesNotDropARefuser(t *testing.T) {
	h := NewProxyEventsHub()
	h.SetLogForTest(nil)
	sub := NewEventSubscriber()
	h.Register("ds", sub)
	for i := 0; i < eventBuffer+1; i++ {
		sub.Send(&pb.ControlEvent{Kind: &pb.ControlEvent_RefreshCatalog{RefreshCatalog: &pb.RefreshCatalog{}}})
	}
	if n := h.RequestRefresh("ds"); n != 0 {
		t.Errorf("RequestRefresh onto a full subscriber notified %d, want 0 — a full buffer is SKIPPED, "+
			"never blocked on", n)
	}
	if _, ok := h.Attached()["ds"]; !ok {
		t.Error("RequestRefresh DEREGISTERED the refuser; only the open-run dispatch may do that")
	}
}
