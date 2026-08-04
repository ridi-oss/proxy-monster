package core

// ProxyEventsHubTest.kt's one case that registries_test.go does not reach.
//
// Six of its seven cases wedge a stream by filling or closing a Kotlin `Channel`, and in Kotlin those
// two are the SAME condition: `trySend` on a closed channel and on a full one both return a failed
// ChannelResult. Go splits them — a full buffer is a failed non-blocking send, while a CLOSED
// subscriber is a separate `done` signal — so the closed-stream case needs its own test rather than
// being a rewording of the full-buffer one.

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
)

// TestRequestOpenRunOnAClosedSubscriberIsWedgedNotNotAttached is ProxyEventsHubTest case 3, and its
// Kotlin comment states exactly why the distinction is load-bearing: "'no proxy attached' sends an
// operator looking for a proxy that is in fact running."
//
// 🔒 The condition is REGISTERED BUT DEAD — the shape a load balancer produces when it resets the
// events stream on a transient health-check blip. The hub still holds the subscriber, so collapsing
// this into NOT_ATTACHED would report "nothing is there" about a proxy that is running.
//
// ⚠️ Closing WITHOUT deregistering is the point. [ProxyEventsHub.Deregister] closes the subscriber AND
// removes it, which would legitimately be NOT_ATTACHED; a Go port that only ever closed through
// Deregister would make this state unreachable and the Kotlin's distinction untestable.
//
// KT: ProxyEventsHubTest.kt#a closed stream is WEDGED, not NOT_ATTACHED
// KT: ProxyEventsHubTest.kt#a wedged stream is dropped so liveness stops claiming it — the Kotlin's own closed-channel path
func TestRequestOpenRunOnAClosedSubscriberIsWedgedNotNotAttached(t *testing.T) {
	h := NewProxyEventsHub()
	h.SetLogForTest(nil)
	sub := NewEventSubscriber()
	h.Register("ds", sub)

	// The Kotlin's `channel.close()`: the stream is dead while the registration survives it.
	sub.Close()
	if !h.AttachedTo("ds") {
		t.Fatal("closing a subscriber must not deregister it; this test needs the registered-but-dead state")
	}

	if got := h.RequestOpenRun("ds", "session", "token", make([]byte, 16), nil); got != DispatchWedged {
		t.Errorf("RequestOpenRun onto a CLOSED subscriber = %s, want WEDGED — NOT_ATTACHED would send an "+
			"operator looking for a proxy that is in fact running", got)
	}
	// Case 5's claim, on the closed-channel path the Kotlin actually uses for it: the dead stream is
	// dropped, so liveness stops claiming it and the next request is honestly NOT_ATTACHED.
	if h.AttachedTo("ds") {
		t.Error("the wedged subscriber is still attached; the liveness view would keep reporting an unreachable proxy")
	}
	if got := h.RequestOpenRun("ds", "session", "token", make([]byte, 16), nil); got != DispatchNotAttached {
		t.Errorf("the second RequestOpenRun = %s, want NOT_ATTACHED — once dropped the datasource genuinely "+
			"has no proxy", got)
	}
}

// TestRequestRefreshSkipsAClosedStream is ProxyEventsHubTest case 7 on the CLOSED-channel path the
// Kotlin uses for it, next to registries_test.go's full-buffer variant. Both must answer 0: a wedged
// stream is skipped, never counted as notified, because the admin's "refresh now" would otherwise
// report success against a proxy that received nothing.
// KT: ProxyEventsHubTest.kt#a refresh push skips a wedged stream rather than counting it — the Kotlin's own closed-channel path
func TestRequestRefreshSkipsAClosedStream(t *testing.T) {
	h := NewProxyEventsHub()
	h.SetLogForTest(nil)
	sub := NewEventSubscriber()
	h.Register("ds", sub)
	sub.Close()

	if n := h.RequestRefresh("ds"); n != 0 {
		t.Errorf("RequestRefresh onto a closed subscriber notified %d, want 0", n)
	}
	// The refresh asymmetry holds on this path too: a missed catalog refresh is recoverable, so the
	// refuser is NOT evicted here even though the open-run dispatch would evict it.
	if !h.AttachedTo("ds") {
		t.Error("RequestRefresh deregistered the refuser; only the open-run dispatch may do that")
	}
	// Sanity: the subscriber really is refusing, so the 0 above is the skip and not an empty registry.
	if sub.Send(&pb.ControlEvent{}) {
		t.Error("a closed subscriber accepted a send")
	}
}
