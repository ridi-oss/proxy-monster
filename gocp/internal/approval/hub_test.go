package approval

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------------------------
// `TaskCompletionHubTest.kt` — 85 LOC, 7 cases, pure unit (07-tasks-approvals-results.md §10).
//
// ORACLE: TaskCompletionHub.kt, 61 LOC.
// ---------------------------------------------------------------------------------------------

// recv reads one event without hanging a failing test forever.
func recv(t *testing.T, ch <-chan TaskEvent) (TaskEvent, bool) {
	t.Helper()
	select {
	case e, open := <-ch:
		return e, open
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a task event")
		return TaskEvent{}, false
	}
}

// none asserts nothing arrives. The window is short on purpose: publish is synchronous and
// non-blocking, so an event that was going to arrive has already been buffered by the time Publish
// returns.
func none(t *testing.T, ch <-chan TaskEvent) {
	t.Helper()
	select {
	case e := <-ch:
		t.Fatalf("unexpected event %#v", e)
	case <-time.After(50 * time.Millisecond):
	}
}

// Case 1 — a subscriber receives an event published to its principal.
// KT: TaskCompletionHubTest.kt#a subscriber receives an event published to its principal
func TestASubscriberReceivesAnEventPublishedToItsPrincipal(t *testing.T) {
	h := NewTaskCompletionHub()
	ch := h.Subscribe("alice")
	defer h.Unsubscribe("alice", ch)

	h.Publish("alice", TaskEvent{TaskID: 7, Status: "EXECUTED"})

	got, _ := recv(t, ch)
	if got != (TaskEvent{TaskID: 7, Status: "EXECUTED"}) {
		t.Errorf("got %#v", got)
	}
}

// Case 2 — publishing with no subscribers is a no-op, not a panic and not a leaked map entry.
// KT: TaskCompletionHubTest.kt#publish to a principal with no subscribers is a no-op
func TestPublishWithNoSubscribersIsANoOp(t *testing.T) {
	h := NewTaskCompletionHub()
	h.Publish("nobody", TaskEvent{TaskID: 1, Status: "FAILED"})
	if len(h.subscribers) != 0 {
		t.Errorf("publish created %d subscriber entries; it must create none", len(h.subscribers))
	}
}

// Case 3 — an event reaches EVERY open stream of the same principal (one per browser tab).
// KT: TaskCompletionHubTest.kt#an event reaches every open stream of the same principal
func TestAnEventReachesEveryOpenStreamOfTheSamePrincipal(t *testing.T) {
	h := NewTaskCompletionHub()
	tab1, tab2 := h.Subscribe("alice"), h.Subscribe("alice")
	defer h.Unsubscribe("alice", tab1)
	defer h.Unsubscribe("alice", tab2)

	// The WHOLE event must arrive on every stream, not just its id — the Kotlin compares the event
	// VALUE, so a fan-out that delivered the right task with the wrong terminal status would fail there
	// and must fail here.
	want := TaskEvent{TaskID: 2, Status: "EXECUTED"}
	h.Publish("alice", want)

	for i, ch := range []chan TaskEvent{tab1, tab2} {
		if got, _ := recv(t, ch); got != want {
			t.Errorf("tab %d: got %#v, want %#v", i, got, want)
		}
	}
}

// 🔒 Case 4 — a principal only receives ITS OWN events. The whole hub is a per-principal fan-out and
// a keying bug here pushes another user's task ids into a tab.
// KT: TaskCompletionHubTest.kt#a principal only receives its own events
func TestAPrincipalOnlyReceivesItsOwnEvents(t *testing.T) {
	h := NewTaskCompletionHub()
	alice, bob := h.Subscribe("alice"), h.Subscribe("bob")
	defer h.Unsubscribe("alice", alice)
	defer h.Unsubscribe("bob", bob)

	h.Publish("alice", TaskEvent{TaskID: 3, Status: "EXECUTED"})

	if got, _ := recv(t, alice); got.TaskID != 3 {
		t.Errorf("alice: got %#v", got)
	}
	none(t, bob)
}

// Case 5 — a publish to a PARTY SET delivers once per principal, even when a principal repeats.
//
// The repeat is not hypothetical: a self-approved task has requester == approver, so without the
// de-duplication the one open tab receives its terminal event twice.
// KT: TaskCompletionHubTest.kt#publish to a party set delivers once per principal even when a principal repeats
func TestPublishToAPartySetDeliversOncePerPrincipalEvenWhenAPrincipalRepeats(t *testing.T) {
	h := NewTaskCompletionHub()
	ch := h.Subscribe("alice")
	defer h.Unsubscribe("alice", ch)

	h.PublishTo([]string{"alice", "alice", "bob"}, TaskEvent{TaskID: 4, Status: "CANCELLED"})

	if got, _ := recv(t, ch); got.TaskID != 4 {
		t.Errorf("got %#v", got)
	}
	none(t, ch)
}

// Case 6 — unsubscribe removes the channel AND closes it, and evicts the now-empty principal entry.
//
// Closing is what lets the SSE loop's receive end; without it the stream would block forever on a
// hub that no longer holds it.
// KT: TaskCompletionHubTest.kt#unsubscribe removes and closes the channel
func TestUnsubscribeRemovesAndClosesTheChannel(t *testing.T) {
	h := NewTaskCompletionHub()
	ch := h.Subscribe("alice")

	h.Unsubscribe("alice", ch)

	if _, open := recv(t, ch); open {
		t.Error("unsubscribe must CLOSE the channel")
	}
	if _, present := h.subscribers["alice"]; present {
		t.Error("the empty principal entry must be evicted, not left behind")
	}
	// Idempotent: a second unsubscribe must not double-close (a panic) — the SSE handler's defer can
	// run after an explicit close on some paths.
	h.Unsubscribe("alice", ch)
	// And a publish after unsubscribe must not send on a closed channel.
	h.Publish("alice", TaskEvent{TaskID: 5, Status: "FAILED"})
}

// ⚠️ Case 7 — 🔒 INV-A7-40 — A FULL SUBSCRIBER BUFFER DROPS THE OLDEST AND NEVER BLOCKS THE
// PUBLISHER, KEEPING THE NEWEST EVENT.
//
// This is the Go GAP the area doc calls out (§8, §11 Q6): a plain buffered channel with
// select/default drops the NEWEST, which is the opposite policy and would pin a stuck client to the
// 64 stalest events — never learning the terminal state, i.e. exactly the failure the buffer exists
// to prevent.
//
// The assertion is therefore in two halves, and BOTH are needed:
//
//	(a) the publisher never blocks — measured by the fact that this test completes;
//	(b) the NEWEST event survives, and the OLDEST is the one that went.
//
// A drop-newest implementation passes (a) and fails (b), which is the discrimination that matters.
// KT: TaskCompletionHubTest.kt#a full subscriber buffer drops oldest and never blocks the publisher, keeping the newest event
func TestAFullSubscriberBufferDropsOldestAndKeepsTheNewest(t *testing.T) {
	h := NewTaskCompletionHub()
	ch := h.Subscribe("alice")
	defer h.Unsubscribe("alice", ch)

	// Fill the buffer exactly, then overflow it by one.
	for i := range HubBufferCapacity {
		h.Publish("alice", TaskEvent{TaskID: int64(i), Status: "EXECUTED"})
	}
	newest := TaskEvent{TaskID: 9999, Status: "CANCELLED"}
	h.Publish("alice", newest) // (a) — must not block

	drained := make([]TaskEvent, 0, HubBufferCapacity)
	for {
		select {
		case e := <-ch:
			drained = append(drained, e)
			continue
		default:
		}
		break
	}

	if len(drained) != HubBufferCapacity {
		t.Fatalf("buffer held %d events, want %d", len(drained), HubBufferCapacity)
	}
	if drained[len(drained)-1] != newest {
		t.Errorf("(b) the NEWEST event was dropped: last buffered is %#v, want %#v",
			drained[len(drained)-1], newest)
	}
	if drained[0].TaskID != 1 {
		t.Errorf("(b) the OLDEST event should have been dropped: first buffered is task %d, want 1",
			drained[0].TaskID)
	}
}
