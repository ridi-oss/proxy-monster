package approval

import "sync"

// HubBufferCapacity is `Channel<TaskEvent>(capacity = 64, onBufferOverflow = DROP_OLDEST)`
// (TaskCompletionHub.kt:38).
const HubBufferCapacity = 64

// TaskCompletionHub is the in-process, per-principal fan-out of task terminal transitions
// (TaskCompletionHub.kt, 61 LOC; 07-tasks-approvals-results.md §8).
//
// Single-replica by design: the run goroutine that terminalizes a task and the SSE stream that serves
// the principal live in the same process, so a plain in-memory map suffices. A multi-replica
// LISTEN/NOTIFY fan-out is a documented follow-up (docs/backlog.md).
//
// 🔒 INV-A7-40 — THE PUSH IS A PURE ACCELERATOR, NEVER THE SOURCE OF TRUTH. The web still polls a
// task to a terminal state, so a dropped event only delays an update. Accordingly [Hub.Publish] is
// NON-BLOCKING and a full buffer DROPS THE OLDEST, so a slow or stuck client can never make the run
// goroutine block or grow memory unbounded.
//
// ⚠️ LANGUAGE-FORCED DEVIATION — Go has no DROP_OLDEST. A buffered channel with a `select`/`default`
// gives "never block", but its overflow policy is drop-NEWEST, which is the opposite: a stuck client
// would then be pinned to the 64 STALEST events and never learn the terminal state, i.e. exactly the
// failure the buffer exists to avoid. [Hub.Publish] therefore drains one and retries — the
// "drain-one-then-send" of §11 Q6. That is not atomic with the send, so under a concurrent RECEIVER a
// publish can occasionally land in a slot the receiver had already freed; the observable effect is
// one fewer drop, never a lost newest event. TestAFullSubscriberBufferDropsOldestAndKeepsTheNewest
// pins the property the Kotlin's case 7 asserts.
type TaskCompletionHub struct {
	mu sync.Mutex
	// subscribers is `ConcurrentHashMap<String, CopyOnWriteArrayList<Channel<TaskEvent>>>` —
	// principal → one channel per browser tab/connection.
	subscribers map[string][]chan TaskEvent
	// closed tracks which channels Unsubscribe has already closed, so a Publish racing an
	// Unsubscribe cannot send on a closed channel. Kotlin's Channel.trySend on a closed channel
	// returns a failed result; Go PANICS, and a panic in the run goroutine takes the process down.
	closed map[chan TaskEvent]bool
}

// NewTaskCompletionHub builds an empty hub.
func NewTaskCompletionHub() *TaskCompletionHub {
	return &TaskCompletionHub{
		subscribers: map[string][]chan TaskEvent{},
		closed:      map[chan TaskEvent]bool{},
	}
}

// Subscribe opens a subscription for principal. The caller MUST [TaskCompletionHub.Unsubscribe] it
// when the stream ends — the SSE handler does it in a defer.
func (h *TaskCompletionHub) Subscribe(principal string) chan TaskEvent {
	ch := make(chan TaskEvent, HubBufferCapacity)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.subscribers[principal] = append(h.subscribers[principal], ch)
	return ch
}

// Unsubscribe removes the channel, evicts the principal's entry when it was the last one, and CLOSES
// the channel — all three, as `unsubscribe` does.
//
// Closing is what lets a consumer's range/receive end. It is idempotent: a second Unsubscribe of the
// same channel neither closes twice (a panic) nor removes another tab's channel.
func (h *TaskCompletionHub) Unsubscribe(principal string, ch chan TaskEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	list := h.subscribers[principal]
	for i, c := range list {
		if c == ch {
			h.subscribers[principal] = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	if len(h.subscribers[principal]) == 0 {
		// `list.ifEmpty { null }` — evict the key rather than leaving an empty list per principal
		// that ever opened a tab.
		delete(h.subscribers, principal)
	}
	if !h.closed[ch] {
		h.closed[ch] = true
		close(ch)
	}
}

// Publish is the best-effort push of event to every open stream of principal. It NEVER blocks.
func (h *TaskCompletionHub) Publish(principal string, event TaskEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, ch := range h.subscribers[principal] {
		if h.closed[ch] {
			continue
		}
		send(ch, event)
	}
}

// PublishTo is `publish(principals: Collection<String>, event)` — push to a set of parties (a
// workflow task's requester + approver), DE-DUPLICATED via Kotlin's `toSet()`.
//
// The de-duplication is observable: a self-approved task has requester == approver, and without it
// the one open tab would receive the same terminal event twice.
func (h *TaskCompletionHub) PublishTo(principals []string, event TaskEvent) {
	seen := make(map[string]bool, len(principals))
	for _, p := range principals {
		if seen[p] {
			continue
		}
		seen[p] = true
		h.Publish(p, event)
	}
}

// send is the DROP_OLDEST emulation. See the deviation note on [TaskCompletionHub].
func send(ch chan TaskEvent, event TaskEvent) {
	select {
	case ch <- event:
		return
	default:
	}
	// Full. Discard the OLDEST buffered event and retry once. The retry can still fail only if a
	// concurrent publisher refilled the slot, in which case dropping this event is the same
	// best-effort outcome the Kotlin's bounded channel gives.
	select {
	case <-ch:
	default:
	}
	select {
	case ch <- event:
	default:
	}
}
