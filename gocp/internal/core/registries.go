package core

import (
	"log/slog"
	"sync"

	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
)

// ---- RequesterIpRegistry (A7, 07-tasks-approvals-results.md §"Registries") --------------------

// RequesterIPRegistry is the CP-only decide-time carrier for the HTTP requester IP, keyed by the
// token's SHA-256 hash — NEVER the raw token.
//
// It exists because the gRPC Decide handler sees only the resolved TOKEN, not the HTTP request that
// minted it: an editor/approver-exec statement is authorized against the IP attested when the
// control plane minted its ephemeral token, which is the only moment the real client address was
// visible. Lives on [ControlPlaneCore] for the same reason RunChannels does (INV-A1-1's neighbours).
//
// 🔒 INV-A7-33 — Put and Set have DELIBERATELY DIFFERENT null semantics, and collapsing them is a
// live fail-open:
//   - Put(hash, nil) is a NO-OP. It is the mint-time write; the key does not exist yet, so there is
//     nothing to refresh and it must not plant an absent-key sentinel.
//   - Set(hash, nil) REMOVES the entry. It is the per-decision refresh: a persistent session queried
//     from a network whose requester_ip cannot be resolved must not inherit the (possibly trusted)
//     open-time IP. The attribute goes absent ⇒ fail-closed, never stale.
//
// Entry lifetime == token lifetime: Put at issuance, Remove on revoke (both success and failure
// paths). An absent entry makes Get return nil ⇒ `requester_ip` is simply absent on that decision.
type RequesterIPRegistry struct {
	mu sync.RWMutex
	m  map[string]string
}

// NewRequesterIPRegistry builds an empty registry.
func NewRequesterIPRegistry() *RequesterIPRegistry {
	return &RequesterIPRegistry{m: map[string]string{}}
}

// Put is the MINT-time write. A nil ip is a no-op (INV-A7-33).
func (r *RequesterIPRegistry) Put(tokenHash string, ip *string) {
	if ip == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[tokenHash] = *ip
}

// Set is the PER-DECISION refresh. A nil ip REMOVES the entry (INV-A7-33).
func (r *RequesterIPRegistry) Set(tokenHash string, ip *string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ip == nil {
		delete(r.m, tokenHash)
		return
	}
	r.m[tokenHash] = *ip
}

// Get returns the stored IP, or nil when absent.
func (r *RequesterIPRegistry) Get(tokenHash string) *string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.m[tokenHash]
	if !ok {
		return nil
	}
	return &v
}

// Remove drops the entry (token revoke).
func (r *RequesterIPRegistry) Remove(tokenHash string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, tokenHash)
}

// ---- RunChannelRegistry (A7) ------------------------------------------------------------------

// Attached is the claimed run stream: the outbound channel the RunExec HANDLER drains onto the wire,
// plus the private inbound channel the handler pushes every later proxy message into.
type Attached struct {
	// Outbound is written by A7's RunExecService and drained by the RunExec handler.
	Outbound chan *pb.ControlRunMsg
	// Inbound carries the proxy's post-Ready messages to whoever is running the session.
	Inbound chan *pb.ProxyRunMsg
}

// PendingRunSession is one registered, not-yet-claimed run session.
type PendingRunSession struct {
	SessionID string
	// Ready is completed by Attach with the Attached record. Buffered(1) so Attach never blocks.
	Ready chan *Attached
}

// RunChannelRegistry is the pending-run-session map A10's RunExec claims from.
//
// 🔒 INV-A7-32 / INV-A10-32 — a session is claimable EXACTLY ONCE. [RunChannelRegistry.Attach]
// removes-then-completes atomically, so an unknown id and a duplicate claim are indistinguishable by
// design (both are NOT_FOUND at the RPC). A claimed-twice stream could otherwise share another
// request's token and query.
//
// The producer side — the code that registers a session, nudges the proxy over Events, awaits Ready
// and drives the query exchange — is internal/runexec's RunExecService.
type RunChannelRegistry struct {
	mu      sync.Mutex
	pending map[string]*PendingRunSession
}

// NewRunChannelRegistry builds an empty registry.
func NewRunChannelRegistry() *RunChannelRegistry {
	return &RunChannelRegistry{pending: map[string]*PendingRunSession{}}
}

// Register is Kotlin's `check(putIfAbsent(...) == null)`: a duplicate session id is a programming
// error, reported rather than silently overwriting a live session's claim slot.
func (r *RunChannelRegistry) Register(p *PendingRunSession) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.pending[p.SessionID]; exists {
		return false
	}
	r.pending[p.SessionID] = p
	return true
}

// Attach claims sessionID for outbound. Remove-then-complete, under one lock.
func (r *RunChannelRegistry) Attach(sessionID string, outbound chan *pb.ControlRunMsg) *Attached {
	r.mu.Lock()
	p, ok := r.pending[sessionID]
	if ok {
		delete(r.pending, sessionID)
	}
	r.mu.Unlock()
	if !ok {
		return nil
	}
	a := &Attached{Outbound: outbound, Inbound: make(chan *pb.ProxyRunMsg, runInboundBuffer)}
	p.Ready <- a
	return a
}

// Remove drops a pending session. A no-op when Attach already removed it, which is what makes the
// RunExec handler's unconditional cleanup safe on the failed-claim path (INV-A10-34).
func (r *RunChannelRegistry) Remove(sessionID string) *PendingRunSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.pending[sessionID]
	if !ok {
		return nil
	}
	delete(r.pending, sessionID)
	return p
}

// runInboundBuffer mirrors Kotlin's `Channel(BUFFERED)` default capacity (64).
const runInboundBuffer = 64

// ---- TableDetailChannelRegistry (A5 TableDetailExec.kt) ---------------------------------------

// AttachedTableDetail is the claimed table-detail stream.
type AttachedTableDetail struct {
	Outbound chan *pb.ControlTableDetailMsg
	Inbound  chan *pb.ProxyTableDetailMsg
}

// PendingTableDetailSession is one registered, not-yet-claimed table-detail session.
type PendingTableDetailSession struct {
	SessionID string
	Ready     chan *AttachedTableDetail
}

// TableDetailChannelRegistry is RunChannelRegistry's sibling for the admin table-browser stream.
// Same claim-exactly-once contract; a separate map because the two streams carry different messages
// and a shared one would let a RunExec Ready claim a table-detail session.
//
// TODO(A5): the producer side (TableDetailExec.kt's request/await) is a later increment.
type TableDetailChannelRegistry struct {
	mu      sync.Mutex
	pending map[string]*PendingTableDetailSession
}

// NewTableDetailChannelRegistry builds an empty registry.
func NewTableDetailChannelRegistry() *TableDetailChannelRegistry {
	return &TableDetailChannelRegistry{pending: map[string]*PendingTableDetailSession{}}
}

// Register is `check(putIfAbsent(...) == null)`.
func (r *TableDetailChannelRegistry) Register(p *PendingTableDetailSession) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.pending[p.SessionID]; exists {
		return false
	}
	r.pending[p.SessionID] = p
	return true
}

// Attach claims sessionID. Remove-then-complete, under one lock.
func (r *TableDetailChannelRegistry) Attach(sessionID string, outbound chan *pb.ControlTableDetailMsg) *AttachedTableDetail {
	r.mu.Lock()
	p, ok := r.pending[sessionID]
	if ok {
		delete(r.pending, sessionID)
	}
	r.mu.Unlock()
	if !ok {
		return nil
	}
	a := &AttachedTableDetail{Outbound: outbound, Inbound: make(chan *pb.ProxyTableDetailMsg, runInboundBuffer)}
	p.Ready <- a
	return a
}

// Remove drops a pending session; a no-op after Attach.
func (r *TableDetailChannelRegistry) Remove(sessionID string) *PendingTableDetailSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.pending[sessionID]
	if !ok {
		return nil
	}
	delete(r.pending, sessionID)
	return p
}

// ---- ProxyEventsHub (A12) ---------------------------------------------------------------------

// EventSubscriber is one live Events stream. The `done` channel is what makes [EventSubscriber.Send]
// safe.
//
// 🔒 A12 INV-A12-14, restated as the Go hazard it becomes: a send on a CLOSED Go channel PANICS
// rather than failing, so the hub must never close a subscriber's channel out from under a producer.
// Close() closes `done` only; the buffered `ch` is left to the garbage collector, and every send
// selects on `done` first.
type EventSubscriber struct {
	ch   chan *pb.ControlEvent
	done chan struct{}
	once sync.Once
}

// NewEventSubscriber builds a subscriber with the buffered channel the Events handler drains.
func NewEventSubscriber() *EventSubscriber {
	return &EventSubscriber{ch: make(chan *pb.ControlEvent, eventBuffer), done: make(chan struct{})}
}

// eventBuffer is the per-subscriber queue depth. Kotlin's channelFlow default is BUFFERED (64).
const eventBuffer = 64

// C is the receive side the Events handler ranges over.
func (s *EventSubscriber) C() <-chan *pb.ControlEvent { return s.ch }

// Send offers an event. It reports false when the subscriber is closed OR its queue is full — a slow
// proxy must never block the control plane's own goroutines, and a dropped push is recoverable (the
// proxy re-reads on its next 4-minute stream rotation) while a wedged control plane is not.
func (s *EventSubscriber) Send(ev *pb.ControlEvent) bool {
	select {
	case <-s.done:
		return false
	default:
	}
	select {
	case s.ch <- ev:
		return true
	case <-s.done:
		return false
	default:
		return false
	}
}

// Close marks the subscriber dead. Idempotent; never closes `ch`.
func (s *EventSubscriber) Close() { s.once.Do(func() { close(s.done) }) }

// ProxyEventsHub is the per-datasource fan-out of control events onto the proxy-opened Events
// streams.
//
// 🔒 INV-A10-35 / A12 INV-A12-12 — THE CONTROL PLANE NEVER DIALS INTO A PROXY. It only ever writes
// back down a pipe the proxy opened, which is what lets a proxy sit behind NAT with no inbound
// listener. Every RPC that "pushes" (RefreshCatalog, OpenRunChannel, OpenTableDetailChannel) does so
// through this hub.
//
// The request/response half — [ProxyEventsHub.RequestOpenRun] and its Dispatch outcomes — is A7's
// producer side and landed with RunExecService.
type ProxyEventsHub struct {
	mu   sync.RWMutex
	subs map[string]map[*EventSubscriber]struct{}
	log  *slog.Logger
}

// NewProxyEventsHub builds an empty hub.
func NewProxyEventsHub() *ProxyEventsHub {
	return &ProxyEventsHub{subs: map[string]map[*EventSubscriber]struct{}{}, log: slog.Default()}
}

// newProxyEventsHubWithLog is what [New] uses so the hub's wedge warnings reach the process logger a
// test captures. A nil logger is tolerated by [ProxyEventsHub.deregisterWedged].
func newProxyEventsHubWithLog(log *slog.Logger) *ProxyEventsHub {
	h := NewProxyEventsHub()
	h.log = log
	return h
}

// SetLogForTest points the hub's wedge warnings somewhere else, or silences them with nil. It exists
// only so the wedge cases in this package's own suite do not print a warning per assertion; production
// gets its logger through [New].
func (h *ProxyEventsHub) SetLogForTest(log *slog.Logger) { h.log = log }

// Register adds a subscriber for datasourceName.
func (h *ProxyEventsHub) Register(datasourceName string, s *EventSubscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	set, ok := h.subs[datasourceName]
	if !ok {
		set = map[*EventSubscriber]struct{}{}
		h.subs[datasourceName] = set
	}
	set[s] = struct{}{}
}

// Deregister removes a subscriber and closes it.
func (h *ProxyEventsHub) Deregister(datasourceName string, s *EventSubscriber) {
	h.mu.Lock()
	set, ok := h.subs[datasourceName]
	if ok {
		delete(set, s)
		if len(set) == 0 {
			delete(h.subs, datasourceName)
		}
	}
	h.mu.Unlock()
	s.Close()
}

// AttachedTo reports whether any proxy currently holds an Events stream for datasourceName. This is
// the liveness view: "the open stream IS the liveness signal".
//
// ⚠️ It has NO Kotlin counterpart — the hub there exposes only the set form, [ProxyEventsHub.Attached]
// — and it is named `AttachedTo` rather than `Attached` so the set form can carry the Kotlin's name.
// That matters because `attached()` is the method BOTH consumer interfaces declare
// (`management.ProxyAttachments`, `datasource.ProxyEvents`), and Go satisfies an interface by name.
func (h *ProxyEventsHub) AttachedTo(datasourceName string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs[datasourceName]) > 0
}

// Attached is `fun attached(): Set<String>` (ProxyEventsHub.kt:144) — "datasource names with at least
// one open Events stream", the admin "which datasources have a proxy attached" view.
//
// A `map[string]struct{}` because membership is the only thing ever asked of it — see
// management.ProxyAttachments, which this satisfies, as does datasource.ProxyEvents.
//
// 🔒 The empty-list entries the Kotlin filters out cannot exist here: [ProxyEventsHub.Deregister]
// deletes a name's map entry when its last subscriber goes. The filter is kept anyway, because the
// two implementations must not disagree if that ever changes — a ghost name in this set is a liveness
// view that reports a proxy which is not there.
func (h *ProxyEventsHub) Attached() map[string]struct{} {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make(map[string]struct{}, len(h.subs))
	for name, set := range h.subs {
		if len(set) > 0 {
			out[name] = struct{}{}
		}
	}
	return out
}

// RequestRefresh is `fun requestRefresh(name): Int` (ProxyEventsHub.kt:53-59) — fan a `RefreshCatalog`
// out to every open stream for name and return how many accepted it.
//
// 🔒 0 IS AN HONEST ANSWER, NOT AN ERROR: no proxy attached ⇒ the admin's "refresh now" is a no-op and
// says so. A full send buffer (a wedged proxy) is SKIPPED, never blocked on — [EventSubscriber.Send]
// is already non-blocking, which is the `trySend(...).isSuccess` the Kotlin counts.
//
// ⚠️ Unlike `dispatch`, this does NOT deregister a stream that refuses the event. That asymmetry is
// the Kotlin's: a missed catalog refresh is recoverable on the proxy's next stream rotation, so a
// refusal here is not evidence the stream is dead.
func (h *ProxyEventsHub) RequestRefresh(datasourceName string) int {
	return h.Publish(datasourceName, &pb.ControlEvent{
		Kind: &pb.ControlEvent_RefreshCatalog{RefreshCatalog: &pb.RefreshCatalog{}},
	})
}

// Publish fans an event out to every subscriber of datasourceName and reports how many accepted it.
func (h *ProxyEventsHub) Publish(datasourceName string, ev *pb.ControlEvent) int {
	sent := 0
	for _, s := range h.snapshot(datasourceName) {
		if s.Send(ev) {
			sent++
		}
	}
	return sent
}

// snapshot copies the subscriber set so a send never runs under the hub's lock — Deregister takes the
// write lock, and [ProxyEventsHub.dispatch] deregisters a refuser mid-iteration.
func (h *ProxyEventsHub) snapshot(datasourceName string) []*EventSubscriber {
	h.mu.RLock()
	defer h.mu.RUnlock()
	subs := make([]*EventSubscriber, 0, len(h.subs[datasourceName]))
	for s := range h.subs[datasourceName] {
		subs = append(subs, s)
	}
	return subs
}

// Dispatch is `enum class Dispatch { SENT, NOT_ATTACHED, WEDGED }` (ProxyEventsHub.kt:75).
//
// 🔒 The three-valued answer is the point, and a boolean is the bug it replaced. NOT_ATTACHED and
// WEDGED look identical to a caller that only gets true/false, and the operator answer differs:
// NOT_ATTACHED means no proxy is there, WEDGED means one IS registered but its channel will not take
// an event — a stream already closed by a reset the server has not finished tearing down, or a
// consumer that stopped draining. Reporting both as "no proxy attached" sends whoever debugs it
// looking for a proxy that is in fact running (A7's INV-A7-34, the consumer side).
type Dispatch int

// The three Dispatch outcomes.
const (
	DispatchSent Dispatch = iota
	DispatchNotAttached
	DispatchWedged
)

// String makes a failed dispatch readable in a log line and a test failure.
func (d Dispatch) String() string {
	switch d {
	case DispatchSent:
		return "SENT"
	case DispatchNotAttached:
		return "NOT_ATTACHED"
	case DispatchWedged:
		return "WEDGED"
	default:
		return "UNKNOWN"
	}
}

// dispatch hands ev to EXACTLY ONE attached replica — `private fun dispatch(name, what, event)`
// (ProxyEventsHub.kt:85-96).
//
// 🔒 THE FIRST NON-BLOCKING SEND THAT SUCCEEDS WINS, AND THE FAN-OUT STOPS THERE. Broadcasting would
// make EVERY attached replica dial a run stream and open a backend connection for the same one CP
// request — N backend connections per query, and N-1 of them orphaned.
//
// ⚠️ A channel that REFUSES the event is deregistered here rather than left in place, and that
// asymmetry with [ProxyEventsHub.RequestRefresh] is the Kotlin's: a refuser cannot serve a later
// request either, and leaving it registered means `attached()` keeps reporting a proxy that cannot be
// reached — the liveness view would lie until the stream's own close handler eventually ran. A missed
// catalog refresh, by contrast, is recoverable on the proxy's next stream rotation, so RequestRefresh
// does NOT treat a refusal as evidence the stream is dead.
func (h *ProxyEventsHub) dispatch(datasourceName, what string, ev *pb.ControlEvent) Dispatch {
	subs := h.snapshot(datasourceName)
	// `streams[name] ?: return NOT_ATTACHED`, plus the empty-list case the Kotlin reaches through
	// `refused.isEmpty()`. Both mean the same thing: nothing is listening.
	refused := make([]*EventSubscriber, 0, len(subs))
	for _, s := range subs {
		if s.Send(ev) {
			h.deregisterWedged(datasourceName, refused, what)
			return DispatchSent
		}
		refused = append(refused, s)
	}
	h.deregisterWedged(datasourceName, refused, what)
	if len(refused) == 0 {
		return DispatchNotAttached
	}
	return DispatchWedged
}

func (h *ProxyEventsHub) deregisterWedged(datasourceName string, refused []*EventSubscriber, what string) {
	for _, s := range refused {
		h.Deregister(datasourceName, s)
	}
	if len(refused) > 0 && h.log != nil {
		h.log.Warn("proxy stream would not accept an event (closed or its buffer is full); dropping it",
			"datasource", datasourceName, "event", what, "streams", len(refused))
	}
}

// RequestOpenRun asks exactly one attached proxy replica to dial a run stream —
// `fun requestOpenRun(name, sessionId, ephemeralToken, connectionId, onOpen)`
// (ProxyEventsHub.kt:104-119).
//
// 🔒 INV-A10-35 / A12 INV-A12-12 — this is the ONLY way the control plane "reaches" a proxy: it
// writes an OpenRunChannel down a pipe the PROXY opened, and the proxy then dials back. Nothing here
// connects outward, which is what lets a proxy sit behind NAT with no inbound listener.
func (h *ProxyEventsHub) RequestOpenRun(
	datasourceName, sessionID, ephemeralToken string, connectionID []byte, onOpen []*pb.Refetch,
) Dispatch {
	commands := make([]*pb.ProxyCommand, 0, len(onOpen))
	for _, r := range onOpen {
		commands = append(commands, &pb.ProxyCommand{Command: &pb.ProxyCommand_Refetch{Refetch: r}})
	}
	return h.dispatch(datasourceName, "an open-run request", &pb.ControlEvent{
		Kind: &pb.ControlEvent_OpenRunChannel{OpenRunChannel: &pb.OpenRunChannel{
			SessionId:      sessionID,
			EphemeralToken: ephemeralToken,
			ConnectionId:   connectionID,
			OnOpen:         commands,
		}},
	})
}

// RequestOpenTableDetail is `requestOpenTableDetail(name, sessionId, schema, table)`
// (ProxyEventsHub.kt:122-131) — RequestOpenRun's sibling for the admin table-browser stream, over the
// same one-replica dispatch.
//
//	TODO(A5): TableDetailExec.kt's producer side is still unported; this is the hub half it needs.
func (h *ProxyEventsHub) RequestOpenTableDetail(datasourceName, sessionID, schema, table string) Dispatch {
	return h.dispatch(datasourceName, "a table-detail request", &pb.ControlEvent{
		Kind: &pb.ControlEvent_OpenTableDetailChannel{OpenTableDetailChannel: &pb.OpenTableDetailChannel{
			SessionId: sessionID,
			Schema:    schema,
			Table:     table,
		}},
	})
}
