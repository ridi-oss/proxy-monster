package core

import (
	"sync"

	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
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
// TODO(A7): RunExecService — the producer side that registers a session, nudges the proxy over
// Events, awaits Ready and drives the query exchange — is a later increment. This is the registry
// half A10 cannot be written without.
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
// TODO(A12): the request/response half (requestOpenRun's NOT_ATTACHED / WEDGED outcomes, the
// per-datasource wedge detection) is a later increment. Attached/Register/Deregister/Publish is the
// part A10's Events handler needs.
type ProxyEventsHub struct {
	mu   sync.RWMutex
	subs map[string]map[*EventSubscriber]struct{}
}

// NewProxyEventsHub builds an empty hub.
func NewProxyEventsHub() *ProxyEventsHub {
	return &ProxyEventsHub{subs: map[string]map[*EventSubscriber]struct{}{}}
}

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

// Attached reports whether any proxy currently holds an Events stream for datasourceName. This is
// the liveness view: "the open stream IS the liveness signal".
func (h *ProxyEventsHub) Attached(datasourceName string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs[datasourceName]) > 0
}

// Publish fans an event out to every subscriber of datasourceName and reports how many accepted it.
func (h *ProxyEventsHub) Publish(datasourceName string, ev *pb.ControlEvent) int {
	h.mu.RLock()
	subs := make([]*EventSubscriber, 0, len(h.subs[datasourceName]))
	for s := range h.subs[datasourceName] {
		subs = append(subs, s)
	}
	h.mu.RUnlock()

	sent := 0
	for _, s := range subs {
		if s.Send(ev) {
			sent++
		}
	}
	return sent
}
