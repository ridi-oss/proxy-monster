package runexec

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/core"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/token"
)

// QueryTimeoutMessage is `RunExecService.QUERY_TIMEOUT_MESSAGE` (RunExec.kt:645).
//
// 🔒 INV-A7-31 — IT IS A CROSS-LANGUAGE STRING CONTRACT. A statement the proxy aborted at
// PM_QUERY_TIMEOUT carries this EXACT sentinel as its RunError message; [collectResponse] matches it to
// attribute a timeout (→ `query.proxy_timeout`, task FAILED) rather than a generic failure — and,
// crucially, never as a success: some backends (MySQL SLEEP) return a row when interrupted, so the
// watchdog's verdict, not the backend's, decides the outcome.
//
// 🔒 THE VALUE IS MACHINE-CHECKED AGAINST goproxy's `run.QueryTimeoutMessage`, not hand-matched. The
// Kotlin pair could only be kept in step by eye; a Go control plane can link the producer. The check
// is TestQueryTimeoutMessageMatchesGoproxyVerbatim in internal/app's `goproxywire`-tagged suite, which
// imports goproxy/run and compares the two constants.
//
// 🔴 IT IS DELIBERATELY NOT A DIRECT `= run.QueryTimeoutMessage` ALIAS, and the reason is a boot
// failure, not taste: goproxy/run imports goproxy/internal/pb, which registers the file
// "controlplane.proto" in protoregistry.GlobalFiles — as does controlplane/internal/pb. The runtime's
// default conflict policy is PANIC, so a production import of goproxy/run would abort the control
// plane in init() before main() runs. That is why the wire suite needs
// GOLANG_PROTOBUF_REGISTRATION_CONFLICT=warn and a build tag. Sharing the constant means one test
// linking both and failing on drift; it cannot mean one declaration until goproxy's pb directory is
// renamed.
const QueryTimeoutMessage = "statement aborted: PM_QUERY_TIMEOUT exceeded"

// outboundSendBudget bounds the ONE blocking send in this file (the RunQuery), for the reason doc.go's
// divergence 3 states: a Go channel whose drainer has died fills rather than failing, and an unbounded
// send under the cancel gate would wedge [Service.CancelActiveRun] with it.
//
// It is generous relative to what it guards — a gRPC send goroutine draining a 64-deep buffer — so a
// merely busy stream is never mistaken for a dead one.
const outboundSendBudget = 10 * time.Second

// cleanupBudget bounds the cleanup DB work (the token revoke). doc.go divergence 2.
const cleanupBudget = 10 * time.Second

// Deps is what the service needs beyond the shared core.
type Deps struct {
	// Core is the ONE shared graph (INV-A1-1). RunChannels, RunRequesterIPs, ProxyEventsHub,
	// ConnectionCatalog, TokenStore, UserGroupStore, AuditStore and DB all come from it — and they must
	// be the SAME instances the gRPC surface holds, or the proxy's Ready lands on a registry this
	// service never registered into.
	Core *core.ControlPlaneCore
	// QueryTimeoutSeconds is `RunExecService(core, queryTimeoutSeconds)`'s second parameter — the
	// configured PM_QUERY_TIMEOUT ceiling a single statement may run for. It drives the two token TTLs
	// and nothing else. Zero takes Kotlin's default of 600.
	QueryTimeoutSeconds int64
	Log                 *slog.Logger
}

// Service is `class RunExecService(core, queryTimeoutSeconds)`.
type Service struct {
	core *core.ControlPlaneCore
	log  *slog.Logger

	// The two TTLs are computed ONCE at construction, exactly as the Kotlin's `private val`s are.
	runTokenTTLSeconds       int64
	editorSessionTTLSeconds  int64
	defaultExchangeTimeoutMs int64

	activeMu   sync.Mutex
	activeRuns map[int64]*activeRun

	sessionsMu   sync.Mutex
	openSessions map[string]*openEditorSession

	// newSessionID is `UUID.randomUUID().toString()`, injectable so a test can force the
	// duplicate-registration path Kotlin's `check(putIfAbsent(...) == null)` guards.
	newSessionID func() string
	// nowNanos is System.nanoTime(), injectable for the idle sweep.
	nowNanos func() int64
}

var _ query.RunExec = (*Service)(nil)

// New builds the service.
func New(d Deps) *Service {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	q := d.QueryTimeoutSeconds
	if q <= 0 {
		// `queryTimeoutSeconds: Long = 600L` — the default that exists "so the many Config-free test
		// constructions compile unchanged".
		q = 600
	}
	return &Service{
		core:                     d.Core,
		log:                      log,
		runTokenTTLSeconds:       config.RunTokenTTLSeconds(q),
		editorSessionTTLSeconds:  config.EditorSessionTTLSeconds(q),
		defaultExchangeTimeoutMs: config.ExchangeTimeoutMS,
		activeRuns:               map[int64]*activeRun{},
		openSessions:             map[string]*openEditorSession{},
		newSessionID:             randomUUIDv4,
		nowNanos:                 func() int64 { return time.Now().UnixNano() },
	}
}

// RunTokenTTLSeconds / EditorSessionTTLSeconds expose what this instance actually computed, so a test
// asserts the SHIPPED value rather than recomputing the formula.
func (s *Service) RunTokenTTLSeconds() int64      { return s.runTokenTTLSeconds }
func (s *Service) EditorSessionTTLSeconds() int64 { return s.editorSessionTTLSeconds }

// ---------------------------------------------------------------------------------------------
// The cancel gate
// ---------------------------------------------------------------------------------------------

// activeRun is `private class ActiveRun(val outbound: SendChannel<ControlRunMsg>)`
// (RunExec.kt:188-192): a registered in-flight run, tracked so [Service.CancelActiveRun] can reach its
// stream.
//
// 🔒 INV-A7-35 — THE GATE SERIALISES "veto-or-send the query" AGAINST "cancel", so a cancel is
// strictly ordered relative to the send. Either the cancel wins the gate first and VETOES the send
// (nothing leaves the control plane and the run returns ErrRunCanceledBeforeStart), or the query is
// sent first and the cancel's RunCancel lands AFTER it on the stream — never before, which an idle
// proxy would DROP, letting a just-cancelled query run anyway.
type activeRun struct {
	outbound chan *pb.ControlRunMsg
	gate     sync.Mutex
	canceled bool
	sent     bool
}

// CancelActiveRun is `suspend fun cancelActiveRun(taskId): Boolean` (RunExec.kt:206-213).
//
// Under the run's gate: if the query was already dispatched, a RunCancel goes down its stream (the
// proxy cancels the backend statement); if it has NOT been dispatched yet, the pending send is vetoed
// so the query never leaves the control plane. Returns whether a run was registered.
func (s *Service) CancelActiveRun(_ context.Context, taskID int64) bool {
	s.activeMu.Lock()
	run := s.activeRuns[taskID]
	s.activeMu.Unlock()
	if run == nil {
		return false
	}
	run.gate.Lock()
	defer run.gate.Unlock()
	run.canceled = true
	if run.sent {
		// `trySend` — non-blocking, exactly as the Kotlin: a wedged stream must not wedge the cancel.
		trySend(run.outbound, cancelMsg())
	}
	return true
}

// register is `taskId?.let { id -> ActiveRun(outbound).also { activeRuns[id] = it } }`.
func (s *Service) register(taskID *int64, outbound chan *pb.ControlRunMsg) *activeRun {
	if taskID == nil {
		return nil
	}
	run := &activeRun{outbound: outbound}
	s.activeMu.Lock()
	s.activeRuns[*taskID] = run
	s.activeMu.Unlock()
	return run
}

// deregister is `activeRuns.remove(taskId, ar)` — ConcurrentHashMap's two-argument remove, which only
// removes when the mapped value is still THIS run. A plain delete would drop a LATER run's
// registration for the same task id.
func (s *Service) deregister(taskID *int64, run *activeRun) {
	if taskID == nil || run == nil {
		return
	}
	s.activeMu.Lock()
	if s.activeRuns[*taskID] == run {
		delete(s.activeRuns, *taskID)
	}
	s.activeMu.Unlock()
}

// sendRunQuery is `private suspend fun sendRunQuery(run, outbound, preflight, sql, maxRows)`
// (RunExec.kt:220-237).
//
// 🔒 THE SEND IS INSIDE THE CRITICAL SECTION. Not "the message is built inside and sent outside" —
// that is the reordering bug INV-A7-35 exists to prevent. `preflight` (a DB status re-check) runs
// inside the gate too, so a task cancelled in the database between claim and dispatch is vetoed here
// rather than dispatched and cancelled afterwards.
//
// An untracked run (taskID == nil) has no gate to take and sends directly.
func (s *Service) sendRunQuery(
	ctx context.Context, run *activeRun, outbound chan *pb.ControlRunMsg,
	preflight func() bool, sql string, maxRows int,
) error {
	msg := queryMsg(sql, maxRows)
	if run == nil {
		return s.sendOutbound(ctx, outbound, msg)
	}
	run.gate.Lock()
	defer run.gate.Unlock()
	if (preflight != nil && !preflight()) || run.canceled {
		return query.ErrRunCanceledBeforeStart
	}
	run.sent = true
	return s.sendOutbound(ctx, outbound, msg)
}

// sendOutbound is Kotlin's `outbound.send(msg)` — a cancellable, blocking send. See doc.go divergence
// 3 for the budget.
func (s *Service) sendOutbound(ctx context.Context, outbound chan *pb.ControlRunMsg, msg *pb.ControlRunMsg) error {
	timer := time.NewTimer(outboundSendBudget)
	defer timer.Stop()
	select {
	case outbound <- msg:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errOutboundWedged
	}
}

// errOutboundWedged is the Go analogue of ClosedSendChannelException — the run stream will not take
// the query. It is never returned to a caller; [Service.Run] and [Service.RunOnSession] translate it
// into their own ProxyRunError message, exactly as the Kotlin's catch does.
var errOutboundWedged = errors.New("the run stream would not accept the query")

// ---------------------------------------------------------------------------------------------
// run() — the one-shot path
// ---------------------------------------------------------------------------------------------

// Run is `suspend fun run(...)` (RunExec.kt:258-354).
//
// [query.RunInput.ApproverExec] selects the ephemeral token kind: false mints an EDITOR token (the web
// editor), true an APPROVER_EXEC token (the approver runs an approval). The kind drives the Cedar
// channel — an APPROVER_EXEC token carrying an assume-role set decides on the workflow-executor
// channel.
//
// 🔒 [query.RunInput.AssumeRoles] is the execute-under-R hook with ASSUME-ROLE semantics: a non-empty
// set decides under EXACTLY that role set — AS role R, not the principal's own roles and NOT a union
// (INV-A7-1). The control plane mints it onto the ephemeral token (CP authority, never
// proxy-asserted); the gRPC Decide handler forwards it as decideQuery's providedRoles, which REPLACES
// server role resolution.
//
// 🔒 This is the ONLY minter of APPROVER_EXEC tokens — [Service.OpenSession] mints EDITOR only — so it
// is also the only place APPROVER_EXEC's requester_ip becomes real.
func (s *Service) Run(ctx context.Context, in query.RunInput) (query.QueryResponse, error) {
	started := time.Now()

	kind := token.KindEditor
	if in.ApproverExec {
		kind = token.KindApproverExec
	}
	// STEP 1 — mint under the principal's advisory lock, with the on-transaction deprovisioning
	// re-check. A nil result means the principal is deprovisioned and NOTHING was written.
	issued, err := token.MintForActivePrincipalLocked(ctx, s.core.DB.Pool, s.core.UserGroupStore, in.Principal,
		func(txCtx context.Context, c store.Queryer) (token.Issued, error) {
			// The assume-role set for execute-under-R; empty otherwise. The Decide handler only honors
			// it for the ephemeral kinds, so it can never become a client-asserted role list.
			return s.core.TokenStore.Issue(txCtx, c, kind, in.Principal, in.AssumeRoles, nil, s.runTokenTTLSeconds)
		})
	if err != nil {
		return query.QueryResponse{}, err
	}
	if issued == nil {
		return query.QueryResponse{}, query.NewProxyRunError("principal is deprovisioned", nil)
	}

	// STEP 2 — the requester-IP carrier. 🔒 INV-A7-33: a nil ip is a NO-OP here (mint time), never a
	// planted absent-key sentinel.
	issuedTokenHash := token.Hash(issued.Token)
	s.core.RunRequesterIPs.Put(issuedTokenHash, in.RequesterIP)

	// STEP 3 — the enforcement connection this run's decisions bind to.
	opened, err := s.openCatalogConnection(in.Datasource, in.Principal, kind)
	if err != nil {
		// The token is already minted, so it has to come back off. Nothing else was allocated.
		s.revokeAndForget(ctx, issued.ID, in.Principal, issuedTokenHash)
		return query.QueryResponse{}, err
	}

	// STEP 4 — the rendezvous slot the proxy's Ready will claim.
	sessionID := s.newSessionID()
	pending := &core.PendingRunSession{SessionID: sessionID, Ready: make(chan *core.Attached, 1)}

	var (
		registered bool
		attached   *core.Attached
		run        *activeRun
		response   query.QueryResponse
		runErr     error
	)

	// The `finally` block, as a closure so every early return below goes through it. THE ORDER IS
	// CONTRACTUAL — see [Service.teardown].
	defer func() {
		s.deregister(in.TaskID, run)
		s.teardown(ctx, teardown{
			registered: registered, sessionID: sessionID, pending: pending, attached: attached,
			tokenID: issued.ID, principal: in.Principal, tokenHash: issuedTokenHash,
			connectionID: opened.ConnectionID, datasourceName: in.Datasource.Name,
		})
	}()

	if !s.core.RunChannels.Register(pending) {
		// `check(putIfAbsent(...) == null)` — a duplicate session id is a programming error. Kotlin
		// throws IllegalStateException, which StatusPages turns into 500; a Go error of a non-RunExec
		// kind reaches httpapi.RespondFallback for the same 500 common.fallback.
		return response, errors.New("run session '" + sessionID + "' is already registered")
	}
	registered = true

	// STEP 5 — nudge exactly one attached replica. 🔒 INV-A7-34 keeps the two failure kinds distinct.
	switch s.core.ProxyEventsHub.RequestOpenRun(
		in.Datasource.Name, sessionID, issued.Token, opened.ConnectionID.Bytes(), opened.OnOpen,
	) {
	case core.DispatchSent:
	case core.DispatchNotAttached:
		return response, query.ErrNoProxyAttached
	case core.DispatchWedged:
		return response, query.ErrProxyStreamWedged
	}

	// STEP 6 — await the dial. A timeout here is TYPED, so the route answers 504 rather than 500.
	attached, runErr = s.awaitReady(ctx, pending, in.DialTimeoutMs)
	if runErr != nil {
		return response, runErr
	}

	// STEP 7 — register the cancel gate (only for a tracked task), then dispatch under it.
	run = s.register(in.TaskID, attached.Outbound)
	if err := s.sendRunQuery(ctx, run, attached.Outbound, in.Preflight, in.SQL, in.MaxRows); err != nil {
		return response, s.sendFailure(ctx, err, "proxy run stream closed before the query was sent")
	}

	// STEP 8 — collect, bounded by the exchange budget.
	return s.collectWithin(ctx, attached.Inbound, started, s.exchangeTimeout(in.ExchangeTimeoutMs))
}

// sendFailure is the Kotlin's three-armed catch around sendRunQuery: RunCanceledBeforeStart passes
// through untouched, `currentCoroutineContext().ensureActive()` rethrows a genuine cancellation, and
// anything else becomes a ProxyRunException with the caller's message.
func (s *Service) sendFailure(ctx context.Context, err error, message string) error {
	if errors.Is(err, query.ErrRunCanceledBeforeStart) {
		return err
	}
	// ensureActive(): a cancelled enclosing scope is reported as cancellation, not as a proxy fault.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return query.NewProxyRunError(message, err)
}

// awaitReady is `withTimeout(dialTimeoutMs) { pending.ready.await() }`, with the
// TimeoutCancellationException → ProxyRunTimeoutException mapping.
func (s *Service) awaitReady(ctx context.Context, pending *core.PendingRunSession, dialTimeoutMs int64) (*core.Attached, error) {
	if dialTimeoutMs <= 0 {
		dialTimeoutMs = config.DialTimeoutMS
	}
	timer := time.NewTimer(time.Duration(dialTimeoutMs) * time.Millisecond)
	defer timer.Stop()
	select {
	case a := <-pending.Ready:
		return a, nil
	case <-timer.C:
		return nil, query.ErrProxyRunTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// exchangeTimeout applies `exchangeTimeoutMs: Long = EXCHANGE_TIMEOUT_MS` — the fallback every
// production caller overrides with Config.queryExchangeTimeoutMs.
func (s *Service) exchangeTimeout(ms int64) time.Duration {
	if ms <= 0 {
		ms = s.defaultExchangeTimeoutMs
	}
	return time.Duration(ms) * time.Millisecond
}

// collectWithin is `withTimeout(exchangeTimeoutMs) { collectResponse(inbound, started) }`.
func (s *Service) collectWithin(
	ctx context.Context, inbound chan *pb.ProxyRunMsg, started time.Time, budget time.Duration,
) (query.QueryResponse, error) {
	timer := time.NewTimer(budget)
	defer timer.Stop()
	return s.collectResponse(ctx, timer.C, inbound, started)
}

// teardown carries [Service.Run]'s `finally` block.
//
// 🔒 INV-A7-36 — THE `attached == nil && remove(...) == nil` DANCE HANDLES THE CANCEL/ATTACH RACE. If
// cancellation or the dial timeout races the proxy's claim, Remove wins while the session is still
// pending and there is nothing to close. Otherwise Attach already won and completed Ready, so cleanup
// must RECOVER the outbound channel to send the RunClose — under a non-cancellable context, because
// the enclosing one is already cancelling. Without this the proxy holds a backend connection forever.
//
// 🔒 INV-A7-37 — THE NESTING GUARANTEES REVOKE-THEN-CLEANUP EVEN IF THE CLOSE SEND FAILS. The token
// revoke and the registry removal happen on EVERY path, which is why they are deferred here rather
// than written sequentially after the trySend.
type teardown struct {
	registered     bool
	sessionID      string
	pending        *core.PendingRunSession
	attached       *core.Attached
	tokenID        int64
	principal      string
	tokenHash      string
	connectionID   datasource.ConnectionID
	datasourceName string
}

func (s *Service) teardown(ctx context.Context, t teardown) {
	cleanup, cancel := cleanupContext(ctx)
	defer cancel()

	// INV-A7-37's innermost `finally`, first in Go's LIFO order so it runs last.
	defer func() {
		s.closeConnectionCatalog(t.connectionID, t.datasourceName)
		s.core.RunRequesterIPs.Remove(t.tokenHash)
		if t.registered {
			s.core.RunChannels.Remove(t.sessionID)
		}
	}()
	defer func() {
		if _, err := s.core.TokenStore.Revoke(cleanup, t.tokenID, t.principal); err != nil {
			s.log.Warn("run cleanup: ephemeral token revoke failed", "token", t.tokenID, "err", err)
		}
	}()

	attached := t.attached
	if t.registered && attached == nil && s.core.RunChannels.Remove(t.sessionID) == nil {
		// Attach won: Ready is completed (or is being completed) with the record, so this receive
		// terminates. Ready is buffered(1) precisely so Attach's send never blocks.
		select {
		case attached = <-t.pending.Ready:
		case <-cleanup.Done():
			s.log.Warn("run cleanup: could not recover the attached run stream; the proxy may hold its backend connection",
				"session", t.sessionID)
		}
	}
	if attached != nil {
		trySend(attached.Outbound, closeMsg())
	}
}

// cleanupContext is doc.go divergence 2 — a WithoutCancel copy with its own budget, so a cancelled or
// client-disconnected request still revokes its ephemeral token.
func cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), cleanupBudget)
}

// openCatalogConnection is `core.connectionCatalog.open(Binding(...), ds.defaultSchemas +
// ds.engine.systemSchemas, adoptHeldContent = ds.engine.catalogIsConnectionIndependent)`.
//
// 🔒 INV-A5-6 — adoptHeldContent must come from the ENGINE, never be hardcoded. True for MySQL, where
// a catalog scan cannot vary by connection; FALSE for Postgres, where pg_temp_* is per-session and
// adopting another connection's content would let this one decide against tables it cannot see.
func (s *Service) openCatalogConnection(
	ds datasource.Datasource, principal string, kind token.Kind,
) (datasource.OpenConnection, error) {
	system, err := datasource.SystemSchemaNames(ds.Engine)
	if err != nil {
		return datasource.OpenConnection{}, err
	}
	adopt, err := datasource.CatalogIsConnectionIndependent(ds.Engine)
	if err != nil {
		return datasource.OpenConnection{}, err
	}
	schemas := append(append([]string{}, ds.DefaultSchemas...), system...)
	return s.core.ConnectionCatalog.Open(
		datasource.Binding{DatasourceName: ds.Name, Principal: principal, TokenKind: string(kind)},
		schemas, adopt,
	), nil
}

// closeConnectionCatalog is `private fun closeConnectionCatalog(connectionId, datasourceName)`
// (RunExec.kt:542-546) MINUS its runBlocking wrapper — doc.go divergence 1. A rejection is swallowed
// exactly as the Kotlin's `runCatching` swallows a throw: the connection is already gone or was never
// ours, and neither is worth failing a completed query over.
func (s *Service) closeConnectionCatalog(connectionID datasource.ConnectionID, datasourceName string) {
	if connectionID == "" {
		return
	}
	if rejected, ok := s.core.ConnectionCatalog.Close(connectionID, datasourceName).(datasource.Rejected); ok {
		s.log.Debug("run cleanup: connection catalog close rejected",
			"datasource", datasourceName, "reason", rejected.Description)
	}
}

// revokeAndForget is the two-line unwind for a failure that happens after the mint but before
// anything else was allocated.
func (s *Service) revokeAndForget(ctx context.Context, tokenID int64, principal, tokenHash string) {
	cleanup, cancel := cleanupContext(ctx)
	defer cancel()
	if _, err := s.core.TokenStore.Revoke(cleanup, tokenID, principal); err != nil {
		s.log.Warn("run cleanup: ephemeral token revoke failed", "token", tokenID, "err", err)
	}
	s.core.RunRequesterIPs.Remove(tokenHash)
}

// ---------------------------------------------------------------------------------------------
// Persistent per-editor-session streams
// ---------------------------------------------------------------------------------------------

// openEditorSession is `data class OpenEditorSession(...)` (RunExec.kt:65-79): one held proxy stream
// plus its per-session token.
//
// `mutex` serialises queries on the single stream — two concurrent queries would interleave on it —
// and `lastUsedNanos` drives idle reaping. Held only while the session is live; removed and revoked on
// close.
type openEditorSession struct {
	sessionID      string
	principal      string
	tokenID        int64
	datasourceName string
	attached       *core.Attached
	connectionID   datasource.ConnectionID
	// lastUsedNanos is Kotlin's `@Volatile var` — atomic because [Service.SweepIdleSessions] reads it
	// without taking the session's mutex.
	lastUsedNanos atomic.Int64
	mu            sync.Mutex
	// tokenHash lets closeSession remove this session's requester-IP entry alongside its token revoke.
	tokenHash string
}

// OpenSession is `suspend fun openSession(principal, ds, requesterIp)` (RunExec.kt:374-418).
//
// Mint a per-session EDITOR token, dial ONE proxy stream, and hold it. The proxy keeps its dedicated
// backend connection alive for the life of the session. On ANY failure to establish, the pending
// registration, the token and any half-open stream are cleaned up before returning.
func (s *Service) OpenSession(
	ctx context.Context, principal string, ds datasource.Datasource, requesterIP *string,
) (string, error) {
	issued, err := token.MintForActivePrincipalLocked(ctx, s.core.DB.Pool, s.core.UserGroupStore, principal,
		func(txCtx context.Context, c store.Queryer) (token.Issued, error) {
			return s.core.TokenStore.Issue(txCtx, c, token.KindEditor, principal, nil, nil, s.editorSessionTTLSeconds)
		})
	if err != nil {
		return "", err
	}
	if issued == nil {
		return "", query.NewProxyRunError("principal is deprovisioned", nil)
	}
	issuedTokenHash := token.Hash(issued.Token)
	s.core.RunRequesterIPs.Put(issuedTokenHash, requesterIP)

	opened, err := s.openCatalogConnection(ds, principal, token.KindEditor)
	if err != nil {
		s.revokeAndForget(ctx, issued.ID, principal, issuedTokenHash)
		return "", err
	}

	sessionID := s.newSessionID()
	pending := &core.PendingRunSession{SessionID: sessionID, Ready: make(chan *core.Attached, 1)}
	var attached *core.Attached

	// `catch (e: Throwable) { …the same recovery dance… ; throw e }`. Written as a named failure path
	// rather than a defer because the SUCCESS path must NOT tear the session down.
	fail := func(err error) (string, error) {
		if attached == nil && s.core.RunChannels.Remove(sessionID) == nil {
			cleanup, cancel := cleanupContext(ctx)
			select {
			case attached = <-pending.Ready:
			case <-cleanup.Done():
			}
			cancel()
		}
		if attached != nil {
			trySend(attached.Outbound, closeMsg())
		}
		cleanup, cancel := cleanupContext(ctx)
		defer cancel()
		if _, revokeErr := s.core.TokenStore.Revoke(cleanup, issued.ID, principal); revokeErr != nil {
			s.log.Warn("openSession cleanup: token revoke failed", "token", issued.ID, "err", revokeErr)
		}
		s.closeConnectionCatalog(opened.ConnectionID, ds.Name)
		s.core.RunRequesterIPs.Remove(issuedTokenHash)
		s.core.RunChannels.Remove(sessionID)
		return "", err
	}

	if !s.core.RunChannels.Register(pending) {
		return fail(errors.New("run session '" + sessionID + "' is already registered"))
	}
	switch s.core.ProxyEventsHub.RequestOpenRun(
		ds.Name, sessionID, issued.Token, opened.ConnectionID.Bytes(), opened.OnOpen,
	) {
	case core.DispatchSent:
	case core.DispatchNotAttached:
		return fail(query.ErrNoProxyAttached)
	case core.DispatchWedged:
		return fail(query.ErrProxyStreamWedged)
	}
	// ⚠️ openSession does NOT take a dial-timeout parameter in the Kotlin — it uses DIAL_TIMEOUT_MS
	// flat. Reproduced, so an editor open is bounded by the same measured cold-open budget.
	attached, err = s.awaitReady(ctx, pending, config.DialTimeoutMS)
	if err != nil {
		return fail(err)
	}

	session := &openEditorSession{
		sessionID: sessionID, principal: principal, tokenID: issued.ID, datasourceName: ds.Name,
		attached: attached, connectionID: opened.ConnectionID, tokenHash: issuedTokenHash,
	}
	session.lastUsedNanos.Store(s.nowNanos())
	s.sessionsMu.Lock()
	s.openSessions[sessionID] = session
	s.sessionsMu.Unlock()
	return sessionID, nil
}

// lookupSession is `openSessions[sessionId]?.takeIf { it.principal == principal }`.
func (s *Service) lookupSession(sessionID, principal string) *openEditorSession {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	session := s.openSessions[sessionID]
	if session == nil || session.principal != principal {
		return nil
	}
	return session
}

// isLive is the `openSessions[sessionId] !== session` identity re-check, inverted.
//
// 🔒 IDENTITY, NOT EQUALITY. A concurrent lock-free [Service.CloseSession] (the DELETE route or the
// idle sweep) may have removed and revoked this session while a query queued for its mutex. `!==` is
// safe because sessionID is a fresh UUID, so a re-open can never resurrect the same object.
func (s *Service) isLive(session *openEditorSession) bool {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	return s.openSessions[session.sessionID] == session
}

// RunOnSession is `suspend fun runOnSession(...)` (RunExec.kt:431-494).
//
// Run one query on an open session's stream and return its ENFORCED result. Serialised per session (a
// session runs one statement at a time). A stream failure closes the session fail-closed. The
// principal MUST own the session — no cross-principal use.
//
// 🔒 The requester IP is refreshed onto the session token's registry entry UNDER THE MUTEX AND BEFORE
// THE QUERY CROSSES THE WIRE, so the gRPC decide it triggers reads exactly this query's value.
// requester_ip is resolved fresh per decision, so a session opened from one network and queried from
// another decides against the CURRENT request's IP. A nil RequesterIP CLEARS the entry (INV-A7-33) —
// fail-closed, never leaving the open-time IP stale.
func (s *Service) RunOnSession(ctx context.Context, in query.SessionRunInput) (query.QueryResponse, error) {
	session := s.lookupSession(in.SessionID, in.Principal)
	if session == nil {
		return query.QueryResponse{}, query.NewProxyRunError("no such editor session", nil)
	}

	// 🔒 The OUTER finally (RunExec.kt:485-493): if a lock-free CloseSession raced this query and won,
	// the registry Set below may have RE-CREATED an entry the close already swept — AFTER the token
	// was revoked. Sweep it back out so a stale entry can never outlive its token. Idempotent with
	// CloseSession's own remove; a no-op on the normal path.
	defer func() {
		if !s.isLive(session) && session.tokenHash != "" {
			s.core.RunRequesterIPs.Remove(session.tokenHash)
		}
	}()

	session.mu.Lock()
	defer session.mu.Unlock()

	if !s.isLive(session) {
		return query.QueryResponse{}, query.NewProxyRunError("no such editor session", nil)
	}

	run := s.register(in.TaskID, session.attached.Outbound)
	defer s.deregister(in.TaskID, run)

	started := time.Now()
	session.lastUsedNanos.Store(s.nowNanos())
	// 🔒 BEFORE THE SEND. Moving this below sendRunQuery leaves the decide this query triggers reading
	// the PREVIOUS query's (or the open-time) IP — see EditorSessionDecideTimingDbTest, whose whole
	// existence is to fail when it moves.
	if session.tokenHash != "" {
		s.core.RunRequesterIPs.Set(session.tokenHash, in.RequesterIP)
	}

	if err := s.sendRunQuery(ctx, run, session.attached.Outbound, in.Preflight, in.SQL, in.MaxRows); err != nil {
		if errors.Is(err, query.ErrRunCanceledBeforeStart) {
			return query.QueryResponse{}, err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return query.QueryResponse{}, ctxErr
		}
		s.CloseSession(in.SessionID)
		return query.QueryResponse{}, query.NewProxyRunError("editor session stream closed before the query was sent", err)
	}

	response, err := s.collectWithin(ctx, session.attached.Inbound, started, s.exchangeTimeout(in.ExchangeTimeoutMs))
	switch {
	case err == nil:
		return response, nil
	case errors.Is(err, query.ErrProxyRunTimeout):
		s.CloseSession(in.SessionID)
		return query.QueryResponse{}, err
	default:
		// A query-level error — a cancelled statement, a backend error — ends the persistent PROXY
		// session (its run loop returns on any query error), so drop the CP-side one too. The next
		// submit then reopens cleanly instead of failing on a since-dead stream.
		var pre *query.ProxyRunError
		if errors.As(err, &pre) {
			s.CloseSession(in.SessionID)
		}
		return query.QueryResponse{}, err
	}
}

// SessionDatasourceName is `fun sessionDatasourceName(sessionId, principal)` (RunExec.kt:503-504).
//
// 🔒 OWNER-SCOPED, mirroring RunOnSession's ownership check: not-found for an unknown OR a not-owned
// id. The async editor submit resolves the task's datasource this way, so a leaked session id can
// never launch a task against another principal's connection.
func (s *Service) SessionDatasourceName(sessionID, principal string) (string, bool) {
	session := s.lookupSession(sessionID, principal)
	if session == nil {
		return "", false
	}
	return session.datasourceName, true
}

// CloseSessionOwnedBy is `fun closeSessionOwnedBy(sessionId, principal)` (RunExec.kt:512-516).
//
// 🔒 A non-owner (or an unknown id) is a SILENT NO-OP that reveals nothing about whether the id
// exists, and — the part that matters — cannot tear down that user's held connection or revoke its
// token. Returns true iff a session the caller owned was closed.
func (s *Service) CloseSessionOwnedBy(sessionID, principal string) bool {
	if s.lookupSession(sessionID, principal) == nil {
		return false
	}
	s.CloseSession(sessionID)
	return true
}

// CloseSessionsForPrincipal is `fun closeSessionsForPrincipal(principal)` (RunExec.kt:518-520) — the
// session-end seam's hook, so signing out releases the backend connections the tabs were holding.
func (s *Service) CloseSessionsForPrincipal(principal string) {
	s.sessionsMu.Lock()
	ids := make([]string, 0, len(s.openSessions))
	for id, session := range s.openSessions {
		if session.principal == principal {
			ids = append(ids, id)
		}
	}
	s.sessionsMu.Unlock()
	for _, id := range ids {
		s.CloseSession(id)
	}
}

// CloseSession is `fun closeSession(sessionId)` (RunExec.kt:523-533): end the proxy stream and revoke
// the token. IDEMPOTENT — a missing session is a no-op, which is what makes the DELETE route's 204 and
// the idle sweep safe to overlap.
//
// Not owner-scoped: it is the internal primitive. [Service.CloseSessionOwnedBy] is the one a route
// reaches.
func (s *Service) CloseSession(sessionID string) {
	s.sessionsMu.Lock()
	session := s.openSessions[sessionID]
	if session != nil {
		delete(s.openSessions, sessionID)
	}
	s.sessionsMu.Unlock()
	if session == nil {
		return
	}
	trySend(session.attached.Outbound, closeMsg())
	// `finally` — every one of these runs even if the close send failed.
	cleanup, cancel := cleanupContext(context.Background())
	defer cancel()
	if _, err := s.core.TokenStore.Revoke(cleanup, session.tokenID, session.principal); err != nil {
		s.log.Warn("closeSession: token revoke failed", "token", session.tokenID, "err", err)
	}
	s.closeConnectionCatalog(session.connectionID, session.datasourceName)
	if session.tokenHash != "" {
		s.core.RunRequesterIPs.Remove(session.tokenHash)
	}
	s.core.RunChannels.Remove(sessionID)
}

// SweepIdleSessions is `fun sweepIdleSessions(maxIdleMs)` (RunExec.kt:536-539) — reap sessions idle
// longer than maxIdleMs, releasing their backend connections. Called on A1's 15-minute timer with
// 30 minutes.
func (s *Service) SweepIdleSessions(maxIdleMs int64) int {
	cutoff := s.nowNanos() - maxIdleMs*1_000_000
	s.sessionsMu.Lock()
	ids := make([]string, 0, len(s.openSessions))
	for id, session := range s.openSessions {
		if session.lastUsedNanos.Load() < cutoff {
			ids = append(ids, id)
		}
	}
	s.sessionsMu.Unlock()
	for _, id := range ids {
		s.CloseSession(id)
	}
	return len(ids)
}

// OpenSessionCount is a test/diagnostic read of the live session count. It has no Kotlin counterpart
// (the Kotlin's map is directly reachable from its own test file); it exists so the sweep and the
// close-for-principal paths are observable without exporting the map.
func (s *Service) OpenSessionCount() int {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	return len(s.openSessions)
}

// ---------------------------------------------------------------------------------------------
// Message builders
// ---------------------------------------------------------------------------------------------

// maxWireRows is the ceiling `maxRows.coerceIn(0, 5000)` clamps to.
const maxWireRows = 5000

// coerceMaxRows is `maxRows.coerceIn(0, 5000)`.
//
// 🔒 ZERO IS PRESERVED, AND IT IS A WIRE SENTINEL, NOT A MISTAKE: 0 means "use the proxy's default
// (500)", which the proxy re-coerces into [1, 5000]. Clamping to [1, 5000] here would turn every
// default-max-rows query into a one-row query.
func coerceMaxRows(n int) int32 {
	if n < 0 {
		return 0
	}
	if n > maxWireRows {
		return maxWireRows
	}
	return int32(n)
}

func queryMsg(sql string, maxRows int) *pb.ControlRunMsg {
	return &pb.ControlRunMsg{Kind: &pb.ControlRunMsg_Query{Query: &pb.RunQuery{
		Sql: sql, MaxRows: coerceMaxRows(maxRows),
	}}}
}

func closeMsg() *pb.ControlRunMsg {
	return &pb.ControlRunMsg{Kind: &pb.ControlRunMsg_Close{Close: &pb.RunClose{}}}
}

func cancelMsg() *pb.ControlRunMsg {
	return &pb.ControlRunMsg{Kind: &pb.ControlRunMsg_Cancel{Cancel: &pb.RunCancel{}}}
}

// trySend is Kotlin's `SendChannel.trySend(...)` — offer, never block, ignore the outcome.
//
// 🔒 It must stay non-blocking. Every caller is a cleanup or a cancel path, and blocking there on a
// wedged proxy would hold the cancel gate (or the teardown) open indefinitely.
func trySend(ch chan *pb.ControlRunMsg, msg *pb.ControlRunMsg) bool {
	select {
	case ch <- msg:
		return true
	default:
		return false
	}
}

// randomUUIDv4 is `UUID.randomUUID().toString()` — 122 random bits in the canonical 8-4-4-4-12 hex
// form, version nibble 4, variant bits 10.
//
// Hand-rolled for the reason internal/session/cookie.go states at its identical helper: the module has
// github.com/google/uuid only as an INDIRECT dependency, and promoting it to write sixteen bytes of
// CSPRNG output is not a trade worth making.
//
//	TODO: two copies now. If a third appears, lift one into internal/types (the only leaf both
//	internal/session and this package can import) rather than adding it.
//
// 🔒 A CSPRNG FAILURE PANICS RATHER THAN FALLING BACK, matching
// datasource.ConnectionCatalogRegistry.Open's documented choice at the same kind of identifier. A run
// session id is not cosmetic: it travels to the proxy over the Events stream and whoever presents it
// back CLAIMS the session, ephemeral token included (INV-A7-32). A guessable one is a token
// disclosure, so a non-CSPRNG id must never be issued.
func randomUUIDv4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Errorf("runexec: run session id CSPRNG read failed: %w", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, 36)
	for i, v := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, hexDigits[v>>4], hexDigits[v&0x0f])
	}
	return string(out)
}
