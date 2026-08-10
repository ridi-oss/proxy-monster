package com.ridi.oss.proxymonster.controlplane

import com.google.protobuf.ByteString
import com.ridi.oss.proxymonster.grpc.ControlRunMsg
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.ProxyRunMsg
import com.ridi.oss.proxymonster.grpc.controlRunMsg
import com.ridi.oss.proxymonster.grpc.runCancel
import com.ridi.oss.proxymonster.grpc.runClose
import com.ridi.oss.proxymonster.grpc.runQuery
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.SendChannel
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

// Floor for a one-shot run token's TTL; the effective TTL grows to cover PM_QUERY_TIMEOUT (see
// RunExecService.runTokenTtlSeconds). The floor alone must outlast a full-length dial-back + target-DB open +
// exchange, so a short PM_QUERY_TIMEOUT cannot leave an opening session's token expiring mid-statement.
private const val RUN_TOKEN_TTL_FLOOR_SECONDS = 900L
// A persistent editor SESSION token outlives many queries; give it a generous absolute TTL (sliding
// refresh-on-activity is a follow-up) and bound the session with idle-sweep + explicit close. Per-session
// and revoked on close, so a long TTL is not a standing credential.
private const val EDITOR_SESSION_TTL_SECONDS = 8 * 3600L
// Headroom over PM_QUERY_TIMEOUT for a one-shot run token's TTL. The token must outlive the WHOLE run it
// authorizes — the stream dial-back (RUN_DIALBACK_TIMEOUT_MS) + the hard-capped target-DB open
// (RUN_OPEN_TIMEOUT_MS) + the query exchange (PM_QUERY_TIMEOUT + QUERY_EXCHANGE_GRACE_MS) — so this grace
// must exceed dial-back + open + the exchange grace (15 + 120 + 150 = 285s), the remainder being a
// revalidation buffer. The open being HARD-capped (not merely liveness-bounded) keeps that sum finite;
// ConfigGuardTest pins the arithmetic so a change to any of those bounds cannot silently under-budget this.
private const val TOKEN_TTL_GRACE_SECONDS = 300L
// The control-plane dispatched this run earlier and is waiting for the proxy to open a stream for it. When the
// proxy opens that stream it sends the run's session id as the first frame, so the control-plane can tell WHICH
// pending run the new stream is for. This bounds only that — the proxy opening the stream and sending the id —
// which is near-instant when the proxy is alive. A proxy that got the dispatch but cannot open the stream
// (dead/wedged, or drained between dispatch and dial) fails here rather than hanging; the target-DB open that
// follows is bounded by RUN_NO_PROGRESS_TIMEOUT_MS + RUN_OPEN_TIMEOUT_MS.
internal const val RUN_DIALBACK_TIMEOUT_MS = 15_000L
// Once the control-plane knows which run the stream is for, the proxy heartbeats RunProgress while it dials +
// authenticates the backend and runs its on-open catalog commands, then sends RunServing. The CP waits for
// RunServing under TWO bounds: this no-progress gap — a dead or cut proxy stops heartbeating and fails fast —
// AND the absolute ceiling below. A heartbeat proves the PROXY is alive, NOT that the backend is advancing, so
// a proxy blocked on a wedged backend read keeps ticking; RUN_OPEN_TIMEOUT_MS is what bounds that.
internal const val RUN_NO_PROGRESS_TIMEOUT_MS = 15_000L
// Absolute ceiling on the whole target-DB open (the dial-back above excluded): even while heartbeats keep the
// no-progress bound reset, the open cannot exceed this. Sized at the old blind dial budget so a legitimately
// slow open is not regressed, while a stalled-but-heartbeating one fails here instead of riding the backend
// read-idle timeout — and, being finite, it keeps the run token's TTL grace (which must outlast the open)
// sufficient.
internal const val RUN_OPEN_TIMEOUT_MS = 120_000L
// The table-detail channel keeps a single fixed dial bound (metadata-only introspection, no slow backend
// open with liveness heartbeats), so it is unaffected by the run-channel's dial-back/no-progress split.
internal const val DIAL_TIMEOUT_MS = 120_000L
// Fallback only: every production path passes Config.queryExchangeTimeoutMs, which tracks
// PM_QUERY_TIMEOUT plus a grace so the proxy's own watchdog always fires first. This value exists for
// callers that supply no config, and matches the default query timeout on the same principle.
internal const val EXCHANGE_TIMEOUT_MS = 630_000L

/** A CP-driven request waiting for the proxy to dial its dedicated [ControlRunMsg] stream. */
data class PendingSession(
    val sessionId: String,
    val principal: String,
    val tokenId: Long,
    val ready: CompletableDeferred<Attached>,
)

/** The two directions of one claimed run stream. */
data class Attached(
    val outbound: SendChannel<ControlRunMsg>,
    val inbound: Channel<ProxyRunMsg>,
)

/** An open persistent editor session: one held proxy stream ([attached]) + its per-session token,
 *  keyed by [sessionId]. [mutex] serializes queries on the single stream (one statement at a time);
 *  [lastUsedNanos] drives idle reaping. Held only while the session is live; removed + revoked on close. */
data class OpenEditorSession(
    val sessionId: String,
    val principal: String,
    val tokenId: Long,
    val datasourceName: String,
    val attached: Attached,
    val connectionId: ByteString,
    @Volatile var lastUsedNanos: Long = System.nanoTime(),
    val mutex: Mutex = Mutex(),
    // The HTTP requester IP observed at open, and the session token's hash — so [closeSession]
    // can remove this session's [ControlPlaneCore.runRequesterIps] entry alongside its token revoke.
    // Defaulted (null) so existing constructions (incl. test fixtures) compile unchanged.
    val requesterIp: String? = null,
    val tokenHash: String? = null,
)

/**
 * Matches a CP-driven request to the proxy-dialed `RunExec` stream that serves it, by the session id the
 * proxy sends as the stream's first frame. A session can be claimed exactly once: [attach] atomically
 * removes it from the pending map, so an unknown or duplicate stream is rejected instead of being allowed
 * to share another request's token/query.
 */
class RunChannelRegistry {
    private val pending = ConcurrentHashMap<String, PendingSession>()

    fun register(session: PendingSession) {
        check(pending.putIfAbsent(session.sessionId, session) == null) {
            "run session '${session.sessionId}' is already registered"
        }
    }

    fun attach(sessionId: String, outbound: SendChannel<ControlRunMsg>): Attached? {
        val session = pending.remove(sessionId) ?: return null
        val attached = Attached(outbound, Channel(Channel.BUFFERED))
        session.ready.complete(attached)
        return attached
    }

    fun remove(sessionId: String): PendingSession? = pending.remove(sessionId)
}

/**
 * A CP-only carrier for the HTTP requester IP (docs/authz-context.md) observed when an
 * ephemeral EDITOR/APPROVER_EXEC token was minted ([RunExecService.openSession] / [RunExecService.run]),
 * keyed by the token's SHA-256 hash ([tokenHash] — never the raw token, mirroring `proxy_token.token_hash`).
 * Consumed by the gRPC `decide` handler (ControlPlaneGrpcService), which sees only the resolved token — not
 * the HTTP request that minted it — so this is how the requester_ip attested at mint time reaches the async
 * decide-time Cedar context. Entry lifetime == token lifetime: [put] at issuance, [remove] on revoke (both the
 * success and failure/cleanup paths) so a stale entry never outlives its token. An absent entry (never minted
 * with an IP, or already removed) means [get] returns null — requester_ip is then simply absent on that
 * decision, fail-closed (a tag/policy conditioned on it doesn't fire), never a stale/wrong IP resurrected from
 * a since-revoked token. Lives on [ControlPlaneCore] (`runRequesterIps`) for the SAME reason `runChannels`
 * does: [com.ridi.oss.proxymonster.controlplane.grpc.ControlPlaneGrpcService] is constructed independently in
 * Main.kt, before `Application.module`'s [RunExecService] exists — only `core`-held state reaches both.
 *
 * For a ONE-SHOT token ([RunExecService.run]) the entry is a constant of the token's short life. For a
 * PERSISTENT session ([RunExecService.openSession]) the token outlives many queries, so [runOnSession]
 * REFRESHES the entry ([set]) to each query's own requester_ip before the decision — requester_ip is resolved
 * fresh per decision (authz-context.md), never frozen at open time, so a session opened from one network but
 * queried from another decides against the CURRENT request's IP, not the stale one.
 */
class RequesterIpRegistry {
    private val ips = ConcurrentHashMap<String, String>()

    /** A null [ip] is a no-op — nothing to carry, and it must not clobber (or plant) an absent-key sentinel.
     *  This is the MINT-time write ([run]/[openSession]): the key doesn't exist yet, so there is nothing to
     *  refresh — [set] is the per-decision refresh that must also be able to CLEAR a since-changed IP. */
    fun put(tokenHash: String, ip: String?) {
        if (ip != null) ips[tokenHash] = ip
    }

    /** Per-decision REFRESH ([runOnSession]): set [tokenHash]'s carried IP to exactly [ip], INCLUDING clearing
     *  it when [ip] is null. Unlike [put], a null here is NOT a no-op — a persistent session queried from a
     *  network whose requester_ip can't be resolved must not inherit the (possibly trusted) open-time IP; the
     *  attribute goes absent → fail-closed, never stale. */
    fun set(tokenHash: String, ip: String?) {
        if (ip == null) ips.remove(tokenHash) else ips[tokenHash] = ip
    }

    fun get(tokenHash: String): String? = ips[tokenHash]

    fun remove(tokenHash: String) {
        ips.remove(tokenHash)
    }
}

sealed class RunExecException(message: String, cause: Throwable? = null) : Exception(message, cause)

class NoProxyAttachedException : RunExecException("no proxy is attached to this datasource")

/**
 * A proxy IS attached, but its event stream would not accept the request — already closed by a reset the
 * server has not finished tearing down, or its consumer stopped draining. Separate from
 * [NoProxyAttachedException] because the operator answer differs: nothing is missing, a live stream is
 * unusable, and the wedged one has been dropped so the proxy's own reconnect can replace it. Retrying
 * after that reconnect is the fix; looking for an absent proxy is not.
 */
class ProxyStreamWedgedException : RunExecException("the proxy's event stream would not accept the request")

class ProxyRunTimeoutException(cause: Throwable? = null) :
    RunExecException("the proxy run channel timed out", cause)

class ProxyRunException(message: String, cause: Throwable? = null) : RunExecException(message, cause)

class RunCanceledBeforeStartException : RunExecException("the run was canceled before it started")

/** Runs one CP-driven query over a proxy-dialed `RunExec` stream. */
class RunExecService(
    private val core: ControlPlaneCore,
    // The configured PM_QUERY_TIMEOUT ceiling a single statement may run for. The run/session token must
    // outlive the whole exchange it backs (dial + this window + revalidation), else a genuine long query
    // fails UNAUTHENTICATED when the proxy revalidates the token mid-run. Defaulted so the many
    // Config-free test constructions compile unchanged.
    queryTimeoutSeconds: Long = 600L,
) {
    private val activeRuns = ConcurrentHashMap<Long, ActiveRun>()

    /**
     * A registered in-flight run, tracked so [cancelActiveRun] can reach its stream. The [gate] serializes
     * "veto-or-send the query" against "cancel", so a cancel is strictly ordered relative to the query send:
     * it either wins the gate first and vetoes the send (nothing leaves the CP), or the query is sent first
     * and the cancel's `RunCancel` lands AFTER it on the stream — never before, which an idle proxy would
     * drop, letting a just-canceled query run anyway.
     */
    private class ActiveRun(val outbound: SendChannel<ControlRunMsg>) {
        val gate = Mutex()
        var canceled = false
        var sent = false
    }

    // A one-shot run token grows with PM_QUERY_TIMEOUT (keeping the prior 300s as a floor for short
    // timeouts); an editor SESSION token keeps its generous absolute TTL but is never allowed to expire
    // before a single query on it could finish.
    private val runTokenTtlSeconds = runTokenTtlSeconds(queryTimeoutSeconds)
    private val editorSessionTtlSeconds = editorSessionTtlSeconds(queryTimeoutSeconds)

    /**
     * Cancel the in-flight run for [taskId] if one is registered. Under the run's [ActiveRun.gate]: if the
     * query was already dispatched, a `RunCancel` is sent down its stream (the proxy cancels the backend
     * statement); if it has NOT been dispatched yet, the pending send is vetoed (the run coroutine throws
     * [RunCanceledBeforeStartException]) so the query never leaves the CP. Returns whether a run was found.
     */
    suspend fun cancelActiveRun(taskId: Long): Boolean {
        val run = activeRuns[taskId] ?: return false
        run.gate.withLock {
            run.canceled = true
            if (run.sent) run.outbound.trySend(controlRunMsg { cancel = runCancel {} })
        }
        return true
    }

    /**
     * Dispatch a `RunQuery` under the task's cancel gate (when tracked): if a cancel already won, veto the
     * send with [RunCanceledBeforeStartException]; otherwise mark it sent and send UNDER the gate so a
     * racing cancel is ordered strictly after. [preflight] (a DB status re-check) runs inside the gate too.
     */
    private suspend fun sendRunQuery(
        run: ActiveRun?,
        outbound: SendChannel<ControlRunMsg>,
        preflight: (() -> Boolean)?,
        sql: String,
        maxRows: Int,
    ) {
        val msg = controlRunMsg { query = runQuery { this.sql = sql; this.maxRows = maxRows.coerceIn(0, 5000) } }
        if (run == null) {
            outbound.send(msg)
            return
        }
        run.gate.withLock {
            if (preflight?.invoke() == false || run.canceled) throw RunCanceledBeforeStartException()
            run.sent = true
            outbound.send(msg)
        }
    }

    /**
     * Run one query over a proxy-dialed RunExec stream, decided as [principal]; the proxy executes on the
     * target and streams back the ENFORCED (decided + masked) result — the control-plane never dials.
     *
     * [approverExec] selects the ephemeral token kind: false mints an EDITOR token (the web editor), true
     * mints an APPROVER_EXEC token (the approver runs an approval). The kind drives the Cedar channel
     * (an APPROVER_EXEC token carrying an assume-role set decides on the workflow-executor channel).
     *
     * [assumeRoles] is the APPROVAL execute-under-R hook with ASSUME-ROLE semantics: a non-empty set decides
     * under EXACTLY that role set — the query runs AS role R, not [principal]'s own roles and not a union.
     * The control-plane mints it onto the ephemeral token (CP authority, never proxy-asserted); the gRPC
     * Decide handler forwards it as decideQuery's providedRoles (which REPLACES server role resolution).
     * Empty (the editor / no-R approver-exec) => decide under [principal]'s own server-resolved roles.
     *
     * [requesterIp] is the requester-IP carrier: the HTTP caller's requester IP, recorded into
     * [ControlPlaneCore.runRequesterIps] under this token's hash so the gRPC decide handler can attach it
     * to the Cedar context at decide time. This is the ONLY minter of APPROVER_EXEC tokens — [openSession]
     * mints EDITOR only — so covering it is what makes APPROVER_EXEC's requester_ip real, not just EDITOR's.
     */
    suspend fun run(
        principal: String,
        ds: Datasource,
        sql: String,
        maxRows: Int,
        approverExec: Boolean = false,
        assumeRoles: Set<String> = emptySet(),
        requesterIp: String? = null,
        taskId: Long? = null,
        preflight: (() -> Boolean)? = null,
        exchangeTimeoutMs: Long = EXCHANGE_TIMEOUT_MS,
        dialTimeoutMs: Long = RUN_DIALBACK_TIMEOUT_MS,
        noProgressMs: Long = RUN_NO_PROGRESS_TIMEOUT_MS,
        openTimeoutMs: Long = RUN_OPEN_TIMEOUT_MS,
    ): QueryResponse {
        val started = System.nanoTime()
        val issued = core.dataSource.mintForActivePrincipalLocked(principal, core.userGroupStore) { c ->
            core.tokenStore.issue(
                kind = if (approverExec) TokenKind.APPROVER_EXEC else TokenKind.EDITOR,
                principal = principal,
                // The assume-role set for execute-under-R; empty otherwise. The Decide handler only honors
                // this for the ephemeral kinds, so it can never become a client-asserted role list.
                roles = assumeRoles.toList(),
                name = null,
                ttlSeconds = runTokenTtlSeconds,
                c = c,
            )
        } ?: throw ProxyRunException("principal is deprovisioned")
        val issuedTokenHash = tokenHash(issued.token)
        core.runRequesterIps.put(issuedTokenHash, requesterIp)

        val kind = (if (approverExec) TokenKind.APPROVER_EXEC else TokenKind.EDITOR).name
        val opened = core.connectionCatalog.open(
            Binding(ds.name, principal, kind),
            ds.defaultSchemas + ds.engine.systemSchemas,
            adoptHeldContent = ds.engine.catalogIsConnectionIndependent,
        )
        val sessionId = UUID.randomUUID().toString()
        val pending = PendingSession(sessionId, principal, issued.id, CompletableDeferred())
        var registered = false
        var attached: Attached? = null
        var activeRun: ActiveRun? = null

        try {
            core.runChannels.register(pending)
            registered = true
            when (core.proxyEventsHub.requestOpenRun(ds.name, sessionId, issued.token, opened.connectionId, opened.onOpen)) {
                ProxyEventsHub.Dispatch.SENT -> Unit
                ProxyEventsHub.Dispatch.NOT_ATTACHED -> throw NoProxyAttachedException()
                ProxyEventsHub.Dispatch.WEDGED -> throw ProxyStreamWedgedException()
            }

            attached = try {
                withTimeout(dialTimeoutMs) { pending.ready.await() }
            } catch (e: TimeoutCancellationException) {
                throw ProxyRunTimeoutException(e)
            }

            val channel = attached
            // The stream is matched to this run the moment the proxy opens it (its first frame carries the
            // run's id); the target-DB open is still in flight. Wait for RunServing, bounding the wait by
            // lack of progress (each RunProgress heartbeat resets it) so a stalled or broken open fails fast
            // instead of riding a blind dial budget.
            awaitServing(channel.inbound, noProgressMs, openTimeoutMs)
            // Keep 0 as the wire "use the proxy's default (500)" sentinel; the proxy re-coerces to [1,5000]
            // and maps 0 -> 500 (wire contract). The gate below vetoes the send if a cancel already won.
            activeRun = taskId?.let { id -> ActiveRun(channel.outbound).also { activeRuns[id] = it } }
            try {
                sendRunQuery(activeRun, channel.outbound, preflight, sql, maxRows)
            } catch (e: RunCanceledBeforeStartException) {
                throw e
            } catch (e: Exception) {
                currentCoroutineContext().ensureActive()
                throw ProxyRunException("proxy run stream closed before the query was sent", e)
            }

            return try {
                withTimeout(exchangeTimeoutMs) {
                    collectResponse(channel.inbound, started)
                }
            } catch (e: TimeoutCancellationException) {
                throw ProxyRunTimeoutException(e)
            }
        } finally {
            val ar = activeRun
            if (taskId != null && ar != null) activeRuns.remove(taskId, ar)
            // If cancellation/timeout races the claim, remove wins while still pending; otherwise attach
            // already won and will complete [ready] synchronously, giving cleanup the outbound channel.
            if (registered && attached == null && core.runChannels.remove(sessionId) == null) {
                attached = withContext(NonCancellable) { pending.ready.await() }
            }
            try {
                attached?.outbound?.trySend(controlRunMsg { close = runClose {} })
                // Also close inbound so the gRPC handler tears down promptly. The RunClose above aborts the
                // proxy's target-DB open (it reads its inbound throughout); closing inbound here makes the handler's
                // next forward-send fail and end its collect, so the handler and its buffered frames aren't
                // retained until the proxy's stream close propagates back. Idempotent with the handler's own
                // close on the normal path.
                attached?.inbound?.close()
            } finally {
                try {
                    core.tokenStore.revoke(issued.id, principal)
                } finally {
                    closeConnectionCatalog(opened.connectionId, ds.name)
                    core.runRequesterIps.remove(issuedTokenHash)
                    if (registered) core.runChannels.remove(sessionId)
                }
            }
        }
    }

    // ---- Persistent per-editor-session streams (stateful editor, connection-model.md) ----
    // Unlike run() (one-shot: open→query→close, backing the approval-execute path and /api/query), an editor
    // SESSION holds ONE proxy-dialed stream — hence one dedicated backend connection — across MANY queries, so
    // SET/USE, temp objects, and BEGIN…COMMIT persist across the session, exactly like a native wire client.
    // This is the path the web SQL editor drives. Enforcement stays PER-STATEMENT (each query re-decides
    // against the connection's live namespace/catalog); a persistent connection is a data-plane fact, not an
    // authz relaxation. The per-session token carries a fixed absolute TTL (sliding refresh-on-activity is a
    // follow-up); the session is bounded by idle-sweep and explicit close.
    private val openSessions = ConcurrentHashMap<String, OpenEditorSession>()

    /**
     * Open a persistent editor session: mint a per-session EDITOR token, dial one proxy stream, and hold it.
     * The proxy keeps its dedicated backend connection alive for the life of the session. On any failure to
     * establish, the pending registration, token, and any half-open stream are cleaned up before throwing.
     *
     * [requesterIp] is the requester-IP carrier (see [run]'s doc) — recorded under the session token's hash
     * so every query decided on this session sees the requester IP that opened it.
     */
    suspend fun openSession(principal: String, ds: Datasource, requesterIp: String? = null): String {
        val issued = core.dataSource.mintForActivePrincipalLocked(principal, core.userGroupStore) { c ->
            core.tokenStore.issue(TokenKind.EDITOR, principal, emptyList(), null, editorSessionTtlSeconds, c)
        } ?: throw ProxyRunException("principal is deprovisioned")
        val issuedTokenHash = tokenHash(issued.token)
        core.runRequesterIps.put(issuedTokenHash, requesterIp)
        val opened = core.connectionCatalog.open(
            Binding(ds.name, principal, TokenKind.EDITOR.name),
            ds.defaultSchemas + ds.engine.systemSchemas,
            adoptHeldContent = ds.engine.catalogIsConnectionIndependent,
        )
        val sessionId = UUID.randomUUID().toString()
        val pending = PendingSession(sessionId, principal, issued.id, CompletableDeferred())
        var attached: Attached? = null
        try {
            core.runChannels.register(pending)
            when (core.proxyEventsHub.requestOpenRun(ds.name, sessionId, issued.token, opened.connectionId, opened.onOpen)) {
                ProxyEventsHub.Dispatch.SENT -> Unit
                ProxyEventsHub.Dispatch.NOT_ATTACHED -> throw NoProxyAttachedException()
                ProxyEventsHub.Dispatch.WEDGED -> throw ProxyStreamWedgedException()
            }
            attached = try {
                withTimeout(RUN_DIALBACK_TIMEOUT_MS) { pending.ready.await() }
            } catch (e: TimeoutCancellationException) {
                throw ProxyRunTimeoutException(e)
            }
            // Wait for the target-DB open to finish (RunServing), bounded by lack of progress — see run().
            awaitServing(attached.inbound, RUN_NO_PROGRESS_TIMEOUT_MS, RUN_OPEN_TIMEOUT_MS)
            openSessions[sessionId] = OpenEditorSession(
                sessionId, principal, issued.id, ds.name, attached, opened.connectionId,
                requesterIp = requesterIp, tokenHash = issuedTokenHash,
            )
            return sessionId
        } catch (e: Throwable) {
            // If the dial raced the claim, `remove` wins while still pending; otherwise attach already
            // completed [ready], so recover the outbound channel (NonCancellable) to send a close.
            if (attached == null && core.runChannels.remove(sessionId) == null) {
                attached = withContext(NonCancellable) { pending.ready.await() }
            }
            attached?.outbound?.trySend(controlRunMsg { close = runClose {} })
            // Close inbound too, so the gRPC handler tears down promptly (see run()'s finally). The RunClose
            // above aborts the proxy's target-DB open; closing inbound ends the handler without waiting for the
            // proxy's stream close to propagate. On success the held session keeps the stream.
            attached?.inbound?.close()
            runCatching { core.tokenStore.revoke(issued.id, principal) }
            closeConnectionCatalog(opened.connectionId, ds.name)
            core.runRequesterIps.remove(issuedTokenHash)
            core.runChannels.remove(sessionId)
            throw e
        }
    }

    /**
     * Run one query on an open session's stream and return its ENFORCED result. Serialized per session (a
     * session runs one statement at a time — two concurrent queries would interleave on the single stream).
     * A stream failure closes the session fail-closed. [principal] must own the session (no cross-principal use).
     *
     * [requesterIp] is the requester-IP carrier for THIS query's HTTP request. It is refreshed onto the
     * session token's registry entry (under the mutex, before the query crosses the wire, so the gRPC decide it
     * triggers reads exactly this value) — requester_ip is resolved fresh each decision (authz-context.md), so a
     * session opened from one network and queried from another decides against the current request's IP, not the
     * open-time one. A null [requesterIp] CLEARS the entry (fail-closed), never leaving the open-time IP stale.
     */
    suspend fun runOnSession(
        sessionId: String,
        principal: String,
        sql: String,
        maxRows: Int,
        requesterIp: String? = null,
        taskId: Long? = null,
        preflight: (() -> Boolean)? = null,
        exchangeTimeoutMs: Long = EXCHANGE_TIMEOUT_MS,
    ): QueryResponse {
        val session = openSessions[sessionId]?.takeIf { it.principal == principal }
            ?: throw ProxyRunException("no such editor session")
        try {
            return session.mutex.withLock {
                // Re-check under the mutex: a concurrent [closeSession] (DELETE / idle sweep) — which is lock-free
                // — may have removed + revoked this session while we queued for the lock. If so, bail fail-closed
                // rather than run a query on (and refresh the registry entry of) a since-revoked token. `!==` is a
                // safe identity check: sessionId is a fresh UUID, so a re-open can never resurrect the same object.
                if (openSessions[sessionId] !== session) throw ProxyRunException("no such editor session")
                val run = taskId?.let { id -> ActiveRun(session.attached.outbound).also { activeRuns[id] = it } }
                try {
                    val started = System.nanoTime()
                    session.lastUsedNanos = started
                    // Refresh the requester_ip this session's next decision will see to the CURRENT request's IP,
                    // under the mutex + before the query is sent — the proxy's decide (keyed by the session token's
                    // hash) then reads this query's IP, never a stale open-time one.
                    session.tokenHash?.let { core.runRequesterIps.set(it, requesterIp) }
                    try {
                        // Sends under the run gate (preflight + cancel re-check), so a concurrent cancel either
                        // vetoes this send or is ordered strictly after it — never a dropped-then-run query.
                        sendRunQuery(run, session.attached.outbound, preflight, sql, maxRows)
                    } catch (e: RunCanceledBeforeStartException) {
                        throw e
                    } catch (e: Exception) {
                        currentCoroutineContext().ensureActive()
                        closeSession(sessionId)
                        throw ProxyRunException("editor session stream closed before the query was sent", e)
                    }
                    try {
                        withTimeout(exchangeTimeoutMs) { collectResponse(session.attached.inbound, started) }
                    } catch (e: TimeoutCancellationException) {
                        closeSession(sessionId)
                        throw ProxyRunTimeoutException(e)
                    } catch (e: ProxyRunException) {
                        // A query-level error — a canceled statement, a backend error — ends the persistent proxy
                        // session (the run loop returns on any query error), so drop the CP-side session too. The
                        // next submit then reopens a fresh one cleanly instead of failing on a since-dead stream.
                        closeSession(sessionId)
                        throw e
                    }
                } finally {
                    if (taskId != null && run != null) activeRuns.remove(taskId, run)
                }
            }
        } finally {
            // If a lock-free [closeSession] raced this query and won (the session is no longer the live one), the
            // registry `set` above may have RE-CREATED an entry the close already swept — after the token was
            // revoked. Sweep it back out so a stale entry can never outlive its token (idempotent with
            // closeSession's own remove). On the normal path the session is still live, so this is a no-op.
            if (openSessions[sessionId] !== session) {
                session.tokenHash?.let(core.runRequesterIps::remove)
            }
        }
    }

    /**
     * The datasource NAME an open session is bound to, but ONLY when [principal] owns it (mirrors
     * [runOnSession]'s ownership check). Null for an unknown / not-owned session — the async editor submit
     * route resolves the task's datasource from the held session this way, so a leaked session id can never
     * launch a task against another principal's connection. Returns the name (the caller resolves the
     * [Datasource] via its store); the session holds no numeric id.
     */
    fun sessionDatasourceName(sessionId: String, principal: String): String? =
        openSessions[sessionId]?.takeIf { it.principal == principal }?.datasourceName

    /**
     * Close a session on behalf of [principal], but ONLY if they own it — mirrors [runOnSession]'s ownership
     * check so a principal who learns another user's sessionId cannot tear down that user's held connection or
     * revoke its token. A non-owner (or an unknown id) is a silent no-op that reveals nothing about whether the
     * id exists. Returns true iff a session the caller owned was closed.
     */
    fun closeSessionOwnedBy(sessionId: String, principal: String): Boolean {
        if (openSessions[sessionId]?.principal != principal) return false
        closeSession(sessionId)
        return true
    }

    fun closeSessionsForPrincipal(principal: String) {
        openSessions.values.filter { it.principal == principal }.forEach { closeSession(it.sessionId) }
    }

    /** End a session's proxy stream + revoke its token. Idempotent (a missing session is a no-op). */
    fun closeSession(sessionId: String) {
        val session = openSessions.remove(sessionId) ?: return
        try {
            session.attached.outbound.trySend(controlRunMsg { close = runClose {} })
        } finally {
            runCatching { core.tokenStore.revoke(session.tokenId, session.principal) }
            closeConnectionCatalog(session.connectionId, session.datasourceName)
            session.tokenHash?.let(core.runRequesterIps::remove)
            core.runChannels.remove(sessionId)
        }
    }

    /** Reap sessions idle longer than [maxIdleMs] (called on a timer) — releases the backend connection. */
    fun sweepIdleSessions(maxIdleMs: Long) {
        val cutoffNanos = System.nanoTime() - maxIdleMs * 1_000_000
        openSessions.values.filter { it.lastUsedNanos < cutoffNanos }.forEach { closeSession(it.sessionId) }
    }

    /** Keep suspend cleanup out of run()'s already-large state machine (JDK verifier sensitivity). */
    private fun closeConnectionCatalog(connectionId: ByteString, datasourceName: String) {
        runCatching {
            kotlinx.coroutines.runBlocking { core.connectionCatalog.close(connectionId, datasourceName) }
        }
    }

    /**
     * Wait for the proxy to finish its target-DB open and announce RunServing, under two bounds. A stream
     * closed before serving (a redeploy cutting the run) fails at once; a proxy that stops heartbeating fails
     * within [noProgressMs]; and — because a RunProgress heartbeat proves the proxy is alive but NOT that its
     * target-DB open is advancing — a proxy that keeps ticking while its open is wedged fails at the absolute
     * [openTimeoutMs] ceiling rather than riding the backend read-idle timeout. A terminal RunError during the
     * open (backend unreachable, catalog init failed) is surfaced as-is. The stream is already matched to
     * this run (attached), so every one of these is attributable — there is no blind wait, unlike the old
     * pre-RunReady gap.
     */
    private suspend fun awaitServing(inbound: Channel<ProxyRunMsg>, noProgressMs: Long, openTimeoutMs: Long) {
        val deadlineNanos = System.nanoTime() + openTimeoutMs * 1_000_000
        while (true) {
            val remainingMs = (deadlineNanos - System.nanoTime()) / 1_000_000
            if (remainingMs <= 0) throw ProxyRunTimeoutException()
            val result = try {
                withTimeout(minOf(noProgressMs, remainingMs)) { inbound.receiveCatching() }
            } catch (e: TimeoutCancellationException) {
                throw ProxyRunTimeoutException(e)
            }
            val message = result.getOrNull()
                ?: throw ProxyRunException("proxy run stream closed before it was ready to serve")
            when {
                message.hasProgress() -> continue
                message.hasServing() -> return
                message.hasError() -> {
                    if (message.error.message == QUERY_TIMEOUT_MESSAGE) throw ProxyRunTimeoutException()
                    throw ProxyRunException(message.error.message.ifBlank { "proxy run open failed" })
                }
                else -> throw ProxyRunException("proxy sent a run response before it was ready to serve")
            }
        }
    }

    private suspend fun collectResponse(inbound: Channel<ProxyRunMsg>, started: Long): QueryResponse {
        var decision: com.ridi.oss.proxymonster.grpc.RunDecision? = null
        var action: EnfAction? = null
        var columns: List<String>? = null
        val rows = ArrayList<List<String?>>()

        for (message in inbound) {
            when {
                message.hasDecision() -> {
                    if (decision != null) throw ProxyRunException("proxy sent more than one run decision")
                    val received = message.decision
                    val mapped = received.decision.knownOrDeny()
                    decision = received
                    action = mapped
                    if (mapped == EnfAction.DENY) {
                        return response(received, mapped, emptyList(), emptyList(), null, started)
                    }
                }

                message.hasResultRows() -> {
                    if (decision == null) {
                        throw ProxyRunException("proxy sent run rows before a decision")
                    }
                    if (action == EnfAction.DENY) {
                        throw ProxyRunException("proxy sent run rows after a deny decision")
                    }
                    val chunk = message.resultRows
                    val firstColumns = columns
                    if (firstColumns == null) {
                        columns = chunk.columnsList
                    }
                    val expectedWidth = (columns ?: emptyList()).size
                    rows += chunk.rowsList.map { row ->
                        if (row.valuesCount != expectedWidth) {
                            throw ProxyRunException("proxy sent a run row with the wrong column count")
                        }
                        row.valuesList.map { value -> if (value.isNull) null else value.value }
                    }
                }

                message.hasDone() -> {
                    val received = decision
                        ?: throw ProxyRunException("proxy completed a run query before a decision")
                    val receivedAction = action
                        ?: throw ProxyRunException("proxy completed a run query without a verdict")
                    if (receivedAction == EnfAction.DENY) {
                        throw ProxyRunException("proxy sent RunDone after a deny decision")
                    }
                    val rowsAffected = message.done.rowsAffected.let { if (it == -1) null else it }
                    return response(received, receivedAction, columns ?: emptyList(), rows, rowsAffected, started)
                }

                message.hasError() -> {
                    // A statement the proxy aborted at PM_QUERY_TIMEOUT carries an exact sentinel — attribute it
                    // as a timeout (→ query.proxy_timeout, task FAILED), never a generic failure or a success.
                    if (message.error.message == QUERY_TIMEOUT_MESSAGE) throw ProxyRunTimeoutException()
                    throw ProxyRunException(message.error.message.ifBlank { "proxy run execution failed" })
                }

                message.hasSessionReady() -> throw ProxyRunException(
                    "proxy sent RunReady more than once",
                )

                message.hasServing() -> throw ProxyRunException("proxy sent RunServing more than once")

                // A heartbeat after serving carries no result — ignore it rather than fail the run.
                message.hasProgress() -> Unit

                else -> throw ProxyRunException("proxy sent an empty run message")
            }
        }

        throw ProxyRunException("proxy run stream closed before a terminal response")
    }

    private fun response(
        decision: com.ridi.oss.proxymonster.grpc.RunDecision,
        action: EnfAction,
        columns: List<String>,
        rows: List<List<String?>>,
        rowsAffected: Int?,
        started: Long,
    ): QueryResponse {
        val decisionId = decision.decisionId.takeIf { it != 0L }
        val piiTouched = decisionId?.let { core.auditStore.get(it)?.piiTouched } ?: emptyList()
        return QueryResponse(
            decision = action,
            decisionId = decisionId,
            denyReason = decision.denyReason.ifBlank { null },
            maskedColumns = decision.maskedColumnsList,
            piiTouched = piiTouched,
            effectiveRoles = decision.effectiveRolesList,
            columns = columns,
            rows = rows,
            rowsAffected = rowsAffected,
            latencyMs = (System.nanoTime() - started) / 1_000_000,
        )
    }

    companion object {
        // Must match goproxy `run.QueryTimeoutMessage` verbatim: the exact RunError text the proxy sends when
        // its PM_QUERY_TIMEOUT watchdog aborts a statement, so a timed-out run is attributed as a timeout.
        const val QUERY_TIMEOUT_MESSAGE = "statement aborted: PM_QUERY_TIMEOUT exceeded"

        /** TTL for a one-shot run token, grown so it always outlives a statement running for [queryTimeoutSeconds]. */
        fun runTokenTtlSeconds(queryTimeoutSeconds: Long): Long =
            maxOf(RUN_TOKEN_TTL_FLOOR_SECONDS, queryTimeoutSeconds + TOKEN_TTL_GRACE_SECONDS)

        /** TTL for a persistent editor-session token, never shorter than a single query could run. */
        fun editorSessionTtlSeconds(queryTimeoutSeconds: Long): Long =
            maxOf(EDITOR_SESSION_TTL_SECONDS, queryTimeoutSeconds + TOKEN_TTL_GRACE_SECONDS)
    }
}
