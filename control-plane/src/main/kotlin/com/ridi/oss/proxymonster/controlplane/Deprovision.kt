package com.ridi.oss.proxymonster.controlplane

import java.sql.Connection
import javax.sql.DataSource

/**
 * The per-principal serialization primitive every teardown path (this file, the renew route's locked
 * re-mint, SCIM rename) shares: `pg_advisory_xact_lock(hashtext(principal))`, a Postgres
 * transaction-scoped advisory lock automatically released at commit/rollback. Call it FIRST inside a
 * transaction, before any read/write that must not interleave with a concurrent teardown/re-mint for
 * the SAME principal. Re-entrant within a session (a session/transaction that already holds the lock
 * can acquire it again for free — see the Postgres advisory-locks docs), so composing callers (e.g.
 * [revokeActiveCredentialsTx] called from inside a transaction that already locked [principal]) never
 * deadlock themselves.
 */
internal fun Connection.advisoryLockPrincipal(principal: String) {
    prepareStatement("SELECT pg_advisory_xact_lock(hashtext(?))").use { ps ->
        ps.setString(1, principal)
        ps.executeQuery().use { it.next() }
    }
}

/**
 * Run [body] on a fresh connection inside a committed transaction — the manual-commit idiom this
 * module already uses ad hoc (`Access.kt`'s `approve`, `QueryResultStore`'s private `inTransaction`),
 * pulled out here so every locked-teardown call site in this part shares ONE implementation. Rolls
 * back on any exception; always restores `autoCommit`.
 */
internal inline fun <T> DataSource.inTx(body: (Connection) -> T): T = connection.use { c ->
    c.autoCommit = false
    try {
        val out = body(c)
        c.commit()
        out
    } catch (e: Exception) {
        c.rollback(); throw e
    } finally {
        c.autoCommit = true
    }
}

/**
 * Deprovisioning backstop (docs/auth-model.md "Deprovisioning propagates two ways"): kill every
 * currently-active credential for [principal], immediately, rather than waiting for natural expiry —
 * wire tokens, JIT access grants, daemon session windows, and web sessions. Closing daemon windows
 * makes deprovisioning durable: even a later reactivation cannot reuse an old renewal secret, and
 * ending web rows invalidates existing browser cookies immediately.
 *
 * Called from authoritative SCIM and local-admin deprovision paths. Returns the total number of
 * credentials revoked (tokens + grants + daemon windows + web sessions), for logging/observability.
 *
 * All four revokes run in one transaction guarded by [advisoryLockPrincipal], serialized against
 * every other write path touching the same principal (the renew route's locked re-mint and SCIM or
 * local-admin rename/deactivation). [dataSource] is pulled from [tokenStore] purely as a connection
 * source; every store passed here uses the same pooled DataSource.
 */
fun revokeActiveCredentials(
    principal: String,
    tokenStore: TokenStore,
    accessStore: AccessStore,
    daemonSessionStore: PrincipalSessionStore,
): Int = tokenStore.dataSource.inTx { c -> revokeActiveCredentialsTx(principal, c, tokenStore, accessStore, daemonSessionStore) }

/**
 * The composable core of [revokeActiveCredentials]: the token, grant, daemon-window, and web-session
 * revokes share one lock and a caller-supplied connection [c], so an app_user rename, tombstone, or
 * active-state change can commit atomically with credential teardown. Takes [advisoryLockPrincipal]
 * itself (idempotent and re-entrant if the caller already holds it), so direct callers cannot forget
 * the serialization boundary.
 */
fun revokeActiveCredentialsTx(
    principal: String,
    c: Connection,
    tokenStore: TokenStore,
    accessStore: AccessStore,
    daemonSessionStore: PrincipalSessionStore,
): Int {
    c.advisoryLockPrincipal(principal)
    return tokenStore.revokeAllForPrincipal(principal, c) +
        accessStore.revokeAllForPrincipal(principal, c) +
        daemonSessionStore.deactivateAllForPrincipal(principal, c) +
        daemonSessionStore.endAllWebForPrincipal(principal, ENDED_DEACTIVATED, c)
}

/**
 * Issue a credential for [principal] ONLY if it isn't deprovisioned, running the deactivation CHECK
 * and the [mint] on ONE transaction under the per-principal advisory lock — the mint-side twin of
 * [revokeActiveCredentialsTx]. A concurrent teardown takes the SAME lock, so it either
 * commits fully BEFORE this lock is acquired ([UserGroupStore.isDeactivated] then reads true -> null,
 * nothing is minted) or fully AFTER this transaction commits (its sweep revokes whatever [mint] just
 * inserted). The web-session mint additionally resolves role eligibility inside [mint], under this
 * same lock, so group reconciliation cannot end existing sessions and then lose a race to a zero-role
 * insert. Without the lock a teardown could slip its revoke between the check and the INSERT, leaving
 * a credential that outlives deprovisioning or group revocation. Returns null when [principal] is
 * deprovisioned — the caller maps that to 403; otherwise [mint]'s result. Every Kotlin credential mint
 * ([TokenService.mintUser], the device-poll session mint, run tokens) funnels through here so the
 * check-then-mint TOCTOU is closed in one place.
 */
fun <T> DataSource.mintForActivePrincipalLocked(
    principal: String,
    userGroupStore: UserGroupStore,
    mint: (Connection) -> T,
): T? = inTx { c ->
    c.advisoryLockPrincipal(principal)
    if (userGroupStore.isDeactivated(principal, c)) null else mint(c)
}
