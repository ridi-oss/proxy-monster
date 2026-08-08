package com.ridi.oss.proxymonster.controlplane.notify

/**
 * Out-of-band task notifications (docs/notifications.md).
 *
 * A notification tells someone a task changed. It is never authorization: it carries no result data, and
 * every action it offers re-authorizes from scratch when taken. Three layers, each replaceable on its own —
 * the workflow states an [NotificationEvent], [NotificationRouter] resolves who should hear it, and a
 * [NotificationTransport] delivers. The workflow knows nothing about Slack.
 */

/** What happened. The workflow states this once; who hears it and how are decided downstream. */
enum class NotificationEvent(val wire: String) {
    TASK_REQUESTED("task.requested"),
    TASK_DECIDED("task.decided"),
    TASK_EXECUTED("task.executed"),
    TASK_FAILED("task.failed"),
    TASK_CANCELLED("task.cancelled"),
    ;

    /** True when this event should edit an existing message rather than start a new thread of its own. */
    val isUpdate: Boolean get() = this != TASK_REQUESTED

    companion object {
        fun fromWire(wire: String): NotificationEvent? = entries.firstOrNull { it.wire == wire }

        /** The terminal task status → the event announcing it. Null for a non-terminal status. */
        fun forTerminalStatus(status: String): NotificationEvent? = when (status) {
            "EXECUTED" -> TASK_EXECUTED
            "FAILED" -> TASK_FAILED
            "CANCELLED" -> TASK_CANCELLED
            else -> null
        }
    }
}

/**
 * How much of the requester's statement may leave the building (docs/notifications.md, "The statement in the
 * message"). A statement's literals can be the very values a policy protects — `WHERE rrn = '…'` leaks a
 * value masking never sees, because masking acts on results.
 */
enum class StatementDisclosure {
    TRUNCATED,
    FULL,
    OMIT,
    ;

    companion object {
        /** Parse `PM_NOTIFY_STATEMENT`. An unrecognized value is a config error the caller fails fast on. */
        fun parse(raw: String?): StatementDisclosure? =
            raw?.trim()?.uppercase()?.let { v -> entries.firstOrNull { it.name == v } }
    }
}

/**
 * The statement as it will actually appear, and whether anything was cut.
 *
 * [complete] is the gate on approve-and-run: an approver may only decide from a message carrying the WHOLE
 * statement. The test is what the recipient can read, never which mode the operator configured — a short
 * statement under TRUNCATED was not truncated, and a long one under FULL is still elided by a transport's own
 * length ceiling. See [renderStatement].
 */
data class RenderedStatement(val text: String?, val complete: Boolean)

/**
 * Apply [disclosure] to [sql], then the transport's own [hardLimit] (0 = none). The result is [complete] only
 * when the full statement survived both — the flag is an input to rendering, and the button is decided after.
 */
fun renderStatement(
    sql: String?,
    disclosure: StatementDisclosure,
    maxChars: Int,
    hardLimit: Int = 0,
): RenderedStatement {
    if (sql == null) return RenderedStatement(null, complete = false)
    if (disclosure == StatementDisclosure.OMIT) return RenderedStatement(null, complete = false)

    // The tightest applicable ceiling wins. FULL has no configured limit of its own, so only the transport's
    // applies; TRUNCATED takes the smaller of the two.
    val configured = if (disclosure == StatementDisclosure.TRUNCATED) maxChars else Int.MAX_VALUE
    val ceiling = when {
        hardLimit <= 0 -> configured
        else -> minOf(configured, hardLimit)
    }
    if (ceiling <= 0) return RenderedStatement(null, complete = false)
    if (sql.length <= ceiling) return RenderedStatement(sql, complete = true)
    // The ellipsis has to fit INSIDE the ceiling, or a transport that hard-rejects an over-length field
    // would reject the very message that was truncated to satisfy it.
    val keep = (ceiling - 1).coerceAtLeast(0)
    return RenderedStatement(sql.take(keep) + "…", complete = false)
}

/** An action a message may offer. [OPEN] is always available; the other two are gated. */
enum class NotificationAction { APPROVE_AND_RUN, DENY, OPEN }

/**
 * One notification, transport-neutral. Carries message KEYS and their values rather than finished prose, so
 * a transport renders in its own idiom (Block Kit, MIME) and every locale stays reachable.
 *
 * [statement] is already rendered per [renderStatement]; [actions] already reflects its completeness.
 */
data class NotificationMessage(
    val event: NotificationEvent,
    val taskId: Long,
    val requester: String,
    val datasource: String,
    val roleName: String?,
    val reason: String?,
    val statement: RenderedStatement,
    val decidedBy: String? = null,
    /** DECIDED only: approved rather than rejected. The two read completely differently to a recipient,
     *  and the outbox row records only that a decision happened. */
    val approved: Boolean? = null,
    val rowCount: Int? = null,
    val errorCode: String? = null,
    val deepLink: String,
    val actions: Set<NotificationAction>,
)

/** The outcome of one delivery attempt. Only the transport knows which failures are worth another try. */
sealed interface DeliveryResult {
    /** Delivered; [externalRef] is the handle a later event edits (Slack `channel:ts`). */
    data class Sent(val externalRef: String) : DeliveryResult

    /** Transient — try again after backoff (a 429, a socket drop). */
    data class Retry(val reason: String) : DeliveryResult

    /** Permanent — stop. No address for this principal, a 404, a malformed payload. */
    data class Drop(val reason: String) : DeliveryResult
}

/**
 * A delivery channel. Slack today; email is the second adapter and the reason this seam exists.
 *
 * An unconfigured transport is ABSENT, never degraded — the same posture as an unset `PM_SCIM_TOKEN`
 * disabling SCIM. With no transport configured the whole layer is inert and the workflow is unchanged.
 */
interface NotificationTransport {
    val name: String

    /** The transport's own per-message statement ceiling, 0 when it has none. */
    val statementHardLimit: Int get() = 0

    /** False for a transport with no edit primitive (email); an update then sends a fresh message. */
    val supportsUpdate: Boolean get() = false

    /**
     * This principal's address on this transport, or null when they have none — a null DROPS the row rather
     * than retrying it, since no number of attempts will conjure an address.
     */
    suspend fun addressOf(principal: String, email: String?): String?

    suspend fun deliver(to: String, message: NotificationMessage, locale: String): DeliveryResult

    /** Edit a previously delivered message in place. Only called when [supportsUpdate]. */
    suspend fun update(externalRef: String, message: NotificationMessage, locale: String): DeliveryResult
}
