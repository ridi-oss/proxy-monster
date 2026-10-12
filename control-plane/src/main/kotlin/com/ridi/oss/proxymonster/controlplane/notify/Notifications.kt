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
    TASK_SUBMITTED("task.submitted"),
    TASK_DECIDED("task.decided"),
    /** The requester replaced the SQL: the request is pending again, under a new revision. */
    TASK_EDITED("task.edited"),
    TASK_EXECUTED("task.executed"),
    TASK_FAILED("task.failed"),
    TASK_CANCELLED("task.cancelled"),
    /** A pull request closed without merging after its SQL ran: an alert, so a fresh message. */
    TASK_CLOSED_AFTER_RUN("task.closed_after_run"),
    /** A pull request merged without a file whose SQL ran: an alert, so a fresh message. */
    TASK_MERGED_WITHOUT_FILE("task.merged_without_file"),
    ;

    /** True when this event should edit an existing message rather than start a new thread of its own. The two
     *  creation events — the approvers' request and the requester's own receipt — start threads; every later
     *  event edits the message its recipient already holds, except an alert. */
    val isUpdate: Boolean get() =
        this != TASK_REQUESTED && this != TASK_SUBMITTED && this != TASK_CLOSED_AFTER_RUN && this != TASK_MERGED_WITHOUT_FILE

    /** The events that open a task's thread; a ref already left for one means a prior attempt delivered it. */
    val isCreation: Boolean get() = this == TASK_REQUESTED || this == TASK_SUBMITTED

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
 * Which side of a request a message serves. One person can hold both for the same task — a requester whom
 * policy lets approve their own request is [REQUESTER] (their receipt) AND [APPROVER] (the actionable copy).
 * The two are independent threads, keyed apart so neither deduplicates or overwrites the other.
 */
enum class NotificationKind(val wire: String) {
    APPROVER("approver"),
    REQUESTER("requester"),
    ;

    companion object {
        fun fromWire(wire: String): NotificationKind = entries.firstOrNull { it.wire == wire } ?: APPROVER
    }
}

/**
 * How much of the requester's statement may leave the building (docs/notifications.md, "The statement in the
 * message"). A statement's literals can be the very values a policy protects — `WHERE ssn = '…'` leaks a
 * value masking never sees, because masking acts on results. The disclosure hint
 * (`protectedPredicateLiterals`) flags a statement whose predicate compares a literal against a classified
 * column; [AUTO] and [FULL] both consult it.
 */
enum class StatementDisclosure {
    /** Never show the statement — the message carries metadata only. */
    OMIT,

    /** Show the statement only when the hint has cleared it (no protected literal detected); hide it
     *  otherwise. An unanalyzable statement (no hint) is treated as unsafe and hidden. */
    AUTO,

    /** Show the whole statement while the task is PENDING, so an approver can read it and approve-and-run.
     *  Once the task is HANDLED (decided, executed, failed, cancelled — by anyone), fall back to [AUTO]: hide
     *  the statement if the hint flags a protected literal, so a PII value does not linger in the channel. */
    FULL,
    ;

    companion object {
        /** Parse a normalized `PM_NOTIFY_STATEMENT` value (`omit`|`auto`|`full`). */
        fun parse(raw: String?): StatementDisclosure? =
            raw?.trim()?.uppercase()?.let { v -> entries.firstOrNull { it.name == v } }
    }
}

/**
 * The statement as it will actually appear, and whether anything was cut.
 *
 * [complete] is the gate on approve-and-run: an approver may only decide from a message carrying the WHOLE
 * statement. The test is what the recipient can read, never which mode the operator configured — a statement
 * shown under FULL is still elided by a transport's own length ceiling. See [renderStatement].
 */
data class RenderedStatement(val text: String?, val complete: Boolean)

/**
 * The statement text to place in a message. [show] is the disclosure decision the caller has already made
 * (mode × event × hint); a false [show] or a null [sql] yields no text. When shown, the only cut is the
 * transport's own [hardLimit] (0 = none): [complete] is true only when the whole statement fit under it, and
 * that flag is what gates approve-and-run.
 */
fun renderStatement(sql: String?, show: Boolean, hardLimit: Int = 0): RenderedStatement {
    if (sql == null || !show) return RenderedStatement(null, complete = false)
    if (hardLimit <= 0 || sql.length <= hardLimit) return RenderedStatement(sql, complete = true)
    // The ellipsis has to fit INSIDE the ceiling, or a transport that hard-rejects an over-length field
    // would reject the very message that was truncated to satisfy it.
    val keep = (hardLimit - 1).coerceAtLeast(0)
    return RenderedStatement(sql.take(keep) + "…", complete = false)
}

/**
 * Whether a message may show the statement, from the operator's [disclosure] mode, whether the task is still
 * [pending] (the approvers' request, before any decision), and whether the disclosure hint has [cleared] the
 * statement (no protected literal detected — an unanalyzed statement is NOT cleared). OMIT never shows; AUTO
 * always defers to the hint; FULL shows a pending statement whatever the hint says, then falls back to AUTO
 * once the task is handled, so a protected literal does not linger in the channel after the decision.
 */
fun discloseStatement(disclosure: StatementDisclosure, pending: Boolean, cleared: Boolean): Boolean =
    when (disclosure) {
        StatementDisclosure.OMIT -> false
        StatementDisclosure.AUTO -> cleared
        StatementDisclosure.FULL -> pending || cleared
    }

/** An action a message may offer. [OPEN] is always available; the others are gated. [APPROVE] approves without
 *  running, for a request whose run is started elsewhere (a pull request's merge). */
enum class NotificationAction { APPROVE_AND_RUN, APPROVE, DENY, OPEN }

/**
 * One notification, transport-neutral. Carries message KEYS and their values rather than finished prose, so
 * a transport renders in its own idiom (Block Kit, MIME) and every locale stays reachable.
 *
 * [statement] is already rendered per [renderStatement]; [actions] already reflects its completeness.
 */
data class NotificationMessage(
    val event: NotificationEvent,
    val taskId: Long,
    val revision: Int,
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
    /** SUBMITTED only: the approvers the request was routed to, shown to the requester as their receipt.
     *  Plain identities, not `<@id>` mentions — the requester learns who can act without re-pinging them. */
    val notifiedApprovers: List<String> = emptyList(),
    val source: String = "console",
    /** A source request's file path, pull request, and the schema its run opens on. */
    val path: String? = null,
    val prUrl: String? = null,
    val schema: String? = null,
    /** DECIDED on a pull-request request: whether auto-merge is already on, so the message need not ask. */
    val autoMergeEnabled: Boolean = false,
    val statementCount: Int = 1,
    /** FAILED only: the failed statement's redacted error. Never rows. */
    val failure: String? = null,
    /** FAILED only: which statement of the batch failed, and its SQL. */
    val failedStatement: FailedStatement? = null,
)

/** [ordinal] is 0-based, as stored on the `query_result` child. */
data class FailedStatement(val ordinal: Int, val sql: String)

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

    /** True when this transport addresses a task rather than a person; it then hears only tasks [taskAddress] names. */
    val addressesTasks: Boolean get() = false

    /** The one address every event of [req] goes to on this transport, or null to address people. */
    fun taskAddress(req: com.ridi.oss.proxymonster.controlplane.AccessRequest): String? = null

    /**
     * This principal's address on this transport, or null when they have none — a null DROPS the row, since no
     * number of attempts will conjure an address. A TRANSIENT failure (a network blip, a rate limit) THROWS
     * instead, so delivery retries rather than dead-lettering the recipient over a passing condition.
     */
    suspend fun addressOf(principal: String, email: String?): String?

    suspend fun deliver(to: String, message: NotificationMessage, locale: String): DeliveryResult

    /** Edit a previously delivered message in place. Only called when [supportsUpdate]. */
    suspend fun update(externalRef: String, message: NotificationMessage, locale: String): DeliveryResult
}
