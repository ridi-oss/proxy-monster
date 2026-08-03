package com.ridi.oss.proxymonster.controlplane

import kotlinx.serialization.Serializable

/**
 * The outcome of the enforcement triad (DESIGN.md). ERROR is the internal-failure
 * case (proxy couldn't reach a verdict), distinct from the fail-closed DENY.
 */
@Serializable
enum class Decision { ALLOW, MASK, DENY, ERROR }

/**
 * One tamper-evident audit event. This is the wire contract shared by the proxy
 * (which emits records to /api/ingest/decision) and the UI (which reads them back) —
 * keep the field names/shape stable. The server fills [id] and [ts] when null.
 */
@Serializable
data class AuditEvent(
    val id: Long? = null,              // server-assigned; proxy ingest leaves null
    val ts: String? = null,            // ISO-8601 instant; server fills if null
    val principal: String,
    val roles: List<String> = emptyList(),
    val datasource: String,
    val clientAddr: String? = null,
    val statement: String,
    val decision: Decision,
    val failedStage: String? = null,   // parse|validate|convert|lineage
    val effectiveNamespace: List<String> = emptyList(),
    val maskedColumns: List<String> = emptyList(),
    // The tagged columns touched, not only `pii`-tagged ones; see decideQuery (Query.kt).
    val piiTouched: List<String> = emptyList(),
    val latencyMs: Long = 0,
    val detail: String? = null,
    // Which surface/phase the decision came from (wire|editor|workflow-executor|workflow-viewer) and the
    // derived context.tags it earned. Nullable/defaulted because proxy ingest may leave them unset.
    val channel: String? = null,
    val contextTags: List<String> = emptyList(),
    // Management decisions attach the exact Cedar action/resource and a mutation outcome. Optional for
    // the query/wire audit contract.
    val authzAction: String? = null,
    val authzResource: String? = null,
    val outcome: String? = null,
    val kind: String = "decision",
    val rowsReturned: Long? = null,
    val bytesReturned: Long? = null,
    val decisionId: Long? = null,
)
