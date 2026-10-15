package com.ridi.oss.proxymonster.controlplane

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import com.google.protobuf.ByteString
import com.google.protobuf.Descriptors.FieldDescriptor
import com.google.protobuf.InvalidProtocolBufferException
import com.google.protobuf.Message
import com.ridi.oss.proxymonster.athena.pb.AthenaCachedContext
import com.ridi.oss.proxymonster.athena.pb.AthenaNativeDescriptor
import com.ridi.oss.proxymonster.athena.pb.AthenaNativeInstruction
import com.ridi.oss.proxymonster.athena.pb.AthenaObservationSource
import com.ridi.oss.proxymonster.athena.pb.AthenaResourceObservation
import com.ridi.oss.proxymonster.athena.pb.NativeAuthorizationPhase
import com.ridi.oss.proxymonster.athena.pb.athenaContextRef
import com.ridi.oss.proxymonster.athena.pb.athenaNativeInstructions
import com.ridi.oss.proxymonster.analyzer.pb.column
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.probe.introspectedColumns
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.RequestAuthorization
import com.ridi.oss.proxymonster.grpc.Verdict
import java.time.Instant

internal const val ATHENA_CACHED_CONTEXT_VERSION = 1
internal const val ATHENA_BINDING_BYTES = 32
private const val MAX_EXPECTED_WIDTH = 1 shl 20

internal const val NATIVE_NOT_AUTHORIZED = "native.not_authorized"
internal const val NATIVE_INVALID_DESCRIPTOR = "native.invalid_descriptor"
internal const val NATIVE_SCOPE_VIOLATION = "native.scope_violation"
internal const val NATIVE_CONTEXT_UNAVAILABLE = "native.context_unavailable"

/** [rawName], a literal Athena name (an API field, not SQL text), folded as the analyzer does; null when it cannot be normalized. */
private fun athenaCanonicalName(rawName: String): String? =
    introspectedColumns(Engine.ATHENA, null, listOf(column { catalog = rawName }))?.single()?.catalog

private class Deny(val code: String) : RuntimeException(code, null, false, false)

/**
 * Reads one Athena API call from the proxy's descriptor. Every operation has a [Category]: StartQueryExecution
 * goes through SQL admission (Decide), status/result reads bind to [principal]'s own cached execution contexts,
 * metadata reads release once every observed resource passes native.invoke, history listings keep only owned
 * executions, and everything else is native.invoke on its specific resource. An operation not in [AthenaOperations] is denied.
 */
internal fun athenaRequestAccess(request: RequestAuthorization, datasourceName: String, principal: String, now: Instant): RequestAccess = try {
    if (!request.hasAthena()) throw Deny(NATIVE_NOT_AUTHORIZED)
    val descriptor = validDescriptor(request.athena)
    val operation = AthenaOperations.byName[descriptor.operation] ?: throw Deny(NATIVE_NOT_AUTHORIZED)
    val resources = mutableListOf<NativeResourceRef>()
    val instructions = athenaInstructions(descriptor, operation, decodeBody(descriptor.body), datasourceName, principal, now, resources)
    RequestAccess.Native("athena:${descriptor.operation}", resources, NativeInstructions.Athena(instructions))
} catch (e: Deny) {
    RequestAccess.Denied(e.code)
} catch (_: MalformedNativeBody) {
    RequestAccess.Denied(NATIVE_INVALID_DESCRIPTOR)
}

private fun AthenaResourceObservation.ref() = NativeResourceRef(kind, id, if (hasOwner()) owner else null)

/** The instructions for an admitted call; adds to [resources] what native.invoke must allow first. */
private fun athenaInstructions(
    descriptor: AthenaNativeDescriptor,
    operation: AthenaOperation,
    body: ObjectNode,
    datasourceName: String,
    principal: String,
    now: Instant,
    resources: MutableList<NativeResourceRef>,
) = athenaNativeInstructions {
    val response = descriptor.phase == NativeAuthorizationPhase.NATIVE_AUTHORIZATION_PHASE_RESPONSE
    when (operation.category) {
        Category.SQL_SUBMISSION -> {
            if (response) throw Deny(NATIVE_NOT_AUTHORIZED)
            validateSubmissionScope(descriptor, body)
            action = AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_REQUIRE_SQL_ADMISSION
        }
        Category.METADATA, Category.NATIVE -> {
            val named = operation.resources(body).map { (kind, id) -> NativeResourceRef(kind, id) }
            resources += named.ifEmpty { listOf(NativeResourceRef("datasource", datasourceName)) }
            descriptor.observationsList.mapTo(resources) { it.ref() }
            action = if (response) AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_RELEASE_METADATA else AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_FORWARD_REQUEST
        }
        Category.EXECUTION -> {
            val ids = operation.resources(body).map { it.second }.distinct()
            val owned = ownedContexts(descriptor, principal, now)
            val refs = ids.map { id -> owned[id] ?: throw Deny(NATIVE_CONTEXT_UNAVAILABLE) }
            descriptor.observationsList.forEach { observation ->
                if (observation.kind == QUERY_EXECUTION) {
                    if (observation.id !in owned || observation.id !in ids) throw Deny(NATIVE_CONTEXT_UNAVAILABLE)
                } else {
                    resources += observation.ref()
                }
            }
            if (response) {
                action = AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_APPLY_ORIGINAL_CONTEXT
                refs.forEach { ctx -> contexts.add(athenaContextRef { resourceId = ctx.resourceId; contextId = ctx.contextId }) }
            } else {
                action = AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_FORWARD_REQUEST
            }
        }
        Category.HISTORY -> {
            // A listing shows only the caller's own executions: the proxy keeps the ids referenced here.
            val owned = ownedContexts(descriptor, principal, now)
            descriptor.observationsList.forEach { observation ->
                if (observation.kind == QUERY_EXECUTION) {
                    owned[observation.id]?.let { ctx -> contexts.add(athenaContextRef { resourceId = ctx.resourceId; contextId = ctx.contextId }) }
                } else {
                    resources += observation.ref()
                }
            }
            action = if (response) AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_APPLY_ORIGINAL_CONTEXT else AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_FORWARD_REQUEST
        }
    }
}

// A context counts only when it is the principal's, bound to this descriptor's target, and unexpired.
private fun ownedContexts(descriptor: AthenaNativeDescriptor, principal: String, now: Instant): Map<String, AthenaCachedContext> {
    val binding = descriptor.target.targetBinding
    return descriptor.cachedContextsList.filter { ctx ->
        ctx.owner == principal && ctx.targetBinding == binding &&
            (ctx.expiresAt.seconds > now.epochSecond || ctx.expiresAt.seconds == now.epochSecond && ctx.expiresAt.nanos > now.nano)
    }.associateBy { it.resourceId }
}

private fun validateSubmissionScope(descriptor: AthenaNativeDescriptor, body: ObjectNode) {
    val target = descriptor.target
    if (!body.has("QueryString") || !body["QueryString"].isTextual) throw Deny(NATIVE_INVALID_DESCRIPTOR)
    body["ExecutionParameters"]?.let { params ->
        if (!params.isArray || params.any { !it.isTextual }) throw Deny(NATIVE_INVALID_DESCRIPTOR)
    }
    body["WorkGroup"]?.let { if (!it.isTextual) throw Deny(NATIVE_INVALID_DESCRIPTOR) }
    body["QueryExecutionContext"]?.let { if (!it.isObject) throw Deny(NATIVE_INVALID_DESCRIPTOR) }
    body["ResultConfiguration"]?.let { if (!it.isObject) throw Deny(NATIVE_INVALID_DESCRIPTOR) }
    val ctx = body["QueryExecutionContext"]
    fun inScope(requested: JsonNode?, configured: String, canonical: (String) -> String = { it }): Boolean {
        if (requested == null) return true
        if (!requested.isTextual) throw Deny(NATIVE_INVALID_DESCRIPTOR)
        return configured.isNotBlank() && canonical(requested.textValue()) == canonical(configured)
    }
    val athenaName = { rawName: String -> athenaCanonicalName(rawName) ?: throw Deny(NATIVE_INVALID_DESCRIPTOR) }
    if (!inScope(body["WorkGroup"], target.defaultWorkgroup)) throw Deny(NATIVE_SCOPE_VIOLATION)
    if (!inScope(ctx?.get("Catalog"), target.defaultCatalog, athenaName)) throw Deny(NATIVE_SCOPE_VIOLATION)
    if (!inScope(ctx?.get("Database"), target.defaultDatabase, athenaName)) throw Deny(NATIVE_SCOPE_VIOLATION)
    // A client-chosen output location is an S3 write through the proxy's role, outside the configured scope.
    if (body["ResultConfiguration"]?.get("OutputLocation") != null) throw Deny(NATIVE_SCOPE_VIOLATION)
    // Result reuse returns an earlier execution's rows under a new id; today's plan cannot vouch for them.
    if (body.has("ResultReuseConfiguration")) throw Deny(NATIVE_SCOPE_VIOLATION)
}

private fun validDescriptor(descriptor: AthenaNativeDescriptor): AthenaNativeDescriptor {
    if (descriptor.service != "athena" || descriptor.operation.isBlank()) throw Deny(NATIVE_NOT_AUTHORIZED)
    if (descriptor.method != "POST" || descriptor.path != "/" || descriptor.rawQuery.isNotEmpty()) throw Deny(NATIVE_INVALID_DESCRIPTOR)
    if (descriptor.functionalHeadersList.any { it.name.isBlank() }) throw Deny(NATIVE_INVALID_DESCRIPTOR)
    if (descriptor.phase != NativeAuthorizationPhase.NATIVE_AUTHORIZATION_PHASE_REQUEST &&
        descriptor.phase != NativeAuthorizationPhase.NATIVE_AUTHORIZATION_PHASE_RESPONSE
    ) throw Deny(NATIVE_INVALID_DESCRIPTOR)
    if (!descriptor.hasTarget() || descriptor.target.targetBinding.size() != ATHENA_BINDING_BYTES) throw Deny(NATIVE_INVALID_DESCRIPTOR)
    if (descriptor.phase == NativeAuthorizationPhase.NATIVE_AUTHORIZATION_PHASE_REQUEST && descriptor.observationsCount > 0) {
        throw Deny(NATIVE_INVALID_DESCRIPTOR)
    }
    descriptor.observationsList.forEach { observation ->
        if (observation.source != AthenaObservationSource.ATHENA_OBSERVATION_SOURCE_AWS_RESPONSE ||
            observation.kind.isBlank() || observation.id.isBlank() || observation.hasOwner() && observation.owner.isBlank()
        ) throw Deny(NATIVE_INVALID_DESCRIPTOR)
    }
    descriptor.cachedContextsList.forEach { if (!it.isWellFormed()) throw Deny(NATIVE_INVALID_DESCRIPTOR) }
    if (descriptor.cachedContextsList.distinctBy { it.resourceId }.size != descriptor.cachedContextsCount) throw Deny(NATIVE_INVALID_DESCRIPTOR)
    return descriptor
}

private fun decodeBody(body: ByteString): ObjectNode {
    val node = try {
        json.readTree(body.newInput())
    } catch (_: Exception) {
        throw Deny(NATIVE_INVALID_DESCRIPTOR)
    }
    return node as? ObjectNode ?: throw Deny(NATIVE_INVALID_DESCRIPTOR)
}

private val json: ObjectMapper = ObjectMapper()
    .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
    .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)

internal fun AthenaCachedContext.isWellFormed(): Boolean {
    if (version != ATHENA_CACHED_CONTEXT_VERSION || contextId.isBlank() || resourceId.isBlank() || owner.isBlank()) return false
    if (targetBinding.size() != ATHENA_BINDING_BYTES || !hasExpiresAt() || !expiresAt.isValidTimestamp()) return false
    if (hasExpectedWidth() && expectedWidth > MAX_EXPECTED_WIDTH) return false
    if (metadataDigest.size() != 0 && metadataDigest.size() != ATHENA_BINDING_BYTES) return false
    if (requestBinding.size() != 0 && requestBinding.size() != ATHENA_BINDING_BYTES) return false
    return isTrimmedVerdict(enforcementInstructions, if (hasExpectedWidth()) expectedWidth else null)
}

/** Enforcement instructions carry only what the result path applies: decision, masks, unmaskable, sanitize, decision id. */
internal fun isTrimmedVerdict(bytes: ByteString, expectedWidth: Int?): Boolean {
    if (bytes.isEmpty) return false
    val verdict = try {
        Verdict.parseFrom(bytes)
    } catch (_: InvalidProtocolBufferException) {
        return false
    }
    if (verdict.hasUnknownFieldsDeep() || verdict.toByteString() != bytes) return false
    if (verdict.decision != EnfAction.ALLOW && verdict.decision != EnfAction.MASK) return false
    if (verdict.decision == EnfAction.ALLOW && verdict.masksCount > 0) return false
    val trimmed = verdict.toBuilder().clearDecision().clearMasks().clearUnmaskablePermitted().clearSanitizeDiagnostics().clearDecisionId().build()
    if (trimmed.allFields.isNotEmpty()) return false
    return verdict.masksList.all { mask ->
        mask.hasOrdinal() && mask.ordinal >= 0 && (expectedWidth == null || mask.ordinal < expectedWidth)
    }
}

// The proto well-known Timestamp range: 0001-01-01T00:00:00Z to 9999-12-31T23:59:59.999999999Z.
private fun com.google.protobuf.Timestamp.isValidTimestamp() = seconds in -62135596800L..253402300799L && nanos in 0..999_999_999

private fun Message.hasUnknownFieldsDeep(): Boolean {
    if (unknownFields.serializedSize > 0) return true
    return allFields.any { (field, value) ->
        field.type == FieldDescriptor.Type.MESSAGE && when {
            field.isRepeated -> (value as List<*>).any { (it as Message).hasUnknownFieldsDeep() }
            else -> (value as Message).hasUnknownFieldsDeep()
        }
    }
}

private const val QUERY_EXECUTION = "query-execution"

internal enum class Category { SQL_SUBMISSION, METADATA, EXECUTION, HISTORY, NATIVE }

internal class AthenaOperation(val name: String, val category: Category, val resources: (ObjectNode) -> List<Pair<String, String>>)

/** Every Athena API operation, keyed by its `X-Amz-Target` suffix; an operation absent here is denied.
 *  A list without a named scope authorizes the datasource itself; its response releases only observed resources. */
internal object AthenaOperations {
    private fun ObjectNode.str(field: String): String {
        val value = get(field)
        if (value == null || !value.isTextual || value.textValue().isBlank()) throw invalid()
        return value.textValue()
    }

    private fun ObjectNode.strs(field: String): List<String> {
        val value = get(field)
        if (value == null || !value.isArray || value.isEmpty || value.any { !it.isTextual || it.textValue().isBlank() }) throw invalid()
        return value.map { it.textValue() }
    }

    private fun ObjectNode.optStr(field: String): String? {
        val value = get(field) ?: return null
        if (!value.isTextual || value.textValue().isBlank()) throw invalid()
        return value.textValue()
    }

    private fun invalid() = MalformedNativeBody()

    private fun one(kind: String, id: (ObjectNode) -> String): (ObjectNode) -> List<Pair<String, String>> = { listOf(kind to id(it)) }

    /** [names] joined with `/`, each an Athena name in its canonical spelling. */
    private fun catalogPath(vararg names: String): (ObjectNode) -> String = { body -> names.joinToString("/") { athenaName(body.str(it)) } }

    private fun athenaName(rawName: String): String = athenaCanonicalName(rawName) ?: throw invalid()

    private fun many(kind: String, ids: (ObjectNode) -> List<String>): (ObjectNode) -> List<Pair<String, String>> = { body -> ids(body).map { kind to it } }
    private fun none(): (ObjectNode) -> List<Pair<String, String>> = { emptyList() }

    private val operations = listOf(
        AthenaOperation("StartQueryExecution", Category.SQL_SUBMISSION, none()),

        AthenaOperation("GetQueryExecution", Category.EXECUTION, one(QUERY_EXECUTION) { it.str("QueryExecutionId") }),
        AthenaOperation("BatchGetQueryExecution", Category.EXECUTION, many(QUERY_EXECUTION) { it.strs("QueryExecutionIds") }),
        AthenaOperation("GetQueryResults", Category.EXECUTION, one(QUERY_EXECUTION) { it.str("QueryExecutionId") }),
        AthenaOperation("GetQueryResultsStream", Category.EXECUTION, one(QUERY_EXECUTION) { it.str("QueryExecutionId") }),
        AthenaOperation("StopQueryExecution", Category.EXECUTION, one(QUERY_EXECUTION) { it.str("QueryExecutionId") }),
        AthenaOperation("GetQueryRuntimeStatistics", Category.EXECUTION, one(QUERY_EXECUTION) { it.str("QueryExecutionId") }),
        AthenaOperation("ListQueryExecutions", Category.HISTORY, none()),

        AthenaOperation("ListDataCatalogs", Category.METADATA, none()),
        AthenaOperation("GetDataCatalog", Category.METADATA, one("data-catalog", catalogPath("Name"))),
        AthenaOperation("ListDatabases", Category.METADATA, one("data-catalog", catalogPath("CatalogName"))),
        AthenaOperation("GetDatabase", Category.METADATA, one("database", catalogPath("CatalogName", "DatabaseName"))),
        AthenaOperation("ListTableMetadata", Category.METADATA, one("database", catalogPath("CatalogName", "DatabaseName"))),
        AthenaOperation("GetTableMetadata", Category.METADATA, one("table", catalogPath("CatalogName", "DatabaseName", "TableName"))),
        AthenaOperation("ListWorkGroups", Category.METADATA, none()),
        AthenaOperation("GetWorkGroup", Category.METADATA, one("workgroup") { it.str("WorkGroup") }),
        AthenaOperation("GetPreparedStatement", Category.METADATA, one("prepared-statement") { "${it.str("WorkGroup")}/${it.str("StatementName")}" }),
        AthenaOperation("BatchGetPreparedStatement", Category.METADATA, many("prepared-statement") { body -> body.strs("PreparedStatementNames").map { "${body.str("WorkGroup")}/$it" } }),
        AthenaOperation("ListPreparedStatements", Category.METADATA, one("workgroup") { it.str("WorkGroup") }),
        AthenaOperation("GetNamedQuery", Category.METADATA, one("named-query") { it.str("NamedQueryId") }),
        AthenaOperation("BatchGetNamedQuery", Category.METADATA, many("named-query") { it.strs("NamedQueryIds") }),
        AthenaOperation("ListNamedQueries", Category.METADATA, one("workgroup") { it.optStr("WorkGroup") ?: "primary" }),
        AthenaOperation("ListEngineVersions", Category.METADATA, none()),
        AthenaOperation("ListApplicationDPUSizes", Category.METADATA, none()),
        AthenaOperation("GetCapacityReservation", Category.METADATA, one("capacity-reservation") { it.str("Name") }),
        AthenaOperation("ListCapacityReservations", Category.METADATA, none()),
        AthenaOperation("GetCapacityAssignmentConfiguration", Category.METADATA, one("capacity-reservation") { it.str("CapacityReservationName") }),
        AthenaOperation("ListTagsForResource", Category.METADATA, one("tagged-resource") { it.str("ResourceARN") }),

        AthenaOperation("CreatePreparedStatement", Category.NATIVE, one("prepared-statement") { "${it.str("WorkGroup")}/${it.str("StatementName")}" }),
        AthenaOperation("UpdatePreparedStatement", Category.NATIVE, one("prepared-statement") { "${it.str("WorkGroup")}/${it.str("StatementName")}" }),
        AthenaOperation("DeletePreparedStatement", Category.NATIVE, one("prepared-statement") { "${it.str("WorkGroup")}/${it.str("StatementName")}" }),
        AthenaOperation("CreateNamedQuery", Category.NATIVE, one("workgroup") { it.optStr("WorkGroup") ?: "primary" }),
        AthenaOperation("UpdateNamedQuery", Category.NATIVE, one("named-query") { it.str("NamedQueryId") }),
        AthenaOperation("DeleteNamedQuery", Category.NATIVE, one("named-query") { it.str("NamedQueryId") }),
        AthenaOperation("CreateWorkGroup", Category.NATIVE, one("workgroup") { it.str("Name") }),
        AthenaOperation("UpdateWorkGroup", Category.NATIVE, one("workgroup") { it.str("WorkGroup") }),
        AthenaOperation("DeleteWorkGroup", Category.NATIVE, one("workgroup") { it.str("WorkGroup") }),
        AthenaOperation("CreateDataCatalog", Category.NATIVE, one("data-catalog", catalogPath("Name"))),
        AthenaOperation("UpdateDataCatalog", Category.NATIVE, one("data-catalog", catalogPath("Name"))),
        AthenaOperation("DeleteDataCatalog", Category.NATIVE, one("data-catalog", catalogPath("Name"))),
        AthenaOperation("CreateCapacityReservation", Category.NATIVE, one("capacity-reservation") { it.str("Name") }),
        AthenaOperation("UpdateCapacityReservation", Category.NATIVE, one("capacity-reservation") { it.str("Name") }),
        AthenaOperation("CancelCapacityReservation", Category.NATIVE, one("capacity-reservation") { it.str("Name") }),
        AthenaOperation("DeleteCapacityReservation", Category.NATIVE, one("capacity-reservation") { it.str("Name") }),
        AthenaOperation("PutCapacityAssignmentConfiguration", Category.NATIVE, one("capacity-reservation") { it.str("CapacityReservationName") }),
        AthenaOperation("TagResource", Category.NATIVE, one("tagged-resource") { it.str("ResourceARN") }),
        AthenaOperation("UntagResource", Category.NATIVE, one("tagged-resource") { it.str("ResourceARN") }),
        AthenaOperation("GetResourceDashboard", Category.METADATA, one("tagged-resource") { it.str("ResourceARN") }),
    )

    val byName: Map<String, AthenaOperation> = operations.associateBy { it.name }
}

internal class MalformedNativeBody : RuntimeException("malformed native body", null, false, false)
