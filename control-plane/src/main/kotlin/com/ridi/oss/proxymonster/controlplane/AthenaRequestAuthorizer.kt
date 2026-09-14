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
import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.authorizeNativeResource
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.RequestAuthorization
import com.ridi.oss.proxymonster.grpc.Verdict
import java.time.Clock

internal const val ATHENA_NATIVE_DESCRIPTOR_VERSION = 1
internal const val ATHENA_NATIVE_INSTRUCTIONS_VERSION = 1
internal const val ATHENA_CACHED_CONTEXT_VERSION = 1
internal const val ATHENA_BINDING_BYTES = 32
private const val MAX_EXPECTED_WIDTH = 1 shl 20

internal const val NATIVE_NOT_AUTHORIZED = "native.not_authorized"
internal const val NATIVE_INVALID_DESCRIPTOR = "native.invalid_descriptor"
internal const val NATIVE_SCOPE_VIOLATION = "native.scope_violation"
internal const val NATIVE_CONTEXT_UNAVAILABLE = "native.context_unavailable"

internal object AthenaRequestAuthorizer : RequestAuthorizer by AthenaNativeAuthorizer()

internal class AthenaNativeAuthorizer(private val clock: Clock = Clock.systemUTC()) : RequestAuthorizer {
    private class Deny(val code: String) : RuntimeException(code, null, false, false)

    override fun authorize(
        request: RequestAuthorization,
        datasource: Datasource,
        principal: String,
        roles: Set<String>,
        context: AuthzContext,
        authz: Authz,
    ): RequestAdmission = try {
        if (request.datasourceName.isBlank() || request.datasourceName != datasource.name || !request.hasNative()) throw Deny(NATIVE_NOT_AUTHORIZED)
        if (request.native.descriptorVersion != ATHENA_NATIVE_DESCRIPTOR_VERSION) throw Deny(NATIVE_INVALID_DESCRIPTOR)
        val descriptor = decodeDescriptor(request.native.descriptorPayload)
        val operation = AthenaOperations.byName[descriptor.operation] ?: throw Deny(NATIVE_NOT_AUTHORIZED)
        val body = decodeBody(descriptor.body)
        val gate = Gate(datasource, principal, roles, context.copy(tags = emptySet(), stmtKind = null, nativeOperation = null), authz, descriptor)
        if (!authorizeMetadata(authz, principal, roles, datasource, gate.context)) throw Deny(NATIVE_NOT_AUTHORIZED)
        RequestAdmission.Allowed(admit(gate, operation, body).toByteString())
    } catch (e: Deny) {
        RequestAdmission.Denied(e.code)
    } catch (_: MalformedNativeBody) {
        RequestAdmission.Denied(NATIVE_INVALID_DESCRIPTOR)
    }

    private class Gate(
        val datasource: Datasource,
        val principal: String,
        val roles: Set<String>,
        val context: AuthzContext,
        val authz: Authz,
        val descriptor: AthenaNativeDescriptor,
    ) {
        val cedarOperation = "athena:${descriptor.operation}"

        fun invoke(kind: String, id: String, owner: String? = null) {
            val resource = AuthzResource.NativeResource(datasource.name, kind, id, owner, datasource.tags)
            if (authz.authorizeNativeResource(principal, roles, resource, cedarOperation, context) !is AuthzDecision.Allow) throw Deny(NATIVE_NOT_AUTHORIZED)
        }

        fun invoke(observation: AthenaResourceObservation) =
            invoke(observation.kind, observation.id, if (observation.hasOwner()) observation.owner else null)
    }

    private fun admit(gate: Gate, operation: AthenaOperation, body: ObjectNode) = athenaNativeInstructions {
        version = ATHENA_NATIVE_INSTRUCTIONS_VERSION
        val response = gate.descriptor.phase == NativeAuthorizationPhase.NATIVE_AUTHORIZATION_PHASE_RESPONSE
        when (operation.category) {
            Category.SQL_SUBMISSION -> {
                if (response) throw Deny(NATIVE_NOT_AUTHORIZED)
                validateSubmissionScope(gate.descriptor, body)
                action = AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_REQUIRE_SQL_ADMISSION
            }
            Category.METADATA, Category.NATIVE -> {
                operation.resources(body).ifEmpty { listOf("datasource" to gate.datasource.name) }.forEach { (kind, id) -> gate.invoke(kind, id) }
                gate.descriptor.observationsList.forEach(gate::invoke)
                action = if (response) AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_RELEASE_METADATA else AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_FORWARD_REQUEST
            }
            Category.EXECUTION -> {
                val ids = operation.resources(body).map { it.second }.distinct()
                val owned = ownedContexts(gate)
                val refs = ids.map { id -> owned[id] ?: throw Deny(NATIVE_CONTEXT_UNAVAILABLE) }
                gate.descriptor.observationsList.forEach { observation ->
                    if (observation.kind == QUERY_EXECUTION) {
                        if (observation.id !in owned || observation.id !in ids) throw Deny(NATIVE_CONTEXT_UNAVAILABLE)
                    } else {
                        gate.invoke(observation)
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
                val owned = ownedContexts(gate)
                gate.descriptor.observationsList.forEach { observation ->
                    if (observation.kind == QUERY_EXECUTION) {
                        owned[observation.id]?.let { ctx -> contexts.add(athenaContextRef { resourceId = ctx.resourceId; contextId = ctx.contextId }) }
                    } else {
                        gate.invoke(observation)
                    }
                }
                action = if (response) AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_APPLY_ORIGINAL_CONTEXT else AthenaNativeInstruction.ATHENA_NATIVE_INSTRUCTION_FORWARD_REQUEST
            }
        }
    }

    // A context counts only when it is the principal's, bound to this descriptor's target, and unexpired.
    private fun ownedContexts(gate: Gate): Map<String, AthenaCachedContext> {
        val now = clock.instant()
        val binding = gate.descriptor.target.targetBinding
        return gate.descriptor.cachedContextsList.filter { ctx ->
            ctx.owner == gate.principal && ctx.targetBinding == binding &&
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
        fun inScope(value: JsonNode?, configured: String): Boolean {
            if (value == null) return true
            if (!value.isTextual) throw Deny(NATIVE_INVALID_DESCRIPTOR)
            return configured.isNotBlank() && value.textValue().equals(configured, ignoreCase = true)
        }
        if (!inScope(body["WorkGroup"], target.defaultWorkgroup)) throw Deny(NATIVE_SCOPE_VIOLATION)
        if (!inScope(ctx?.get("Catalog"), target.defaultCatalog)) throw Deny(NATIVE_SCOPE_VIOLATION)
        if (!inScope(ctx?.get("Database"), target.defaultDatabase)) throw Deny(NATIVE_SCOPE_VIOLATION)
        // A client-chosen output location is an S3 write through the proxy's role, outside the configured scope.
        if (body["ResultConfiguration"]?.get("OutputLocation") != null) throw Deny(NATIVE_SCOPE_VIOLATION)
        // Result reuse returns an earlier execution's rows under a new id; today's plan cannot vouch for them.
        if (body.has("ResultReuseConfiguration")) throw Deny(NATIVE_SCOPE_VIOLATION)
    }

    private fun decodeDescriptor(payload: ByteString): AthenaNativeDescriptor {
        val descriptor = try {
            AthenaNativeDescriptor.parseFrom(payload)
        } catch (_: InvalidProtocolBufferException) {
            throw Deny(NATIVE_INVALID_DESCRIPTOR)
        }
        if (descriptor.hasUnknownFieldsDeep()) throw Deny(NATIVE_INVALID_DESCRIPTOR)
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

    private companion object {
        val json: ObjectMapper = ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
    }
}

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
        AthenaOperation("GetDataCatalog", Category.METADATA, one("data-catalog") { it.str("Name") }),
        AthenaOperation("ListDatabases", Category.METADATA, one("data-catalog") { it.str("CatalogName") }),
        AthenaOperation("GetDatabase", Category.METADATA, one("database") { "${it.str("CatalogName")}/${it.str("DatabaseName")}" }),
        AthenaOperation("ListTableMetadata", Category.METADATA, one("database") { "${it.str("CatalogName")}/${it.str("DatabaseName")}" }),
        AthenaOperation("GetTableMetadata", Category.METADATA, one("table") { "${it.str("CatalogName")}/${it.str("DatabaseName")}/${it.str("TableName")}" }),
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
        AthenaOperation("CreateDataCatalog", Category.NATIVE, one("data-catalog") { it.str("Name") }),
        AthenaOperation("UpdateDataCatalog", Category.NATIVE, one("data-catalog") { it.str("Name") }),
        AthenaOperation("DeleteDataCatalog", Category.NATIVE, one("data-catalog") { it.str("Name") }),
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
