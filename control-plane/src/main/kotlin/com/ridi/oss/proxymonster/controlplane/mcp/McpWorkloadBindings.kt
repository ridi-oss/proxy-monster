package com.ridi.oss.proxymonster.controlplane.mcp

import com.ridi.oss.proxymonster.controlplane.ApiError
import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.cpgo.ConditionValues
import com.ridi.oss.proxymonster.cpgo.WorkloadBinding
import com.ridi.oss.proxymonster.cpgo.WorkloadBindingError
import com.ridi.oss.proxymonster.cpgo.WorkloadBindingInput
import com.ridi.oss.proxymonster.cpgo.WorkloadBindingsGrpcKt.WorkloadBindingsCoroutineStub
import com.ridi.oss.proxymonster.cpgo.bindingCaller
import com.ridi.oss.proxymonster.cpgo.deleteBindingRequest
import com.ridi.oss.proxymonster.cpgo.listBindingsRequest
import com.ridi.oss.proxymonster.cpgo.workloadBindingInput
import com.ridi.oss.proxymonster.cpgo.writeBindingRequest
import io.grpc.Channel
import io.grpc.StatusException
import io.grpc.protobuf.StatusProto
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put

class WorkloadBindingsBridge(channel: Channel) {
    private val stub = WorkloadBindingsCoroutineStub(channel)

    fun list(): JsonObject = call {
        val bindings = stub.listBindings(listBindingsRequest {}).bindingsList
        structuredOf(buildJsonObject { put("bindings", JsonArray(bindings.map { it.json() })) })
    }

    fun create(args: JsonObject, context: McpRequestContext): JsonObject = call {
        structuredOf(stub.createBinding(writeBindingRequest { caller = context.caller(); binding = args.bindingInput() }).json())
    }

    fun update(args: JsonObject, context: McpRequestContext): JsonObject = call {
        structuredOf(stub.updateBinding(writeBindingRequest { caller = context.caller(); binding = args.bindingInput() }).json())
    }

    fun delete(args: JsonObject, context: McpRequestContext): JsonObject = call {
        stub.deleteBinding(deleteBindingRequest { caller = context.caller(); name = args.string("name").orEmpty() })
        structuredOf(buildJsonObject { put("deleted", true) })
    }

    private fun <T> call(block: suspend () -> T): T = runBlocking {
        try {
            block()
        } catch (e: StatusException) {
            val detail = StatusProto.fromThrowable(e)?.detailsList?.firstOrNull { it.`is`(WorkloadBindingError::class.java) }
                ?.unpack(WorkloadBindingError::class.java)
                ?: throw IllegalStateException("cp-go workload binding bridge: ${e.status.code}: ${e.status.description}", e)
            throw ManagementException(ApiError(detail.code, detail.paramsList.associate { it.key to it.value }))
        }
    }

    private companion object {
        fun structuredOf(value: JsonElement) = buildJsonObject { put("result", value) }

        fun McpRequestContext.caller() = bindingCaller {
            principal = this@caller.principal
            clientAddr = requesterIp.orEmpty()
        }

        fun JsonObject.bindingInput(): WorkloadBindingInput {
            val args = this
            return workloadBindingInput {
                name = args.string("name").orEmpty()
                issuer = args.string("issuer").orEmpty()
                subject = args.string("subject").orEmpty()
                args.string("description")?.let { description = it }
                args.string("principal")?.let { principal = it }
                args.strings("purposes")?.let { purposes.addAll(it) }
                args.strings("mcpScopes")?.let { mcpScopes.addAll(it) }
                args.int("ttlSeconds")?.let { ttlSeconds = it }
                args.boolean("enabled")?.let { enabled = it }
                args.conditions().forEach { (claim, values) ->
                    conditions.put(claim, ConditionValues.newBuilder().addAllValues(values).build())
                }
            }
        }

        fun JsonObject.strings(name: String): List<String>? {
            val value = get(name) ?: return null
            if (value is JsonNull) return null
            val array = value as? JsonArray ?: throw McpInputException()
            return array.map { (it as? JsonPrimitive)?.takeIf(JsonPrimitive::isString)?.contentOrNull ?: throw McpInputException() }
        }

        fun JsonObject.conditions(): Map<String, List<String>> {
            val value = get("conditions") ?: return emptyMap()
            if (value is JsonNull) return emptyMap()
            val obj = value as? JsonObject ?: throw McpInputException()
            return obj.mapValues { (_, v) ->
                when {
                    v is JsonPrimitive && v.isString -> listOf(v.content)
                    v is JsonArray -> v.map { (it as? JsonPrimitive)?.takeIf(JsonPrimitive::isString)?.contentOrNull ?: throw McpInputException() }
                    else -> throw McpInputException()
                }
            }
        }

        fun WorkloadBinding.json(): JsonObject = buildJsonObject {
            put("id", id)
            put("name", name)
            if (hasDescription()) put("description", description)
            put("issuer", issuer)
            put("subject", subject)
            put(
                "conditions",
                JsonObject(conditionsMap.toSortedMap().mapValues { (_, v) -> JsonArray(v.valuesList.map(::JsonPrimitive)) }),
            )
            put("principal", principal)
            put("purposes", JsonArray(purposesList.map(::JsonPrimitive)))
            put("mcpScopes", JsonArray(mcpScopesList.map(::JsonPrimitive)))
            put("ttlSeconds", ttlSeconds)
            put("enabled", enabled)
            put("createdAt", createdAt)
            put("updatedAt", updatedAt)
        }
    }
}
