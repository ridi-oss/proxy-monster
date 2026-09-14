package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.grpc.ConnectionInfo
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.grpc.connectionInfo
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI

object ConnectionInfoSerializer : KSerializer<ConnectionInfo> {
    override val descriptor = buildClassSerialDescriptor("ConnectionInfo") {
        element<String>("endpoint")
        element("properties", MapSerializer(String.serializer(), String.serializer()).descriptor)
    }

    override fun serialize(encoder: Encoder, value: ConnectionInfo) {
        (encoder as JsonEncoder).encodeJsonElement(buildJsonObject {
            put("endpoint", JsonPrimitive(value.endpoint))
            put("properties", JsonObject(value.propertiesMap.mapValues { JsonPrimitive(it.value) }))
        })
    }

    override fun deserialize(decoder: Decoder): ConnectionInfo {
        val value = (decoder as JsonDecoder).decodeJsonElement().jsonObject
        return connectionInfo {
            endpoint = value["endpoint"]?.jsonPrimitive?.content.orEmpty()
            value["properties"]?.jsonObject?.forEach { (key, value) -> properties[key] = value.jsonPrimitive.content }
        }
    }
}

internal fun Engine.validateConnectionInfo(info: ConnectionInfo?) {
    if (info != null) definition.validateConnectionInfo(info)
}

internal fun validateNativeConnectionInfo(info: ConnectionInfo, allowedProperties: Set<String>) {
    if (info.propertiesMap.keys.any { it !in allowedProperties }) invalidConnectionInfo()
    if (info.endpoint.isEmpty()) {
        if (info.propertiesCount != 0) invalidConnectionInfo()
        return
    }
    val uri = runCatching { URI("tcp://${info.endpoint}") }.getOrNull() ?: invalidConnectionInfo()
    if (uri.host.isNullOrBlank() || uri.port !in 1..65535 || uri.userInfo != null ||
        !uri.path.isNullOrEmpty() || uri.query != null || uri.fragment != null
    ) invalidConnectionInfo()
}

private fun invalidConnectionInfo(): Nothing = throw ManagementException(ApiError("datasource.invalid_connection_info"))
