package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.analyzer.pb.EngineConfig as PbEngineConfig
import com.ridi.oss.proxymonster.controlplane.engines.AthenaEngineDefinition
import com.ridi.oss.proxymonster.controlplane.engines.MySqlEngineDefinition
import com.ridi.oss.proxymonster.controlplane.engines.PostgresEngineDefinition
import com.ridi.oss.proxymonster.grpc.ConnectionInfo
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.probe.Dialect
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

interface EngineDefinition {
    val engine: Engine
    val wireName: String
    val dialect: Dialect
    val requestAuthorizer: RequestAuthorizer
    val connectionProperties: Set<String>
    val systemSchemas: Set<String>
    val catalogIsConnectionIndependent: Boolean

    fun catalogName(dbName: String): String
    fun defaultSchema(dbName: String): String
    fun resolveSchema(requestedSchema: String, dbName: String): String
    fun requireCaseMode(lowerCaseTableNames: Int?): Int?
    fun isFixedSystemSchema(schema: String): Boolean
    fun isSystemSchema(schema: String): Boolean
    fun splitEngineConfig(datasource: Datasource): PbEngineConfig?
    fun analyzerEngineConfig(datasource: Datasource, ansiQuotes: Boolean): PbEngineConfig
    fun parseServerVersion(raw: String?): Pair<String?, Boolean>
    fun manifestSeries(version: String): String
    fun validateConnectionInfo(info: ConnectionInfo)
}

private val engineDefinitions = listOf(MySqlEngineDefinition, PostgresEngineDefinition, AthenaEngineDefinition).associateBy { it.engine }

val Engine.definition: EngineDefinition
    get() = checkNotNull(engineDefinitions[this]) { "unregistered engine: $this" }

val Engine.wireName: String get() = definition.wireName
val Engine.dialect: Dialect get() = definition.dialect
val Engine.systemSchemas: Set<String> get() = definition.systemSchemas
val Engine.catalogIsConnectionIndependent: Boolean get() = definition.catalogIsConnectionIndependent

val Engine.isMySql: Boolean get() = this == Engine.MYSQL
val Engine.isPostgres: Boolean get() = this == Engine.POSTGRES

fun Engine.catalogName(dbName: String): String = definition.catalogName(dbName)
fun Engine.defaultSchema(dbName: String): String = definition.defaultSchema(dbName)
fun Engine.resolveSchema(requestedSchema: String, dbName: String): String = definition.resolveSchema(requestedSchema, dbName)
fun Engine.requireCaseMode(lowerCaseTableNames: Int?): Int? = definition.requireCaseMode(lowerCaseTableNames)
fun Engine.isFixedSystemSchema(schema: String): Boolean = definition.isFixedSystemSchema(schema)
fun Engine.isSystemSchema(schema: String): Boolean = definition.isSystemSchema(schema)
fun Engine.parseServerVersion(raw: String?): Pair<String?, Boolean> = definition.parseServerVersion(raw)
fun Datasource.splitEngineConfig(): PbEngineConfig? = engine.definition.splitEngineConfig(this)

fun engineFromWire(raw: String): Engine =
    engineFromWireOrNull(raw) ?: throw IllegalArgumentException("unknown datasource engine '$raw'")

fun engineFromWireOrNull(raw: String): Engine? =
    engineDefinitions.values.firstOrNull { it.wireName == raw.lowercase() }?.engine

object EngineWireSerializer : KSerializer<Engine> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Engine", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: Engine) = encoder.encodeString(value.wireName)
    override fun deserialize(decoder: Decoder): Engine = engineFromWire(decoder.decodeString())
}
