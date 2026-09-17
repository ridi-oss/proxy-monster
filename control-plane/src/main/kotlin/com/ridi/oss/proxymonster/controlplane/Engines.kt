package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.analyzer.pb.EngineConfig as PbEngineConfig
import com.ridi.oss.proxymonster.analyzer.pb.FunctionCatalog
import com.ridi.oss.proxymonster.analyzer.pb.SessionObservation
import com.ridi.oss.proxymonster.controlplane.engines.MySqlEngineDefinition
import com.ridi.oss.proxymonster.controlplane.engines.PostgresEngineDefinition
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.probe.Dialect
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Everything the control plane knows about one engine. The proto [Engine] stays the domain type; this is
 * the single home for every per-engine decision, so no call site branches on the engine itself. Adding an
 * engine means one object here plus its row in [engineDefinitions], not a hunt through the call sites.
 */
interface EngineDefinition {
    val engine: Engine
    /** The persistence, registration, and JSON string: "mysql", "postgres". */
    val wireName: String
    /** The analyzer SQL dialect. */
    val dialect: Dialect
    /** The fixed, enumerable system schemas whose content is identical across every datasource of one version. */
    val systemSchemas: Set<String>
    /** True when one connection's catalog measurement answers for every connection of the datasource. */
    val catalogIsConnectionIndependent: Boolean

    /** The analyzer catalog segment for a datasource whose registration database is [dbName]. */
    fun catalogName(dbName: String): String
    /** The schema an unqualified table resolves to when no per-request schema is given. */
    fun defaultSchema(dbName: String): String
    /** Maps the cross-engine "public" selector to [defaultSchema]; any other value is an explicit schema. */
    fun resolveSchema(requestedSchema: String, dbName: String): String
    /** The MySQL lower_case_table_names mode the analyzer needs, or null for an engine without one. */
    fun requireCaseMode(lowerCaseTableNames: Int?): Int?
    /** [systemSchemas] membership with engine-correct casing; the catalog pool key predicate. */
    fun isFixedSystemSchema(schema: String): Boolean
    /** [isFixedSystemSchema] plus the engine's ephemeral per-session schemas (Postgres pg_temp_*, pg_toast). */
    fun isSystemSchema(schema: String): Boolean
    /** The analyzer config for splitting a batch before any session exists; null when introspection has not captured what the dialect needs. */
    fun splitEngineConfig(datasource: Datasource): PbEngineConfig?
    /** The analyzer config for one statement decision, with the live session facts. */
    fun analyzerEngineConfig(datasource: Datasource, session: SessionObservation): PbEngineConfig
    /** (comparable server version, isAurora) from the raw `version()` string; null version when unparsable. */
    fun parseServerVersion(raw: String?): Pair<String?, Boolean>
    /** The classification-manifest series a parsed version belongs to: MySQL "8.0", Postgres "17". */
    fun manifestSeries(version: String): String
    /** The function inventory the analyzer resolves calls against, tiered from routines (schema -> names). */
    fun functionCatalog(routines: Map<String, List<String>>, engineVersion: String?): FunctionCatalog
    /**
     * The system columns every table has beyond its introspected ones (PostgreSQL ctid/xmin/…; a real column
     * of that name wins). They resolve when written, never expand from `*`, and cannot be classified.
     */
    fun implicitColumns(rows: List<CatalogColumn>): List<CatalogColumn>
}

private val engineDefinitions = listOf(MySqlEngineDefinition, PostgresEngineDefinition).associateBy { it.engine }

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
fun Engine.functionCatalog(routines: Map<String, List<String>>, engineVersion: String?): FunctionCatalog =
    definition.functionCatalog(routines, engineVersion)
fun Engine.implicitColumns(rows: List<CatalogColumn>): List<CatalogColumn> = definition.implicitColumns(rows)
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

