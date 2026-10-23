package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.analyzer.pb.EngineConfig as PbEngineConfig
import com.ridi.oss.proxymonster.analyzer.pb.TargetSettings
import com.ridi.oss.proxymonster.analyzer.pb.targetSettings
import com.ridi.oss.proxymonster.analyzer.pb.FunctionCatalog
import com.ridi.oss.proxymonster.analyzer.pb.SessionObservation
import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.grpc.ConnectionInfo
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.probe.Dialect
import com.ridi.oss.proxymonster.probe.GoEngine
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Everything the control plane knows about one engine, read from its Go definition ([GoEngine]). The proto
 * [Engine] stays the domain type; no call site branches on the engine itself.
 */
class EngineDefinition internal constructor(val engine: Engine) {
    private val go = GoEngine.of(engine)
    private val facts = go.facts

    /** The persistence, registration, and JSON string: "mysql", "postgres". */
    val wireName: String = facts.wireName
    /** The analyzer SQL dialect. */
    val dialect: Dialect = Dialect.entries.single { it.wireName == wireName }
    /** The ConnectionInfo property keys this engine's proxies may publish; anything else is refused at register. */
    val connectionProperties: Set<String> = facts.connectionPropertiesList.toSet()
    /** The fixed, enumerable system schemas whose content is identical across every datasource of one version. */
    val systemSchemas: Set<String> = facts.systemSchemasList.toSet()
    /** True when one connection's catalog measurement answers for every connection of the datasource. */
    val catalogIsConnectionIndependent: Boolean = facts.catalogIsConnectionIndependent
    /** True when the proxy can prepare a statement on the target without running it (`check_target_error`). */
    val checksTargetErrors: Boolean = facts.checksTargetErrors
    /** True when the engine has a statement that makes a schema a session's default. */
    val defaultSchemaSettable: Boolean = facts.defaultSchemaSettable
    /** The character that quotes an identifier in the engine's SQL; a quote inside the name is doubled. */
    val identifierQuote: String = facts.identifierQuote

    /** The canonical analyzer catalog for a datasource registered on [registeredDbName], which is not normalized. */
    fun catalogName(registeredDbName: String): String = go.catalogName(registeredDbName)
    /** The schema an unqualified table resolves to when no per-request schema is given; [registeredDbName] and the result are not normalized. */
    fun defaultSchema(registeredDbName: String): String = go.defaultSchema(registeredDbName)
    /** [systemSchemas] membership of [canonicalSchema], compared exactly; the catalog pool key predicate. */
    fun isFixedSystemSchema(canonicalSchema: String): Boolean = go.schemaKind(canonicalSchema).fixedSystem
    /** [isFixedSystemSchema] plus the engine's ephemeral per-session schemas (Postgres pg_temp_*, pg_toast). */
    fun isSystemSchema(canonicalSchema: String): Boolean = go.schemaKind(canonicalSchema).system
    /** True when [canonicalSchema] is the engine's session temp schema (Postgres pg_temp, pg_temp_3), compared exactly. */
    fun isTempSchema(canonicalSchema: String): Boolean = go.schemaKind(canonicalSchema).temp
    /** The analyzer config for one statement decision, with the per-statement facts the proxy sent. */
    fun analyzerEngineConfig(datasource: Datasource, session: SessionObservation): PbEngineConfig =
        go.analyzerConfig(datasource.targetSettings(), session)
    /** (comparable server version, isAurora) from the raw `version()` string; null version when unparsable. */
    fun parseServerVersion(raw: String?): Pair<String?, Boolean> =
        go.serverVersion(raw).let { (if (it.hasVersion()) it.version else null) to it.aurora }
    /** The classification-manifest series a parsed version belongs to: MySQL "8.0", Postgres "17". */
    fun manifestSeries(version: String): String = go.manifestSeries(version)
    /** The function inventory the analyzer resolves calls against, tiered from routines (schema -> names). */
    fun functionCatalog(routines: Map<String, List<String>>, engineVersion: String?): FunctionCatalog =
        go.functionCatalog(routines, engineVersion)
    /**
     * The system columns every table has beyond its introspected ones (PostgreSQL ctid/xmin/…; a real column
     * of that name wins). They resolve when written, never expand from `*`, and cannot be classified. [rows]
     * and the result are canonical.
     */
    fun implicitColumns(rows: List<CatalogColumn>): List<CatalogColumn> {
        if (facts.implicitColumnsCount == 0) return emptyList()
        data class TableId(val catalog: String, val schema: String, val table: String, val isTemp: Boolean)
        val existing = HashMap<TableId, MutableSet<String>>()
        for (row in rows) {
            existing.getOrPut(TableId(row.catalog, row.schema, row.table, row.isTemp)) { HashSet() } += row.column
        }
        return existing.flatMap { (id, columns) ->
            facts.implicitColumnsList.mapNotNull { implicit ->
                if (implicit.name in columns) return@mapNotNull null
                CatalogColumn(
                    catalog = id.catalog, schema = id.schema, table = id.table, column = implicit.name,
                    dataType = implicit.dataType, sqlType = implicit.dataType, ordinal = 0, nullable = false,
                    isTemp = id.isTemp, implicit = true,
                )
            }
        }
    }
    /** Refuses a ConnectionInfo this engine's proxies must not publish. */
    fun validateConnectionInfo(info: ConnectionInfo) {
        if (!go.connectionInfoValid(info.endpoint, info.propertiesMap)) {
            throw ManagementException(ApiError("datasource.invalid_connection_info"))
        }
    }
    /** The statement that makes [canonicalSchema] a session's default, quoted exactly: MySQL ``USE `app` ``. */
    fun defaultSchemaStatement(canonicalSchema: String): String = go.defaultSchemaStatement(canonicalSchema)

    /** [name] as one quoted identifier: MySQL a`b -> `a``b`. */
    fun quoteIdentifier(name: String): String = "$identifierQuote${name.replace(identifierQuote, identifierQuote + identifierQuote)}$identifierQuote"
}

private val engineDefinitions = listOf(Engine.MYSQL, Engine.POSTGRES, Engine.ATHENA).map(::EngineDefinition).associateBy { it.engine }

val Engine.definition: EngineDefinition
    get() = checkNotNull(engineDefinitions[this]) { "unregistered engine: $this" }

val Engine.wireName: String get() = definition.wireName
val Engine.dialect: Dialect get() = definition.dialect
val Engine.systemSchemas: Set<String> get() = definition.systemSchemas
val Engine.catalogIsConnectionIndependent: Boolean get() = definition.catalogIsConnectionIndependent
val Engine.checksTargetErrors: Boolean get() = definition.checksTargetErrors

fun Engine.catalogName(registeredDbName: String): String = definition.catalogName(registeredDbName)
fun Engine.defaultSchema(registeredDbName: String): String = definition.defaultSchema(registeredDbName)
fun Engine.isFixedSystemSchema(canonicalSchema: String): Boolean = definition.isFixedSystemSchema(canonicalSchema)
fun Engine.isSystemSchema(canonicalSchema: String): Boolean = definition.isSystemSchema(canonicalSchema)
fun Engine.isTempSchema(canonicalSchema: String): Boolean = definition.isTempSchema(canonicalSchema)
fun Engine.parseServerVersion(raw: String?): Pair<String?, Boolean> = definition.parseServerVersion(raw)
fun Engine.functionCatalog(routines: Map<String, List<String>>, engineVersion: String?): FunctionCatalog =
    definition.functionCatalog(routines, engineVersion)
fun Engine.implicitColumns(rows: List<CatalogColumn>): List<CatalogColumn> = definition.implicitColumns(rows)
fun Datasource.splitEngineConfig(): PbEngineConfig = engine.definition.analyzerEngineConfig(this, SessionObservation.getDefaultInstance())

/** What introspection reported, and the ConnectionInfo properties; the analyzer refuses to fold names when its engine needs a fact still missing. */
fun Datasource.targetSettings(): TargetSettings {
    val ds = this
    return targetSettings {
        ds.engineVersion?.let { engineVersion = it }
        ds.mysqlLowerCaseTableNames?.let { mysqlLowerCaseTableNames = it }
        ds.connectionInfo?.let { properties.putAll(it.propertiesMap) }
    }
}

fun engineFromWire(raw: String): Engine =
    engineFromWireOrNull(raw) ?: throw IllegalArgumentException("unknown datasource engine '$raw'")

fun engineFromWireOrNull(raw: String): Engine? =
    engineDefinitions.values.firstOrNull { it.wireName == raw }?.engine

object EngineWireSerializer : KSerializer<Engine> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Engine", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: Engine) = encoder.encodeString(value.wireName)
    override fun deserialize(decoder: Decoder): Engine = engineFromWire(decoder.decodeString())
}

