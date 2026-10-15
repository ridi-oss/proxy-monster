package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.analyzer.pb.EngineConfig as PbEngineConfig
import com.ridi.oss.proxymonster.analyzer.pb.FunctionCatalog
import com.ridi.oss.proxymonster.analyzer.pb.SessionObservation
import com.ridi.oss.proxymonster.analyzer.pb.StatementFacts
import com.ridi.oss.proxymonster.controlplane.engines.AthenaEngineDefinition
import com.ridi.oss.proxymonster.controlplane.engines.MySqlEngineDefinition
import com.ridi.oss.proxymonster.controlplane.engines.PostgresEngineDefinition
import com.ridi.oss.proxymonster.grpc.ConnectionInfo
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.grpc.ProxyCommand
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
    /** Decides a metadata request that has no SQL session behind it (a catalog or table-metadata read). */
    val requestAuthorizer: RequestAuthorizer
    /** The ConnectionInfo property keys this engine's proxies may publish; anything else is refused at register. */
    val connectionProperties: Set<String>
    /** The fixed, enumerable system schemas whose content is identical across every datasource of one version. */
    val systemSchemas: Set<String>
    /** True when one connection's catalog measurement answers for every connection of the datasource. */
    val catalogIsConnectionIndependent: Boolean
    /** True when the proxy can prepare a statement on the target without running it (`check_target_error`). */
    val checksTargetErrors: Boolean

    /** The canonical analyzer catalog segment for a datasource registered on [registeredDbName], which is not normalized. */
    fun catalogName(registeredDbName: String): String
    /** The schema an unqualified table resolves to when no per-request schema is given; [registeredDbName] and the result are not normalized. */
    fun defaultSchema(registeredDbName: String): String
    /** Maps the cross-engine "public" selector to [defaultSchema]; any other value is an explicit schema. */
    /** The MySQL lower_case_table_names mode the analyzer needs, or null for an engine without one. */
    fun requireCaseMode(lowerCaseTableNames: Int?): Int?
    /** [systemSchemas] membership of [canonicalSchema], compared exactly; the catalog pool key predicate. */
    fun isFixedSystemSchema(canonicalSchema: String): Boolean
    /** [isFixedSystemSchema] plus the engine's ephemeral per-session schemas (Postgres pg_temp_*, pg_toast). */
    fun isSystemSchema(canonicalSchema: String): Boolean
    /** True when [canonicalSchema] is the engine's session temp schema (Postgres pg_temp, pg_temp_3), compared exactly. */
    fun isTempSchema(canonicalSchema: String): Boolean = false
    /** The analyzer config for splitting a batch before any session exists; null when introspection has not captured what the dialect needs. */
    fun splitEngineConfig(datasource: Datasource): PbEngineConfig?
    /**
     * The analyzer config for one statement decision, with the per-statement facts the proxy sent (session
     * observations and, for Athena, the request scope). A definition refuses facts it does not model.
     */
    fun analyzerEngineConfig(datasource: Datasource, session: SessionObservation): PbEngineConfig
    /**
     * The commands the proxy must run before this statement can be decided, read from an unresolved analysis
     * that asks for more input (Athena: fetch the prepared statement `EXECUTE` names). Empty = decidable now.
     */
    fun beforeDecideCommands(facts: StatementFacts): List<ProxyCommand> = emptyList()
    /** (comparable server version, isAurora) from the raw `version()` string; null version when unparsable. */
    fun parseServerVersion(raw: String?): Pair<String?, Boolean>
    /** The classification-manifest series a parsed version belongs to: MySQL "8.0", Postgres "17". */
    fun manifestSeries(version: String): String
    /** The function inventory the analyzer resolves calls against, tiered from routines (schema -> names). */
    fun functionCatalog(routines: Map<String, List<String>>, engineVersion: String?): FunctionCatalog
    /**
     * The system columns every table has beyond its introspected ones (PostgreSQL ctid/xmin/…; a real column
     * of that name wins). They resolve when written, never expand from `*`, and cannot be classified. [rows]
     * and the result are canonical.
     */
    fun implicitColumns(rows: List<CatalogColumn>): List<CatalogColumn>
    /** Refuses a ConnectionInfo this engine's proxies must not publish (see [validateNativeConnectionInfo]). */
    fun validateConnectionInfo(info: ConnectionInfo)
    /** Builds the statement that makes [canonicalSchema][it] a session's default, quoted exactly; null where the engine has none. */
    val defaultSchemaStatement: ((canonicalSchema: String) -> String)? get() = null
    /** The character that quotes an identifier in the engine's SQL; a quote inside the name is doubled. */
    val identifierQuote: Char

    fun quoteIdentifier(name: String): String =
        "$identifierQuote${name.replace("$identifierQuote", "$identifierQuote$identifierQuote")}$identifierQuote"
}

private val engineDefinitions = listOf(MySqlEngineDefinition, PostgresEngineDefinition, AthenaEngineDefinition).associateBy { it.engine }

val Engine.definition: EngineDefinition
    get() = checkNotNull(engineDefinitions[this]) { "unregistered engine: $this" }

val Engine.wireName: String get() = definition.wireName
val Engine.dialect: Dialect get() = definition.dialect
val Engine.systemSchemas: Set<String> get() = definition.systemSchemas
val Engine.catalogIsConnectionIndependent: Boolean get() = definition.catalogIsConnectionIndependent
val Engine.checksTargetErrors: Boolean get() = definition.checksTargetErrors

val Engine.isMySql: Boolean get() = this == Engine.MYSQL
val Engine.isPostgres: Boolean get() = this == Engine.POSTGRES

fun Engine.catalogName(registeredDbName: String): String = definition.catalogName(registeredDbName)
fun Engine.defaultSchema(registeredDbName: String): String = definition.defaultSchema(registeredDbName)
fun Engine.requireCaseMode(lowerCaseTableNames: Int?): Int? = definition.requireCaseMode(lowerCaseTableNames)
fun Engine.isFixedSystemSchema(canonicalSchema: String): Boolean = definition.isFixedSystemSchema(canonicalSchema)
fun Engine.isSystemSchema(canonicalSchema: String): Boolean = definition.isSystemSchema(canonicalSchema)
fun Engine.isTempSchema(canonicalSchema: String): Boolean = definition.isTempSchema(canonicalSchema)
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

