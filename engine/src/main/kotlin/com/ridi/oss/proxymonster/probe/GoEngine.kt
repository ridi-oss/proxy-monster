package com.ridi.oss.proxymonster.probe

import com.ridi.oss.proxymonster.analyzer.pb.EngineCallRequestKt
import com.ridi.oss.proxymonster.analyzer.pb.EngineCallResponse
import com.ridi.oss.proxymonster.analyzer.pb.EngineConfig
import com.ridi.oss.proxymonster.analyzer.pb.EngineDatasource
import com.ridi.oss.proxymonster.analyzer.pb.EngineFacts
import com.ridi.oss.proxymonster.analyzer.pb.EngineFactsCall
import com.ridi.oss.proxymonster.analyzer.pb.FunctionCatalog
import com.ridi.oss.proxymonster.analyzer.pb.SchemaKind
import com.ridi.oss.proxymonster.analyzer.pb.ServerVersion
import com.ridi.oss.proxymonster.analyzer.pb.SessionObservation
import com.ridi.oss.proxymonster.analyzer.pb.analyzerConfigCall
import com.ridi.oss.proxymonster.analyzer.pb.engineCallRequest
import com.ridi.oss.proxymonster.analyzer.pb.engineConnectionInfo
import com.ridi.oss.proxymonster.analyzer.pb.functionCatalogCall
import com.ridi.oss.proxymonster.analyzer.pb.schemaFunctions
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.sqlglotgo.Sqlglot
import java.util.concurrent.ConcurrentHashMap

/** One target engine's Go definition (analyzer/engines), called over FFM; a failed call throws IllegalArgumentException. */
class GoEngine private constructor(val engine: Engine) {
    /** The engine's constants, read once: wire name `mysql`, quote `` ` ``, system schemas. */
    val facts: EngineFacts = call { facts = EngineFactsCall.getDefaultInstance() }.facts

    private val schemaKinds = ConcurrentHashMap<String, SchemaKind>()

    /** The analyzer catalog for a datasource registered on [registeredDbName]: MySQL `def`, Postgres the name. */
    fun catalogName(registeredDbName: String): String = call { catalogName = registeredDbName }.text

    /** The schema an unqualified table resolves to: MySQL the registered database, Postgres `public`. */
    fun defaultSchema(registeredDbName: String): String = call { defaultSchema = registeredDbName }.text

    /** How the engine treats [canonicalSchema]: Postgres pg_temp_3 is system and temp. Cached per name. */
    fun schemaKind(canonicalSchema: String): SchemaKind =
        schemaKinds.computeIfAbsent(canonicalSchema) { call { schemaKind = it }.schemaKind }

    /** The analyzer config for one decision or a batch split. */
    fun analyzerConfig(datasource: EngineDatasource, session: SessionObservation): EngineConfig =
        call {
            analyzerConfig = analyzerConfigCall {
                this.datasource = datasource
                this.session = session
            }
        }.analyzerConfig

    /** The comparable version from version(): `8.0.mysql_aurora.3.04.0` -> 8.0, aurora. */
    fun serverVersion(raw: String?): ServerVersion = call { serverVersion = raw.orEmpty() }.serverVersion

    /** The classification-manifest series of [version]: MySQL 8.0.44 -> 8.0, Postgres 16.4 -> 16. */
    fun manifestSeries(version: String): String = call { manifestSeries = version }.text

    /** The analyzer's function inventory from introspected [routines] (schema -> names, in schema order). */
    fun functionCatalog(routines: Map<String, List<String>>, engineVersion: String?): FunctionCatalog = call {
        functionCatalog = functionCatalogCall {
            routines.forEach { (schema, names) -> this.routines += schemaFunctions { this.schema = schema; this.names += names } }
            this.engineVersion = engineVersion.orEmpty()
        }
    }.functionCatalog

    /** Whether this engine's proxies may publish [endpoint] and [properties]. */
    fun connectionInfoValid(endpoint: String, properties: Map<String, String>): Boolean = call {
        connectionInfo = engineConnectionInfo {
            this.endpoint = endpoint
            this.properties.putAll(properties)
        }
    }.valid

    /** The statement that makes [canonicalSchema] a session's default: MySQL ``USE `app` ``. */
    fun defaultSchemaStatement(canonicalSchema: String): String = call { defaultSchemaStatement = canonicalSchema }.text

    private fun call(build: EngineCallRequestKt.Dsl.() -> Unit): EngineCallResponse {
        val request = engineCallRequest {
            engine = this@GoEngine.engine
            build()
        }
        val response = EngineCallResponse.parseFrom(Sqlglot.engineCall(request.toByteArray()))
        require(response.error.isEmpty()) { response.error }
        return response
    }

    companion object {
        private val byEngine = ConcurrentHashMap<Engine, GoEngine>()

        fun of(engine: Engine): GoEngine = byEngine.computeIfAbsent(engine, ::GoEngine)
    }
}
