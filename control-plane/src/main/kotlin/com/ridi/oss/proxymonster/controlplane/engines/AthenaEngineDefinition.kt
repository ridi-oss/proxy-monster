package com.ridi.oss.proxymonster.controlplane.engines

import com.ridi.oss.proxymonster.analyzer.pb.EngineConfig
import com.ridi.oss.proxymonster.analyzer.pb.FunctionCatalog
import com.ridi.oss.proxymonster.analyzer.pb.SessionObservation
import com.ridi.oss.proxymonster.grpc.proxyCommand
import com.ridi.oss.proxymonster.grpc.ProxyCommand
import com.ridi.oss.proxymonster.athena.pb.fetchAthenaPreparedDefinition
import com.ridi.oss.proxymonster.analyzer.pb.StatementFacts
import com.ridi.oss.proxymonster.athena.pb.athenaSqlContext
import com.ridi.oss.proxymonster.analyzer.pb.engineConfig
import com.ridi.oss.proxymonster.analyzer.pb.functionCatalog
import com.ridi.oss.proxymonster.classification.AthenaNativeFunctions
import com.ridi.oss.proxymonster.controlplane.ApiError
import com.ridi.oss.proxymonster.controlplane.AthenaRequestAuthorizer
import com.ridi.oss.proxymonster.controlplane.CatalogColumn
import com.ridi.oss.proxymonster.controlplane.Datasource
import com.ridi.oss.proxymonster.controlplane.EngineDefinition
import com.ridi.oss.proxymonster.controlplane.RequestAuthorizer
import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.grpc.ConnectionInfo
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.probe.Dialect
import java.net.URI

/**
 * Athena: one datasource is one workgroup + data catalog + default database in one region, all published
 * as ConnectionInfo properties. Catalog names fold to lowercase; there is no session case mode and no
 * per-connection catalog content. Requests arrive as JSON API calls, so the native authorizer decides them.
 */
internal object AthenaEngineDefinition : EngineDefinition {
    override val engine = Engine.ATHENA
    override val wireName = "athena"
    override val dialect = Dialect.ATHENA
    override val requestAuthorizer: RequestAuthorizer = AthenaRequestAuthorizer
    override val connectionProperties = setOf("region", "workgroup", "catalog", "database")
    override val systemSchemas = setOf("information_schema")
    override val catalogIsConnectionIndependent = true

    override fun catalogName(dbName: String): String = dbName.lowercase()
    override fun defaultSchema(dbName: String): String = dbName
    override fun requireCaseMode(lowerCaseTableNames: Int?): Int? = null
    override fun isFixedSystemSchema(schema: String): Boolean = schema.lowercase() in systemSchemas
    override fun isSystemSchema(schema: String): Boolean = isFixedSystemSchema(schema)
    override fun splitEngineConfig(datasource: Datasource): EngineConfig = analyzerEngineConfig(datasource, SessionObservation.getDefaultInstance())
    override fun analyzerEngineConfig(datasource: Datasource, session: SessionObservation): EngineConfig = engineConfig {
        engine = Engine.ATHENA
        engineVersion = datasource.engineVersion.orEmpty()
        // A decision that carries no request (an editor run, a stored-result view) runs in the datasource's
        // registered workgroup with no parameters.
        this.session = if (session.hasAthena()) session else session.toBuilder()
            .setAthena(athenaSqlContext { workgroup = datasource.connectionInfo?.propertiesMap?.get("workgroup").orEmpty() }).build()
    }

    override fun beforeDecideCommands(facts: StatementFacts): List<ProxyCommand> {
        if (!facts.hasAthenaPreparedDefinitionNeed()) return emptyList()
        val need = facts.athenaPreparedDefinitionNeed
        return listOf(proxyCommand { fetchAthenaPreparedDefinition = fetchAthenaPreparedDefinition { workgroup = need.workgroup; name = need.name } })
    }

    override fun parseServerVersion(raw: String?): Pair<String?, Boolean> =
        raw?.let { version.matchEntire(it.trim())?.groupValues?.get(1) } to false

    override fun manifestSeries(version: String): String = version

    // Athena exposes no routine catalog, so the builtins are the pinned list for the engine version.
    override fun functionCatalog(routines: Map<String, List<String>>, engineVersion: String?): FunctionCatalog = functionCatalog {
        builtinFunctions.addAll(AthenaNativeFunctions.forVersion(engineVersion))
    }

    override fun implicitColumns(rows: List<CatalogColumn>): List<CatalogColumn> = emptyList()

    override fun validateConnectionInfo(info: ConnectionInfo) {
        fun invalid(): Nothing = throw ManagementException(ApiError("datasource.invalid_connection_info"))
        if (info.propertiesMap.keys.any { it !in connectionProperties }) invalid()
        if (info.endpoint.isEmpty() && info.propertiesCount == 0) return
        if (info.propertiesMap.keys != connectionProperties || info.propertiesMap.values.any { it.isBlank() }) invalid()
        if (!region.matches(info.propertiesMap.getValue("region"))) invalid()
        if (info.endpoint.isEmpty()) return
        val uri = runCatching { URI(info.endpoint) }.getOrNull() ?: invalid()
        if (uri.scheme != "https" || uri.host.isNullOrBlank() || uri.userInfo != null || uri.query != null ||
            uri.fragment != null || uri.path !in listOf("", "/") || uri.port != -1 && uri.port !in 1..65535
        ) invalid()
    }

    private val version = Regex("(?:Athena engine version )?([0-9]+)", RegexOption.IGNORE_CASE)
    private val region = Regex("[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+")
}
