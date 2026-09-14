package com.ridi.oss.proxymonster.controlplane.engines

import com.ridi.oss.proxymonster.analyzer.pb.EngineConfig
import com.ridi.oss.proxymonster.analyzer.pb.engineConfig
import com.ridi.oss.proxymonster.controlplane.Datasource
import com.ridi.oss.proxymonster.controlplane.EngineDefinition
import com.ridi.oss.proxymonster.controlplane.MetadataRequestAuthorizer
import com.ridi.oss.proxymonster.controlplane.RequestAuthorizer
import com.ridi.oss.proxymonster.controlplane.validateNativeConnectionInfo
import com.ridi.oss.proxymonster.grpc.ConnectionInfo
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.probe.Dialect

internal object PostgresEngineDefinition : EngineDefinition {
    override val engine = Engine.POSTGRES
    override val wireName = "postgres"
    override val dialect = Dialect.POSTGRES
    override val requestAuthorizer: RequestAuthorizer = MetadataRequestAuthorizer
    override val connectionProperties: Set<String> = emptySet()
    override val systemSchemas = setOf("pg_catalog", "information_schema")
    // pg_temp_* schemas and transactional DDL depend on the connection.
    override val catalogIsConnectionIndependent = false

    override fun catalogName(dbName: String): String = dbName
    override fun defaultSchema(dbName: String): String = "public"
    override fun resolveSchema(requestedSchema: String, dbName: String): String = requestedSchema
    override fun requireCaseMode(lowerCaseTableNames: Int?): Int? = null
    override fun isFixedSystemSchema(schema: String): Boolean = schema in systemSchemas
    override fun isSystemSchema(schema: String): Boolean =
        isFixedSystemSchema(schema) || schema.startsWith("pg_temp_") || schema.startsWith("pg_toast")

    override fun splitEngineConfig(datasource: Datasource): EngineConfig = analyzerEngineConfig(datasource, false)

    override fun analyzerEngineConfig(datasource: Datasource, ansiQuotes: Boolean): EngineConfig = engineConfig {
        engine = this@PostgresEngineDefinition.engine
        engineVersion = datasource.engineVersion ?: ""
        if (ansiQuotes) mysqlAnsiQuotes = true
    }

    override fun parseServerVersion(raw: String?): Pair<String?, Boolean> {
        if (raw.isNullOrBlank()) return null to false
        val version = postgresVersion.find(raw)?.groupValues?.get(1) ?: numericVersion.find(raw)?.value
        return version to raw.contains("aurora", ignoreCase = true)
    }

    override fun manifestSeries(version: String): String = version.substringBefore(".")
    override fun validateConnectionInfo(info: ConnectionInfo) = validateNativeConnectionInfo(info, connectionProperties)

    private val postgresVersion = Regex("""PostgreSQL\s+(\d+(?:\.\d+)?)""")
    private val numericVersion = Regex("""\d+(?:\.\d+)?""")
}
