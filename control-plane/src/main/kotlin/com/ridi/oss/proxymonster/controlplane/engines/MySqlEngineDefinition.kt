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

internal object MySqlEngineDefinition : EngineDefinition {
    override val engine = Engine.MYSQL
    override val wireName = "mysql"
    override val dialect = Dialect.MYSQL
    override val requestAuthorizer: RequestAuthorizer = MetadataRequestAuthorizer
    override val connectionProperties: Set<String> = emptySet()
    override val systemSchemas = setOf("information_schema", "mysql", "performance_schema", "sys")
    // MySQL temporary tables are absent from information_schema.COLUMNS.
    override val catalogIsConnectionIndependent = true

    override fun catalogName(dbName: String): String = "def"
    override fun defaultSchema(dbName: String): String = dbName
    override fun resolveSchema(requestedSchema: String, dbName: String): String =
        if (requestedSchema == "public") defaultSchema(dbName) else requestedSchema

    override fun requireCaseMode(lowerCaseTableNames: Int?): Int = requireNotNull(lowerCaseTableNames) {
        "MySQL lower_case_table_names has not been captured by introspection"
    }

    override fun isFixedSystemSchema(schema: String): Boolean = schema.lowercase() in systemSchemas
    override fun isSystemSchema(schema: String): Boolean = isFixedSystemSchema(schema)

    override fun splitEngineConfig(datasource: Datasource): EngineConfig? {
        if (datasource.engineVersion.isNullOrBlank() || datasource.mysqlLowerCaseTableNames == null) return null
        return analyzerEngineConfig(datasource, false)
    }

    override fun analyzerEngineConfig(datasource: Datasource, ansiQuotes: Boolean): EngineConfig = engineConfig {
        engine = this@MySqlEngineDefinition.engine
        engineVersion = datasource.engineVersion ?: ""
        mysqlLowerCaseTableNames = requireCaseMode(datasource.mysqlLowerCaseTableNames)
        if (ansiQuotes) mysqlAnsiQuotes = true
    }

    override fun parseServerVersion(raw: String?): Pair<String?, Boolean> {
        if (raw.isNullOrBlank()) return null to false
        // 8.0.mysql_aurora.3.04.0 identifies MySQL 8.0, not Aurora 3.04.0.
        val base = raw.substringBefore("mysql_aurora").substringBefore("(aurora")
        val version = patchVersion.find(base)?.value ?: minorVersion.find(base)?.value
        return version to raw.contains("aurora", ignoreCase = true)
    }

    override fun manifestSeries(version: String): String = version.split(".").take(2).joinToString(".")
    override fun validateConnectionInfo(info: ConnectionInfo) = validateNativeConnectionInfo(info, connectionProperties)

    private val patchVersion = Regex("""\d+\.\d+\.\d+""")
    private val minorVersion = Regex("""\d+\.\d+""")
}
