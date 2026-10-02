package com.ridi.oss.proxymonster.controlplane.engines

import com.ridi.oss.proxymonster.analyzer.pb.EngineConfig
import com.ridi.oss.proxymonster.analyzer.pb.FunctionCatalog
import com.ridi.oss.proxymonster.analyzer.pb.functionCatalog
import com.ridi.oss.proxymonster.analyzer.pb.schemaFunctions
import com.ridi.oss.proxymonster.classification.PostgresGrammarFunctions
import com.ridi.oss.proxymonster.classification.PostgresSystemColumns
import com.ridi.oss.proxymonster.analyzer.pb.SessionObservation
import com.ridi.oss.proxymonster.analyzer.pb.engineConfig
import com.ridi.oss.proxymonster.controlplane.CatalogColumn
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
    override fun requireCaseMode(lowerCaseTableNames: Int?): Int? = null
    override fun isFixedSystemSchema(schema: String): Boolean = schema in systemSchemas
    override fun isSystemSchema(schema: String): Boolean =
        isFixedSystemSchema(schema) || schema.startsWith("pg_temp_") || schema.startsWith("pg_toast")
    override val defaultSchemaStatement = { schema: String -> "SET search_path TO \"${schema.replace("\"", "\"\"")}\"" }

    override fun splitEngineConfig(datasource: Datasource): EngineConfig = analyzerEngineConfig(datasource, SessionObservation.getDefaultInstance())

    override fun analyzerEngineConfig(datasource: Datasource, session: SessionObservation): EngineConfig = engineConfig {
        engine = this@PostgresEngineDefinition.engine
        engineVersion = datasource.engineVersion ?: ""
        this.session = session
    }

    override fun parseServerVersion(raw: String?): Pair<String?, Boolean> {
        if (raw.isNullOrBlank()) return null to false
        val version = postgresVersion.find(raw)?.groupValues?.get(1) ?: numericVersion.find(raw)?.value
        return version to raw.contains("aurora", ignoreCase = true)
    }

    override fun validateConnectionInfo(info: ConnectionInfo) = validateNativeConnectionInfo(info, connectionProperties)
    override fun manifestSeries(version: String): String = version.substringBefore(".")

    // {"pg_catalog": [abs], "public": [add_tax], "pg_temp_3": [x]} -> builtins = [abs, coalesce, ...] (grammar
    // keywords have no pg_proc row), udf public = [add_tax], pg_temp_3 dropped
    override fun functionCatalog(routines: Map<String, List<String>>, engineVersion: String?): FunctionCatalog = functionCatalog {
        val pgCatalog = (routines["pg_catalog"].orEmpty() + PostgresGrammarFunctions.names).distinct()
        builtinFunctions.addAll(pgCatalog)
        systemFunctionSchemas.add(schemaFunctions { schema = "pg_catalog"; names.addAll(pgCatalog) })
        routines.forEach { (schema, names) ->
            when {
                schema == "pg_catalog" -> Unit
                isFixedSystemSchema(schema) -> systemFunctionSchemas.add(schemaFunctions { this.schema = schema; this.names.addAll(names) })
                !isSystemSchema(schema) -> udfSchemas.add(schemaFunctions { this.schema = schema; this.names.addAll(names) })
            }
        }
    }

    // A real column of a system-column name wins; some system views have an ordinary xmin.
    override fun implicitColumns(rows: List<CatalogColumn>): List<CatalogColumn> {
        data class TableId(val catalog: String, val schema: String, val table: String, val isTemp: Boolean)
        val existing = HashMap<TableId, MutableSet<String>>()
        for (row in rows) {
            existing.getOrPut(TableId(row.catalog, row.schema, row.table, row.isTemp)) { HashSet() } += row.column
        }
        return existing.flatMap { (id, columns) ->
            PostgresSystemColumns.byName.mapNotNull { (name, type) ->
                if (name in columns) return@mapNotNull null
                CatalogColumn(
                    catalog = id.catalog, schema = id.schema, table = id.table, column = name,
                    dataType = type, sqlType = type, ordinal = 0, nullable = false,
                    isTemp = id.isTemp, implicit = true,
                )
            }
        }
    }

    private val postgresVersion = Regex("""PostgreSQL\s+(\d+(?:\.\d+)?)""")
    private val numericVersion = Regex("""\d+(?:\.\d+)?""")
}
