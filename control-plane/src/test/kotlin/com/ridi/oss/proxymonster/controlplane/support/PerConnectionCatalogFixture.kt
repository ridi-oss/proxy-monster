package com.ridi.oss.proxymonster.controlplane.support

import com.google.protobuf.ByteString
import com.ridi.oss.proxymonster.controlplane.Binding
import com.ridi.oss.proxymonster.controlplane.effectiveCatalog
import com.ridi.oss.proxymonster.controlplane.CatalogMutationResult
import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.Datasource
import com.ridi.oss.proxymonster.controlplane.FragmentColumn
import com.ridi.oss.proxymonster.controlplane.OpenConnection
import com.ridi.oss.proxymonster.controlplane.sqlTypeFor
import com.ridi.oss.proxymonster.controlplane.support.storedRoutines
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.analyzer.pb.column
import com.ridi.oss.proxymonster.grpc.schemaFragmentPush
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.sql.Connection

/** The per-schema routine read each engine's target answers, with the schema as the one parameter. */
private val Engine.testRoutinesSql: String
    get() = when (this) {
        Engine.MYSQL -> "SELECT ROUTINE_NAME FROM information_schema.ROUTINES WHERE ROUTINE_TYPE = 'FUNCTION' AND ROUTINE_SCHEMA = ?"
        Engine.POSTGRES -> "SELECT p.proname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = ?"
        else -> error("engine has no routines: $this")
    }

/** Test helper that turns the fixture's real target-introspected rows into immutable connection fragments. */
class PerConnectionCatalogFixture(val enforcement: EnforcementFixture) {
    val core = ControlPlaneCore(enforcement.dataSource)
    val datasource: Datasource = core.datasourceStore.get(enforcement.datasource.id)!!

    init {
        // A new control plane requires a fresh push before trusting stored functions.
        core.datasourceStore.pushTestCatalog(
            datasource, enforcement.targetJdbcUrl, enforcement.targetUser, enforcement.targetPassword,
        )
    }

    suspend fun openAndPush(
        principal: String = "analyst@example.com",
        schemas: Collection<String> = datasource.defaultSchemas,
        tokenKind: String = "USER",
        withRoutines: Boolean = true,
    ): OpenConnection {
        val opened = core.connectionCatalog.open(Binding(datasource.name, principal, tokenKind, datasource.effectiveCatalog), schemas)
        val bySchema = enforcement.datasourceStore.catalog(datasource.id).columns.groupBy { it.schema }
        val routines = if (withRoutines) enforcement.datasourceStore.storedRoutines(datasource.id) else emptyMap()
        for (schema in schemas.distinct()) {
            val rows = bySchema[schema].orEmpty().map { row ->
                FragmentColumn(row.catalog, row.schema, row.table, row.column, row.sqlType, row.ordinal, row.nullable)
            }
            push(opened.connectionId, schema, rows, routines[schema].orEmpty(), backendGeneration = 1)
        }
        return opened
    }

    /**
     * Scan one schema through the caller-owned target-DB connection. This intentionally observes that
     * connection's transaction-local DDL rather than opening a fresh connection or copying metadata rows.
     */
    suspend fun pushFromTarget(
        target: Connection,
        connectionId: ByteString,
        schema: String,
        backendGeneration: Long = 1,
        unchanged: Boolean = false,
    ) {
        val rows = ArrayList<FragmentColumn>()
        val columnSql =
            """SELECT table_schema, table_name, column_name, data_type, ordinal_position, is_nullable
               FROM information_schema.columns
               WHERE table_schema = ?
               ORDER BY table_schema, table_name, ordinal_position"""
        target.prepareStatement(columnSql).use { ps ->
            ps.setString(1, schema)
            ps.executeQuery().use { rs ->
                while (rs.next()) {
                    rows += FragmentColumn(
                        catalog = datasource.effectiveCatalog,
                        schema = rs.getString(1),
                        table = rs.getString(2),
                        column = rs.getString(3),
                        dataType = sqlTypeFor(rs.getString(4)),
                        ordinal = rs.getInt(5),
                        nullable = rs.getString(6) == "YES",
                    )
                }
            }
        }
        val routines = ArrayList<String>()
        target.prepareStatement(datasource.engine.testRoutinesSql).use { ps ->
            ps.setString(1, schema)
            ps.executeQuery().use { rs -> while (rs.next()) routines += rs.getString(1).lowercase(java.util.Locale.ROOT) }
        }
        push(connectionId, schema, rows, routines.distinct(), backendGeneration, unchanged)
    }

    private suspend fun push(
        connectionId: ByteString,
        schema: String,
        rows: List<FragmentColumn>,
        routines: List<String>,
        backendGeneration: Long,
        unchanged: Boolean = false,
    ) {
        val result = core.connectionCatalog.applyPush(
            schemaFragmentPush {
                this.connectionId = connectionId
                datasourceName = datasource.name
                catalog = datasource.effectiveCatalog
                this.schema = schema
                contentHash = hash(rows, routines)
                this.unchanged = unchanged
                this.backendGeneration = backendGeneration
                if (!unchanged) {
                    this.routines.addAll(routines)
                    columns.addAll(rows.map { row ->
                        column {
                            catalog = datasource.effectiveCatalog
                            this.schema = row.schema
                            table = row.table
                            this.column = row.column
                            dataType = row.dataType
                            ordinal = row.ordinal
                            nullable = row.nullable
                        }
                    })
                }
            },
            datasource,
        )
        check(result is CatalogMutationResult.Applied) { "fixture fragment push rejected: $result" }
    }

    private fun hash(rows: List<FragmentColumn>, routines: List<String>): ByteString {
        val encoded = ByteArrayOutputStream()
        DataOutputStream(encoded).use { out ->
            rows.forEach { row ->
                out.writeUTF(row.schema)
                out.writeUTF(row.table)
                out.writeUTF(row.column)
                out.writeUTF(row.dataType)
                out.writeInt(row.ordinal)
                out.writeBoolean(row.nullable)
            }
            routines.forEach(out::writeUTF)
        }
        return ByteString.copyFrom(MessageDigest.getInstance("SHA-256").digest(encoded.toByteArray()))
    }
}
