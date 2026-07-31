package com.ridi.oss.proxymonster.controlplane.support

import com.google.protobuf.ByteString
import com.ridi.oss.proxymonster.controlplane.Binding
import com.ridi.oss.proxymonster.controlplane.CatalogMutationResult
import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.Datasource
import com.ridi.oss.proxymonster.controlplane.FragmentColumn
import com.ridi.oss.proxymonster.controlplane.OpenConnection
import com.ridi.oss.proxymonster.controlplane.sqlTypeFor
import com.ridi.oss.proxymonster.grpc.column
import com.ridi.oss.proxymonster.grpc.schemaFragmentPush
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.sql.Connection

/** Test helper that turns the fixture's real target-introspected rows into immutable connection fragments. */
class PerConnectionCatalogFixture(val enforcement: EnforcementFixture) {
    val core = ControlPlaneCore(enforcement.dataSource)
    val datasource: Datasource = core.datasourceStore.get(enforcement.datasource.id)!!

    suspend fun openAndPush(
        principal: String = "analyst@example.com",
        schemas: Collection<String> = datasource.defaultSchemas,
    ): OpenConnection {
        val opened = core.connectionCatalog.open(Binding(datasource.name, principal, "USER"), schemas)
        val bySchema = enforcement.datasourceStore.catalog(datasource.id).groupBy { it.schema }
        for (schema in schemas.distinct()) {
            val rows = bySchema[schema].orEmpty().map { row ->
                FragmentColumn(row.schema, row.table, row.column, row.sqlType, row.ordinal, row.nullable)
            }
            push(opened.connectionId, schema, rows, backendGeneration = 1)
        }
        return opened
    }

    /**
     * Scan one schema through the caller-owned backend connection. This intentionally observes that
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
        push(connectionId, schema, rows, backendGeneration, unchanged)
    }

    private suspend fun push(
        connectionId: ByteString,
        schema: String,
        rows: List<FragmentColumn>,
        backendGeneration: Long,
        unchanged: Boolean = false,
    ) {
        val result = core.connectionCatalog.applyPush(
            schemaFragmentPush {
                this.connectionId = connectionId
                datasourceName = datasource.name
                this.schema = schema
                contentHash = hash(rows)
                // The fixture reads the schema straight off the target and computes the hash over exactly
                // the rows it pushes, which is what a coherent bracket asserts.
                hashTrusted = true
                this.unchanged = unchanged
                this.backendGeneration = backendGeneration
                if (!unchanged) {
                    columns.addAll(rows.map { row ->
                        column {
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

    private fun hash(rows: List<FragmentColumn>): ByteString {
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
        }
        return ByteString.copyFrom(MessageDigest.getInstance("SHA-256").digest(encoded.toByteArray()))
    }
}
