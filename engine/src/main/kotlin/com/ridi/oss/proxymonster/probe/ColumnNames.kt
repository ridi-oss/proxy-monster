package com.ridi.oss.proxymonster.probe

import com.ridi.oss.proxymonster.analyzer.pb.Column
import com.ridi.oss.proxymonster.analyzer.pb.ColumnNamesResponse
import com.ridi.oss.proxymonster.analyzer.pb.TargetSettings
import com.ridi.oss.proxymonster.analyzer.pb.columnNamesRequest
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.analyzer.GoBinding

/** A column a person named, in the spelling the analyzer keys its catalog on; only [parseColumn] makes one. */
class ColumnKey internal constructor(val catalog: String, val schema: String, val table: String, val column: String) {
    override fun equals(other: Any?) =
        other is ColumnKey && catalog == other.catalog && schema == other.schema && table == other.table && column == other.column

    override fun hashCode() = listOf(catalog, schema, table, column).hashCode()

    override fun toString() = "$catalog.$schema.$table.$column"
}

/** The engine refused the datasource: MySQL before introspection reports lower_case_table_names. */
class DatasourceRejectedException : RuntimeException("the engine refused the datasource")

/**
 * Names a person typed, read as SQL identifiers in the engine's dialect; null when one is not an identifier.
 * Throws [DatasourceRejectedException] when the engine refuses [targetSettings].
 *
 *   Postgres: Users.SSN -> users.ssn, "App"."T" -> App.T
 */
fun parseColumn(engine: Engine, targetSettings: TargetSettings, catalog: String, schema: String, table: String, column: String): ColumnKey? {
    val typed = Column.newBuilder().setCatalog(catalog).setSchema(schema).setTable(table).setColumn(column).build()
    val c = columnNames(engine, targetSettings, listOf(typed), GoBinding::parseColumns)?.single() ?: return null
    return ColumnKey(c.catalog, c.schema, c.table, c.column)
}

/** Names the engine's own catalog reported, in canonical spelling; null when they cannot be normalized. */
fun introspectedColumns(engine: Engine, targetSettings: TargetSettings, rows: List<Column>): List<Column>? =
    columnNames(engine, targetSettings, rows, GoBinding::introspectedColumns)

private fun columnNames(engine: Engine, targetSettings: TargetSettings, columns: List<Column>, call: (ByteArray) -> ByteArray): List<Column>? = try {
    if (columns.any { c -> listOf(c.catalog, c.schema, c.table, c.column).any { !GoBinding.hasWellFormedUtf16(it) } }) return null
    val request = columnNamesRequest {
        this.engine = engine
        this.target = targetSettings
        this.columns.addAll(columns)
    }
    val response = ColumnNamesResponse.parseFrom(call(request.toByteArray()))
    when (response.error) {
        ColumnNamesResponse.Error.NONE -> response.columnsList.toList().takeIf { it.size == columns.size }
        ColumnNamesResponse.Error.DATASOURCE_REJECTED -> throw DatasourceRejectedException()
        else -> null
    }
} catch (e: DatasourceRejectedException) {
    throw e
} catch (_: Throwable) {
    null
}
