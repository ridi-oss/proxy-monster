package com.ridi.oss.proxymonster.probe

import com.ridi.oss.proxymonster.analyzer.pb.Column
import com.ridi.oss.proxymonster.analyzer.pb.ColumnNamesResponse
import com.ridi.oss.proxymonster.analyzer.pb.columnNamesRequest
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.sqlglotgo.Sqlglot

/** A column a person named, in the spelling the analyzer keys its catalog on; only [parseColumn] makes one. */
class ColumnKey internal constructor(val catalog: String, val schema: String, val table: String, val column: String) {
    override fun equals(other: Any?) =
        other is ColumnKey && catalog == other.catalog && schema == other.schema && table == other.table && column == other.column

    override fun hashCode() = listOf(catalog, schema, table, column).hashCode()

    override fun toString() = "$catalog.$schema.$table.$column"
}

/**
 * Names a person typed, read as SQL identifiers in the engine's dialect; null when one is not an identifier.
 *
 *   Postgres: Users.SSN -> users.ssn, "App"."T" -> App.T
 */
fun parseColumn(engine: Engine, lowerCaseTableNames: Int?, catalog: String, schema: String, table: String, column: String): ColumnKey? {
    val typed = Column.newBuilder().setCatalog(catalog).setSchema(schema).setTable(table).setColumn(column).build()
    val c = columnNames(engine, lowerCaseTableNames, listOf(typed), Sqlglot::parseColumns)?.single() ?: return null
    return ColumnKey(c.catalog, c.schema, c.table, c.column)
}

/** Names the engine's own catalog reported, in canonical spelling; null when they cannot be normalized. */
fun introspectedColumns(engine: Engine, lowerCaseTableNames: Int?, rows: List<Column>): List<Column>? =
    columnNames(engine, lowerCaseTableNames, rows, Sqlglot::introspectedColumns)

private fun columnNames(engine: Engine, lowerCaseTableNames: Int?, columns: List<Column>, call: (ByteArray) -> ByteArray): List<Column>? = try {
    if (columns.any { c -> listOf(c.catalog, c.schema, c.table, c.column).any { !Sqlglot.hasWellFormedUtf16(it) } }) return null
    val request = columnNamesRequest {
        this.engine = engine
        lowerCaseTableNames?.let { mysqlLowerCaseTableNames = it }
        this.columns.addAll(columns)
    }
    val response = ColumnNamesResponse.parseFrom(call(request.toByteArray()))
    if (response.ok && response.columnsCount == columns.size) response.columnsList.toList() else null
} catch (_: Throwable) {
    null
}
