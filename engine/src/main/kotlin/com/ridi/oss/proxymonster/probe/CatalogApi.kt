package com.ridi.oss.proxymonster.probe

import com.ridi.oss.proxymonster.analyzer.pb.CatalogSnapshot
import com.ridi.oss.proxymonster.analyzer.pb.Column
import com.ridi.oss.proxymonster.analyzer.pb.EngineConfig
import com.ridi.oss.proxymonster.analyzer.pb.Namespace
import com.ridi.oss.proxymonster.analyzer.pb.StatementFacts

/**
 * Render the catalog identity used by analyzer output and control-plane catalog matching.
 *
 * [column]'s identity arrives already canonical: goproxy normalizes every catalog column (its bulk
 * introspection push AND the per-connection schema-fragment refetch path both call
 * analyzer/probe.NormalizeRelation directly, in-process) before it ever reaches the control plane. No
 * normalization decision is made here — this is pure concatenation of already-canonical parts.
 */
fun columnKey(namespace: Namespace, column: Column): String {
    validateNamespace(namespace)
    validateColumn(column)
    return "${column.catalog.ifBlank { namespace.catalog }}.${column.schema}.${column.table}.${column.column}"
}

/**
 * A ready-to-use analyzer bound to one datasource snapshot: namespace, catalog, and engine config. It
 * provides parse + lineage for SQL strings. The native probe is a pure function of its inputs, so an [Analyzer] is cheap to construct per
 * request. [namespaceProto], [catalogProto], and [engineConfigProto] are the exact request inputs the
 * caller supplied and [analyzerFor] validated — held once and reused by every [analyze] call (only
 * `sql` varies per call; the engine identity/version/settings never change mid-request).
 *
 * [columnKeys] is every input column's key, in the same order given to [analyzerFor] — exposed so a
 * caller needing a key per catalog row (e.g. the control-plane's exact lineage-key index) can reuse
 * what construction already computed, instead of re-deriving them via a second full-catalog walk.
 */
class Analyzer internal constructor(
    internal val namespaceProto: Namespace,
    internal val catalogProto: CatalogSnapshot,
    internal val engineConfigProto: EngineConfig,
    val columnKeys: List<String>,
) {
    // sqlglot parses a trailing terminator ';', surrounding whitespace, and a ';' inside a string
    // literal on its own, and fail-closes a genuine multi-statement (>1 parsed statement) — so no
    // pre-cleaning is needed here.
    fun analyze(sql: String): StatementFacts =
        SqlglotProbe.analyze(sql, namespaceProto, catalogProto, engineConfigProto)
}

/** Build an [Analyzer] from an insertion-ordered flat catalog and engine config snapshot. */
fun analyzerFor(namespace: Namespace, catalog: CatalogSnapshot, engineConfig: EngineConfig): Analyzer {
    validateNamespace(namespace)
    // Validation already renders every column's key while checking for collisions; reuse those as the
    // exposed columnKeys instead of re-deriving them.
    return Analyzer(
        namespaceProto = namespace,
        catalogProto = catalog,
        engineConfigProto = engineConfig,
        columnKeys = validateUniqueness(namespace.catalog, catalog.columnsList),
    )
}

private data class SchemaIdentity(val catalog: String, val schema: String)
private data class TableIdentity(val schema: SchemaIdentity, val table: String)
private data class ColumnIdentity(val table: TableIdentity, val column: String)

private fun validateNamespace(namespace: Namespace) {
    require(namespace.catalog.isNotBlank()) { "analyzer namespace catalog is required" }
    require(namespace.searchPathList.isNotEmpty()) { "analyzer namespace searchPath is required" }
    namespace.searchPathList.forEach { require(it.isNotBlank()) { "analyzer namespace searchPath entries are required" } }
}

private fun validateColumn(column: Column) {
    require(column.schema.isNotBlank()) { "column schema is required" }
    require(column.table.isNotBlank()) { "column table is required" }
    require(column.column.isNotBlank()) { "column name is required" }
    require(column.dataType.isNotBlank()) { "column dataType is required" }
}

/** Validates the catalog's identities are collision-free, returning each column's rendered key (same
 *  order as [columns], same value [columnKey] would produce) so callers needing those keys don't
 *  re-derive them. Every column's identity already arrives canonical (goproxy normalizes at
 *  introspection), so there is nothing here to fold or compare against a raw spelling — only two
 *  genuine risks remain: an exact duplicate (schema, table, column) triple, and two DIFFERENT
 *  identities whose dot-joined key happens to render identically (a dot embedded in a raw identifier,
 *  e.g. catalog "a.b" + schema "c" vs. catalog "a" + schema "b.c", both -> "a.b.c"). */
private fun validateUniqueness(namespaceCatalog: String, columns: List<Column>): List<String> {
    val seenColumns = LinkedHashSet<ColumnIdentity>()
    val renderedTables = LinkedHashMap<String, TableIdentity>()
    val renderedColumns = LinkedHashMap<String, ColumnIdentity>()
    val renderedKeys = ArrayList<String>(columns.size)

    for (column in columns) {
        validateColumn(column)
        val schema = SchemaIdentity(column.catalog.ifBlank { namespaceCatalog }, column.schema)
        val table = TableIdentity(schema, column.table)
        val renderedTable = listOf(schema.catalog, schema.schema, table.table).joinToString(".")
        val previousRenderedTable = renderedTables.putIfAbsent(renderedTable, table)
        require(previousRenderedTable == null || previousRenderedTable == table) {
            "catalog table identities render to the same analyzer key '$renderedTable': " +
                "$previousRenderedTable and $table"
        }

        val columnIdentity = ColumnIdentity(table, column.column)
        val rendered = "$renderedTable.${columnIdentity.column}"
        require(seenColumns.add(columnIdentity)) {
            "catalog contains duplicate column identity: $rendered"
        }

        val previousColumn = renderedColumns.putIfAbsent(rendered, columnIdentity)
        require(previousColumn == null || previousColumn == columnIdentity) {
            "catalog column identities render to the same analyzer key '$rendered': $previousColumn and $columnIdentity"
        }
        renderedKeys.add(rendered)
    }
    return renderedKeys
}
