package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.analyzer.pb.column
import com.ridi.oss.proxymonster.probe.ColumnKey
import com.ridi.oss.proxymonster.probe.DatasourceRejectedException
import com.ridi.oss.proxymonster.probe.introspectedColumns
import com.ridi.oss.proxymonster.probe.parseColumn
import com.ridi.oss.proxymonster.grpc.ObjectRef
import com.ridi.oss.proxymonster.grpc.objectRef

/** The catalog the proxy measured on its connection, or the engine's default until the first catalog push. */
internal val Datasource.effectiveCatalog: String
    get() = currentCatalog ?: engine.catalogName(dbName)

/** [fold], refused while the analyzer rejects the datasource: MySQL before introspection reports lower_case_table_names. */
private inline fun <T> foldOrRefuse(fold: () -> T): T = try {
    fold()
} catch (_: DatasourceRejectedException) {
    throw ManagementException(ApiError("datasource.case_mode_unknown"))
}

/** The first stored default schema, not normalized, whose canonical name is not a system schema. */
internal fun Datasource.firstUserDefaultSchema(): String? {
    val reported = targetSettings()
    return defaultSchemas.firstOrNull { storedSchema ->
        val canonicalSchema = foldOrRefuse { introspectedColumns(engine, reported, listOf(column { schema = storedSchema })) }?.single()?.schema
        canonicalSchema != null && !engine.isSystemSchema(canonicalSchema)
    }
}

/** [firstUserDefaultSchema] as SQL identifier text, quoted so [columnKey] keeps the target's spelling. */
internal fun Datasource.defaultSchemaIdentifier(): String? = firstUserDefaultSchema()?.let(engine.definition::quoteIdentifier)

/** A canonical catalog; it must be this datasource's. */
internal fun Datasource.requireCatalog(catalog: String): String {
    if (catalog.isBlank() || catalog != effectiveCatalog) throw ManagementException(ApiError("datasource.invalid_catalog"))
    return catalog
}

/** A column a person named, parsed by the engine's dialect; its catalog must be this datasource's. */
internal fun Datasource.columnKey(catalog: String, schema: String, table: String, column: String): ColumnKey {
    val key = foldOrRefuse { parseColumn(engine, targetSettings(), catalog, schema, table, column) }
        ?: throw ManagementException(ApiError("common.invalid_value", mapOf("field" to "column")))
    requireCatalog(key.catalog)
    return key
}

/** The catalog a catalog push reports; it must be one the engine could actually produce (MySQL: "def"). */
internal fun Datasource.measuredCatalog(catalog: String): String {
    if (catalog.isBlank() || engine.catalogName(catalog) != catalog) throw ManagementException(ApiError("datasource.invalid_catalog"))
    return catalog
}

internal fun namespace(catalog: String, schema: String): ObjectRef = objectRef {
    this.catalog = catalog
    this.schema = schema
}

internal fun columnRef(catalog: String, schema: String, table: String, column: String): ObjectRef = objectRef {
    this.catalog = catalog
    this.schema = schema
    this.table = table
    this.column = column
}

internal fun Datasource.namespaces(schemas: Collection<String>): List<ObjectRef> =
    schemas.map { namespace(effectiveCatalog, it) }
