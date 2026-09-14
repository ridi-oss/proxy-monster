package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.grpc.NamespaceRef
import com.ridi.oss.proxymonster.grpc.namespaceRef

data class ColumnIdentity(val catalog: String, val schema: String, val table: String, val column: String)

internal val Datasource.effectiveCatalog: String
    get() = currentCatalog ?: engine.catalogName(dbName)

internal fun Datasource.resolveCatalog(requested: String?, expected: String = effectiveCatalog): String {
    if (expected.isBlank() || (requested != null && (requested.isBlank() || requested != expected))) {
        throw ManagementException(ApiError("datasource.invalid_catalog"))
    }
    return requested ?: expected
}

internal fun Datasource.measuredCatalog(requested: String?): String {
    val catalog = requested ?: effectiveCatalog
    if (catalog.isBlank() || engine.catalogName(catalog) != catalog) {
        throw ManagementException(ApiError("datasource.invalid_catalog"))
    }
    return catalog
}

internal fun namespace(catalog: String, schema: String): NamespaceRef = namespaceRef {
    this.catalog = catalog
    this.schema = schema
}

internal fun Datasource.namespaces(schemas: Collection<String>): List<NamespaceRef> =
    schemas.map { namespace(effectiveCatalog, it) }
