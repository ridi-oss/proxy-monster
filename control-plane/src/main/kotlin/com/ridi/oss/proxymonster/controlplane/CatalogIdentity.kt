package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.grpc.ObjectRef
import com.ridi.oss.proxymonster.grpc.objectRef

/** The catalog the proxy measured on its connection, or the engine's default until the first catalog push. */
internal val Datasource.effectiveCatalog: String
    get() = currentCatalog ?: engine.catalogName(dbName)

/** The catalog a request names; it must be this datasource's. */
internal fun Datasource.requireCatalog(catalog: String): String {
    if (catalog.isBlank() || catalog != effectiveCatalog) throw ManagementException(ApiError("datasource.invalid_catalog"))
    return catalog
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
