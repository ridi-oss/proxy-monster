package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.analyzer.pb.CatalogSnapshot

/** A datasource as its proxy leaves it at boot: registered, with an empty catalog of database `app` pushed. */
fun DatasourceStore.seed(name: String, engine: String, catalog: String = engineFromWire(engine).catalogName("app")): Datasource {
    val ds = register(
        name = name, engine = engineFromWire(engine), host = "", port = 0, dbName = "",
        tags = emptyList(), advertiseAddr = "", advertiseCertChain = null, advertiseWireTls = false,
    )
    storePushedCatalog(
        id = ds.id, defaultSchemas = listOf(ds.engine.defaultSchema("app")), mysqlLowerCaseTableNames = null, engineVersion = "",
        catalog = CatalogSnapshot.getDefaultInstance(), currentCatalog = catalog,
    )
    return checkNotNull(get(ds.id))
}
