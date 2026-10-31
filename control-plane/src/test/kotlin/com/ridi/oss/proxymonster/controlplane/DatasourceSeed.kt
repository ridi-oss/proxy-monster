package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.analyzer.pb.CatalogSnapshot

/** A datasource as its proxy leaves it at boot: registered, with an empty catalog of database `app` pushed. */
fun DatasourceStore.seed(name: String, engine: String, catalog: String = engineFromWire(engine).catalogName("app")): Datasource {
    val ds = registerOnly(name, engine)
    storePushedCatalog(
        id = ds.id, defaultSchemas = listOf(ds.engine.defaultSchema("app")), mysqlLowerCaseTableNames = null, engineVersion = "",
        catalog = CatalogSnapshot.getDefaultInstance(), currentCatalog = catalog,
    )
    return checkNotNull(get(ds.id))
}

/** A datasource whose proxy has registered but not yet pushed a catalog. */
fun DatasourceStore.registerOnly(name: String, engine: String): Datasource = register(
    name = name, engine = engineFromWire(engine), targetInfo = "", dbName = "",
    tags = emptyList(), advertiseAddr = "", advertiseCertChain = null, advertiseWireTls = false,
)
