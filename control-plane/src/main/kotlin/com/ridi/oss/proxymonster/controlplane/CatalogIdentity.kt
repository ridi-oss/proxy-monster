package com.ridi.oss.proxymonster.controlplane

/** The catalog every connection to this datasource is in: MySQL "def", PostgreSQL the database. */
internal val Datasource.effectiveCatalog: String
    get() = engine.catalogName(dbName)
