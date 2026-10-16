package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.canonicalColumns
import com.ridi.oss.proxymonster.controlplane.support.pushedColumn
import com.ridi.oss.proxymonster.grpc.Engine
import kotlin.test.Test
import kotlin.test.assertEquals

/** Every Kotlin-side Athena fold must agree with the analyzer's, non-ASCII included. */
class AthenaNameFoldTest {
    private fun analyzerFold(name: String): String =
        canonicalColumns(Engine.ATHENA, "3", null, listOf(pushedColumn(name, name, name, "varchar", 1, true, catalog = name))).single().catalog

    @Test
    fun `the catalog name fold agrees with the analyzer on ASCII`() {
        for (name in listOf("AwsDataCatalog", "awsdatacatalog", "LAKE_01")) {
            assertEquals(analyzerFold(name), Engine.ATHENA.catalogName(name), name)
        }
    }

    @Test
    fun `the catalog name fold agrees with the analyzer on non-ASCII`() {
        for (name in listOf("İstanbul", "STRAẞE", "Straße", "ÇAĞ")) {
            assertEquals(analyzerFold(name), Engine.ATHENA.catalogName(name), name)
        }
        assertEquals(analyzerFold("İNFORMATION_SCHEMA") == "information_schema", Engine.ATHENA.isSystemSchema(analyzerFold("İNFORMATION_SCHEMA")))
    }

    @Test
    fun `system schema detection agrees with the analyzer fold`() {
        for (name in listOf("information_schema", "INFORMATION_SCHEMA", "Information_Schema", "information_schemas")) {
            assertEquals(analyzerFold(name) == "information_schema", Engine.ATHENA.isSystemSchema(analyzerFold(name)), name)
        }
    }
}
