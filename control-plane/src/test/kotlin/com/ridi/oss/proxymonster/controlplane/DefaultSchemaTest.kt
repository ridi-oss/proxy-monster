package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.Engine
import kotlin.test.Test
import kotlin.test.assertEquals

class DefaultSchemaTest {
    private fun first(engine: Engine, lctn: Int?, vararg schemas: String): String? =
        Datasource(1, "ds", engine, "", 0, "app", defaultSchemas = schemas.toList(), engineVersion = "8.0.44".takeIf { engine == Engine.MYSQL }, mysqlLowerCaseTableNames = lctn).firstUserDefaultSchema()

    @Test
    fun `skips only schemas whose canonical name is a system schema`() {
        assertEquals("SYS", first(Engine.MYSQL, 0, "SYS", "app"))
        assertEquals("Mysql", first(Engine.MYSQL, 0, "sys", "Mysql"))
        assertEquals("app", first(Engine.MYSQL, 1, "SYS", "app"))
        assertEquals("PG_CATALOG", first(Engine.POSTGRES, null, "pg_catalog", "PG_CATALOG"))
        assertEquals("sales", first(Engine.ATHENA, null, "INFORMATION_SCHEMA", "sales"))
        assertEquals(null, first(Engine.MYSQL, 1, "Information_Schema"))
    }
}
