package com.ridi.oss.proxymonster.probe

import com.ridi.oss.proxymonster.analyzer.pb.EngineDatasource
import com.ridi.oss.proxymonster.analyzer.pb.engineDatasource
import com.ridi.oss.proxymonster.grpc.Engine
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class ColumnNamesTest {
    @Test fun `the engine folds by the reported datasource and refuses an unreported one`() {
        val reported = engineDatasource { engineVersion = "8.0.46"; mysqlLowerCaseTableNames = 1 }
        assertEquals("def.app.users.ssn", parseColumn(Engine.MYSQL, reported, "def", "App", "Users", "SSN").toString())
        assertNull(parseColumn(Engine.MYSQL, reported, "def", "app", "users", "'SSN'"))
        assertFailsWith<DatasourceRejectedException> {
            parseColumn(Engine.MYSQL, EngineDatasource.getDefaultInstance(), "def", "app", "users", "ssn")
        }
        assertEquals("shop.public.users.ssn", parseColumn(Engine.POSTGRES, EngineDatasource.getDefaultInstance(), "shop", "public", "Users", "SSN").toString())
    }
}
