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

    @Test fun `Postgres keeps quoted case and folds only ASCII of unquoted names`() {
        val pg = EngineDatasource.getDefaultInstance()
        assertEquals("shop.App.T.SSN", parseColumn(Engine.POSTGRES, pg, "shop", "\"App\"", "\"T\"", "\"SSN\"").toString())
        assertEquals("shop.app.Users.ssn", parseColumn(Engine.POSTGRES, pg, "shop", "App", "\"Users\"", "SSN").toString())
        assertEquals("shop.public.cafÉ.ssn", parseColumn(Engine.POSTGRES, pg, "shop", "public", "CAFÉ", "ssn").toString())
        assertEquals("shop.pg_catalog.pg_class.relname", parseColumn(Engine.POSTGRES, pg, "shop", "PG_CATALOG", "PG_CLASS", "RELNAME").toString())
        assertEquals("shop.PG_CATALOG.pg_class.relname", parseColumn(Engine.POSTGRES, pg, "shop", "\"PG_CATALOG\"", "pg_class", "relname").toString())
    }

    @Test fun `MySQL folds table names by lower_case_table_names and columns always`() {
        fun mysql(lctn: Int) = engineDatasource { engineVersion = "8.4.6"; mysqlLowerCaseTableNames = lctn }
        assertEquals("def.App.Users.email", parseColumn(Engine.MYSQL, mysql(0), "def", "App", "Users", "Email").toString())
        assertEquals("def.app.users.email", parseColumn(Engine.MYSQL, mysql(1), "def", "App", "Users", "Email").toString())
        assertEquals("def.app.users.email", parseColumn(Engine.MYSQL, mysql(2), "def", "App", "Users", "Email").toString())
        assertEquals("def.App.Users.email", parseColumn(Engine.MYSQL, mysql(0), "def", "`App`", "`Users`", "`EMAIL`").toString())
    }

    @Test fun `Athena folds every part`() {
        val athena = engineDatasource { engineVersion = "3" }
        assertEquals("awsdatacatalog.hr.salaries.ssn", parseColumn(Engine.ATHENA, athena, "AwsDataCatalog", "HR", "Salaries", "SSN").toString())
    }
}
