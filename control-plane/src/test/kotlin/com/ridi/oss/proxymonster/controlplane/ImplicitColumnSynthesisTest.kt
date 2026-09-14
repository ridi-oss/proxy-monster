package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.analyzer.pb.FunctionCatalog
import com.ridi.oss.proxymonster.grpc.Engine
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The production synthesis path (analyzerAndCatalogIndex → Engine.implicitColumns) — the seam the
 *  analyzer's own tests mirror with a helper that can drift. */
class ImplicitColumnSynthesisTest {
    private fun ds(engine: Engine) = Datasource(
        id = 1, name = "t", engine = engine, host = "h", port = 5432, dbName = "acme",
        defaultSchemas = listOf("public"),
        mysqlLowerCaseTableNames = if (engine == Engine.MYSQL) 0 else null,
        engineVersion = if (engine == Engine.MYSQL) "8.0.44" else "PostgreSQL 16.4",
    )

    private fun col(schema: String, table: String, column: String, temp: Boolean = false) = CatalogColumn(
        catalog = "acme", schema = schema, table = table, column = column,
        dataType = "text", sqlType = "text", ordinal = 1, nullable = true, isTemp = temp,
    )

    @Test
    fun `postgres tables gain the six implicit system columns, marked implicit`() {
        val (index, analyzer) = analyzerAndCatalogIndex(
            ds(Engine.POSTGRES), Catalog(listOf(col("public", "users", "id"), col("public", "orders", "id")), FunctionCatalog.getDefaultInstance()),
            emptyList(), listOf("public"),
        )
        val implicit = index.snapshot.columnsList.filter { it.implicit }
        assertEquals(12, implicit.size, "six per table")
        assertTrue(implicit.all { it.column in PostgresSystemColumnsNames }, "$implicit")
        // The analyzer resolves an explicit ctid read against the synthesized schema.
        val facts = analyzer.analyze("SELECT ctid FROM users")
        assertTrue(facts.resolved, facts.detail)
        assertTrue(
            facts.resultReadsList.any { it.hasColumn() && it.column.column == "ctid" },
            "ctid must emit a Column grant: ${facts.resultReadsList}",
        )
        // …and star expansion excludes them.
        val star = analyzer.analyze("SELECT * FROM users")
        assertTrue(star.resolved, star.detail)
        assertEquals(listOf("id"), star.outputColumnsList, "star must expand visible columns only")
    }

    @Test
    fun `temp tables inherit isTemp on their implicit columns`() {
        val (index, _) = analyzerAndCatalogIndex(
            ds(Engine.POSTGRES), Catalog(listOf(col("public", "users", "id")), FunctionCatalog.getDefaultInstance()),
            listOf(col("pg_temp_3", "scratch", "v", temp = true)), listOf("public"),
        )
        val scratchImplicit = index.rowsByKey.values.none { it.table == "scratch" && it.implicit && !it.isTemp }
        assertTrue(scratchImplicit, "a temp table's implicit columns must stay temp")
    }

    @Test
    fun `a real introspected column named after a system column wins and stays visible`() {
        // System VIEWS expose ordinary columns with these names (pg_replication_slots.xmin): the real
        // column keeps its catalog identity and appears in * — no implicit twin is synthesized.
        val (index, analyzer) = analyzerAndCatalogIndex(
            ds(Engine.POSTGRES), Catalog(listOf(col("pg_catalog", "pg_replication_slots", "xmin"), col("pg_catalog", "pg_replication_slots", "slot_name")), FunctionCatalog.getDefaultInstance()),
            emptyList(), listOf("public"),
        )
        assertTrue(index.snapshot.columnsList.none { it.implicit && it.column == "xmin" }, "no implicit xmin twin")
        val star = analyzer.analyze("SELECT * FROM pg_catalog.pg_replication_slots")
        assertTrue(star.resolved, star.detail)
        assertTrue("xmin" in star.outputColumnsList, "the REAL xmin is visible in *: ${star.outputColumnsList}")
    }

    @Test
    fun `mysql synthesizes nothing`() {
        val (index, _) = analyzerAndCatalogIndex(
            ds(Engine.MYSQL), Catalog(listOf(col("acme", "users", "id")), FunctionCatalog.getDefaultInstance()),
            emptyList(), listOf("acme"),
        )
        assertTrue(index.snapshot.columnsList.none { it.implicit })
    }
}

private val PostgresSystemColumnsNames = setOf("ctid", "xmin", "xmax", "cmin", "cmax", "tableoid")
