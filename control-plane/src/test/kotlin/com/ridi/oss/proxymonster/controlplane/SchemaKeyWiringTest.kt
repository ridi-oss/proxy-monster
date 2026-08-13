package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.analyzer.pb.columnSpec
import com.ridi.oss.proxymonster.analyzer.pb.engineConfig as pbEngineConfig
import com.ridi.oss.proxymonster.analyzer.pb.namespace as pbNamespace
import com.ridi.oss.proxymonster.analyzer.pb.relationIdentity
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.probe.analyzerFor
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class SchemaKeyWiringTest {
    private val postgresEngineConfig = pbEngineConfig { engine = Engine.POSTGRES }
    private val mysqlEngineConfig = pbEngineConfig { engine = Engine.MYSQL; engineVersion = "8.0.46"; mysqlLowerCaseTableNames = 1 }

    private fun catalogColumn(
        catalog: String = "acme",
        schema: String,
        table: String,
        column: String,
    ) = CatalogColumn(
        catalog = catalog,
        schema = schema,
        table = table,
        column = column,
        dataType = "character varying",
        sqlType = "VARCHAR",
        ordinal = 1,
        nullable = false,
    )

    private fun specsFor(catalog: List<CatalogColumn>) = catalog.map { col ->
        columnSpec {
            this.catalog = col.catalog
            identity = relationIdentity {
                schema = col.schema
                table = col.table
                column = col.column
            }
            dataType = col.sqlType
            pii = col.classification != null
        }
    }

    @Test
    fun `an emitted key absent from the catalog cannot fall back to a same-named table in another schema`() {
        val namespace = pbNamespace { catalog = "acme"; searchPath.add("public") }
        val catalog = listOf(catalogColumn(schema = "public", table = "users", column = "ssn"))
        val specs = specsFor(catalog)
        val index = buildCatalogColumnIndex(catalog, specs, analyzerFor(namespace, specs, postgresEngineConfig))

        val denied = assertIs<CatalogCoverage.Denied>(
            catalogCoverage(index, setOf("acme.analytics.users.ssn")),
        )

        assertContains(denied.reason, "absent from catalog")
        assertIs<CatalogCoverage.Covered>(catalogCoverage(index, setOf("acme.public.users.ssn")))
    }

    @Test
    fun `duplicate catalog keys are rejected as ambiguous`() {
        // Catalog identity arrives already canonical (goproxy normalizes at introspection), so a
        // duplicate key can only mean two rows literally share the same identity — the
        // rejection surfaces from analyzerFor's own validation (the same walk that builds
        // Analyzer.columnKeys), not from a second, separate walk inside buildCatalogColumnIndex.
        val namespace = pbNamespace {
            catalog = "def"
            searchPath.add("app")
        }
        val catalog = listOf(
            catalogColumn(catalog = "def", schema = "app", table = "users", column = "ssn"),
            catalogColumn(catalog = "def", schema = "app", table = "users", column = "ssn"),
        )

        assertFailsWith<IllegalArgumentException> {
            analyzerFor(namespace, specsFor(catalog), mysqlEngineConfig)
        }
    }

    @Test
    fun `dot-containing identifiers that render to one key are rejected rather than parsed`() {
        val namespace = pbNamespace { catalog = "acme"; searchPath.add("public") }
        val catalog = listOf(
            catalogColumn(schema = "public", table = "users.archive", column = "ssn"),
            catalogColumn(schema = "public.users", table = "archive", column = "ssn"),
        )

        assertFailsWith<IllegalArgumentException> {
            analyzerFor(namespace, specsFor(catalog), postgresEngineConfig)
        }
    }
}
