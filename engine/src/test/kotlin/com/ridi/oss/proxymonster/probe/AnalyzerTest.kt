package com.ridi.oss.proxymonster.probe

import com.ridi.oss.proxymonster.analyzer.pb.ColumnSpec
import com.ridi.oss.proxymonster.analyzer.pb.FailureClass
import com.ridi.oss.proxymonster.analyzer.pb.columnSpec
import com.ridi.oss.proxymonster.analyzer.pb.engineConfig
import com.ridi.oss.proxymonster.analyzer.pb.namespace
import com.ridi.oss.proxymonster.analyzer.pb.relationIdentity
import com.ridi.oss.proxymonster.grpc.Engine
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AnalyzerTest {
    private fun column(catalog: String, schema: String, table: String, name: String, pii: Boolean = false): ColumnSpec =
        columnSpec {
            this.catalog = catalog
            identity = relationIdentity {
                this.schema = schema
                this.table = table
                column = name
            }
            dataType = "VARCHAR"
            this.pii = pii
        }

    private val ns = namespace {
        catalog = "acme"
        searchPath.add("public")
    }
    private val config = engineConfig { engine = Engine.POSTGRES }
    private val columns = listOf(
        column("acme", "public", "users", "id"),
        column("acme", "public", "users", "ssn", pii = true),
    )

    @Test
    fun `analyzer retains validated request snapshot and returns StatementFacts`() {
        val analyzer = analyzerFor(ns, columns, config)
        val facts = analyzer.analyze("select ssn from users")
        assertTrue(facts.resolved)
        assertEquals(ns, analyzer.namespaceProto)
        assertEquals(columns, analyzer.catalogProto)
        assertEquals(setOf("acme.public.users.ssn"), analyzer.piiColumns)
        assertTrue(facts.resultReadsList.any { it.hasColumn() && it.column.identity.column == "ssn" })
    }

    @Test
    fun `invalid catalog identity fails before native analysis`() {
        assertFailsWith<IllegalArgumentException> {
            analyzerFor(
                ns,
                listOf(column("acme", "public", "users", "id"), column("acme", "public", "users", "id")),
                config,
            )
        }
    }

    @Test
    fun `malformed and batched statements fail closed with explicit failure classes`() {
        val analyzer = analyzerFor(ns, columns, config)
        val malformed = analyzer.analyze("select 'unterminated")
        assertFalse(malformed.resolved)
        assertEquals(FailureClass.FAILURE_CLASS_UNANALYZABLE, malformed.failureClass)

        val batch = analyzer.analyze("select 1; select 2")
        assertFalse(batch.resolved)
        assertEquals(FailureClass.FAILURE_CLASS_INADMISSIBLE, batch.failureClass)
    }
}
