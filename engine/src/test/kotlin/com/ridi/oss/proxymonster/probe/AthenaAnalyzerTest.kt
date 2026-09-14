package com.ridi.oss.proxymonster.probe

import com.ridi.oss.proxymonster.analyzer.pb.FailureClass
import com.ridi.oss.proxymonster.analyzer.pb.catalogSnapshot
import com.ridi.oss.proxymonster.analyzer.pb.column
import com.ridi.oss.proxymonster.analyzer.pb.engineConfig
import com.ridi.oss.proxymonster.analyzer.pb.namespace
import com.ridi.oss.proxymonster.athena.pb.athenaPreparedDefinition
import com.ridi.oss.proxymonster.athena.pb.athenaSqlContext
import com.ridi.oss.proxymonster.grpc.Engine
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AthenaAnalyzerTest {
    private val analyzer = analyzerFor(
        namespace {
            catalog = "awsdatacatalog"
            searchPath.add("sample")
        },
        catalogSnapshot {
            columns += listOf("awsdatacatalog", "archive").map { catalog ->
                column {
                    this.catalog = catalog
                    schema = "sample"
                    table = "users"
                    column = "email"
                    dataType = "VARCHAR"
                }
            }
        },
        engineConfig { engine = Engine.ATHENA },
    )
    private val context = athenaSqlContext { workgroup = "sample" }

    @Test
    fun `FFM preserves per-column catalogs and executable qualification`() {
        val facts = analyzer.analyze("SELECT * FROM archive.sample.users", context)
        assertTrue(facts.resolved, facts.detail)
        assertTrue(facts.resultReadsList.any { it.hasColumn() && it.column.catalog == "archive" })
        assertTrue(facts.hasAthenaSubmission())
        assertTrue(facts.athenaSubmission.queryString.contains("\"archive\".\"sample\".\"users\""))
        assertEquals(listOf("awsdatacatalog.sample.users.email", "archive.sample.users.email"), analyzer.columnKeys)
    }

    @Test
    fun `FFM requests trusted prepared definition in the current workgroup`() {
        val missing = analyzer.analyze("EXECUTE lookup_user", context)
        assertFalse(missing.resolved)
        assertEquals("lookup_user", missing.athenaPreparedDefinitionNeed.name)
        assertEquals("sample", missing.athenaPreparedDefinitionNeed.workgroup)
        val trusted = athenaSqlContext {
            workgroup = "sample"
            preparedDefinitions.add(athenaPreparedDefinition {
                workgroup = "sample"
                name = "lookup_user"
                queryString = "SELECT email FROM users"
            })
        }
        val facts = analyzer.analyze("EXECUTE lookup_user", trusted)
        assertTrue(facts.resolved, facts.detail)
        assertTrue(facts.hasAthenaSubmission())
        assertFalse(facts.athenaSubmission.queryString.startsWith("EXECUTE"))
    }

    @Test
    fun `FFM binds native parameters and prepared definitions to the same executed SQL`() {
        val direct = analyzer.analyze(
            "SELECT email FROM users WHERE email = ?",
            athenaSqlContext {
                workgroup = "sample"
                executionParameters.add("'sample@example.test'")
            },
        )
        val prepared = analyzer.analyze(
            "EXECUTE lookup_user USING 'sample@example.test'",
            athenaSqlContext {
                workgroup = "sample"
                preparedDefinitions.add(athenaPreparedDefinition {
                    workgroup = "sample"
                    name = "lookup_user"
                    queryString = "SELECT email FROM users WHERE email = ?"
                })
            },
        )
        assertTrue(direct.resolved, direct.detail)
        assertTrue(prepared.resolved, prepared.detail)
        assertTrue(direct.hasAthenaSubmission())
        assertEquals(direct.athenaSubmission, prepared.athenaSubmission)
        assertEquals(direct.resultReadsList, prepared.resultReadsList)
        assertEquals(0, prepared.athenaSubmission.executionParametersCount)
        assertFalse(prepared.athenaSubmission.queryString.contains("?"))
    }

    @Test
    fun `FFM cannot analyze without Athena context`() {
        val facts = analyzer.analyze("SELECT email FROM users")
        assertFalse(facts.resolved)
        assertEquals(FailureClass.FAILURE_CLASS_UNANALYZABLE, facts.failureClass)
        assertFalse(facts.hasAthenaSubmission())
    }
}
