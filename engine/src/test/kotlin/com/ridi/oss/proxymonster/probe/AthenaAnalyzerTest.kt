package com.ridi.oss.proxymonster.probe

import com.ridi.oss.proxymonster.analyzer.pb.FailureClass
import com.ridi.oss.proxymonster.analyzer.pb.catalogSnapshot
import com.ridi.oss.proxymonster.analyzer.pb.column
import com.ridi.oss.proxymonster.analyzer.pb.engineConfig
import com.ridi.oss.proxymonster.analyzer.pb.namespace
import com.ridi.oss.proxymonster.athena.pb.AthenaSqlContext
import com.ridi.oss.proxymonster.athena.pb.athenaPreparedDefinition
import com.ridi.oss.proxymonster.athena.pb.athenaSqlContext
import com.ridi.oss.proxymonster.grpc.Engine
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AthenaAnalyzerTest {
    private fun analyzerWith(scope: AthenaSqlContext?) = analyzerFor(
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
        engineConfig {
            engine = Engine.ATHENA
            if (scope != null) athena = scope
        },
    )
    private val analyzer = analyzerWith(athenaSqlContext { workgroup = "sample" })

    @Test
    fun `FFM preserves per-column catalogs and executable qualification`() {
        val facts = analyzer.analyze("SELECT * FROM archive.sample.users")
        assertTrue(facts.resolved, facts.detail)
        assertTrue(facts.resultReadsList.any { it.hasColumn() && it.column.catalog == "archive" })
        assertTrue(facts.hasAthenaSubmission())
        assertTrue(facts.rewrittenSql.contains("\"archive\".\"sample\".\"users\""))
        assertEquals(listOf("awsdatacatalog.sample.users.email", "archive.sample.users.email"), analyzer.columnKeys)
    }

    @Test
    fun `FFM requests trusted prepared definition in the current workgroup`() {
        val missing = analyzer.analyze("EXECUTE lookup_user")
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
        val facts = analyzerWith(trusted).analyze("EXECUTE lookup_user")
        assertTrue(facts.resolved, facts.detail)
        assertTrue(facts.hasAthenaSubmission())
        assertFalse(facts.rewrittenSql.startsWith("EXECUTE"))
    }

    @Test
    fun `FFM binds native parameters and prepared definitions to the same executed SQL`() {
        val direct = analyzerWith(
            athenaSqlContext {
                workgroup = "sample"
                executionParameters.add("'sample@example.test'")
            },
        ).analyze("SELECT email FROM users WHERE email = ?")
        val prepared = analyzerWith(
            athenaSqlContext {
                workgroup = "sample"
                preparedDefinitions.add(athenaPreparedDefinition {
                    workgroup = "sample"
                    name = "lookup_user"
                    queryString = "SELECT email FROM users WHERE email = ?"
                })
            },
        ).analyze("EXECUTE lookup_user USING 'sample@example.test'")
        assertTrue(direct.resolved, direct.detail)
        assertTrue(prepared.resolved, prepared.detail)
        assertTrue(direct.hasAthenaSubmission())
        assertEquals(direct.rewrittenSql, prepared.rewrittenSql)
        assertEquals(direct.athenaSubmission, prepared.athenaSubmission)
        assertEquals(direct.resultReadsList, prepared.resultReadsList)
        assertEquals(0, prepared.athenaSubmission.executionParametersCount)
        assertFalse(prepared.rewrittenSql.contains("?"))
    }

    @Test
    fun `FFM cannot analyze without Athena scope`() {
        val facts = analyzerWith(null).analyze("SELECT email FROM users")
        assertFalse(facts.resolved)
        assertEquals(FailureClass.FAILURE_CLASS_UNANALYZABLE, facts.failureClass)
        assertFalse(facts.hasAthenaSubmission())
    }
}
