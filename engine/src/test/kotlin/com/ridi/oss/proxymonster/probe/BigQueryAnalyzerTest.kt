package com.ridi.oss.proxymonster.probe

import com.ridi.oss.proxymonster.analyzer.pb.catalogSnapshot
import com.ridi.oss.proxymonster.analyzer.pb.column
import com.ridi.oss.proxymonster.analyzer.pb.engineConfig
import com.ridi.oss.proxymonster.analyzer.pb.namespace
import com.ridi.oss.proxymonster.analyzer.pb.sessionObservation
import com.ridi.oss.proxymonster.bigquery.pb.bigQuerySqlContext
import com.ridi.oss.proxymonster.grpc.Engine
import kotlin.test.Test
import kotlin.test.assertTrue

class BigQueryAnalyzerTest {
    private val analyzer = analyzerFor(
        namespace {
            catalog = "sample-project"
            searchPath.add("Sales")
        },
        catalogSnapshot {
            columns += column {
                catalog = "sample-project"
                schema = "Sales"
                table = "Users"
                column = "email"
                dataType = "STRING"
            }
        },
        engineConfig {
            engine = Engine.BIGQUERY
            session = sessionObservation { bigquery = bigQuerySqlContext { project = "sample-project" } }
        },
    )

    @Test
    fun `FFM reports AI calls under the ai schema the manifest classifies`() {
        val facts = analyzer.analyze("SELECT AI.GENERATE(email) FROM Users")
        assertTrue("ai.generate" in facts.functionsList, facts.toString())
    }
}
