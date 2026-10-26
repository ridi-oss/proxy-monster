package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.analyzer.pb.MaskedDisposition
import com.ridi.oss.proxymonster.analyzer.pb.predicateLiteral
import com.ridi.oss.proxymonster.analyzer.pb.requireResultReadGrant
import com.ridi.oss.proxymonster.analyzer.pb.statementFacts
import com.ridi.oss.proxymonster.grpc.objectRef
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ResultRequirementsTest {
    private val t3 = objectRef { catalog = "app"; schema = "pg_temp_3"; table = "t3" }
    private val other = objectRef { catalog = "app"; schema = "pg_temp_3"; table = "other" }

    private val facts = statementFacts {
        resolved = true
        outputColumns += "n"
        resultReads += requireResultReadGrant {
            column = t3.toBuilder().setColumn("n").build()
            maskedDisposition = MaskedDisposition.MASKED_DISPOSITION_MASK_OUTPUT
            outputOrdinals += 0
        }
        rewrittenSql = "select n from t3"
        predicateLiterals += predicateLiteral { column = objectRef { catalog = "app"; schema = "public"; table = "users"; column = "ssn" } }
    }

    @Test
    fun `keeps the fields a decision reads and drops the rest`() {
        val requirements = resultRequirementsOf(facts, emptySet())
        assertEquals(facts.resultReadsList, requirements.facts.resultReadsList)
        assertEquals(listOf("n"), requirements.facts.outputColumnsList)
        assertTrue(requirements.facts.resolved)
        assertFalse(requirements.facts.hasRewrittenSql())
        assertTrue(requirements.facts.predicateLiteralsList.isEmpty(), "a literal from the query text is not stored")
    }

    @Test
    fun `keeps only the temp tables the facts reference`() {
        assertEquals(listOf(t3), resultRequirementsOf(facts, setOf(t3, other)).tempTablesList)
    }
}
