package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.EnfAction
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Red-team write regressions through the production StatementFacts grant walk. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RedTeamDmlTest {
    private lateinit var postgres: EnforcementFixture
    private lateinit var mysql: EnforcementFixture

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        postgres = EnforcementFixture.postgres()
        mysql = EnforcementFixture.mysql()
    }

    private fun denied(fixture: EnforcementFixture, sql: String) {
        val result = fixture.run(sql, principal = "writer@example.com")
        assertEquals(EnfAction.DENY, result.decision, "must deny write exfiltration: $sql; ${result.denyReason}")
        assertTrue(result.rows.isEmpty())
    }

    @Test
    fun `writes cannot persist masked source values`() {
        for (fixture in listOf(postgres, mysql)) {
            denied(fixture, "insert into users(email) select ssn from users")
            denied(fixture, "update users set email = ssn")
        }
    }

    @Test
    fun `write predicates and transformed payloads remain non-maskable`() {
        for (fixture in listOf(postgres, mysql)) {
            denied(fixture, "update users set email = 'x' where ssn = 'secret'")
            denied(fixture, "insert into users(email) select upper(ssn) from users")
        }
    }
}
