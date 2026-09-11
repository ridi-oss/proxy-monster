package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.EnfAction
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class ResultCapDecideDbTest {
    @Test
    fun `MySQL caps count tagged unmasked outputs not masked or predicate columns`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "executor-unmasked",
                cedarSrc = """permit(principal in Role::"analyst", action == Action::"result.read.unmasked", resource) when { context has channel && context.channel == "workflow-executor" };""",
            ),
            updatedBy = "test",
        )
        fun check(sql: String, action: EnfAction, tags: Set<String>, channel: Channel = Channel.WIRE) {
            val decision = fx.decide(sql, channel = channel)
            assertEquals(action, decision.action, decision.denyReason)
            assertEquals(tags, decision.unmaskedTags, sql)
        }
        check("select ssn from users", EnfAction.ALLOW, setOf("pii"), Channel.WORKFLOW_EXECUTOR)
        check("select ssn from users", EnfAction.MASK, emptySet<String>())
        check("select id from users", EnfAction.ALLOW, emptySet<String>())
        check("select id from users where ssn is not null", EnfAction.ALLOW, emptySet<String>(), Channel.WORKFLOW_EXECUTOR)
        check("select 42", EnfAction.ALLOW, emptySet<String>())
        check("show databases", EnfAction.ALLOW, emptySet<String>())
    }

}
