package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.EnfAction
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

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
            assertEquals(false, decision.unbounded, sql)
        }
        check("select ssn from users", EnfAction.ALLOW, setOf("pii"), Channel.WORKFLOW_EXECUTOR)
        check("select ssn from users", EnfAction.MASK, emptySet<String>())
        check("select id from users", EnfAction.ALLOW, emptySet<String>())
        check("select id from users where ssn is not null", EnfAction.ALLOW, emptySet<String>(), Channel.WORKFLOW_EXECUTOR)
        check("select 42", EnfAction.ALLOW, emptySet<String>())
        check("show databases", EnfAction.ALLOW, emptySet<String>())
    }
    // An aggregate, DISTINCT transform, or scalar subquery returns the tagged value through an output the
    // analyzer binds no ordinal to (it is not maskable), so keying the tight cap on a bound ordinal alone
    // would hand the general bucket to a statement that returns exactly the same SSNs.
    @Test
    fun `an unmasked tagged read reaching an unbound output takes the tight cap`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        fx.cedarPolicyStore.create(
            CedarPolicyInput("unmasked", """permit(principal in Role::"analyst", action == Action::"result.read.unmasked", resource);"""),
            updatedBy = "test",
        )
        fun check(sql: String, tags: Set<String>) {
            val decision = fx.decide(sql)
            assertNotEquals(EnfAction.DENY, decision.action, "$sql: ${decision.denyReason}")
            assertEquals(tags, decision.unmaskedTags, sql)
        }
        check("select ssn from users", setOf("pii"))
        check("select max(ssn) from users", setOf("pii"))
        check("select max(ssn) from users group by id", setOf("pii"))
        check("select distinct upper(ssn) from users", setOf("pii"))
        check("select group_concat(ssn) from users", setOf("pii"))
        // A predicate-only read returns no tagged value, and an unbound output over untagged columns alone
        // (count(*)) is not a tagged one — both stay general.
        check("select id from users where ssn is not null", emptySet<String>())
        check("select 1 from users where ssn is not null", emptySet<String>())
        check("select count(*) from users", emptySet<String>())
        check("select 1 from users order by ssn", emptySet<String>())
    }

    // A tagged base column feeding an output that a mask from ANOTHER base column covers never reaches the
    // client in the clear, so the statement stays general.
    @Test
    fun `a masked output over a mixed tagged source stays general`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        val ds = fx.datasource
        val schema = ds.engine.defaultSchema(ds.dbName)
        fx.datasourceStore.upsertClassification(
            ds.id,
            ClassificationInput(schema = schema, table = "users", column = "email", tags = listOf("pii")),
        )
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                "email-unmasked",
                """permit(principal in Role::"analyst", action == Action::"result.read.unmasked", resource == Column::"${ds.name}/${ds.engine.catalogName(ds.dbName)}/$schema/users/email");""",
            ),
            updatedBy = "test",
        )
        val refreshed = fx.datasourceStore.get(ds.id)!!
        val email = fx.decide("select email from users", datasource = refreshed)
        assertEquals(EnfAction.ALLOW, email.action, email.denyReason)
        assertEquals(setOf("pii"), email.unmaskedTags)
        val mixed = fx.decide("select concat(ssn, email) from users", datasource = refreshed)
        assertEquals(EnfAction.MASK, mixed.action, mixed.denyReason)
        assertEquals(emptySet<String>(), mixed.unmaskedTags)
        val both = fx.decide("select email, ssn from users", datasource = refreshed)
        assertEquals(EnfAction.MASK, both.action, both.denyReason)
        assertEquals(setOf("pii"), both.unmaskedTags)
    }

    // A write's RETURNING has no output ordinals, yet returns the value: an unmasked tagged column there
    // takes the tight cap, and a masked one denies the statement as any other unmaskable position does.
    @Test
    fun `PostgreSQL RETURNING of a tagged column takes the tight cap`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.postgres()
        val masked = fx.decide("update users set id = id returning ssn", principal = "updater@example.com")
        assertEquals(EnfAction.DENY, masked.action)
        val plain = fx.decide("update users set id = id returning id", principal = "updater@example.com")
        assertEquals(EnfAction.ALLOW, plain.action, plain.denyReason)
        assertEquals(emptySet<String>(), plain.unmaskedTags)
        fx.cedarPolicyStore.create(
            CedarPolicyInput("updater-unmasked", """permit(principal in Role::"update-writer", action == Action::"result.read.unmasked", resource);"""),
            updatedBy = "test",
        )
        val clear = fx.decide("update users set id = id returning ssn", principal = "updater@example.com")
        assertEquals(EnfAction.ALLOW, clear.action, clear.denyReason)
        assertEquals(setOf("pii"), clear.unmaskedTags)
        val wildcard = fx.decide("update users set id = id returning *", principal = "updater@example.com")
        assertEquals(EnfAction.ALLOW, wildcard.action, wildcard.denyReason)
        assertEquals(setOf("pii"), wildcard.unmaskedTags)
        fx.cedarPolicyStore.create(
            CedarPolicyInput("analyst-unmasked", """permit(principal in Role::"analyst", action == Action::"result.read.unmasked", resource);"""),
            updatedBy = "test",
        )
        val wholeRow = fx.decide("select users from users")
        assertEquals(EnfAction.ALLOW, wholeRow.action, wholeRow.denyReason)
        assertEquals(setOf("pii"), wholeRow.unmaskedTags)
        val json = fx.decide("select to_jsonb(u) from users u")
        assertEquals(EnfAction.ALLOW, json.action, json.denyReason)
        assertEquals(setOf("pii"), json.unmaskedTags)
        val predicateOnly = fx.decide("select (select id from users where ssn is not null limit 1) from orders")
        assertEquals(EnfAction.ALLOW, predicateOnly.action, predicateOnly.denyReason)
        assertEquals(emptySet<String>(), predicateOnly.unmaskedTags)
    }

    // `exception.unmaskable` relays a MASK verdict's rows RAW on the binary protocol, so the tagged values
    // reach the client in the clear and must carry the tight cap the masked relay does not need.
    @Test
    fun `a permitted mask bypass takes the tight cap`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        fun caps(sql: String): Set<String> {
            val decision = fx.decide(sql)
            assertEquals(EnfAction.MASK, decision.action, decision.denyReason)
            return decision.unmaskedTags
        }
        assertEquals(emptySet<String>(), caps("select ssn from users"))
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                "unmaskable",
                """permit(principal in Role::"analyst", action == Action::"exception.unmaskable", resource == Datasource::"${fx.datasource.name}");""",
            ),
            updatedBy = "test",
        )
        assertEquals(setOf("pii"), caps("select ssn from users"))
        // The grant tightens only a statement that actually bypasses a mask; an unmasked read stays general.
        val untagged = fx.decide("select id from users")
        assertEquals(EnfAction.ALLOW, untagged.action, untagged.denyReason)
        assertEquals(emptySet<String>(), untagged.unmaskedTags)
    }

    // Fail-closed: a verdict that relays rows carries a concrete cap, whatever exit produced it. The
    // exception.unanalyzable relay matters most — it relays VERBATIM and UNMASKED, so an uncapped one is
    // exactly the dump the caps exist to bound.
    @Test
    fun `the analyzed, passthrough, and unanalyzable-relay exits each stamp a cap`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                "dev-unanalyzable",
                """permit(principal, action == Action::"exception.unanalyzable", resource == Datasource::"${fx.datasource.name}");""",
            ),
            updatedBy = "test",
        )
        for (sql in listOf(
            "select id from users",             // analyzed
            "show databases",                   // passthrough
            "select missing_column from users", // unanalyzable relay
        )) {
            val decision = fx.decide(sql)
            assertNotEquals(EnfAction.DENY, decision.action, "$sql: ${decision.denyReason}")
            assertEquals(false, decision.unbounded, sql)
            assertEquals(emptySet(), decision.unmaskedTags, sql)
        }
    }
}
