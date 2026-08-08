package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Prove the request-context overlay is actually WIRED THROUGH `decideQuery` (not just
 * correct in isolation) against a real store + Cedar engine. This is the boundary the mechanism tests
 * (ChannelContextAuthzTest / TagResolutionTest) don't reach — here a channel-gated grant's verdict flips
 * with the server channel, so if the overlay were removed the test fails. Also asserts the audit records
 * the channel through the real run path. Skips cleanly with no Docker.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ChannelDecideAuditDbTest {
    private lateinit var fx: EnforcementFixture

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
    }

    private fun decide(sql: String, channel: Channel, clientContext: AuthzContext = AuthzContext()) =
        decideQuery(
            principal = "analyst@example.com",
            ds = fx.datasource,
            sql = sql,
            channel = channel,
            catalog = fx.datasourceStore.catalog(fx.datasource.id),
            policyStore = fx.policyStore,
            accessStore = fx.accessStore,
            userGroupStore = fx.userGroupStore,
            roleResolver = fx.roleResolver,
            authz = fx.authz,
            context = clientContext,
            systemClassification = SystemClassificationService(),
        )

    @Test
    fun `the audit record carries the channel through the real run path`() {
        val r = fx.run("select id, rrn from users order by id")
        val rec = fx.auditStore.get(r.decisionId!!)
        assertEquals("editor", rec?.channel, "a runEnforcedQuery decision must audit channel=editor")
    }

    @Test
    fun `the editor channel passthrough-allows a session statement, workflow phases still deny`() {
        // The stateful editor may run SET/USE/BEGIN (its held connection persists them; the proxy
        // re-probes the live path per query, so it's safe). The one-shot workflow phases still deny.
        val editor = decide("SET search_path = public", Channel.EDITOR)
        assertEquals(EnfAction.ALLOW, editor.action, "editor session may passthrough SET: ${editor.denyReason}")
        assertTrue(editor.passthrough, "SET is a session-mutating passthrough on the editor channel")

        val begin = decide("BEGIN", Channel.EDITOR)
        assertEquals(EnfAction.ALLOW, begin.action, "editor session may passthrough BEGIN: ${begin.denyReason}")

        val wfexec = decide("SET search_path = public", Channel.WORKFLOW_EXECUTOR)
        assertEquals(EnfAction.DENY, wfexec.action, "a workflow-executor one-shot may not run a session statement")
    }

    @Test
    fun `a DENY decision's audit row carries the derived context tag`() {
        // Audit fidelity: a derived context.tag must be recorded on EVERY decision's audit row, not
        // just the ALLOW/MASK column path. Seed a tag rule that fires on the editor channel (fx.run decides +
        // audits AS editor), then run a query that DENYs at the deny-by-default column gate (the ungranted
        // `orders` table). That DENY exits decideQuery via `policyDeny` (grant-override else branch) — which
        // is the path most likely to drop them: assert the round-tripped audit_event.context_tags contains
        // the tag, so a policyDeny (or any DENY/passthrough helper) that stops carrying the derived tags
        // fails here rather than silently thinning the audit row.
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "derive-editor-origin-tag",
                cedarSrc = """permit(
                    principal, action == Action::"context.tag::editor-origin", resource
                ) when { context has channel && context.channel == "editor" };""",
            ),
            updatedBy = "test",
        )

        // `orders` carries no Cedar grant (fixture) → the column decision DENYs and returns through policyDeny.
        val r = fx.run("select amount from orders")
        assertEquals(EnfAction.DENY, r.decision, "an ungranted table must DENY at the column gate: ${r.denyReason}")

        val rec = fx.auditStore.get(r.decisionId!!)
        assertEquals(Decision.DENY, rec?.decision, "the audit row records the DENY")
        assertTrue(
            rec?.contextTags?.contains("editor-origin") == true,
            "a DENY audit row must carry the derived context.tag it was evaluated under, got: ${rec?.contextTags}",
        )
    }

    @Test
    fun `a channel-gated grant follows the server channel and ignores a client-injected channel`() {
        // The fixture grants analyst select/insert but NOT delete. Add a delete grant that fires ONLY on the
        // editor channel — so the delete kind gate's verdict (stmt.kind.delete is a member of
        // stmt.cat.write.delete) depends on the channel decideQuery overlays.
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "analyst-delete-editor-only",
                cedarSrc = """permit(
                    principal in Role::"analyst", action in [Action::"stmt.cat.write.delete"],
                    resource in Datasource::"${fx.datasource.name}"
                ) when { context has channel && context.channel == "editor" };""",
            ),
            updatedBy = "test",
        )
        val sql = "delete from users where id = 999999"

        // WIRE: the editor-only delete grant does not fire -> the delete kind is unauthorized -> kind-gate deny.
        val wire = decide(sql, Channel.WIRE)
        assertEquals(EnfAction.DENY, wire.action, "wire delete must deny at the kind gate")
        assertTrue(wire.denyReason!!.contains("statement kind 'delete' is not permitted"), "wire deny reason: ${wire.denyReason}")

        // EDITOR: the grant fires -> the delete clears BOTH the kind gate and the verb loop -> ALLOW. A broken
        // channel overlay (EDITOR silently treated as wire) would kind-deny 'delete' exactly like WIRE, whose
        // reason ALSO lacks "stmt.cat.write.delete" — so only pinning ALLOW (not the absence of a verb-loop
        // string) actually catches that regression.
        val editor = decide(sql, Channel.EDITOR)
        assertEquals(EnfAction.ALLOW, editor.action, "editor channel should clear the delete gate, got: ${editor.denyReason}")

        // EDITOR channel but a client injecting channel="wire" + tags: the server enum is authoritative, so
        // it still clears the gate — the injected channel/tags are ignored.
        val injected = decide(sql, Channel.EDITOR, AuthzContext(channel = "wire", tags = setOf("injected")))
        assertEquals(EnfAction.ALLOW, injected.action, "a client-injected channel must be ignored, got: ${injected.denyReason}")
    }

    @Test
    fun `a session temp resolves and reads unmasked via the overlay, unresolvable without it`() {
        // The proxy sends the connection's temp columns; the CP overlays them so a bare name resolves to
        // the temp (what the backend binds). A temp is unclassified + owned by the user → read UNMASKED.
        val tempSchema = "pg_temp_9"
        val tempCol = CatalogColumn(
            catalog = fx.datasource.dbName, schema = tempSchema, table = "scratch", column = "secret",
            dataType = "text", sqlType = "text", ordinal = 1, nullable = true, isTemp = true,
        )
        val sql = "select secret from scratch"
        fun decideTemp(temps: List<CatalogColumn>) = decideQuery(
            principal = "analyst@example.com", ds = fx.datasource, sql = sql, channel = Channel.EDITOR,
            catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
            userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
            liveSearchPath = listOf(tempSchema, "public"),
            systemClassification = SystemClassificationService(),
            tempColumns = temps,
        )
        val withTemp = decideTemp(listOf(tempCol))
        assertEquals(EnfAction.ALLOW, withTemp.action, "a session temp reads unmasked (user owns it): ${withTemp.denyReason}")

        val without = decideTemp(emptyList())
        assertEquals(EnfAction.DENY, without.action, "without the overlay the temp is unresolvable → fail-closed")
    }

    @Test
    fun `a write cannot launder a masked column into a session temp (the unmasked-temp linchpin)`() {
        // Linchpin: a session temp reads UNMASKED only because a write can't copy masked/denied data
        // into one. Both a CTAS and an INSERT-select reading users.rrn (masked) must DENY on the editor
        // channel — even with a temp overlay ACTIVE — via the write-references-masked deny. If this ever
        // regressed, "temps read unmasked" would become an exfiltration primitive (write masked → read plain).
        val tempSchema = "pg_temp_9"
        // A session temp the attacker already holds (in the overlay), as the INSERT sink — the strongest form.
        val scratch = CatalogColumn(
            catalog = fx.datasource.dbName, schema = tempSchema, table = "scratch", column = "rrn",
            dataType = "text", sqlType = "text", ordinal = 1, nullable = true, isTemp = true,
        )
        fun decideWrite(principal: String, sql: String) = decideQuery(
            principal = principal, ds = fx.datasource, sql = sql, channel = Channel.EDITOR,
            catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
            userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
            liveSearchPath = listOf(tempSchema, "public"),
            systemClassification = SystemClassificationService(), tempColumns = listOf(scratch),
        )
        // ddl-writer holds sql.ddl (CTAS), insert-writer holds sql.insert; both read users.rrn as MASKED.
        val ctas = decideWrite("writer@example.com", "create temporary table t2 as select rrn from users")
        assertEquals(EnfAction.DENY, ctas.action, "CTAS from a masked column must DENY: ${ctas.denyReason}")

        val insert = decideWrite("inserter@example.com", "insert into scratch select rrn from users")
        assertEquals(EnfAction.DENY, insert.action, "INSERT-select from a masked column into a temp must DENY: ${insert.denyReason}")
    }

    @Test
    fun `a bare count over a session temp is allowed (uncovered-scan gate skips temps)`() {
        // A temp scan that traces no column (count(*)) would hit the uncovered-scan fail-closed gate like
        // any unknown table — the tempTableIds exclusion lets the owner scan their own temp. Without the
        // overlay the same scan is unresolvable → DENY, so the exclusion is what ALLOWs it, not a hole.
        val tempSchema = "pg_temp_9"
        val tempCol = CatalogColumn(
            catalog = fx.datasource.dbName, schema = tempSchema, table = "scratch", column = "secret",
            dataType = "text", sqlType = "text", ordinal = 1, nullable = true, isTemp = true,
        )
        fun decideCount(temps: List<CatalogColumn>) = decideQuery(
            principal = "analyst@example.com", ds = fx.datasource, sql = "select count(*) from scratch",
            channel = Channel.EDITOR, catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore,
            accessStore = fx.accessStore, userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver,
            authz = fx.authz, liveSearchPath = listOf(tempSchema, "public"),
            systemClassification = SystemClassificationService(), tempColumns = temps,
        )
        assertEquals(EnfAction.ALLOW, decideCount(listOf(tempCol)).action, "count(*) over an owned session temp is allowed")
        assertEquals(EnfAction.DENY, decideCount(emptyList()).action, "without the overlay the temp scan is unresolvable → DENY")
    }
}
