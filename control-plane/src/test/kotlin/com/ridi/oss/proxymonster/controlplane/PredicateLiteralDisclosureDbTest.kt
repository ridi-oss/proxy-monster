package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The reader-neutral disclosure hint [protectedPredicateLiterals] — the check that keeps a protected VALUE in
 * a statement's own text (`WHERE ssn = '987-65-4320'`) out of an approval notification, where masking never
 * reaches it because masking rewrites results, not predicates.
 *
 * The load-bearing property is that this is NOT authorization and shares nothing with it but the analyzer:
 * it takes no principal, so the verdict is identical whoever composed the statement and whether or not they
 * could run it. A statement that DENIES for the requester — the normal reason it goes to the approval
 * workflow at all — is therefore analyzed for disclosure exactly like an allowed one. Withholding triggers on
 * a literal landing on a CLASSIFIED column; never on a protected column merely selected or filtered (masking
 * handles those in the result stream), and never on a literal on an unclassified column.
 *
 * The fixture classifies `users.ssn` (pii + last4 mask); `id`, `email`, `region` are unclassified.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PredicateLiteralDisclosureDbTest {
    private lateinit var fx: EnforcementFixture
    private val analyst = "analyst@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
        // A principal holding the fixture's analyst role: it may read `users`, but `ssn` is masked, so a
        // statement filtering on ssn DENIES for them — the realistic "can't run it, send for approval" case
        // the decoupling cross-check below exercises against the (reader-neutral) hint.
        val analystRole = fx.policyStore.listRoles().first { it.name == fx.role }
        fx.policyStore.createAssignment(RoleAssignmentInput(analyst, analystRole.id))
    }

    /** The disclosure hint for [sql] — no principal, no roles, by construction. */
    private fun hint(sql: String): List<String>? = protectedPredicateLiterals(
        ds = fx.datasourceStore.get(fx.datasource.id)!!,
        sql = sql,
        catalog = fx.datasourceStore.catalog(fx.datasource.id),
    )

    /** The requester's OWN authorization decision — for the cross-check that the hint is decoupled from it. */
    private fun decide(sql: String) = decideQuery(
        principal = analyst, ds = fx.datasourceStore.get(fx.datasource.id)!!, sql = sql,
        channel = Channel.EDITOR, catalog = fx.datasourceStore.catalog(fx.datasource.id),
        policyStore = fx.policyStore, accessStore = fx.accessStore, userGroupStore = fx.userGroupStore,
        roleResolver = fx.roleResolver, authz = fx.authz,
    )

    /** The delivery-side gate the stored flag drives (NotificationService.buildMessage withholds on anything
     *  but a proven-clean `false`): the notification hides the text unless the hint is a non-null empty list. */
    private fun withheld(hint: List<String>?): Boolean = (hint?.isNotEmpty()) != false

    @Test
    fun `a literal on a classified column is reported, so the text is withheld`() {
        val h = hint("SELECT id FROM users WHERE ssn = '987-65-4320'")
        assertTrue(h!!.any { it.endsWith("users.ssn") }, "the value is in the query text; got $h")
        assertTrue(withheld(h))
    }

    @Test
    fun `the hint is decoupled from authz — it reports a literal the requester's own decision denies on`() {
        val sql = "SELECT id FROM users WHERE ssn = '987-65-4320'"
        // The requester CAN'T run this — a masked column in a predicate can't be masked, so decideQuery DENIES,
        // and that DENY is the very reason it's sent for approval. The hint runs on a different path and still
        // reports the literal; the old code lost exactly this the moment the requester's decision denied.
        assertEquals(com.ridi.oss.proxymonster.grpc.EnfAction.DENY, decide(sql).action)
        assertTrue(hint(sql)!!.any { it.endsWith("users.ssn") }, "the hint reports the literal regardless of the DENY")
    }

    @Test
    fun `a classified column merely SELECTED carries no value and is disclosed`() {
        // masking redacts the ssn CELLS when it runs; the statement TEXT holds no protected value.
        val h = hint("SELECT ssn FROM users LIMIT 10")
        assertEquals(emptyList<String>(), h)
        assertTrue(!withheld(h), "nothing to hide → the approver sees the full statement")
    }

    @Test
    fun `a literal on an unclassified column is disclosed`() {
        val h = hint("SELECT ssn FROM users WHERE region = 'KR'")
        assertEquals(emptyList<String>(), h, "region is not classified, so 'KR' reveals nothing protected")
        assertTrue(!withheld(h))
    }

    /**
     * The case that exposed the old reader-dependent bug. A masked column FILTERED with `IS NOT NULL` DENIES
     * for the requester, but the text carries no literal value at all — so an approver must see the statement.
     * The retired `DENY → withhold` shortcut hid it; the reader-neutral hint discloses it.
     */
    @Test
    fun `a classified column filtered without a literal is disclosed, even though it denies for the requester`() {
        val h = hint("SELECT id FROM users WHERE ssn IS NOT NULL")
        assertEquals(emptyList<String>(), h, "IS NOT NULL carries no value; nothing to withhold")
        assertTrue(!withheld(h))
    }

    @Test
    fun `a column-to-column comparison carries no value`() {
        assertEquals(emptyList<String>(), hint("SELECT id FROM users WHERE ssn = region"))
    }

    @Test
    fun `an unanalyzable statement is withheld, never assumed clean`() {
        val h = hint("this is not a valid statement")
        assertEquals(null, h, "cannot be analyzed → unknown, not clean")
        assertTrue(withheld(h))
    }
}
