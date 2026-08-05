package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.ColumnRef
import com.ridi.oss.proxymonster.controlplane.authz.ColumnVerdict
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.authz.authorizeColumns
import com.ridi.oss.proxymonster.controlplane.management.ClassificationProfileManagementService
import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Resolution of shared classification profiles into a datasource's effective column classification.
 *
 * The load-bearing case is `a datasource override cannot drop a tag a profile applied`: that is the
 * whole reason resolution unions rather than replaces, and getting it wrong returns a masked column as
 * cleartext.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ClassificationProfileDbTest {
    private lateinit var ds: DataSource
    private lateinit var store: DatasourceStore
    private lateinit var profileStore: ClassificationProfileStore
    private lateinit var policyStore: PolicyStore
    private lateinit var management: ClassificationProfileManagementService

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_classification_profile"))
        Flyway.configure().dataSource(ds).load().migrate()
        store = DatasourceStore(ds)
        profileStore = ClassificationProfileStore(ds)
        policyStore = PolicyStore(ds)
        management = ClassificationProfileManagementService(profileStore, store)
    }

    private fun datasource(name: String): Datasource =
        store.create(DatasourceInput(name = name, engine = "mysql", host = "h", port = 3306, dbName = "bom"))

    /** catalog_column rows are pushed by a proxy in production; seeded directly here. */
    private fun catalogColumn(datasourceId: Long, schema: String, table: String, column: String, ordinal: Int) {
        ds.connection.use { c ->
            c.prepareStatement(
                """INSERT INTO catalog_column
                   (datasource_id, schema_name, table_name, column_name, data_type, sql_type, ordinal, nullable)
                   VALUES (?, ?, ?, ?, 'varchar', 'VARCHAR', ?, TRUE)""",
            ).use { ps ->
                ps.setLong(1, datasourceId)
                ps.setString(2, schema)
                ps.setString(3, table)
                ps.setString(4, column)
                ps.setInt(5, ordinal)
                ps.executeUpdate()
            }
        }
    }

    @Test
    fun `a datasource override adds tags but cannot drop one the profile applied`() {
        val target = datasource("ds-override")
        val profile = management.createProfile(ClassificationProfileInput("pii-baseline"))
        management.setRule(
            profile.name,
            ClassificationProfileRuleInput("bom", "users", "email", listOf("pii")),
        )
        management.attach(target.name, ProfileAttachmentInput(profile.name))

        // The override deliberately OMITS "pii" — the exfiltration shape this design exists to refuse.
        store.upsertClassification(
            target.id,
            ClassificationInput("bom", "users", "email", listOf("internal"), null),
        )

        val resolved = store.classificationsFor(target.id).getValue(Triple("bom", "users", "email"))
        assertEquals(listOf("internal", "pii"), resolved.tags.sorted(), "the profile's pii tag survives the override")
    }

    @Test
    fun `tags union across several attached profiles`() {
        val target = datasource("ds-multi")
        val pii = management.createProfile(ClassificationProfileInput("multi-pii"))
        val finance = management.createProfile(ClassificationProfileInput("multi-finance"))
        management.setRule(pii.name, ClassificationProfileRuleInput("bom", "users", "email", listOf("pii")))
        management.setRule(finance.name, ClassificationProfileRuleInput("bom", "users", "email", listOf("finance")))
        management.attach(target.name, ProfileAttachmentInput(pii.name, precedence = 0))
        management.attach(target.name, ProfileAttachmentInput(finance.name, precedence = 10))

        // NOT sorted: the assertion has to pin the resolution ORDER, or it passes under any ordering and
        // cannot catch a nondeterministic merge.
        val resolved = store.classificationsFor(target.id).getValue(Triple("bom", "users", "email"))
        assertEquals(listOf("pii", "finance"), resolved.tags, "lower precedence contributes first")
    }

    /**
     * Two attachments sharing a precedence must resolve to the same mask on every read. Without a
     * tie-break the winner is whichever row the planner emitted first, so a plan change could swap a
     * strong mask for a weak one on a column that looks masked either way.
     */
    @Test
    fun `equal-precedence attachments resolve deterministically by profile name`() {
        val target = datasource("ds-equal-precedence")
        val alpha = policyStore.createMaskFn(MaskFnInput("equal-alpha-mask", "FIXED"))
        val beta = policyStore.createMaskFn(MaskFnInput("equal-beta-mask", "LAST_N"))
        // Created in reverse name order so insertion order and name order disagree.
        val second = management.createProfile(ClassificationProfileInput("zz-equal-second"))
        val first = management.createProfile(ClassificationProfileInput("aa-equal-first"))
        management.setRule(second.name, ClassificationProfileRuleInput("bom", "t", "c", listOf("zz"), beta.id))
        management.setRule(first.name, ClassificationProfileRuleInput("bom", "t", "c", listOf("aa"), alpha.id))
        management.attach(target.name, ProfileAttachmentInput(second.name, precedence = 7))
        management.attach(target.name, ProfileAttachmentInput(first.name, precedence = 7))

        val results = (1..8).map { store.classificationsFor(target.id).getValue(Triple("bom", "t", "c")) }
        assertEquals(
            1,
            results.map { it.maskFnId to it.tags }.distinct().size,
            "every read must agree: ${results.map { it.maskFnName to it.tags }.distinct()}",
        )
        assertEquals(alpha.id, results.first().maskFnId, "the alphabetically-first profile breaks the tie")
        assertEquals(listOf("aa", "zz"), results.first().tags)
    }

    @Test
    fun `a negative attachment precedence is refused`() {
        val target = datasource("ds-negative-precedence")
        val profile = management.createProfile(ClassificationProfileInput("negative-precedence-profile"))
        management.setRule(profile.name, ClassificationProfileRuleInput("bom", "t", "c", listOf("pii")))

        val failure = assertFailsWith<ManagementException> {
            management.attach(target.name, ProfileAttachmentInput(profile.name, precedence = -2))
        }
        assertEquals("classification_profile.negative_precedence", failure.error.code)
    }

    /**
     * The datasource's own row sits at -1, so an attachment allowed below it would override the mask the
     * datasource set. The service refuses it; this pins the database as the backstop, since a direct
     * writer bypasses the service entirely.
     */
    @Test
    fun `the database rejects a negative precedence written directly`() {
        val target = datasource("ds-negative-precedence-db")
        val profile = management.createProfile(ClassificationProfileInput("negative-precedence-db-profile"))
        val failure = assertFailsWith<java.sql.SQLException> {
            ds.connection.use { c ->
                c.prepareStatement(
                    """INSERT INTO datasource_classification_profile (datasource_id, profile_id, precedence)
                       VALUES (?, ?, -2)""",
                ).use { ps ->
                    ps.setLong(1, target.id)
                    ps.setLong(2, profile.id)
                    ps.executeUpdate()
                }
            }
        }
        assertTrue(
            "precedence_non_negative" in (failure.message ?: ""),
            "the CHECK constraint must be what refuses it: ${failure.message}",
        )
    }

    /**
     * The app refuses deleting an attached profile, but that check races a concurrent attach under READ
     * COMMITTED. ON DELETE RESTRICT is what makes the cascade impossible rather than merely checked.
     */
    @Test
    fun `the database refuses to cascade a profile delete over a live attachment`() {
        val target = datasource("ds-restrict")
        val profile = management.createProfile(ClassificationProfileInput("restrict-profile"))
        management.setRule(profile.name, ClassificationProfileRuleInput("bom", "users", "email", listOf("pii")))
        management.attach(target.name, ProfileAttachmentInput(profile.name))

        val failure = assertFailsWith<java.sql.SQLException> {
            ds.connection.use { c ->
                c.prepareStatement("DELETE FROM classification_profile WHERE id = ?").use { ps ->
                    ps.setLong(1, profile.id)
                    ps.executeUpdate()
                }
            }
        }
        assertTrue(
            "datasource_classification_profile" in (failure.message ?: ""),
            "the FK must refuse it: ${failure.message}",
        )
        assertEquals(
            listOf("pii"),
            store.classificationsFor(target.id).getValue(Triple("bom", "users", "email")).tags,
            "the column stays classified",
        )
    }

    @Test
    fun `the store refuses a reserved tag even when the service guard is bypassed`() {
        val profile = management.createProfile(ClassificationProfileInput("store-reserved-tag-profile"))
        assertFailsWith<IllegalArgumentException> {
            ds.connection.use { c ->
                profileStore.upsertRule(
                    profile.id,
                    ClassificationProfileRuleInput("bom", "t", "c", listOf("system:critical")),
                    c,
                )
            }
        }
    }

    @Test
    fun `the datasource's own mask function outranks every profile`() {
        val target = datasource("ds-mask-local")
        val profileMask = policyStore.createMaskFn(MaskFnInput("profile-mask", "FIXED"))
        val localMask = policyStore.createMaskFn(MaskFnInput("local-mask", "LAST_N"))
        val profile = management.createProfile(ClassificationProfileInput("mask-profile"))
        management.setRule(
            profile.name,
            ClassificationProfileRuleInput("bom", "cards", "number", listOf("pii"), profileMask.id),
        )
        management.attach(target.name, ProfileAttachmentInput(profile.name))
        store.upsertClassification(
            target.id,
            ClassificationInput("bom", "cards", "number", emptyList(), localMask.id),
        )

        val resolved = store.classificationsFor(target.id).getValue(Triple("bom", "cards", "number"))
        assertEquals(localMask.id, resolved.maskFnId)
        assertEquals("local-mask", resolved.maskFnName)
        assertEquals(listOf("pii"), resolved.tags, "sharpening the mask leaves the profile's tags intact")
    }

    @Test
    fun `the lowest-precedence attachment wins the mask when the datasource sets none`() {
        val target = datasource("ds-mask-precedence")
        val low = policyStore.createMaskFn(MaskFnInput("precedence-low", "FIXED"))
        val high = policyStore.createMaskFn(MaskFnInput("precedence-high", "LAST_N"))
        val first = management.createProfile(ClassificationProfileInput("precedence-first"))
        val second = management.createProfile(ClassificationProfileInput("precedence-second"))
        management.setRule(first.name, ClassificationProfileRuleInput("bom", "t", "c", listOf("pii"), low.id))
        management.setRule(second.name, ClassificationProfileRuleInput("bom", "t", "c", listOf("pii"), high.id))
        management.attach(target.name, ProfileAttachmentInput(first.name, precedence = 5))
        management.attach(target.name, ProfileAttachmentInput(second.name, precedence = 50))

        val resolved = store.classificationsFor(target.id).getValue(Triple("bom", "t", "c"))
        assertEquals(low.id, resolved.maskFnId)
    }

    @Test
    fun `a profile rule reaches a datasource with no classification row of its own`() {
        val target = datasource("ds-profile-only")
        val profile = management.createProfile(ClassificationProfileInput("profile-only"))
        management.setRule(profile.name, ClassificationProfileRuleInput("bom", "users", "ssn", listOf("pii")))
        management.attach(target.name, ProfileAttachmentInput(profile.name))

        val resolved = store.classificationsFor(target.id).getValue(Triple("bom", "users", "ssn"))
        assertEquals(listOf("pii"), resolved.tags)
    }

    @Test
    fun `an unattached datasource resolves only its own rows`() {
        val attached = datasource("ds-attached")
        val bare = datasource("ds-bare")
        val profile = management.createProfile(ClassificationProfileInput("isolation-profile"))
        management.setRule(profile.name, ClassificationProfileRuleInput("bom", "users", "email", listOf("pii")))
        management.attach(attached.name, ProfileAttachmentInput(profile.name))
        store.upsertClassification(bare.id, ClassificationInput("bom", "users", "email", listOf("local"), null))

        assertEquals(listOf("local"), store.classificationsFor(bare.id).getValue(Triple("bom", "users", "email")).tags)
        assertEquals(listOf("pii"), store.classificationsFor(attached.id).getValue(Triple("bom", "users", "email")).tags)
    }

    @Test
    fun `detaching removes the tags the profile contributed`() {
        val target = datasource("ds-detach")
        val profile = management.createProfile(ClassificationProfileInput("detach-profile"))
        management.setRule(profile.name, ClassificationProfileRuleInput("bom", "users", "email", listOf("pii")))
        management.attach(target.name, ProfileAttachmentInput(profile.name))
        assertEquals(listOf("pii"), store.classificationsFor(target.id).getValue(Triple("bom", "users", "email")).tags)

        management.detach(target.name, profile.name)
        assertNull(
            store.classificationsFor(target.id)[Triple("bom", "users", "email")],
            "the column is unclassified once its only contributor is detached",
        )
    }

    @Test
    fun `catalog reads resolve profiles the same way as classificationsFor`() {
        val target = datasource("ds-catalog")
        catalogColumn(target.id, "bom", "users", "email", 1)
        val profile = management.createProfile(ClassificationProfileInput("catalog-profile"))
        management.setRule(profile.name, ClassificationProfileRuleInput("bom", "users", "email", listOf("pii")))
        management.attach(target.name, ProfileAttachmentInput(profile.name))
        store.upsertClassification(
            target.id,
            ClassificationInput("bom", "users", "email", listOf("internal"), null),
        )

        val column = store.catalog(target.id).single { it.column == "email" }
        assertEquals(
            listOf("internal", "pii"),
            column.classification?.tags?.sorted(),
            "both read paths must agree, or one caller enforces on unresolved tags",
        )
    }

    @Test
    fun `a rule may not use the reserved system tag namespace`() {
        val profile = management.createProfile(ClassificationProfileInput("reserved-tag-profile"))
        val failure = assertFailsWith<ManagementException> {
            management.setRule(
                profile.name,
                ClassificationProfileRuleInput("bom", "t", "c", listOf("system:critical")),
            )
        }
        assertEquals("datasource.reserved_tag", failure.error.code)
    }

    @Test
    fun `deleting an attached profile is refused`() {
        val target = datasource("ds-delete-guard")
        val profile = management.createProfile(ClassificationProfileInput("delete-guard-profile"))
        management.setRule(profile.name, ClassificationProfileRuleInput("bom", "users", "email", listOf("pii")))
        management.attach(target.name, ProfileAttachmentInput(profile.name))

        val failure = assertFailsWith<ManagementException> { management.deleteProfile(profile.name) }
        assertEquals("classification_profile.attached", failure.error.code)
        assertTrue(
            target.name in (failure.error.params["datasources"] ?: ""),
            "the refusal names the datasource still attached",
        )

        management.detach(target.name, profile.name)
        assertTrue(management.deleteProfile(profile.name).deleted, "it deletes once nothing is attached")
    }

    @Test
    fun `re-attaching updates the precedence rather than duplicating`() {
        val target = datasource("ds-reattach")
        val profile = management.createProfile(ClassificationProfileInput("reattach-profile"))
        management.setRule(profile.name, ClassificationProfileRuleInput("bom", "t", "c", listOf("pii")))
        management.attach(target.name, ProfileAttachmentInput(profile.name, precedence = 0))
        val attachments = management.attach(target.name, ProfileAttachmentInput(profile.name, precedence = 42))

        assertEquals(1, attachments.size)
        assertEquals(42, attachments.single().precedence)
    }

    @Test
    fun `clearing a rule stops it reaching attached datasources`() {
        val target = datasource("ds-clear-rule")
        val profile = management.createProfile(ClassificationProfileInput("clear-rule-profile"))
        management.setRule(profile.name, ClassificationProfileRuleInput("bom", "users", "email", listOf("pii")))
        management.attach(target.name, ProfileAttachmentInput(profile.name))
        assertEquals(listOf("pii"), store.classificationsFor(target.id).getValue(Triple("bom", "users", "email")).tags)

        management.clearRule(profile.name, "bom", "users", "email")
        assertNull(store.classificationsFor(target.id)[Triple("bom", "users", "email")])
    }

    /**
     * A datasource-only column keeps its tags in the order they were stored: existing callers (and
     * `GrpcRegistrationHandlerDbTest`) read that order, so resolution orders the CONTRIBUTIONS by
     * precedence rather than sorting the tag names.
     */
    @Test
    fun `resolution preserves stored tag order and appends profile tags after the datasource's own`() {
        val target = datasource("ds-tag-order")
        store.upsertClassification(
            target.id,
            ClassificationInput("bom", "users", "rrn", listOf("pii", "government-id"), null),
        )
        assertEquals(
            listOf("pii", "government-id"),
            store.classificationsFor(target.id).getValue(Triple("bom", "users", "rrn")).tags,
            "a datasource-only column is unaffected by profile resolution",
        )

        val profile = management.createProfile(ClassificationProfileInput("tag-order-profile"))
        management.setRule(profile.name, ClassificationProfileRuleInput("bom", "users", "rrn", listOf("audited")))
        management.attach(target.name, ProfileAttachmentInput(profile.name))

        assertEquals(
            listOf("pii", "government-id", "audited"),
            store.classificationsFor(target.id).getValue(Triple("bom", "users", "rrn")).tags,
            "the profile's tags append; the datasource's own order is untouched",
        )
    }

    @Test
    fun `a tag contributed by both the datasource and a profile appears once`() {
        val target = datasource("ds-dup-tag")
        val profile = management.createProfile(ClassificationProfileInput("dup-tag-profile"))
        management.setRule(profile.name, ClassificationProfileRuleInput("bom", "users", "email", listOf("pii")))
        management.attach(target.name, ProfileAttachmentInput(profile.name))
        store.upsertClassification(
            target.id,
            ClassificationInput("bom", "users", "email", listOf("pii"), null),
        )

        assertEquals(
            listOf("pii"),
            store.classificationsFor(target.id).getValue(Triple("bom", "users", "email")).tags,
        )
    }

    /**
     * The seam that matters: a `pii` tag carried ONLY by a profile has to reach Cedar and turn a
     * "read the table unless pii" grant from cleartext into a mask. Every other test here stops at the
     * store, so a resolution regression that never reached the decision path would leave them green.
     *
     * The classifications are resolved from the database rather than constructed, so the datasource →
     * profile → Cedar path runs end to end.
     */
    @Test
    fun `a profile-only pii tag masks a column that would otherwise be returned cleartext`() {
        val target = datasource("ds-enforcement")
        val engine = CedarEngine(
            listOf(
                1L to """permit(principal in Role::"analyst", action == Action::"result.read.unmasked", resource in Table::"ds-enforcement/bom/bom/users") unless { resource in Tag::"pii" };""",
                2L to """permit(principal in Role::"analyst", action == Action::"result.read.masked", resource in Table::"ds-enforcement/bom/bom/users") when { resource in Tag::"pii" };""",
            ),
        )
        val authz = Authz(engine, CedarPolicyStore(ds), RoleSource { emptySet() })

        fun verdictFor(column: String): ColumnVerdict {
            val resolved = store.classificationsFor(target.id)[Triple("bom", "users", column)]
            return authz.authorizeColumns(
                principal = "alice",
                roles = setOf("analyst"),
                datasource = target.name,
                columns = listOf(
                    ColumnRef(
                        key = "bom.bom.users.$column",
                        catalog = "bom",
                        schema = "bom",
                        table = "users",
                        column = column,
                        tags = resolved?.tags.orEmpty(),
                    ),
                ),
            ).getValue("bom.bom.users.$column")
        }

        assertEquals(ColumnVerdict.UNMASKED, verdictFor("email"), "unclassified, so the broad grant applies")

        val profile = management.createProfile(ClassificationProfileInput("enforcement-profile"))
        management.setRule(profile.name, ClassificationProfileRuleInput("bom", "users", "email", listOf("pii")))
        management.attach(target.name, ProfileAttachmentInput(profile.name))

        assertEquals(
            ColumnVerdict.MASKED,
            verdictFor("email"),
            "the profile's pii tag must reach Cedar and flip the verdict",
        )

        // And an override that omits pii must not undo it on the enforcement path either.
        store.upsertClassification(
            target.id,
            ClassificationInput("bom", "users", "email", listOf("internal"), null),
        )
        assertEquals(
            ColumnVerdict.MASKED,
            verdictFor("email"),
            "an override omitting pii must not return the column cleartext",
        )

        management.detach(target.name, profile.name)
        assertEquals(
            ColumnVerdict.UNMASKED,
            verdictFor("email"),
            "detaching is what removes the tag — the documented, explicit path",
        )
    }

    /**
     * A rename must not erase the description as a side effect — the MCP `update_*` tools treat an absent
     * optional argument as "leave it alone", and this profile tool has to match.
     */
    @Test
    fun `renaming a profile with the description omitted preserves it`() {
        val profile = management.createProfile(
            ClassificationProfileInput("rename-keeps-description", "the shared PII baseline"),
        )
        val renamed = ds.connection.use { c ->
            management.updateProfile(
                profile.name,
                ClassificationProfileInput("rename-keeps-description-v2", management.getProfile(profile.name, c).description),
                c,
            )
        }
        assertEquals("rename-keeps-description-v2", renamed.name)
        assertEquals("the shared PII baseline", renamed.description, "a rename must not clear the description")
    }

    @Test
    fun `a profile lists its rule count and the datasources it is attached to`() {
        val first = datasource("ds-summary-a")
        val second = datasource("ds-summary-b")
        val profile = management.createProfile(ClassificationProfileInput("summary-profile", "shared PII rules"))
        management.setRule(profile.name, ClassificationProfileRuleInput("bom", "users", "email", listOf("pii")))
        management.setRule(profile.name, ClassificationProfileRuleInput("bom", "users", "name", listOf("pii")))
        management.attach(first.name, ProfileAttachmentInput(profile.name))
        management.attach(second.name, ProfileAttachmentInput(profile.name))

        val summary = management.getProfile(profile.name)
        assertEquals(2, summary.ruleCount)
        assertEquals(listOf(first.name, second.name).sorted(), summary.attachedDatasources.sorted())
        assertEquals("shared PII rules", summary.description)
    }
}
