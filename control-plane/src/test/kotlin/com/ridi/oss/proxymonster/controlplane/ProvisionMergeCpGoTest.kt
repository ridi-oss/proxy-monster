package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.FakeOidcIdp
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import kotlinx.coroutines.runBlocking
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/** OIDC JIT provisioning through a login on cp-go (support/CpGoStack.kt): additive, and never clobbers a SCIM-owned user. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ProvisionMergeCpGoTest {
    private lateinit var ds: DataSource
    private lateinit var store: UserGroupStore
    private lateinit var idp: FakeOidcIdp
    private lateinit var stack: CpGoStack

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase("pm_provision_merge_cpgo")
        ds = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(ds).load().migrate()
        store = UserGroupStore(ds)
        idp = FakeOidcIdp()
        val config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "provision-merge-test-secret", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        stack = CpGoStack(config, ControlPlaneCore(ds), database, extraEnv = idp.env())
    }

    @AfterAll
    fun teardown() {
        if (::stack.isInitialized) stack.close()
        if (::idp.isInitialized) idp.close()
    }

    private fun login(principal: String, email: String?, groups: List<String>): AppUser = runBlocking {
        idp.login(stack.client(), principal, email, groups)
        assertNotNull(store.getUserByPrincipal(email ?: principal))
    }

    @Test
    fun `provisionFromOidc creates a new source=OIDC user and mirrors the claim's groups`() {
        val user = login("new-jit@example.com", "new-jit@example.com", listOf("eng", "on-call"))
        assertEquals("OIDC", user.source)
        assertEquals("new-jit@example.com", user.email)
        assertEquals(setOf("eng", "on-call"), user.groups.map { it.name }.toSet())

        val eng = store.listGroups().first { it.name == "eng" }
        assertEquals("OIDC", eng.source)
    }

    @Test
    fun `re-provisioning SYNCS group membership to the latest claim (drops removed groups)`() {
        val principal = "additive@example.com"
        login(principal, principal, listOf("group-a", "group-b"))
        val second = login(principal, principal, listOf("group-c"))
        assertEquals(setOf("group-c"), second.groups.map { it.name }.toSet())
    }

    @Test
    fun `provisionFromOidc reuses an existing group's source, whatever it is`() {
        val group = store.createGroup(AppGroupInput(name = "already-local"))
        assertEquals("LOCAL", group.source)
        val user = login("reuse-group@example.com", null, listOf("already-local"))
        assertEquals(setOf("already-local"), user.groups.map { it.name }.toSet())
        assertEquals("LOCAL", store.getGroup(group.id)!!.source)
    }

    @Test
    fun `JIT never clobbers a source=SCIM user's fields`() {
        // cp-go takes the principal from the email claim, so the SCIM row is keyed by the email the login carries.
        val principal = "attacker-supplied@evil.com"
        val scimUser = store.upsertScimUser(
            externalId = "ext-1", principal = principal, email = "scim-owned@example.com",
            displayName = "SCIM Name", active = true,
        )
        assertEquals("SCIM", scimUser.source)

        val afterJit = login("scim-owned-subject", "attacker-supplied@evil.com", listOf("some-group"))
        assertEquals("SCIM", afterJit.source)
        assertEquals("scim-owned@example.com", afterJit.email, "JIT must not overwrite a SCIM-owned user's email")
    }
}
