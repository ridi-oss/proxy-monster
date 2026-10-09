package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.seedDaemonSession
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue

/**
 * `principal_session` carries both session kinds on one table (docs/session-lifetime.md): the store's
 * indexes are present, and `session_key` is unique where set while the NULLs a daemon session leaves
 * keep coexisting.
 */
class PrincipalSessionSchemaDbTest {
    @Test
    fun `the session table carries its indexes and a partial-unique session key`() {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_principal_session_schema"))
        Flyway.configure().dataSource(dataSource).load().migrate()

        // Two daemon sessions, both with a NULL session_key — the partial index must let them coexist.
        val first = dataSource.seedDaemonSession("first@example.com", 7200, 60)
        val second = dataSource.seedDaemonSession("second@example.com", 7200, 60)
        assertTrue(second > first)

        dataSource.connection.use { c ->
            c.prepareStatement("SELECT indexname FROM pg_indexes WHERE tablename = 'principal_session'").use { ps ->
                ps.executeQuery().use { rs ->
                    val names = buildSet { while (rs.next()) add(rs.getString(1)) }
                    assertTrue(
                        setOf(
                            "idx_principal_session_principal",
                            "idx_principal_session_handle",
                            "idx_principal_session_renewal_hash",
                            "idx_principal_session_active",
                            "idx_principal_session_session_key",
                        ).all(names::contains),
                        "missing a session index: $names",
                    )
                }
            }
            c.prepareStatement("SELECT count(*) FROM principal_session WHERE session_key IS NULL").use { ps ->
                ps.executeQuery().use { rs -> rs.next(); assertEquals(2, rs.getInt(1)) }
            }
            c.createStatement().use { st ->
                st.execute(
                    "INSERT INTO principal_session (principal, absolute_expires_at, liveness_status, kind) " +
                        "VALUES ('web-one@example.com', now() + interval '1 hour', 'ACTIVE', 'WEB')",
                )
                st.execute(
                    "INSERT INTO principal_session (principal, absolute_expires_at, liveness_status, kind) " +
                        "VALUES ('web-two@example.com', now() + interval '1 hour', 'ACTIVE', 'WEB')",
                )
                st.execute("UPDATE principal_session SET session_key = 'duplicate-key' WHERE principal = 'web-one@example.com'")
                assertFails("two sessions must not share one session_key") {
                    st.execute("UPDATE principal_session SET session_key = 'duplicate-key' WHERE principal = 'web-two@example.com'")
                }
            }
        }
    }
}
