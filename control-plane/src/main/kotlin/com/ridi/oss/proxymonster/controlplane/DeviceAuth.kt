package com.ridi.oss.proxymonster.controlplane

import javax.sql.DataSource

/** What a pmon login grants when it names no scopes. */
val PMON_DEFAULT_SCOPES: Set<String> = setOf("mcp:read", "mcp:query")

/** Device logins (served by cp-go) are short-lived; nothing is kept past expiry. */
class DeviceLoginStore(private val dataSource: DataSource) {
    fun purgeExpired(): Int = dataSource.connection.use { c ->
        c.prepareStatement("DELETE FROM device_login WHERE expires_at <= now()").use { it.executeUpdate() }
    }
}

