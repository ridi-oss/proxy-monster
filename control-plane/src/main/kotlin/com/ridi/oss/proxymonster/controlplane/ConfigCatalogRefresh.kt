package com.ridi.oss.proxymonster.controlplane

import org.slf4j.LoggerFactory
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

const val CONFIG_CATALOG_REFRESH_WINDOW_MILLIS = 3_000L

/**
 * Sends one `RefreshCatalog` per datasource when a [windowMillis] window opened by the first request closes,
 * so a migration of many DDLs costs one introspection. Best-effort: the ambient refresh is the backstop.
 */
class ConfigCatalogRefresh(
    private val hub: ProxyEventsHub,
    private val windowMillis: Long = CONFIG_CATALOG_REFRESH_WINDOW_MILLIS,
) {
    private val log = LoggerFactory.getLogger(ConfigCatalogRefresh::class.java)
    private val scheduled = ConcurrentHashMap.newKeySet<String>()
    private val timer = ScheduledThreadPoolExecutor(1) { runnable ->
        Thread(runnable, "config-catalog-refresh").apply { isDaemon = true }
    }.apply {
        setKeepAliveTime(30, TimeUnit.SECONDS)
        allowCoreThreadTimeOut(true)
    }

    fun request(datasourceName: String) {
        if (!scheduled.add(datasourceName)) return
        try {
            timer.schedule({ fire(datasourceName) }, windowMillis, TimeUnit.MILLISECONDS)
        } catch (e: Exception) {
            scheduled.remove(datasourceName)
            log.warn("could not schedule a config catalog refresh for datasource '{}'", datasourceName, e)
        }
    }

    private fun fire(datasourceName: String) {
        // Removed before sending, so a change landing while the proxy introspects opens a new window.
        scheduled.remove(datasourceName)
        try {
            if (hub.requestRefresh(datasourceName) == 0) {
                log.info("no proxy attached to datasource '{}'; config catalog refresh after DDL skipped", datasourceName)
            }
        } catch (e: Exception) {
            log.warn("config catalog refresh after DDL failed for datasource '{}'", datasourceName, e)
        }
    }
}
