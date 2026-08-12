package com.ridi.oss.proxymonster.controlplane

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The fail-closed `PM_AUTH_DEBUG` guard (docs/auth-model.md "Security invariants" — "`PM_AUTH_DEBUG`
 * MUST be off in production ... refuse to start with it on unless a `PM_DEV` marker is set") plus
 * the plain OIDC/session-window/SCIM env parsing in [Config.fromEnv]. Pure — no DB, no network.
 */
class ConfigGuardTest {
    private fun envOf(vararg pairs: Pair<String, String>): (String) -> String? {
        val map = pairs.toMap()
        return { key -> map[key] }
    }

    private fun productionEnv(vararg pairs: Pair<String, String>): (String) -> String? = envOf(
        "PM_AUTH_DEBUG" to "false",
        "PM_MCP_RESOURCE" to "https://proxy.example.com/mcp",
        "PM_SESSION_SECRET" to "x".repeat(32),
        "PM_OIDC_ISSUER" to "https://idp.example.com",
        "PM_OIDC_CLIENT_ID" to "cid",
        "PM_OIDC_CLIENT_SECRET" to "secret",
        "PM_OIDC_REDIRECT_URI" to "https://proxy.example.com/auth/oidc/callback",
        "PM_SECRET_TOKEN" to "proxy-shared-secret",
        *pairs,
    )

    @Test fun `bare defaults boot fine (local dev, debug on, dev secret, no oidc)`() {
        val config = Config.fromEnv(envOf())
        assertTrue(config.authDebug)
        assertNull(config.oidc)
        assertEquals(emptySet(), config.trustedProxies, "no PM_TRUSTED_PROXIES -> no trusted edge -> X-Forwarded-For never honored")
    }

    @Test fun `PM_QUERY_TIMEOUT defaults overrides and rejects invalid values`() {
        assertEquals(600, Config.fromEnv(envOf()).queryTimeoutSeconds)
        assertEquals(45, Config.fromEnv(envOf("PM_QUERY_TIMEOUT" to "45")).queryTimeoutSeconds)
        assertFailsWith<IllegalArgumentException> { Config.fromEnv(envOf("PM_QUERY_TIMEOUT" to "0")) }
        assertFailsWith<IllegalArgumentException> { Config.fromEnv(envOf("PM_QUERY_TIMEOUT" to "-1")) }
        // A set-but-non-numeric value fails fast rather than silently defaulting to 600.
        assertFailsWith<IllegalArgumentException> { Config.fromEnv(envOf("PM_QUERY_TIMEOUT" to "abc")) }
    }

    @Test fun `PM_NOTIFY_STATEMENT takes omit auto full, coerces legacy truncated, rejects the rest`() {
        assertEquals("auto", Config.fromEnv(envOf()).notifyStatement, "default is auto")
        assertEquals("omit", Config.fromEnv(envOf("PM_NOTIFY_STATEMENT" to "omit")).notifyStatement)
        assertEquals("full", Config.fromEnv(envOf("PM_NOTIFY_STATEMENT" to "FULL")).notifyStatement)
        // The removed `truncated` must not fail boot — it coerces to `auto` (logged).
        assertEquals("auto", Config.fromEnv(envOf("PM_NOTIFY_STATEMENT" to "truncated")).notifyStatement)
        // Anything else is a config error, not a silent default.
        assertFailsWith<IllegalArgumentException> { Config.fromEnv(envOf("PM_NOTIFY_STATEMENT" to "sometimes")) }
    }

    @Test fun `PM_QUERY_TIMEOUT is bounded to the proxy's duration-safe ceiling (no ms overflow)`() {
        // The shared CP+proxy maximum: accepted here, rejected one above. Keeps queryExchangeTimeoutMs /
        // the run-stream cap from overflowing Long, and keeps the lockstep contract with goproxy exact.
        assertEquals(
            Config.MAX_QUERY_TIMEOUT_SECONDS,
            Config.fromEnv(envOf("PM_QUERY_TIMEOUT" to Config.MAX_QUERY_TIMEOUT_SECONDS.toString())).queryTimeoutSeconds,
        )
        // The accepted maximum still converts to a positive millisecond exchange budget.
        val maxCfg = Config.fromEnv(envOf("PM_QUERY_TIMEOUT" to Config.MAX_QUERY_TIMEOUT_SECONDS.toString()))
        assertTrue(maxCfg.queryExchangeTimeoutMs > 0)
        assertFailsWith<IllegalArgumentException> {
            Config.fromEnv(envOf("PM_QUERY_TIMEOUT" to (Config.MAX_QUERY_TIMEOUT_SECONDS + 1).toString()))
        }
        assertFailsWith<IllegalArgumentException> { Config.fromEnv(envOf("PM_QUERY_TIMEOUT" to Long.MAX_VALUE.toString())) }
    }

    @Test fun `run token TTL outlives the whole run, session TTL outlives the query window`() {
        // The one-shot run token must stay valid for the ENTIRE run it authorizes — the dial-back + the
        // target-DB open + the exchange (PM_QUERY_TIMEOUT + exchange grace) — not merely the query window, else a
        // long query on a slow target-DB open fails UNAUTHENTICATED mid-run when the proxy revalidates the token.
        // The editor-session token's 8h floor spans many queries, so it need only clear one window.
        val runOverheadSeconds =
            (RUN_DIALBACK_TIMEOUT_MS + RUN_OPEN_TIMEOUT_MS) / 1000 + Config.QUERY_EXCHANGE_GRACE_MS / 1000
        // 616 is the smallest timeout at which the old floor-only grace under-budgeted the full run.
        for (timeout in listOf(1L, 600L, 616L, 3600L, 36_000L, Config.MAX_QUERY_TIMEOUT_SECONDS)) {
            assertTrue(
                RunExecService.runTokenTtlSeconds(timeout) >= timeout + runOverheadSeconds,
                "run token TTL must cover dial-back + target-DB open + exchange for timeout=$timeout",
            )
            assertTrue(
                RunExecService.editorSessionTtlSeconds(timeout) > timeout,
                "editor session TTL must exceed the query window for timeout=$timeout",
            )
        }
    }


    @Test fun `the exchange budget outlives the proxy's own statement watchdog`() {
        // The proxy aborts a statement at PM_QUERY_TIMEOUT. This bound sits outside that one, so it has to
        // fire later — otherwise the control plane reports a timeout for a query the proxy goes on to
        // finish, and the two ends disagree about whether it ran.
        for (timeout in listOf(1L, 600L, 3600L, Config.MAX_QUERY_TIMEOUT_SECONDS)) {
            val config = Config.fromEnv(envOf("PM_QUERY_TIMEOUT" to timeout.toString()))
            assertTrue(
                config.queryExchangeTimeoutMs > timeout * 1000,
                "exchange budget must outlast the proxy watchdog for timeout=$timeout",
            )
        }
    }

    @Test fun `PM_TRUSTED_PROXIES parses comma-separated entries, trimmed, with blanks dropped`() {
        assertEquals(
            setOf("10.0.0.1", "10.0.0.2"),
            Config.fromEnv(envOf("PM_TRUSTED_PROXIES" to " 10.0.0.1 , 10.0.0.2 ,, ")).trustedProxies,
        )
        assertEquals(setOf("10.0.0.1"), Config.fromEnv(envOf("PM_TRUSTED_PROXIES" to "10.0.0.1")).trustedProxies)
        assertEquals(emptySet(), Config.fromEnv(envOf("PM_TRUSTED_PROXIES" to "")).trustedProxies)
        assertEquals(emptySet(), Config.fromEnv(envOf("PM_TRUSTED_PROXIES" to "  ,  ")).trustedProxies)
    }

    @Test fun `debug on plus real oidc config without PM_DEV refuses to start`() {
        assertFailsWith<IllegalArgumentException> {
            Config.fromEnv(
                envOf(
                    "PM_AUTH_DEBUG" to "true",
                    "PM_OIDC_ISSUER" to "https://idp.example.com",
                    "PM_OIDC_CLIENT_ID" to "cid",
                    "PM_OIDC_CLIENT_SECRET" to "secret",
                    "PM_OIDC_REDIRECT_URI" to "https://app.example.com/auth/oidc/callback",
                ),
            )
        }
    }

    @Test fun `debug on plus a real session secret without PM_DEV refuses to start`() {
        assertFailsWith<IllegalArgumentException> {
            Config.fromEnv(envOf("PM_AUTH_DEBUG" to "true", "PM_SESSION_SECRET" to "a-real-production-secret"))
        }
    }

    @Test fun `debug on plus a production-looking context WITH PM_DEV is allowed`() {
        val config = Config.fromEnv(
            envOf(
                "PM_AUTH_DEBUG" to "true",
                "PM_DEV" to "true",
                "PM_OIDC_ISSUER" to "https://idp.example.com",
                "PM_OIDC_CLIENT_ID" to "cid",
                "PM_OIDC_CLIENT_SECRET" to "secret",
                "PM_OIDC_REDIRECT_URI" to "https://proxy.example.com/auth/oidc/callback",
                "PM_SESSION_SECRET" to "x".repeat(32),
            ),
        )
        assertTrue(config.authDebug)
        assertTrue(config.devMarker)
        assertNotNull(config.oidc)
    }

    @Test fun `debug off is always allowed, even with real oidc + session secret`() {
        val config = Config.fromEnv(
            productionEnv(
                "PM_OIDC_ISSUER" to "https://idp.example.com",
                "PM_OIDC_CLIENT_ID" to "cid",
                "PM_OIDC_CLIENT_SECRET" to "secret",
                "PM_OIDC_REDIRECT_URI" to "https://proxy.example.com/auth/oidc/callback",
                "PM_SESSION_SECRET" to "x".repeat(32),
            ),
        )
        assertFalse(config.authDebug)
        assertNotNull(config.oidc)
    }

    @Test fun `debug off rejects the public development session secret`() {
        assertFailsWith<IllegalArgumentException> {
            Config.fromEnv(
                envOf(
                    "PM_AUTH_DEBUG" to "false",
                    "PM_MCP_RESOURCE" to "https://proxy.example.com/mcp",
                ),
            )
        }
    }

    @Test fun `debug off requires a non-blank proxy secret`() {
        assertFailsWith<IllegalArgumentException> { Config.fromEnv(productionEnv("PM_SECRET_TOKEN" to "")) }
        assertFailsWith<IllegalArgumentException> { Config.fromEnv(productionEnv("PM_SECRET_TOKEN" to "   ")) }
        // The actual advisory case: the key entirely absent (env() returns null). productionEnv always sets
        // it, so build a production env without it to pin that the null path fails closed too.
        assertFailsWith<IllegalArgumentException> {
            Config.fromEnv(
                envOf(
                    "PM_AUTH_DEBUG" to "false",
                    "PM_MCP_RESOURCE" to "https://proxy.example.com/mcp",
                    "PM_SESSION_SECRET" to "x".repeat(32),
                    "PM_OIDC_ISSUER" to "https://idp.example.com",
                    "PM_OIDC_CLIENT_ID" to "cid",
                    "PM_OIDC_CLIENT_SECRET" to "secret",
                    "PM_OIDC_REDIRECT_URI" to "https://proxy.example.com/auth/oidc/callback",
                ),
            )
        }
    }

    @Test fun `debug off with a valid proxy secret boots and preserves it`() {
        assertEquals("proxy-shared-secret", Config.fromEnv(productionEnv()).secretToken)
    }

    @Test fun `debug mode preserves the configured proxy secret value verbatim`() {
        assertEquals("   ", Config.fromEnv(envOf("PM_SECRET_TOKEN" to "   ")).secretToken)
    }

    @Test fun `debug off requires secure canonical MCP origins`() {
        assertFailsWith<IllegalArgumentException> {
            Config.fromEnv(
                productionEnv("PM_MCP_RESOURCE" to "http://proxy.example.com/mcp"),
            )
        }
        val config = Config.fromEnv(productionEnv("PM_MCP_RESOURCE" to "https://PROXY.EXAMPLE.COM/mcp"))
        assertEquals(
            "https://proxy.example.com/mcp",
            config.mcpResource,
        )
        assertEquals("https://proxy.example.com", config.mcpIssuer)
    }

    @Test fun `debug mode leaves oidc null unless all four required fields are present`() {
        val debugEnv = arrayOf("PM_AUTH_DEBUG" to "true", "PM_DEV" to "true")
        assertNull(Config.fromEnv(envOf(*debugEnv, "PM_OIDC_ISSUER" to "https://idp.example.com")).oidc)
        assertNull(
            Config.fromEnv(
                envOf(
                    *debugEnv,
                    "PM_OIDC_ISSUER" to "https://idp.example.com",
                    "PM_OIDC_CLIENT_ID" to "cid",
                    "PM_OIDC_CLIENT_SECRET" to "secret",
                    // redirect_uri missing
                ),
            ).oidc,
        )
    }

    @Test fun `debug off requires complete secure oidc config on the co-hosted callback`() {
        assertFailsWith<IllegalArgumentException> {
            Config.fromEnv(
                envOf(
                    "PM_AUTH_DEBUG" to "false",
                    "PM_MCP_RESOURCE" to "https://proxy.example.com/mcp",
                    "PM_SESSION_SECRET" to "x".repeat(32),
                ),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            Config.fromEnv(productionEnv("PM_OIDC_ISSUER" to "http://idp.example.com"))
        }
        assertFailsWith<IllegalArgumentException> {
            Config.fromEnv(
                productionEnv("PM_OIDC_REDIRECT_URI" to "https://other.example.com/auth/oidc/callback"),
            )
        }
    }

    @Test fun `oidc scopes default to openid profile email groups offline_access`() {
        val config = Config.fromEnv(
            productionEnv(
                "PM_OIDC_ISSUER" to "https://idp.example.com",
                "PM_OIDC_CLIENT_ID" to "cid",
                "PM_OIDC_CLIENT_SECRET" to "secret",
                "PM_OIDC_REDIRECT_URI" to "https://proxy.example.com/auth/oidc/callback",
            ),
        )
        assertEquals("openid profile email groups offline_access", config.oidc?.scopes)
        assertTrue(config.oidc!!.scopes.contains("offline_access"), "device-flow session-renewal needs a refresh token")
    }

    @Test fun `oidc scopes are overridable via PM_OIDC_SCOPES`() {
        val config = Config.fromEnv(
            productionEnv(
                "PM_OIDC_ISSUER" to "https://idp.example.com",
                "PM_OIDC_CLIENT_ID" to "cid",
                "PM_OIDC_CLIENT_SECRET" to "secret",
                "PM_OIDC_REDIRECT_URI" to "https://proxy.example.com/auth/oidc/callback",
                "PM_OIDC_SCOPES" to "openid email",
            ),
        )
        assertEquals("openid email", config.oidc?.scopes)
    }

    @Test fun `session window, web clocks, idp recheck interval, and scim token default sanely`() {
        val config = Config.fromEnv(envOf())
        assertEquals(2 * 3600L, config.sessionWindowSeconds)
        assertEquals(2 * 3600L, config.webSessionAbsoluteSeconds)
        assertEquals(900L, config.webSessionIdleSeconds)
        assertEquals(120L, config.webSessionSlideSeconds)
        assertEquals(60L, config.webSessionIdleWarnLeadSeconds)
        assertEquals(300L, config.webSessionAbsoluteWarnLeadSeconds)
        assertEquals(90L, config.webSessionHeartbeatSeconds)
        assertEquals(300L, config.idpRecheckIntervalSeconds)
        assertNull(config.scimToken)
        assertFalse(config.devMarker)
    }

    @Test fun `idp recheck interval must be positive`() {
        // Zero would busy-loop the liveness sweep; a negative value makes delay() throw and kills it.
        assertFailsWith<IllegalArgumentException> { Config.fromEnv(envOf("PM_IDP_RECHECK_INTERVAL" to "0")) }
        assertFailsWith<IllegalArgumentException> { Config.fromEnv(envOf("PM_IDP_RECHECK_INTERVAL" to "-1")) }
    }

    @Test fun `session window, idp recheck interval, and scim token are overridable`() {
        val config = Config.fromEnv(
            envOf(
                "PM_SESSION_WINDOW" to "3600",
                "PM_IDP_RECHECK_INTERVAL" to "60",
                "PM_SCIM_TOKEN" to "a-standing-scim-secret",
            ),
        )
        assertEquals(3600L, config.sessionWindowSeconds)
        assertEquals(60L, config.idpRecheckIntervalSeconds)
        assertEquals("a-standing-scim-secret", config.scimToken)
    }

    @Test fun `web session UX timings accept duration units`() {
        val config = Config.fromEnv(
            envOf(
                "PM_WEB_SESSION_IDLE_WARN_LEAD" to "2m",
                "PM_WEB_SESSION_ABSOLUTE_WARN_LEAD" to "10m",
                "PM_WEB_SESSION_HEARTBEAT" to "45s",
            ),
        )
        assertEquals(120L, config.webSessionIdleWarnLeadSeconds)
        assertEquals(600L, config.webSessionAbsoluteWarnLeadSeconds)
        assertEquals(45L, config.webSessionHeartbeatSeconds)
    }

    @Test fun `web session absolute duration accepts seconds and concatenated units`() {
        assertEquals(7200L, Config.fromEnv(envOf("PM_WEB_SESSION_ABSOLUTE" to "2h")).webSessionAbsoluteSeconds)
        assertEquals(5400L, Config.fromEnv(envOf("PM_WEB_SESSION_ABSOLUTE" to "1h30m")).webSessionAbsoluteSeconds)
        assertEquals(900L, Config.fromEnv(envOf("PM_WEB_SESSION_ABSOLUTE" to "900")).webSessionAbsoluteSeconds)
        assertEquals(90L, parseDuration("90s"))
        assertEquals(900L, parseDuration("15m"))
    }

    @Test fun `web idle and slide durations accept units and plain seconds`() {
        val config = Config.fromEnv(
            envOf(
                "PM_WEB_SESSION_IDLE" to "15m",
                "PM_WEB_SESSION_SLIDE" to "120",
            ),
        )
        assertEquals(900L, config.webSessionIdleSeconds)
        assertEquals(120L, config.webSessionSlideSeconds)
        assertEquals(120L, Config.fromEnv(envOf("PM_WEB_SESSION_IDLE" to "15m", "PM_WEB_SESSION_SLIDE" to "2m")).webSessionSlideSeconds)
    }

    @Test fun `malformed web session durations fail fast`() {
        for (name in listOf(
            "PM_WEB_SESSION_ABSOLUTE",
            "PM_WEB_SESSION_IDLE",
            "PM_WEB_SESSION_SLIDE",
            "PM_WEB_SESSION_IDLE_WARN_LEAD",
            "PM_WEB_SESSION_ABSOLUTE_WARN_LEAD",
            "PM_WEB_SESSION_HEARTBEAT",
        )) {
            for (raw in listOf("2x", "", "-1h")) {
                assertFailsWith<IllegalArgumentException> {
                    Config.fromEnv(envOf(name to raw))
                }
            }
        }
    }

    @Test fun `web session slide must be strictly less than idle`() {
        assertFailsWith<IllegalArgumentException> {
            Config.fromEnv(envOf("PM_WEB_SESSION_IDLE" to "2m", "PM_WEB_SESSION_SLIDE" to "2m"))
        }
        assertFailsWith<IllegalArgumentException> {
            Config.fromEnv(envOf("PM_WEB_SESSION_IDLE" to "2m", "PM_WEB_SESSION_SLIDE" to "3m"))
        }
        assertEquals(
            119L,
            Config.fromEnv(envOf("PM_WEB_SESSION_IDLE" to "2m", "PM_WEB_SESSION_SLIDE" to "119")).webSessionSlideSeconds,
        )
        assertFailsWith<IllegalArgumentException> {
            Config.fromEnv(envOf()).copy(webSessionSlideSeconds = 900, webSessionIdleSeconds = 900)
        }
    }
}
