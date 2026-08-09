package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals

/**
 * Scanned-table deny-by-default (docs/facts-emission.md). The per-column
 * authz in `Query.kt` (`authorizeColumns` / `PolicyEvaluator`) only sees columns a query TRACES, so a
 * table scanned with zero traced columns — `count(*)`, `SELECT 1`, `EXISTS(...)`, or a cross-join
 * side that only multiplies cardinality — is never asked about by the per-column path and would leak an
 * ungranted table's existence/row-count (reaching system catalogs like `pg_authid`). The analyzer emits
 * every scanned physical relation as `ProbeResult.sources`, and the control-plane requires a `result.read`
 * grant on every UNCOVERED one (`authorizeTables`), DENY otherwise. These tests assert that enforced behavior.
 *
 * Two safety properties this file locks:
 *  1. **Scope-aware, not a name set.** A CTE that SHADOWS a real table name (`WITH orders AS (SELECT 1)
 *     SELECT count(*) FROM orders`) does NOT read the physical table, so it emits no source and ALLOWs;
 *     a CTE BODY that reads the real table (`WITH o AS (SELECT count(*) FROM orders) …`) DOES, and is
 *     gated. This falls out of the analyzer's resolution report (Physical vs CTE/Derived), never a flat
 *     global CTE-name subtraction.
 *  2. **Per-tableID coverage.** A table is covered once any of its columns is a traced fact — the column
 *     grant already exposes that table's cardinality — so a table the principal legitimately reads a
 *     column of (`count(*) FROM users`, with a `users` table grant) still ALLOWs; only a table with no
 *     traced column AND no table grant is denied.
 *
 * Fixture (`EnforcementFixture.postgres()`): `analyst@example.com` holds `result.read` on the `users`
 * table (unmasked except the pii `ssn`) plus `datasource.connect`/`sql.select`; `orders` is UNGRANTED.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class KnownGapsTest {
    private lateinit var fx: EnforcementFixture

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
    }

    @Test
    fun `count(star) on an ungranted table is denied`() {
        val r = fx.run("select count(*) from orders")
        assertEquals(EnfAction.DENY, r.decision, "count(*) on an ungranted table must be denied; got ${r.decision}")
    }

    @Test
    fun `select 1 on an ungranted table is denied`() {
        val r = fx.run("select 1 from orders")
        assertEquals(EnfAction.DENY, r.decision, "select 1 on an ungranted table must be denied; got ${r.decision}")
    }

    @Test
    fun `EXISTS over an ungranted table is denied`() {
        val r = fx.run("select exists(select 1 from orders)")
        assertEquals(EnfAction.DENY, r.decision, "EXISTS over an ungranted table must be denied; got ${r.decision}")
    }

    @Test
    fun `a cross-join scanning an ungranted table is denied even when only the granted side is projected`() {
        val r = fx.run("select u.id from users u, orders o")
        assertEquals(EnfAction.DENY, r.decision, "a cross-join touching an ungranted table must be denied; got ${r.decision}")
    }

    @Test
    fun `a CTE that shadows a real ungranted table name is allowed - the physical table is not read`() {
        // The `orders` in the outer query binds to the CTE (SELECT 1), NOT the backend table, so nothing
        // physical is scanned — ALLOW (analyst holds datasource.connect + sql.select). A naive
        // global-CTE-name fix would either leak the real table or wrongly deny this.
        val r = fx.run("with orders as (select 1) select count(*) from orders")
        assertEquals(
            EnfAction.ALLOW,
            r.decision,
            "a pure CTE shadow reads no physical table and must be allowed; got ${r.decision}: ${r.denyReason}",
        )
    }

    @Test
    fun `a CTE body that reads the real ungranted table is denied`() {
        // Mirror image of the shadow case: the CTE BODY's `from orders` resolves to the physical table,
        // scanned via count(*) with zero traced columns → uncovered → DENY without an orders grant.
        val r = fx.run("with o as (select count(*) as c from orders) select c from o")
        assertEquals(EnfAction.DENY, r.decision, "a CTE body scanning the real ungranted table must be denied; got ${r.decision}")
    }

    @Test
    fun `count(star) on a table the principal has a read grant on is allowed`() {
        // Behavior preservation + per-tableID coverage: analyst holds result.read on the users TABLE, so
        // a zero-column scan of users is authorized by that grant — the table gate must not over-deny it.
        val r = fx.run("select count(*) from users")
        assertEquals(EnfAction.ALLOW, r.decision, "count(*) on a table the principal can read must be allowed; got ${r.decision}")
    }
}
