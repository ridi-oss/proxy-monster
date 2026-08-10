package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * DB-backed enforcement tests: run [runEnforcedForTest] against a real target database through the
 * real control-plane store, proving the enforcement triad end-to-end — masking actually rewrites values, and
 * the two lineage bypasses (scalar-subquery cleartext leak, IN-subquery existence oracle) are DENIED
 * so no rows (masked or otherwise) ever leave the proxy. Containers are shared/reused (see
 * support/TestDatabases.kt). Skips cleanly when no Docker daemon is available.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EnforcementPostgresDbTest {
    private lateinit var fx: EnforcementFixture

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
    }

    @Test
    fun `masked query returns masked ssn, never cleartext`() {
        val r = fx.run("select id, ssn from users order by id")
        assertEquals(EnfAction.MASK, r.decision)
        val ssn = r.rows.map { it[1] }
        assertTrue(fx.cleartextSsn.none { it in ssn }, "cleartext ssn leaked: $ssn")
        assertTrue(ssn.all { it != null && it.startsWith("*") }, "expected masked ssn values, got $ssn")
        assertTrue(ssn.any { it!!.endsWith("4320") }, "expected LAST_N to keep the last 4, got $ssn")
    }

    @Test
    fun `scalar subquery leak is denied and returns no rows`() {
        val r = fx.run("select u.id, (select ssn from users where id = 1) as x from users u")
        assertEquals(EnfAction.DENY, r.decision, "scalar-subquery ssn leak must be denied")
        assertTrue(r.rows.isEmpty(), "a DENY must not return rows")
        assertTrue(r.denyReason!!.contains("subquery"), "deny reason: ${r.denyReason}")
    }

    @Test
    fun `IN subquery oracle is denied`() {
        val r = fx.run("select id from users where region in (select ssn from users)")
        assertEquals(EnfAction.DENY, r.decision, "IN (SELECT ssn ...) oracle must be denied")
        assertTrue(r.rows.isEmpty(), "a DENY must not return rows")
    }

    @Test
    fun `correlated subquery oracle over ssn is denied and returns no rows`() {
        val r = fx.run("select u.id from users u where exists (select 1 from users v where v.region = u.region and u.ssn = '987-65-4320')")
        assertEquals(EnfAction.DENY, r.decision, "correlated ssn oracle must be denied")
        assertTrue(r.rows.isEmpty(), "a DENY must not return rows")
    }

    @Test
    fun `INTERSECT membership oracle over ssn is denied and returns no rows`() {
        val r = fx.run("select region from users intersect select ssn from users")
        assertEquals(EnfAction.DENY, r.decision, "INTERSECT membership oracle must be denied")
        assertTrue(r.rows.isEmpty(), "a DENY must not return rows")
    }

    @Test
    fun `no-FROM query_to_xml data reader is denied and returns no rows`() {
        // Admission-layer bypass: query_to_xml reads users.ssn via a string arg (no FROM, invisible to
        // lineage). Must be denied before execution — no cleartext XML.
        val r = fx.run("select query_to_xml('SELECT ssn FROM users WHERE id = 1', true, false, '')")
        assertEquals(EnfAction.DENY, r.decision, "no-FROM query_to_xml must be denied")
        assertTrue(r.rows.isEmpty(), "a DENY must not return rows")
    }

    @Test
    fun `no-FROM metadata chatter still runs`() {
        // The gate must not break benign connection chatter — version() executes and returns a row.
        val r = fx.run("select version()")
        assertEquals(EnfAction.ALLOW, r.decision)
        assertEquals(1, r.rows.size)
    }

    @Test
    fun `a principal with zero grants cannot enumerate schema via readonly-meta passthrough`() {
        // Security regression: datasource.connect must be checked BEFORE the passthrough switch. If it
        // were checked after, READONLY_META (SHOW/DESCRIBE/no-FROM metadata SELECTs) and
        // TX_CONTROL/SESSION_MUTATING on WIRE would ALLOW unconditionally — a principal with NO grant at
        // all could still enumerate schema metadata. `ghost@example.com` resolves to zero roles
        // (RoleResolver fails closed on an unknown principal) — every passthrough class must now DENY.
        val meta = fx.run("select version()", principal = "ghost@example.com")
        assertEquals(EnfAction.DENY, meta.decision, "READONLY_META must require datasource.connect; reason=${meta.denyReason}")
        assertTrue(meta.denyReason!!.contains("no access to datasource"), "deny reason: ${meta.denyReason}")
    }

    @Test
    fun `non-sensitive query is allowed and returns rows`() {
        val r = fx.run("select id, region from users order by id")
        assertEquals(EnfAction.ALLOW, r.decision)
        assertEquals(2, r.rows.size)
    }

    @Test
    fun `a query on an ungranted table is denied end-to-end — deny-by-default, not cleartext`() {
        // `orders` has no Cedar grant at all. Its columns are unclassified, so a populator that only
        // authorized classified columns would let them fall through as cleartext (the exact bug the
        // deny-by-default inversion fixes). authorizeColumns must return DENIED for every touched
        // column, and PolicyEvaluator must turn that into a DENY with no rows.
        val r = fx.run("select id, amount from orders order by id")
        assertEquals(EnfAction.DENY, r.decision, "an ungranted table must be denied; reason=${r.denyReason}")
        assertTrue(r.rows.isEmpty(), "a DENY must not return rows")
    }

    @Test
    fun `LATERAL correlated leak of ssn is denied and returns no rows`() {
        val r = fx.run("select l.x from users u, lateral (select ssn as x) l")
        assertEquals(EnfAction.DENY, r.decision, "LATERAL ssn leak must be denied")
        assertTrue(r.rows.isEmpty(), "a DENY must not return rows")
    }

    @Test
    fun `recursive CTE anchoring on ssn is denied and returns no rows`() {
        val r = fx.run("with recursive c(x) as (select ssn from users union all select x from c) select x from c")
        assertEquals(EnfAction.DENY, r.decision, "recursive CTE ssn leak must be denied")
        assertTrue(r.rows.isEmpty(), "a DENY must not return rows")
    }

    @Test
    fun `benign correlated exists is allowed`() {
        val r = fx.run("select u.id from users u where exists (select 1 from users v where v.region = u.region and v.id <> u.id) order by u.id")
        assertEquals(EnfAction.ALLOW, r.decision, "benign correlated EXISTS must not over-deny; reason=${r.denyReason}")
    }

    // --- The two once-per-query Cedar gates (datasource.connect, then sql.<kind>) ---

    @Test
    fun `an INSERT without a sql insert grant is denied with a clean reason, not a parse-failure`() {
        val r = fx.run("insert into users values (3,'c@x','x','KR')")
        assertEquals(EnfAction.DENY, r.decision)
        assertTrue(r.denyReason!!.contains("statement kind 'insert' is not permitted"), "deny reason: ${r.denyReason}")
    }

    @Test
    fun `a principal with sql select but no datasource connect is denied first`() {
        // reader@example.com holds sql.select + result.read.unmasked on users but NOT datasource.connect —
        // proves connect is checked before sql.<kind>/columns even though the rest would pass.
        val r = fx.run("select id, region from users", principal = "reader@example.com")
        assertEquals(EnfAction.DENY, r.decision)
        assertTrue(r.denyReason!!.contains("no access to datasource"), "deny reason: ${r.denyReason}")
    }

    @Test
    fun `DDL without a sql ddl grant is denied with a clean reason, not a parse-failure`() {
        val r = fx.run("create table t (id int)")
        assertEquals(EnfAction.DENY, r.decision)
        assertTrue(r.denyReason!!.contains("statement kind 'create_table' is not permitted"), "deny reason: ${r.denyReason}")
    }

    @Test
    fun `CTAS that reads a masked column is denied even with a sql ddl grant`() {
        // writer@example.com HAS sql.ddl — the kind gate passes — but the write-payload rule in
        // PolicyEvaluator.evaluate still denies: a CTAS may not copy a masked/denied column into an
        // unmasked persisted table (docs/authz-model.md's exfiltration worked walk-through).
        val r = fx.run("create table leaked as select ssn from users", principal = "writer@example.com")
        assertEquals(EnfAction.DENY, r.decision)
        assertTrue(r.denyReason!!.contains("cannot be masked") && r.denyReason!!.contains("ssn"), "deny reason: ${r.denyReason}")
    }

    @Test
    fun `CTAS over non-sensitive columns is allowed with a sql ddl grant`() {
        // Positive control: composition of the two gates + the write-payload rule is not always-deny.
        val r = fx.run("create table ddl_allow_probe as select id, region from users", principal = "writer@example.com")
        assertEquals(EnfAction.ALLOW, r.decision, "reason=${r.denyReason}")
    }

    @Test
    fun `a no-FROM SELECT INTO cannot bypass the sql ddl gate via readonly-meta passthrough`() {
        // Regression (integration seam): `SELECT .. INTO` with no FROM was passthrough-classified
        // READONLY_META and ALLOW'd ahead of the gates, so an analyst (connect + read, NO ddl) could create
        // a table. It writes to a target the proxy cannot mask, so its kind is select_into (stmt.cat.ddl):
        // the connect gate passes, the kind gate must DENY — and it must never reach the target DB.
        val r = fx.run("select 1 into stmt_gate_bypass")
        assertEquals(EnfAction.DENY, r.decision, "SELECT INTO must be gated, not passthrough-allowed; reason=${r.denyReason}")
        assertEquals("statement kind 'select_into' is not permitted", r.denyReason, "deny reason: ${r.denyReason}")
    }

    @Test
    fun `a no-FROM SELECT reading a table via UNION TABLE cannot exfiltrate cleartext ssn`() {
        // Red-team regression (integration seam): `SELECT … UNION TABLE users` reads users.ssn with NO
        // FROM word — it was readonly-meta passthrough-ALLOW'd ahead of the gates, streaming cleartext
        // ssn. Must be denied at admission (fail-closed), before role resolution, with no rows.
        val r = fx.run("select 0,'x','x','x' union table users")
        assertEquals(EnfAction.DENY, r.decision, "UNION TABLE read must be denied; reason=${r.denyReason}")
        assertTrue(r.rows.isEmpty(), "a DENY must not return rows")
        assertTrue(fx.cleartextSsn.none { c -> r.rows.any { row -> c in row } }, "no cleartext ssn may leak")
    }

    @Test
    fun `an upsert INSERT is denied without sql update, even though sql insert is granted`() {
        // Security regression: inserter holds write.insert but deliberately NOT write.update. A plain
        // insert works for them; an upsert (ON CONFLICT DO UPDATE) can modify an EXISTING row, so its kind
        // (insert_on_dup) sits under write.update, not write.insert — write.insert alone must not license it.
        try {
            val plain = fx.run("insert into users (id, email, ssn, region) values (9, 'z@x', 'z', 'US')", principal = "inserter@example.com")
            assertEquals(EnfAction.ALLOW, plain.decision, "a plain insert (no upsert clause) must be allowed; reason=${plain.denyReason}")

            val upsert = fx.run(
                "insert into users (id, email, ssn, region) values (1, 'z@x', 'z', 'US') " +
                    "on conflict (id) do update set region = excluded.region",
                principal = "inserter@example.com",
            )
            assertEquals(EnfAction.DENY, upsert.decision, "an upsert must be denied without write.update; reason=${upsert.denyReason}")
            assertEquals("statement kind 'insert_on_dup' is not permitted", upsert.denyReason, "deny reason: ${upsert.denyReason}")
        } finally {
            // The plain insert above (id=9) is a real, ALLOW'd write against the shared target DB — clean
            // it up so sibling tests' row-count assertions (e.g. `non-sensitive query is allowed`, which
            // expects exactly the 2 seeded users) stay valid regardless of JUnit's test execution order.
            // Raw target execution — no enforcement gate to satisfy here, this is test teardown, not a
            // principal's query (the control-plane does not dial the target; the test owns this connection).
            fx.execOnTarget("delete from users where id = 9")
        }
    }

    @Test
    fun `an update-only principal can insert via an upsert (accepted single-category tradeoff)`() {
        // The documented consequence of one-kind-one-category: insert_on_dup is a member of write.update, so an
        // update-only principal (updater@example.com holds write.update, NOT write.insert) can run an upsert
        // that INSERTS a new row on a non-conflicting key. Cedar action-group membership is OR, not AND, so a
        // single category cannot require insert-AND-update; the forward hole (insert-only cannot update) is
        // closed, this reverse one is accepted. Kept as an explicit, tested contract so it cannot regress
        // silently — closing it needs a dedicated composite category, not a code change.
        try {
            val r = fx.run(
                "insert into users (id, email, ssn, region) values (8, 'u@x', 'u', 'US') " +
                    "on conflict (id) do update set region = excluded.region",
                principal = "updater@example.com",
            )
            assertEquals(EnfAction.ALLOW, r.decision, "an update-only upsert is allowed by design; reason=${r.denyReason}")
        } finally {
            fx.execOnTarget("delete from users where id = 8")
        }
    }

    @Test
    fun `UPDATE and DELETE without their sql grants are denied with a clean reason`() {
        // analyst holds only stmt.cat.read (+ result.read.*) — proves the update / delete kinds are gated,
        // not just insert / ddl (the kinds the other gate tests exercise). Neither kind is a member of
        // analyst's read category, so each denies at the kind gate.
        val upd = fx.run("update users set region = 'US' where id = 1")
        assertEquals(EnfAction.DENY, upd.decision)
        assertTrue(upd.denyReason!!.contains("statement kind 'update' is not permitted"), "deny reason: ${upd.denyReason}")

        val del = fx.run("delete from users where id = 1")
        assertEquals(EnfAction.DENY, del.decision)
        assertTrue(del.denyReason!!.contains("statement kind 'delete' is not permitted"), "deny reason: ${del.denyReason}")
    }

    @Test
    fun `a provably-total transform of a masked column redacts in full and the rest of the row returns`() {
        // The headline behavior end-to-end against a real target DB: upper(ssn) is a provably-total transform
        // → the derived cell is blanked to NULL, but the statement is ALLOWed (MASK) and the non-sensitive
        // columns still return — unlike a DENY. Exercises the harness NULL-redaction path for a derived cell.
        val r = fx.run("select id, upper(ssn) from users")
        assertEquals(EnfAction.MASK, r.decision, "upper(ssn) is a total transform → redact, not deny; reason=${r.denyReason}")
        assertTrue(r.rows.isNotEmpty(), "a redact-and-return must return rows (a DENY would not)")
        r.rows.forEach { row ->
            assertEquals(null, row[1], "the derived upper(ssn) cell must be NULL-redacted: $row")
            assertTrue(row[0] != null, "the non-sensitive id column is returned intact: $row")
        }
        assertTrue(
            fx.cleartextSsn.none { c -> r.rows.any { row -> row.any { it != null && c in it } } },
            "no cleartext ssn may leak through the redacted derived column",
        )
    }
}

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EnforcementMysqlDbTest {
    private lateinit var fx: EnforcementFixture

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.mysql()
    }

    @Test
    fun `masked query returns masked ssn, never cleartext`() {
        val r = fx.run("select id, ssn from users order by id")
        assertEquals(EnfAction.MASK, r.decision)
        val ssn = r.rows.map { it[1] }
        assertTrue(fx.cleartextSsn.none { it in ssn }, "cleartext ssn leaked: $ssn")
        assertTrue(ssn.any { it != null && it.endsWith("4320") }, "expected LAST_N masking, got $ssn")
    }

    @Test
    fun `scalar subquery leak is denied and returns no rows`() {
        val r = fx.run("select u.id, (select ssn from users where id = 1) as x from users u")
        assertEquals(EnfAction.DENY, r.decision, "scalar-subquery ssn leak must be denied")
        assertTrue(r.rows.isEmpty(), "a DENY must not return rows")
    }

    @Test
    fun `IN subquery oracle is denied`() {
        val r = fx.run("select id from users where region in (select ssn from users)")
        assertEquals(EnfAction.DENY, r.decision, "IN (SELECT ssn ...) oracle must be denied")
        assertTrue(r.rows.isEmpty(), "a DENY must not return rows")
    }

    @Test
    fun `error-based extraction via extractvalue over a masked column is denied end-to-end`() {
        // A MySQL error-based exfiltration technique: extractvalue() puts a stored value into a 1105 XPATH error
        // message. ssn (masked pii) is read in a NON-OUTPUT position — a function-argument subquery, and the
        // ORDER BY oracle predicate — so admission must DENY before the statement reaches the target DB to
        // produce that error. This is the primary defense, ahead of the proxy's DIAG error-message strip
        // (which is the backstop if enforcement ever had a gap).
        val viaArg = fx.run("select extractvalue(1, concat(0x7e, (select ssn from users limit 1)))")
        assertEquals(EnfAction.DENY, viaArg.decision, "extractvalue over a masked column must be denied; reason=${viaArg.denyReason}")
        assertTrue(viaArg.rows.isEmpty(), "a DENY must not return rows")
        assertTrue(fx.cleartextSsn.none { c -> viaArg.rows.any { row -> c in row } }, "no cleartext ssn may leak")

        // A coercing/transformed read of a masked column — CAST-to-UNSIGNED, `ssn+0` — is DENIED, not
        // redacted (docs/derived-masking.md): only PROVABLY-TOTAL string transforms (upper/substr/…) are
        // redactable; a cast or arithmetic can fault (or warn) on the value, so executing it would leak the
        // raw value through the error-presence / SQLSTATE / warning-count channel that output redaction can't
        // touch. So these stay denied and never reach the target DB.
        val cast = fx.run("select cast(ssn as unsigned) from users")
        assertEquals(EnfAction.DENY, cast.decision, "cast(ssn) is a value-dependent-fault-capable transform → denied; reason=${cast.denyReason}")
        assertTrue(cast.rows.isEmpty(), "a DENY must not return rows")
        val arith = fx.run("select ssn + 0 from users")
        assertEquals(EnfAction.DENY, arith.decision, "ssn+0 (implicit cast) → denied; reason=${arith.denyReason}")

        // The exact shape to guard: extract a benign column while using the masked one as an
        // ORDER BY oracle to pin a chosen row.
        val viaOrderBy = fx.run("select extractvalue(1, concat(0x7e, (select id from users order by (ssn='987-65-4320') desc limit 1)))")
        assertEquals(EnfAction.DENY, viaOrderBy.decision, "a masked column in an ORDER BY predicate must be denied; reason=${viaOrderBy.denyReason}")
        assertTrue(viaOrderBy.rows.isEmpty(), "a DENY must not return rows")
    }

    @Test
    fun `SET user-variable from a subquery is denied (session-state exfiltration)`() {
        // SET @x = (SELECT ssn ...) would stash cleartext in session state for a later `SELECT @x`.
        val r = fx.run("set @pm_leak = (select ssn from users limit 1)")
        assertEquals(EnfAction.DENY, r.decision, "SET carrying a subquery must be denied")
    }

    @Test
    fun `a query on an ungranted table is denied end-to-end — deny-by-default, not cleartext`() {
        // `orders` has no Cedar grant; deny-by-default must return DENY with no rows (see the Postgres
        // twin for the full rationale).
        val r = fx.run("select id, amount from orders order by id")
        assertEquals(EnfAction.DENY, r.decision, "an ungranted table must be denied; reason=${r.denyReason}")
        assertTrue(r.rows.isEmpty(), "a DENY must not return rows")
    }

    // --- The two once-per-query Cedar gates (datasource.connect, then sql.<kind>) — MySQL parity ---

    @Test
    fun `an INSERT without a sql insert grant is denied with a clean reason, not a parse-failure`() {
        val r = fx.run("insert into users values (3,'c@x','x','KR')")
        assertEquals(EnfAction.DENY, r.decision)
        assertTrue(r.denyReason!!.contains("statement kind 'insert' is not permitted"), "deny reason: ${r.denyReason}")
    }

    @Test
    fun `a principal with sql select but no datasource connect is denied first`() {
        val r = fx.run("select id, region from users", principal = "reader@example.com")
        assertEquals(EnfAction.DENY, r.decision)
        assertTrue(r.denyReason!!.contains("no access to datasource"), "deny reason: ${r.denyReason}")
    }

    @Test
    fun `CTAS that reads a masked column is denied even with a sql ddl grant`() {
        val r = fx.run("create table leaked as select ssn from users", principal = "writer@example.com")
        assertEquals(EnfAction.DENY, r.decision)
        assertTrue(r.denyReason!!.contains("cannot be masked") && r.denyReason!!.contains("ssn"), "deny reason: ${r.denyReason}")
    }

    @Test
    fun `a no-FROM SELECT INTO OUTFILE cannot bypass the sql ddl gate (MySQL file-write)`() {
        // MySQL parity for the passthrough-bypass regression: `SELECT .. INTO OUTFILE` writes a server
        // file with no FROM, and was READONLY_META-classified (ALLOW) ahead of the gates. Its kind is
        // select_into_outfile (stmt.cat.admin.file, a server-side FILE write), so analyst — read + metadata
        // + session, no admin — is DENIED at the kind gate before it can ever reach the target DB. A ddl grant
        // alone would not authorize it either: file export is admin.file, not plain ddl.
        val r = fx.run("select 1 into outfile '/tmp/pm_stmt_gate_bypass'")
        assertEquals(EnfAction.DENY, r.decision, "SELECT INTO OUTFILE must be gated; reason=${r.denyReason}")
        assertTrue(r.denyReason!!.contains("statement kind 'select_into_outfile' is not permitted"), "deny reason: ${r.denyReason}")
    }

    @Test
    fun `a no-FROM SELECT reading a table via UNION TABLE cannot exfiltrate cleartext ssn`() {
        // MySQL parity for the UNION TABLE red-team regression (a live cleartext leak):
        // `SELECT … UNION TABLE users` reads users.ssn with no FROM word and must be denied at admission,
        // never reaching the target DB.
        val r = fx.run("select 0,'x','x','x' union table users")
        assertEquals(EnfAction.DENY, r.decision, "UNION TABLE read must be denied; reason=${r.denyReason}")
        assertTrue(r.rows.isEmpty(), "a DENY must not return rows")
        assertTrue(fx.cleartextSsn.none { c -> r.rows.any { row -> c in row } }, "no cleartext ssn may leak")
    }

    @Test
    fun `SELECT INTO after a parenthesized branch cannot bypass the sql ddl gate`() {
        // Regression for the leading-wrapper INTO-depth fix (the exact MySQL case): `(SELECT 1)
        // UNION SELECT 1 INTO @a` mutates @a (a write) but was READONLY_META-classified and passthrough-
        // ALLOW'd ahead of the gates — the leading paren branch hid the INTO. The analyzer finds the INTO
        // recursively and classifies it select_into (stmt.cat.ddl); analyst (connect + read, NO ddl) must
        // be denied at the kind gate, before it can ever reach the target DB.
        val r = fx.run("(select 1) union select 1 into @pm_p3_branch")
        assertEquals(EnfAction.DENY, r.decision, "branch SELECT INTO must be gated; reason=${r.denyReason}")
        assertEquals("statement kind 'select_into' is not permitted", r.denyReason, "deny reason: ${r.denyReason}")
    }
}
