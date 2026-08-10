package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.Engine
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit coverage for the version-parsing side of system-classification (no DB): `parseServerVersion` must
 * extract the base engine release + the Aurora marker from real `version()` strings, INCLUDING Aurora's
 * `mysql_aurora` infix form (`8.0.mysql_aurora.3.04.0` must resolve to the MySQL 8.0
 * manifest, not the Aurora engine version 3.04.0). The service loads the real bundled manifests from the
 * classpath, so this also proves parse→resolve→classify end-to-end.
 */
class SystemClassificationServiceTest {
    private val svc = SystemClassificationService()

    @Test
    fun `parseServerVersion handles vanilla and Aurora formats`() {
        fun parse(e: Engine, v: String) = e.parseServerVersion(v)
        // PostgreSQL
        assertEquals("17.4" to false, parse(Engine.POSTGRES, "PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc"))
        assertEquals("16.13" to true, parse(Engine.POSTGRES, "PostgreSQL 16.13 on aarch64 (aurora 16.13...)"))
        // MySQL vanilla
        assertEquals("8.0.44" to false, parse(Engine.MYSQL, "8.0.44"))
        assertEquals("8.0.44" to false, parse(Engine.MYSQL, "8.0.44-log"))
        // MySQL Aurora — the mysql_aurora infix must NOT let the Aurora engine version leak in
        assertEquals("8.0" to true, parse(Engine.MYSQL, "8.0.mysql_aurora.3.04.0 (aurora 3.04.0)"))
        assertEquals("8.4" to true, parse(Engine.MYSQL, "8.4.mysql_aurora.4.0.0"))
        assertEquals("5.7" to true, parse(Engine.MYSQL, "5.7.mysql_aurora.2.11.4"))
        // Garbage / empty → null (deny-by-default, fail-closed)
        assertNull(parse(Engine.MYSQL, "").first)
        assertNull(parse(Engine.POSTGRES, "   ").first)
    }

    @Test
    fun `Aurora MySQL 3_x version() resolves to the MySQL 8_0 manifest and classifies`() {
        val auroraMysql = "8.0.mysql_aurora.3.04.0 (aurora 3.04.0)"
        // Before the fix this returned null (regex grabbed 3.04.0 → no manifest) → classification inert.
        assertEquals("system:critical", svc.tagForTable(Engine.MYSQL, auroraMysql, "def", "mysql", "user"))
        assertEquals("system:data-leak", svc.tagForTable(Engine.MYSQL, auroraMysql, "def", "information_schema", "COLUMN_STATISTICS"))
        assertEquals("system:catalog", svc.tagForTable(Engine.MYSQL, auroraMysql, "def", "information_schema", "TABLES"))
    }

    @Test
    fun `Aurora PostgreSQL resolves to the PG major manifest`() {
        val auroraPg = "PostgreSQL 17.4 on x86_64 (aurora 17.4...)"
        assertEquals("system:critical", svc.tagForTable(Engine.POSTGRES, auroraPg, "acme", "pg_catalog", "pg_authid"))
        assertEquals("system:catalog", svc.tagForTable(Engine.POSTGRES, auroraPg, "acme", "pg_catalog", "pg_class"))
    }

    @Test
    fun `a fixed system table without a governing manifest is closed`() {
        // No governing manifest (null version, fallback off): a fixed system schema must not fall through
        // untagged (a broad Datasource grant would read it). An explicitly-dangerous manifest tag is kept;
        // everything else — the bare catalog default, an unrecognized table, or a catalog-mismatched one — is
        // treated as system:critical so the unconditional forbid closes it. Fail-closed: unprovable ⇒ critical.
        assertEquals("system:critical", svc.tagForTable(Engine.POSTGRES, null, "acme", "pg_catalog", "pg_authid"))
        assertEquals("system:critical", svc.tagForTable(Engine.MYSQL, null, "def", "mysql", "user"))
        // An explicit data-leak stays data-leak (kept so its own forbid + the system:development relaxation apply).
        assertEquals("system:data-leak", svc.tagForTable(Engine.MYSQL, null, "def", "information_schema", "COLUMN_STATISTICS"))
        // A catalog-default table (no explicit dangerous rule) is closed as critical, not opened as catalog.
        assertEquals("system:critical", svc.tagForTable(Engine.POSTGRES, null, "acme", "pg_catalog", "pg_class"))
        // An unrecognized table in a fixed system schema (not in any shipped manifest) is likewise closed.
        assertEquals("system:critical", svc.tagForTable(Engine.MYSQL, null, "def", "performance_schema", "user_variables_by_thread"))
        // A catalog-mismatched MySQL system table (schema matches, catalog is not "def") must not downgrade to
        // catalog — it is still closed.
        assertEquals("system:critical", svc.tagForTable(Engine.MYSQL, null, "not-def", "mysql", "user"))
        // An ordinary user table is not a system resource, so it is never floored.
        assertNull(svc.tagForTable(Engine.POSTGRES, null, "acme", "public", "orders"))
        // Ephemeral pg_temp_/pg_toast are not fixed system schemas — their connection-local path owns them.
        assertNull(svc.tagForTable(Engine.POSTGRES, null, "acme", "pg_temp_3", "scratch"))
    }

    // tagForFunction resolves a BARE function name (the only form the analyzer can emit, since
    // sqlglot drops the schema qualifier) against the datasource's system/logical schemas + cross-schema
    // rules. A dangerous builtin → its system tag; a safe builtin / user function → null (not marshalled).
    @Test
    fun `tagForFunction classifies dangerous PostgreSQL builtins from the bare name`() {
        val pg = "PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc"
        fun tag(n: String) = svc.tagForFunction(Engine.POSTGRES, pg, n)
        // pg_catalog family (pg_read_) + exacts, resolved despite the missing qualifier.
        assertEquals("system:data-leak", tag("pg_read_file"))
        assertEquals("system:data-leak", tag("pg_read_binary_file"))
        assertEquals("system:data-leak", tag("pg_stat_file"))
        // pg_catalog critical exacts NOT in the dangerousFuncs backstop — the net-new policy coverage.
        assertEquals("system:critical", tag("pg_terminate_backend"))
        assertEquals("system:critical", tag("pg_cancel_backend"))
        assertEquals("system:critical", tag("set_config"))
        assertEquals("system:critical", tag("current_setting"))
        // Cross-schema (`*`) extension functions: exacts (dblink family) + pageinspect families.
        assertEquals("system:data-leak", tag("dblink"))
        assertEquals("system:data-leak", tag("dblink_get_result"))
        assertEquals("system:data-leak", tag("get_raw_page"))
        assertEquals("system:data-leak", tag("heap_page_items")) // heap_page_ family
        // Case-insensitive (PG folds unquoted identifiers).
        assertEquals("system:critical", tag("PG_TERMINATE_BACKEND"))
        // Safe builtins / unclassified user functions → null (never marshalled, never denied).
        assertNull(tag("now"))
        assertNull(tag("count"))
        assertNull(tag("lower"))
        assertNull(tag("my_udf"))
        // No manifest / no version → the version-INDEPENDENT union floor (every shipped manifest of the
        // engine, strongest tag) classifies the FULL manifest dangerous set, not just the thin baseline. So a
        // manifest-only critical like set_config — the data-leak class (a whole-table/page/
        // large-object reader the flat baseline missed) — is forbidden on a no-manifest datasource too,
        // at parity with certified.
        assertEquals("system:data-leak", svc.tagForFunction(Engine.POSTGRES, null, "pg_read_file"))
        assertEquals("system:critical", svc.tagForFunction(Engine.POSTGRES, null, "set_config"))
        assertEquals("system:data-leak", svc.tagForFunction(Engine.POSTGRES, null, "table_to_xml")) // table_to_xml* family, not in the baseline
        assertEquals("system:data-leak", svc.tagForFunction(Engine.POSTGRES, null, "get_raw_page")) // pageinspect exact, not in the baseline
        assertEquals("system:critical", svc.tagForFunction(Engine.POSTGRES, null, "pg_terminate_backend"))
        // A safe builtin / UDF still stays null on a no-manifest datasource — the union floor only raises the
        // manifests' DANGEROUS classifications, it does not deny-by-default every function.
        assertNull(svc.tagForFunction(Engine.POSTGRES, null, "now"))
        assertNull(svc.tagForFunction(Engine.POSTGRES, null, "my_udf"))
    }

    // The version-independent baseline is a FLOOR that classifies the cross-engine-stable dangerous
    // IO/exec builtins on EVERY datasource state — governed or
    // not — with the SAME tag the manifests assign, so removing the hardcode leaves none of them ungated.
    @Test
    fun `the baseline floor classifies every former dangerousFuncs name with or without a manifest`() {
        val pg = "PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc"
        val my = "8.0.44"
        // name -> its manifest/baseline tag (data-leak unless noted critical).
        val dataLeak = listOf(
            "dblink", "dblink_open", "dblink_fetch", "dblink_send_query",
            "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file", "lo_import",
            "query_to_xml", "query_to_xml_and_xmlschema", "xpath_table",
        )
        val critical = listOf("dblink_exec", "lo_export")
        for (fn in dataLeak) {
            // Governed PG: manifest ∪ baseline (floor) = the shared tag.
            assertEquals("system:data-leak", svc.tagForFunction(Engine.POSTGRES, pg, fn), "$fn governed")
            // No manifest (null version): the baseline alone still classifies it.
            assertEquals("system:data-leak", svc.tagForFunction(Engine.POSTGRES, null, fn), "$fn no-manifest baseline")
        }
        for (fn in critical) {
            assertEquals("system:critical", svc.tagForFunction(Engine.POSTGRES, pg, fn), "$fn governed")
            assertEquals("system:critical", svc.tagForFunction(Engine.POSTGRES, null, fn), "$fn no-manifest baseline")
        }
        // MySQL load_file — governed and un-governed both classify via the baseline.
        assertEquals("system:data-leak", svc.tagForFunction(Engine.MYSQL, my, "load_file"), "load_file governed")
        assertEquals("system:data-leak", svc.tagForFunction(Engine.MYSQL, null, "load_file"), "load_file no-manifest baseline")
        // The floor never classifies a safe function, on any datasource state.
        for (safe in listOf("now", "count", "lower", "concat", "my_udf")) {
            assertNull(svc.tagForFunction(Engine.POSTGRES, pg, safe), "$safe governed stays safe")
            assertNull(svc.tagForFunction(Engine.POSTGRES, null, safe), "$safe no-manifest stays safe")
        }
    }

    @Test
    fun `tagForFunction classifies dangerous MySQL builtins including Aurora rds_ from the bare name`() {
        val my = "8.0.mysql_aurora.3.04.0 (aurora 3.04.0)"
        fun tag(n: String) = svc.tagForFunction(Engine.MYSQL, my, n)
        // __builtin__ logical schema: load_file exact + keyring_ family.
        assertEquals("system:data-leak", tag("load_file"))
        assertEquals("system:critical", tag("keyring_key_generate"))
        // mysql.rds_ family: the analyzer drops the `mysql.` qualifier, so the bare `rds_kill` must still
        // resolve against the mysql system schema (the resolver iterates every system schema).
        assertEquals("system:critical", tag("rds_kill"))
        assertEquals("system:critical", tag("rds_set_configuration"))
        assertNull(tag("concat"))
        assertNull(tag("my_udf"))
    }
}
