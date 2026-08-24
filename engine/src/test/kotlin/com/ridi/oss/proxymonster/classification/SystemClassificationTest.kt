package com.ridi.oss.proxymonster.classification

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit proof for the system-classification mechanism (docs/system-classification.md): the
 * strongest-tag-first classifier, boot validation that fail-closes on a malformed manifest, and the
 * version resolver with the opt-in unsupported-version fallback. Uses synthetic manifests — the real
 * curated Aurora manifests are proven separately.
 */
class SystemClassificationTest {

    // ---- classifier ----------------------------------------------------------------------------------

    @Test
    fun `a relation in a system schema defaults to catalog, exact and family raise it to the strongest`() {
        val c = SystemClassifier(
            SystemManifest(
                engine = "postgres", series = "17", manifestVersion = 1, curatedThrough = "17.6",
                systemSchemas = listOf(SystemSchema("*", "pg_catalog")),
                relations = listOf(ObjectRule("pg_catalog", "pg_authid", "system:critical")),
                relationFamilies = listOf(FamilyRule("pg_catalog", "pg_stat_", "system:activity")),
            ),
        )
        assertEquals(SystemTag.CATALOG, c.classifyRelation("acme", "pg_catalog", "pg_class"), "an unlisted system relation is catalog (open)")
        assertEquals(SystemTag.CRITICAL, c.classifyRelation("acme", "pg_catalog", "pg_authid"), "exact critical wins")
        assertEquals(SystemTag.ACTIVITY, c.classifyRelation("acme", "pg_catalog", "pg_stat_activity"), "family activity applies")
        assertNull(c.classifyRelation("acme", "public", "users"), "a user schema is not a system schema → no system tag")
    }

    @Test
    fun `case-insensitive within a system schema, catalog wildcard vs pinned`() {
        val c = SystemClassifier(
            SystemManifest(
                engine = "mysql", series = "8.0", manifestVersion = 1, curatedThrough = "8.0.44",
                systemSchemas = listOf(SystemSchema("def", "mysql")),
                relations = listOf(ObjectRule("mysql", "user", "system:critical")),
            ),
        )
        assertEquals(SystemTag.CRITICAL, c.classifyRelation("def", "MySQL", "USER"), "match folds case")
        assertNull(c.classifyRelation("otherdb", "mysql", "user"), "a pinned catalog must match")
    }

    @Test
    fun `a cross-schema function rule applies in any schema, catalog default only in a system schema`() {
        val c = SystemClassifier(
            SystemManifest(
                engine = "postgres", series = "17", manifestVersion = 1, curatedThrough = "17.6",
                systemSchemas = listOf(SystemSchema("*", "pg_catalog")),
                functions = listOf(ObjectRule("*", "dblink", "system:data-leak")),
                functionFamilies = listOf(FamilyRule("pg_catalog", "pg_read_", "system:data-leak")),
            ),
        )
        assertEquals(SystemTag.DATA_LEAK, c.classifyFunction("acme", "public", "dblink"), "cross-schema dangerous function classified anywhere")
        assertEquals(SystemTag.DATA_LEAK, c.classifyFunction("acme", "pg_catalog", "pg_read_file"), "family in a system schema")
        assertEquals(SystemTag.CATALOG, c.classifyFunction("acme", "pg_catalog", "lower"), "an ordinary system-schema builtin is catalog")
        assertNull(c.classifyFunction("acme", "public", "my_udf"), "a user function is not shipped-classified")
    }

    @Test
    fun `an exact column override replaces the relation tag only for that column`() {
        val c = SystemClassifier(
            SystemManifest(
                engine = "postgres", series = "17", manifestVersion = 1, curatedThrough = "17.6",
                systemSchemas = listOf(SystemSchema("*", "pg_catalog")),
                relations = listOf(ObjectRule("pg_catalog", "pg_locks", "system:activity")),
                columnOverrides = listOf(ColumnRule("pg_catalog", "pg_locks", "transactionid", "system:catalog")),
            ),
        )
        assertEquals(SystemTag.ACTIVITY, c.classifyRelation("acme", "pg_catalog", "pg_locks"))
        assertEquals(SystemTag.CATALOG, c.classifyColumn("acme", "PG_CATALOG", "PG_LOCKS", "TRANSACTIONID"))
        assertEquals(SystemTag.ACTIVITY, c.classifyColumn("acme", "pg_catalog", "pg_locks", "pid"))
        assertNull(c.classifyColumn("acme", "public", "pg_locks", "transactionid"))
    }

    @Test
    fun `a column override outside a system schema aborts`() {
        assertFailsWith<SystemManifestException> {
            SystemClassifier(
                SystemManifest(
                    engine = "postgres", series = "17", manifestVersion = 1, curatedThrough = "17.6",
                    systemSchemas = listOf(SystemSchema("*", "pg_catalog")),
                    columnOverrides = listOf(ColumnRule("public", "users", "id", "system:catalog")),
                ),
            )
        }
    }

    @Test
    fun `a redacted catalog column is exact and stays inside an open system relation`() {
        val c = SystemClassifier(
            SystemManifest(
                engine = "postgres", series = "17", manifestVersion = 1, curatedThrough = "17.6",
                systemSchemas = listOf(SystemSchema("*", "pg_catalog")),
                redactedColumns = listOf(RedactedColumnRule("pg_catalog", "pg_foreign_server", "srvoptions")),
            ),
        )
        assertTrue(c.redactsColumn("acme", "PG_CATALOG", "PG_FOREIGN_SERVER", "SRVOPTIONS"))
        assertFalse(c.redactsColumn("acme", "pg_catalog", "pg_foreign_server", "srvname"))
        assertFalse(c.redactsColumn("acme", "public", "pg_foreign_server", "srvoptions"))
        assertEquals(SystemTag.CATALOG, c.classifyRelation("acme", "pg_catalog", "pg_foreign_server"))
    }

    @Test
    fun `a redacted column outside an open system relation aborts`() {
        assertFailsWith<SystemManifestException> {
            SystemClassifier(
                SystemManifest(
                    engine = "postgres", series = "17", manifestVersion = 1, curatedThrough = "17.6",
                    systemSchemas = listOf(SystemSchema("*", "pg_catalog")),
                    relations = listOf(ObjectRule("pg_catalog", "pg_foreign_server", "system:critical")),
                    redactedColumns = listOf(RedactedColumnRule("pg_catalog", "pg_foreign_server", "srvoptions")),
                ),
            )
        }
        assertFailsWith<SystemManifestException> {
            SystemClassifier(
                SystemManifest(
                    engine = "postgres", series = "17", manifestVersion = 1, curatedThrough = "17.6",
                    systemSchemas = listOf(SystemSchema("*", "pg_catalog")),
                    redactedColumns = listOf(RedactedColumnRule("public", "pg_foreign_server", "srvoptions")),
                ),
            )
        }
    }

    @Test
    fun `a utility command maps to its resource tag`() {
        val c = SystemClassifier(
            SystemManifest(
                engine = "mysql", series = "8.0", manifestVersion = 1, curatedThrough = "8.0.44",
                commands = listOf(CommandRule("SHOW_PROCESSLIST", "information_schema/PROCESSLIST", "system:activity")),
            ),
        )
        assertEquals(SystemTag.ACTIVITY, c.classifyCommand("SHOW_PROCESSLIST"))
        assertNull(c.classifyCommand("SHOW_TABLES"))
    }

    // ---- boot validation (fail-closed) --------------------------------------------------------------

    @Test
    fun `a non-system tag aborts`() {
        assertFailsWith<SystemManifestException> {
            SystemClassifier(
                SystemManifest(
                    engine = "postgres", series = "17", manifestVersion = 1, curatedThrough = "17.6",
                    relations = listOf(ObjectRule("pg_catalog", "pg_authid", "pii")),
                ),
            )
        }
    }

    @Test
    fun `a duplicate exact identity with conflicting tags aborts`() {
        assertFailsWith<SystemManifestException> {
            SystemClassifier(
                SystemManifest(
                    engine = "postgres", series = "17", manifestVersion = 1, curatedThrough = "17.6",
                    relations = listOf(
                        ObjectRule("pg_catalog", "pg_authid", "system:critical"),
                        ObjectRule("pg_catalog", "pg_authid", "system:activity"),
                    ),
                ),
            )
        }
    }

    @Test
    fun `an exact rule that would downgrade a stronger family aborts`() {
        assertFailsWith<SystemManifestException> {
            SystemClassifier(
                SystemManifest(
                    engine = "postgres", series = "17", manifestVersion = 1, curatedThrough = "17.6",
                    systemSchemas = listOf(SystemSchema("*", "pg_catalog")),
                    relations = listOf(ObjectRule("pg_catalog", "pg_secret_thing", "system:activity")),
                    relationFamilies = listOf(FamilyRule("pg_catalog", "pg_secret_", "system:critical")),
                ),
            )
        }
    }

    @Test
    fun `overlapping families with conflicting tags abort`() {
        assertFailsWith<SystemManifestException> {
            SystemClassifier(
                SystemManifest(
                    engine = "postgres", series = "17", manifestVersion = 1, curatedThrough = "17.6",
                    relationFamilies = listOf(
                        FamilyRule("pg_catalog", "pg_stat_activity_", "system:critical"),
                        FamilyRule("pg_catalog", "pg_stat_", "system:activity"),
                    ),
                ),
            )
        }
    }

    // ---- version resolution + fallback --------------------------------------------------------------

    private fun store() = SystemClassificationStore.of(
        listOf(
            SystemManifest("postgres", "16", 1, "16.9"),
            SystemManifest("postgres", "17", 1, "17.6"),
            SystemManifest("mysql", "8.0", 1, "8.0.44"),
            SystemManifest("mysql", "8.4", 1, "8.4.7"),
        ),
    )

    @Test
    fun `an exact major and a newer minor both resolve to the series manifest, no fallback`() {
        val s = store()
        s.resolve("postgres", "17.9", allowFallback = false)!!.let {
            assertEquals("17", it.resolvedSeries); assertFalse(it.isFallback)
        }
        s.resolve("mysql", "8.0.44", allowFallback = false)!!.let {
            assertEquals("8.0", it.resolvedSeries); assertFalse(it.isFallback)
        }
    }

    @Test
    fun `an unsupported major is unavailable without fallback, and falls back to the nearest lower with it`() {
        val s = store()
        assertNull(s.resolve("postgres", "18.3", allowFallback = false), "uncertified major → no manifest (fail-closed)")
        s.resolve("postgres", "18.3", allowFallback = true)!!.let {
            assertEquals("18", it.requestedSeries)
            assertEquals("17", it.resolvedSeries) // nearest lower supported major
            assertTrue(it.isFallback)
        }
    }

    @Test
    fun `a datasource older than every supported major falls back to the lowest`() {
        val s = store()
        s.resolve("postgres", "14.22", allowFallback = true)!!.let {
            assertEquals("16", it.resolvedSeries) // lowest supported, since 14 < all
            assertTrue(it.isFallback)
        }
    }

    @Test
    fun `mysql 8_4 falls back to 8_0 nearest-lower reasoning stays within engine`() {
        val s = store()
        assertNull(s.resolve("mysql", "9.0.0", allowFallback = false))
        s.resolve("mysql", "9.0.0", allowFallback = true)!!.let {
            assertEquals("8.4", it.resolvedSeries) // nearest lower mysql family; never crosses to postgres
            assertTrue(it.isFallback)
        }
    }

    // ---- the real bundled Aurora manifests ----------------------------------------------------------

    @Test
    fun `all four bundled Aurora manifests load, validate, and index`() {
        val s = SystemClassificationStore.load() // throws on any manifest validation failure → this is the boot check
        assertEquals(
            setOf("postgres" to "16", "postgres" to "17", "mysql" to "8.0", "mysql" to "8.4"),
            s.supported(),
        )
        assertTrue(s.checksum.length == 64, "a sha-256 checksum is exposed for diagnostics")
    }

    @Test
    fun `real PostgreSQL classifications (incl Aurora) are correct`() {
        val c = SystemClassificationStore.load().classifierFor("postgres", "17")!!
        assertEquals(SystemTag.CRITICAL, c.classifyRelation("acme", "pg_catalog", "pg_authid"))
        assertEquals(SystemTag.DATA_LEAK, c.classifyRelation("acme", "pg_catalog", "pg_stats"))
        assertEquals(SystemTag.ACTIVITY, c.classifyRelation("acme", "pg_catalog", "pg_stat_activity"))
        assertEquals(SystemTag.ACTIVITY, c.classifyRelation("acme", "pg_catalog", "pg_stat_progress_vacuum"), "family")
        assertEquals(SystemTag.CATALOG, c.classifyRelation("acme", "pg_catalog", "pg_class"), "ordinary catalog stays open")
        assertEquals(SystemTag.CATALOG, c.classifyRelation("acme", "pg_catalog", "pg_foreign_server"))
        assertEquals(SystemTag.CATALOG, c.classifyRelation("acme", "pg_catalog", "pg_foreign_table"))
        assertEquals(SystemTag.ACTIVITY, c.classifyRelation("acme", "pg_catalog", "pg_locks"))
        assertEquals(SystemTag.CATALOG, c.classifyColumn("acme", "pg_catalog", "pg_locks", "transactionid"))
        assertEquals(SystemTag.ACTIVITY, c.classifyColumn("acme", "pg_catalog", "pg_locks", "pid"))
        assertTrue(c.redactsColumn("acme", "pg_catalog", "pg_foreign_server", "srvoptions"))
        assertTrue(c.redactsColumn("acme", "pg_catalog", "pg_foreign_data_wrapper", "fdwoptions"))
        assertTrue(c.redactsColumn("acme", "pg_catalog", "pg_user_mapping", "umoptions"))
        assertTrue(c.redactsColumn("acme", "pg_catalog", "pg_foreign_table", "ftoptions"))
        assertFalse(c.redactsColumn("acme", "pg_catalog", "pg_foreign_server", "srvname"))
        assertFalse(c.redactsColumn("acme", "pg_catalog", "pg_foreign_table", "ftrelid"))
        assertEquals(SystemTag.CRITICAL, c.classifyFunction("acme", "pg_catalog", "set_config"))
        assertEquals(SystemTag.DATA_LEAK, c.classifyFunction("acme", "pg_catalog", "pg_read_file"), "pg_read_ family")
        assertEquals(SystemTag.DATA_LEAK, c.classifyFunction("acme", "public", "dblink"), "cross-schema extension fn")
        assertEquals(SystemTag.CRITICAL, c.classifyFunction("acme", "public", "dblink_exec"), "cross-schema mutation")
        // Aurora proprietary
        assertEquals(SystemTag.ACTIVITY, c.classifyRelation("acme", "pg_catalog", "aurora_replica_status"))
        assertEquals(SystemTag.ACTIVITY, c.classifyRelation("acme", "pg_catalog", "aurora_stat_io"), "aurora_stat_ family")
    }

    @Test
    fun `real MySQL classifications (incl Aurora rds_) are correct`() {
        val c = SystemClassificationStore.load().classifierFor("mysql", "8.0")!!
        assertEquals(SystemTag.CRITICAL, c.classifyRelation("def", "mysql", "user"))
        assertEquals(SystemTag.CRITICAL, c.classifyRelation("def", "information_schema", "USER_PRIVILEGES"))
        assertEquals(SystemTag.DATA_LEAK, c.classifyRelation("def", "information_schema", "COLUMN_STATISTICS"))
        assertEquals(SystemTag.ACTIVITY, c.classifyRelation("def", "information_schema", "PROCESSLIST"))
        assertEquals(SystemTag.ACTIVITY, c.classifyRelation("def", "performance_schema", "events_statements_current"), "family")
        assertEquals(SystemTag.CATALOG, c.classifyRelation("def", "information_schema", "TABLES"), "structure stays open")
        assertEquals(SystemTag.DATA_LEAK, c.classifyFunction("def", "__builtin__", "load_file"))
        assertEquals(SystemTag.CATALOG, c.classifyFunction("def", "__builtin__", "now"), "ordinary builtin is catalog")
        // Aurora proprietary management procedures (mysql.rds_* family → critical)
        assertEquals(SystemTag.CRITICAL, c.classifyFunction("def", "mysql", "rds_kill"))
        assertEquals(SystemTag.CRITICAL, c.classifyFunction("def", "mysql", "rds_set_configuration"))
        assertEquals(SystemTag.ACTIVITY, c.classifyCommand("SHOW_PROCESSLIST"))
    }

    @Test
    fun `the PostgreSQL manifest is a superset of the old dangerousFuncs (must hold before that map retires)`() {
        val c = SystemClassificationStore.load().classifierFor("postgres", "17")!!
        // The dangerous PostgreSQL builtins (load_file is MySQL, checked below). None may classify as catalog/none.
        for (fn in listOf("dblink", "dblink_exec", "dblink_open", "dblink_fetch", "dblink_send_query")) {
            val t = c.classifyFunction("acme", "public", fn)
            assertTrue(t != null && t != SystemTag.CATALOG, "old dangerousFunc $fn must be dangerous-classified, was $t")
        }
        for (fn in listOf("pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file", "lo_import", "lo_export", "query_to_xml", "query_to_xml_and_xmlschema", "xpath_table")) {
            val t = c.classifyFunction("acme", "pg_catalog", fn)
            assertTrue(t != null && t != SystemTag.CATALOG, "old dangerousFunc $fn must be dangerous-classified, was $t")
        }
        val mysql = SystemClassificationStore.load().classifierFor("mysql", "8.4")!!
        val loadFile = mysql.classifyFunction("def", "__builtin__", "load_file")
        assertTrue(loadFile != null && loadFile != SystemTag.CATALOG, "load_file must be dangerous-classified, was $loadFile")
    }

    @Test
    fun `gate regressions - stat-getter, pageinspect, and aurora_stat functions are dangerous, not open`() {
        val c = SystemClassificationStore.load().classifierFor("postgres", "17")!!
        // pg_stat_get_backend_activity(pid) returns another backend's query text — the datum
        // pg_stat_activity (activity) exposes; it must not classify as CATALOG/open.
        assertEquals(SystemTag.ACTIVITY, c.classifyFunction("acme", "pg_catalog", "pg_stat_get_backend_activity"))
        assertEquals(SystemTag.ACTIVITY, c.classifyFunction("acme", "pg_catalog", "pg_stat_get_activity"))
        // pageinspect page-decode functions read page bytes directly (cross-schema extension).
        assertEquals(SystemTag.DATA_LEAK, c.classifyFunction("acme", "public", "bt_page_items"))
        assertEquals(SystemTag.DATA_LEAK, c.classifyFunction("acme", "public", "heap_page_items"))
        assertEquals(SystemTag.DATA_LEAK, c.classifyFunction("acme", "public", "page_header"))
        // aurora_stat_* are functions, not relations.
        assertEquals(SystemTag.ACTIVITY, c.classifyFunction("acme", "pg_catalog", "aurora_stat_system_waits"))
        assertEquals(SystemTag.ACTIVITY, c.classifyFunction("acme", "pg_catalog", "aurora_stat_backend_waits"))
    }

    @Test
    fun `a wildcard-schema relation rule is rejected at boot`() {
        assertFailsWith<SystemManifestException> {
            SystemClassifier(
                SystemManifest(
                    engine = "postgres", series = "17", manifestVersion = 1, curatedThrough = "17.6",
                    relations = listOf(ObjectRule("*", "pg_authid", "system:critical")),
                ),
            )
        }
    }

    @Test
    fun `real version resolution + Aurora fallback`() {
        val s = SystemClassificationStore.load()
        assertEquals("17", s.resolve("postgres", "17.9", allowFallback = false)!!.resolvedSeries)
        assertEquals("8.0", s.resolve("mysql", "8.0.44", allowFallback = false)!!.resolvedSeries)
        // Aurora PG 18 (added Jun 2026) has no manifest yet → nearest-lower fallback to 17
        assertNull(s.resolve("postgres", "18.3", allowFallback = false))
        s.resolve("postgres", "18.3", allowFallback = true)!!.let {
            assertEquals("17", it.resolvedSeries); assertTrue(it.isFallback)
        }
    }
}
