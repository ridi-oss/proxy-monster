package com.ridi.oss.proxymonster.classification

/**
 * A version-INDEPENDENT floor of dangerous-builtin function classifications (docs/facts-emission.md).
 * Every per-version [SystemManifest] governs only the engine majors it is certified for; a datasource
 * whose `engine_version` is absent or an uncertified major resolves to NO manifest, so
 * [SystemClassifier.classifyBareFunction] can classify nothing there — the cross-engine-stable IO/exec
 * builtins would go unclassified → un-forbidden.
 *
 * The primary no-manifest mechanism is the version-independent UNION FLOOR in
 * [com.ridi.oss.proxymonster.controlplane.SystemClassificationService.tagForFunction] — the union of
 * `classifyBareFunction` across every shipped manifest of the engine ([SystemClassificationStore.classifiersForEngine]),
 * which covers the FULL manifest dangerous set (families incl. `table_to_xml*`/pageinspect/`lo_*`) on a
 * no-manifest datasource, at parity with certified. This baseline is a belt-and-suspenders floor: it
 * still classifies its curated set even for an engine with ZERO shipped manifests.
 *
 * It classifies the small, curated set of builtins whose danger does NOT vary by engine version —
 * remote-SQL/exec (`dblink*`), server-side file & large-object IO (`pg_read_file`, `pg_ls_dir`,
 * `pg_stat_file`, `lo_import`/`lo_export`, `load_file`), and arbitrary-SQL-to-XML (`query_to_xml*`,
 * `xpath_table`). Each carries the SAME tag the shipped manifests assign it, so the baseline can never
 * DISAGREE with a governing manifest — [SystemClassificationService] unions the two strongest-first, so
 * the baseline is a FLOOR that only ever RAISES (or matches) the manifest classification, never lowers it.
 *
 * It is deliberately NOT a general denylist: a bare name absent here is untouched (an ordinary safe
 * builtin or a user UDF stays UNCLASSIFIED → not marshalled → not forbidden). Matching is a
 * case-insensitive fold, like the classifier, and by BARE name only — sqlglot drops a function's schema
 * qualifier at parse time, and over-classifying a same-named user function is safe (fail-closed).
 *
 * See [SystemClassifier.classifyBareFunction] for the per-version path this backstops.
 */
object BaselineDangerousFunctions {
    // Bare (lower-case) function name -> the SAME system tag the shipped manifests assign it. Grouped by
    // capability; the tag matches system-classification/postgres/* and mysql/* exactly (verified by
    // SystemClassificationTest's dangerousFuncs-superset test).
    private val byName: Map<String, SystemTag> = mapOf(
        // PostgreSQL dblink — runs SQL on a remote server (exec) / fetches its results (leak).
        "set_config" to SystemTag.CRITICAL,
        "dblink" to SystemTag.DATA_LEAK,
        "dblink_exec" to SystemTag.CRITICAL,
        "dblink_open" to SystemTag.DATA_LEAK,
        "dblink_fetch" to SystemTag.DATA_LEAK,
        "dblink_send_query" to SystemTag.DATA_LEAK,
        // PostgreSQL server-side file & large-object IO.
        "pg_read_file" to SystemTag.DATA_LEAK,
        "pg_read_binary_file" to SystemTag.DATA_LEAK,
        "pg_ls_dir" to SystemTag.DATA_LEAK,
        "pg_stat_file" to SystemTag.DATA_LEAK,
        "lo_import" to SystemTag.DATA_LEAK,
        "lo_export" to SystemTag.CRITICAL,
        // PostgreSQL arbitrary-SQL-string readers.
        "query_to_xml" to SystemTag.DATA_LEAK,
        "query_to_xml_and_xmlschema" to SystemTag.DATA_LEAK,
        "xpath_table" to SystemTag.DATA_LEAK,
        // MySQL server-side file read.
        "load_file" to SystemTag.DATA_LEAK,
    )

    /** The floor system tag for a bare function [name], or null when it is not a cross-engine dangerous builtin. */
    fun classify(name: String): SystemTag? = byName[name.lowercase()]
}
