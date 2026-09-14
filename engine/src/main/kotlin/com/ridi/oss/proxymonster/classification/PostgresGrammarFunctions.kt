package com.ridi.oss.proxymonster.classification

/**
 * PostgreSQL functions the grammar reserves as keywords. They have no pg_proc row, so introspection never
 * sees them, and no user function can shadow them: `CREATE FUNCTION coalesce(...)` is a syntax error.
 */
object PostgresGrammarFunctions {
    val names: List<String> = listOf(
        "coalesce", "greatest", "least", "nullif", "grouping",
        "xmlconcat", "xmlelement", "xmlforest", "xmlparse", "xmlpi", "xmlroot", "xmltable",
    )
}
