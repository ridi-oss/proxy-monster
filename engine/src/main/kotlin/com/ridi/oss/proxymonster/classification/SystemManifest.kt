package com.ridi.oss.proxymonster.classification

import kotlinx.serialization.Serializable

/**
 * The shipped system classification (docs/system-classification.md). Every object in an exposed system
 * schema is one of four `system:` tags; only the dangerous overrides are enumerated — everything else
 * defaults to `system:catalog` (open browsing). These tags are a product fact, immutable and bundled per
 * engine MAJOR version; exact column overrides are bundled with those facts, while policy over them lives
 * in Cedar (`access-model.md`).
 *
 * Strength order (strongest first) drives the classifier: when several rules match one object it takes the
 * STRONGEST tag, so a weaker exact rule can never downgrade a stronger family rule. Over-classifying is
 * safe; under-classifying a credential/data surface is the leak this guards.
 */
enum class SystemTag(val id: String) {
    CRITICAL("system:critical"),
    DATA_LEAK("system:data-leak"),
    ACTIVITY("system:activity"),
    CATALOG("system:catalog"),
    ;

    companion object {
        private val byId = entries.associateBy { it.id }

        /** The tag for a manifest string, or null if it is not one of the four reserved `system:` tags. */
        fun fromId(id: String): SystemTag? = byId[id]

        /** The stronger (lower-ordinal) of two tags — the classifier's precedence combinator. */
        fun stronger(a: SystemTag, b: SystemTag): SystemTag = if (a.ordinal <= b.ordinal) a else b
    }
}

/** An exposed system schema (`catalog: "*"` = the datasource's current database, for PostgreSQL). */
@Serializable
data class SystemSchema(val catalog: String, val schema: String)

/** An exact object rule: schema + object name → tag. `schema: "*"` is allowed only for a cross-schema function. */
@Serializable
data class ObjectRule(val schema: String, val name: String, val tag: String)

/** A validated prefix family (e.g. `pg_stat_progress_*`) → tag. No general regexes: exact/prefix only. */
@Serializable
data class FamilyRule(val schema: String, val prefix: String, val tag: String)

/** An exact system column classification that replaces its relation's tag for traced column reads. */
@Serializable
data class ColumnRule(val schema: String, val table: String, val column: String, val tag: String)

/** A utility command → the resource it exposes + that resource's tag (SHOW/DESCRIBE/…). */
@Serializable
data class CommandRule(val id: String, val resource: String, val tag: String)

/**
 * One bundled manifest, deserialized from `resources/system-classification/<engine>/<series>.json`
 * (docs/system-classification.md). Declarative: schemas + exact/family relation & function rules + exact
 * column overrides + the utility-command map. `series` is the engine major (PostgreSQL `17`, MySQL
 * `8.0`/`8.4`).
 */
@Serializable
data class SystemManifest(
    val engine: String,
    val series: String,
    val manifestVersion: Int,
    val curatedThrough: String,
    val systemSchemas: List<SystemSchema> = emptyList(),
    /** Resource-only Function namespaces never introspected as real databases (MySQL `def/__builtin__`). */
    val logicalFunctionSchemas: List<SystemSchema> = emptyList(),
    val relations: List<ObjectRule> = emptyList(),
    val relationFamilies: List<FamilyRule> = emptyList(),
    val columnOverrides: List<ColumnRule> = emptyList(),
    val functions: List<ObjectRule> = emptyList(),
    val functionFamilies: List<FamilyRule> = emptyList(),
    val commands: List<CommandRule> = emptyList(),
)
