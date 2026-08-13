package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.probe.Dialect
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

// The datasource engine is the proto enum [Engine] (com.ridi.oss.proxymonster.grpc.Engine) used directly
// as the domain type — there is no parallel twin. These extensions are the single home for every
// "is this MySQL or Postgres?" decision, so nothing else compares an engine string literal. MySQL is the
// priority engine and is listed first in each mapping.

/** The canonical persistence / registration / wire string for an engine: "mysql" or "postgres". */
val Engine.wireName: String
    get() = when (this) {
        Engine.MYSQL -> "mysql"
        Engine.POSTGRES -> "postgres"
        else -> error("engine has no canonical wire name: $this")
    }

/**
 * Whether this is MySQL. Calling this at a call site to branch behavior is almost always wrong: per-engine
 * behavior belongs in a method on [Engine] (see [catalogName], [defaultSchema], [requireCaseMode],
 * [parseServerVersion], …), so adding a future engine means implementing the type's methods, not hunting
 * down scattered call-site branches. Kept only for a genuinely local one-off.
 */
val Engine.isMySql: Boolean
    get() = this == Engine.MYSQL

/**
 * Whether this is Postgres. See [isMySql]: prefer a method on [Engine] over branching on this at a call
 * site.
 */
val Engine.isPostgres: Boolean
    get() = this == Engine.POSTGRES

/** The analyzer SQL dialect for this engine. */
val Engine.dialect: Dialect
    get() = when (this) {
        Engine.MYSQL -> Dialect.MYSQL
        Engine.POSTGRES -> Dialect.POSTGRES
        else -> error("engine has no dialect: $this")
    }

/** The analyzer catalog segment: MySQL pins "def"; Postgres uses the database name. */
fun Engine.catalogName(dbName: String): String = when (this) {
    Engine.MYSQL -> "def"
    Engine.POSTGRES -> dbName
    else -> error("engine has no catalog mapping: $this")
}

/**
 * The schema an unqualified table lives under by default for this engine. In ANSI terms a MySQL "database"
 * IS the schema (catalog is always "def"), so the default schema is the database name; Postgres defaults to
 * "public". A per-request schema is used as-is — this is only the fallback when none is specified.
 */
fun Engine.defaultSchema(dbName: String): String = when (this) {
    Engine.MYSQL -> dbName
    Engine.POSTGRES -> "public"
    else -> error("engine has no default schema: $this")
}

/**
 * Resolves a per-request schema to the concrete schema a table lives under. The cross-engine `"public"`
 * default selector maps to this engine's [defaultSchema] (MySQL's database, Postgres's `"public"`); any
 * other value is an explicit schema — for MySQL an explicit database, since a MySQL "database" is the ANSI
 * schema — and is used as-is, so MySQL addresses every database, not only the connection's default. Mirrors
 * `Dialect.ResolveSchema` in the proxy.
 */
fun Engine.resolveSchema(requestedSchema: String, dbName: String): String =
    if (requestedSchema == "public") defaultSchema(dbName) else requestedSchema

/**
 * The MySQL `lower_case_table_names` case-folding mode the analyzer needs, or null for an engine that has
 * no such mode. MySQL requires the value to have been captured by introspection; Postgres has none.
 */
fun Engine.requireCaseMode(lowerCaseTableNames: Int?): Int? = when (this) {
    Engine.MYSQL -> requireNotNull(lowerCaseTableNames) {
        "MySQL lower_case_table_names has not been captured by introspection"
    }
    Engine.POSTGRES -> null
    else -> error("engine has no case mode: $this")
}

/**
 * The engine's concrete, enumerable system namespaces — the fixed catalog schemas whose content is identical
 * across every datasource of the same engine version. This is the single source of truth for those names:
 * the enforcement catalog pools them by engine version, and search-path building enumerates them, so it holds
 * only concrete names — Postgres's per-session `pg_temp_` / `pg_toast` schemas are ephemeral and never appear.
 */
val Engine.systemSchemas: Set<String>
    get() = when (this) {
        Engine.MYSQL -> setOf("information_schema", "mysql", "performance_schema", "sys")
        Engine.POSTGRES -> setOf("pg_catalog", "information_schema")
        else -> error("engine has no system schemas: $this")
    }

/**
 * Whether [schema] is one of the engine's fixed catalog schemas — [systemSchemas] membership with
 * engine-correct casing (MySQL folds; Postgres matches exactly, its unquoted identifiers being canonically
 * lowercase). Excludes Postgres's ephemeral `pg_temp_` / `pg_toast` schemas, so this is the predicate for an
 * enumerable / poolable system schema (the catalog pool key); use [isSystemSchema] for the full test. The
 * MySQL fold is an interim compensation for schema names that reach the control plane un-canonicalized (safe
 * only because MySQL system schemas are always case-insensitive) — see KNOWN_LIMITATIONS.md "Identifier
 * handling".
 */
fun Engine.isFixedSystemSchema(schema: String): Boolean = when (this) {
    Engine.MYSQL -> schema.lowercase() in systemSchemas
    Engine.POSTGRES -> schema in systemSchemas
    else -> error("engine has no system schemas: $this")
}

/**
 * Whether [schema] names any engine-owned system namespace — [isFixedSystemSchema] plus Postgres's ephemeral
 * per-session `pg_temp_` / `pg_toast` schemas (which answer the membership test but are not enumerable, so
 * they stay out of [systemSchemas] / [isFixedSystemSchema]).
 */
fun Engine.isSystemSchema(schema: String): Boolean = when (this) {
    Engine.MYSQL -> isFixedSystemSchema(schema)
    Engine.POSTGRES -> isFixedSystemSchema(schema) || schema.startsWith("pg_temp_") || schema.startsWith("pg_toast")
    else -> error("engine has no system schemas: $this")
}

/**
 * Whether a schema's catalog content is the same for every connection to a datasource, so one connection's
 * measurement answers for all of them.
 *
 * MySQL's temporary tables are absent from `information_schema.COLUMNS` entirely — a session's temp tables
 * cannot appear in a catalog scan, so nothing a scan returns varies by connection. They reach a decision as
 * the per-request temp overlay instead, never through the catalog. PostgreSQL's `pg_temp_*` schemas are real,
 * per-session, and visible in the catalog, so there a fragment is only true for the connection that measured
 * it.
 *
 * Where this is true, a connection may start from catalog content the control plane already holds rather than
 * measuring the target DB itself.
 */
val Engine.catalogIsConnectionIndependent: Boolean
    get() = when (this) {
        Engine.MYSQL -> true
        Engine.POSTGRES -> false
        else -> error("engine has no catalog scope: $this")
    }

/**
 * Parse a wire / registration engine string, fail-closed and case-insensitive: "mysql" → MYSQL,
 * "postgres" → POSTGRES, anything else throws. This is the one gate raw engine input passes through; it
 * accepts exactly the two canonical spellings the store persists and the proxy registers.
 */
fun engineFromWire(raw: String): Engine =
    engineFromWireOrNull(raw)
        ?: throw IllegalArgumentException("unknown datasource engine '$raw' (expected 'mysql' or 'postgres')")

/** Like [engineFromWire] but returns null instead of throwing, for validation paths that render their own error. */
fun engineFromWireOrNull(raw: String): Engine? = when (raw.lowercase()) {
    "mysql" -> Engine.MYSQL
    "postgres" -> Engine.POSTGRES
    else -> null
}

/**
 * Encodes [Engine] as its [wireName] string, so the JSON API shape stays exactly "mysql" / "postgres";
 * decoding accepts the same wire strings via [engineFromWire]. Applied per-field with
 * `@Serializable(with = EngineWireSerializer::class)`.
 */
object EngineWireSerializer : KSerializer<Engine> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Engine", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: Engine) = encoder.encodeString(value.wireName)
    override fun deserialize(decoder: Decoder): Engine = engineFromWire(decoder.decodeString())
}
