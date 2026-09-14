package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.analyzer.pb.FunctionCatalog
import com.ridi.oss.proxymonster.analyzer.pb.functionCatalog
import com.ridi.oss.proxymonster.analyzer.pb.schemaFunctions
import com.ridi.oss.proxymonster.classification.MysqlNativeFunctions
import com.ridi.oss.proxymonster.classification.PostgresGrammarFunctions
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.probe.Dialect
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The typed-engine domain API ([Engines.kt]) — pure, no DB. Pins the parse/serialize round-trip and the
 * fail-closed edges the "engine is a type, not a string" contract depends on, plus the per-engine namespace
 * facts and the [Engine.systemSchemas] set / [Engine.isFixedSystemSchema] / [Engine.isSystemSchema] split.
 */
class EnginesTest {
    @Test fun `engineFromWire accepts the canonical spellings, case-insensitively`() {
        assertEquals(Engine.MYSQL, engineFromWire("mysql"))
        assertEquals(Engine.MYSQL, engineFromWire("MySQL"))
        assertEquals(Engine.POSTGRES, engineFromWire("postgres"))
        assertEquals(Engine.POSTGRES, engineFromWire("POSTGRES"))
    }

    @Test fun `engineFromWire is fail-closed on unknown engines and the postgresql alias`() {
        assertNull(engineFromWireOrNull("postgresql"), "Kotlin and Go both accept exactly {mysql, postgres}")
        assertNull(engineFromWireOrNull("oracle"))
        assertNull(engineFromWireOrNull(""))
        assertFailsWith<IllegalArgumentException> { engineFromWire("postgresql") }
        assertFailsWith<IllegalArgumentException> { engineFromWire("sqlite") }
    }

    @Test fun `EngineWireSerializer round-trips as the exact wire string`() {
        assertEquals("\"mysql\"", Json.encodeToString(EngineWireSerializer, Engine.MYSQL))
        assertEquals("\"postgres\"", Json.encodeToString(EngineWireSerializer, Engine.POSTGRES))
        assertEquals(Engine.MYSQL, Json.decodeFromString(EngineWireSerializer, "\"mysql\""))
        assertEquals(Engine.POSTGRES, Json.decodeFromString(EngineWireSerializer, "\"postgres\""))
    }

    @Test fun `wireName and dialect are the canonical mappings`() {
        assertEquals("mysql", Engine.MYSQL.wireName)
        assertEquals("postgres", Engine.POSTGRES.wireName)
        assertEquals(Dialect.MYSQL, Engine.MYSQL.dialect)
        assertEquals(Dialect.POSTGRES, Engine.POSTGRES.dialect)
    }

    @Test fun `catalogName, defaultSchema and resolveSchema follow each engine's namespace model`() {
        assertEquals("def", Engine.MYSQL.catalogName("app"))
        assertEquals("app", Engine.POSTGRES.catalogName("app"))
        // In ANSI terms a MySQL "database" is the schema, so the default schema is the database name;
        // Postgres defaults to "public".
        assertEquals("app", Engine.MYSQL.defaultSchema("app"))
        assertEquals("public", Engine.POSTGRES.defaultSchema("app"))
        // resolveSchema: the "public" default selector maps to the default schema; any other value is an
        // explicit schema/database used as-is — so MySQL addresses every database, not only "app".
        assertEquals("app", Engine.MYSQL.resolveSchema("public", "app"))
        assertEquals("reporting", Engine.MYSQL.resolveSchema("reporting", "app"))
        assertEquals("public", Engine.POSTGRES.resolveSchema("public", "app"))
        assertEquals("reporting", Engine.POSTGRES.resolveSchema("reporting", "app"))
    }

    @Test fun `value-returning engine methods fail closed on an unspecified engine`() {
        assertFailsWith<IllegalStateException> { Engine.ENGINE_UNSPECIFIED.wireName }
        assertFailsWith<IllegalStateException> { Engine.ENGINE_UNSPECIFIED.dialect }
        assertFailsWith<IllegalStateException> { Engine.ENGINE_UNSPECIFIED.catalogName("db") }
        assertFailsWith<IllegalStateException> { Engine.ENGINE_UNSPECIFIED.defaultSchema("db") }
        assertFailsWith<IllegalStateException> { Engine.ENGINE_UNSPECIFIED.systemSchemas }
        assertFailsWith<IllegalStateException> { Engine.ENGINE_UNSPECIFIED.isFixedSystemSchema("x") }
    }

    @Test fun `systemSchemas is the concrete enumerable set per engine`() {
        assertEquals(setOf("information_schema", "mysql", "performance_schema", "sys"), Engine.MYSQL.systemSchemas)
        assertEquals(setOf("pg_catalog", "information_schema"), Engine.POSTGRES.systemSchemas)
    }

    @Test fun `MySQL system schemas match case-insensitively`() {
        assertTrue(Engine.MYSQL.isSystemSchema("information_schema"))
        assertTrue(Engine.MYSQL.isSystemSchema("INFORMATION_SCHEMA"))
        assertTrue(Engine.MYSQL.isSystemSchema("Information_Schema"))
        assertTrue(Engine.MYSQL.isSystemSchema("mysql"))
        assertTrue(Engine.MYSQL.isSystemSchema("MySQL"))
        assertTrue(Engine.MYSQL.isSystemSchema("performance_schema"))
        assertTrue(Engine.MYSQL.isSystemSchema("PERFORMANCE_SCHEMA"))
        assertTrue(Engine.MYSQL.isSystemSchema("sys"))
        assertTrue(Engine.MYSQL.isSystemSchema("SYS"))
    }

    @Test fun `MySQL non-system schema does not match`() {
        assertFalse(Engine.MYSQL.isSystemSchema("app"))
        assertFalse(Engine.MYSQL.isSystemSchema("acme"))
    }

    @Test fun `Postgres system schemas require exact lowercase spelling, unlike MySQL`() {
        // The Postgres branch does NOT fold case at all.
        assertTrue(Engine.POSTGRES.isSystemSchema("pg_catalog"))
        assertTrue(Engine.POSTGRES.isSystemSchema("information_schema"))
        assertFalse(Engine.POSTGRES.isSystemSchema("PG_CATALOG"), "the Postgres branch does not fold case")
        assertFalse(Engine.POSTGRES.isSystemSchema("INFORMATION_SCHEMA"), "the Postgres branch does not fold case")
    }

    @Test fun `Postgres temp and toast schemas match isSystemSchema by prefix but are not fixed`() {
        // isSystemSchema includes the ephemeral per-session schemas; isFixedSystemSchema (the enumerable /
        // poolable set) deliberately excludes them.
        assertTrue(Engine.POSTGRES.isSystemSchema("pg_temp_5"))
        assertFalse(Engine.POSTGRES.isFixedSystemSchema("pg_temp_5"))
        assertTrue(Engine.POSTGRES.isSystemSchema("pg_toast_16384"))
        assertFalse(Engine.POSTGRES.isFixedSystemSchema("pg_toast_16384"))
        assertFalse(Engine.POSTGRES.isSystemSchema("pg_temp"), "the prefix requires a trailing suffix")
    }

    @Test fun `isFixedSystemSchema keeps each engine's casing but drops the prefixes`() {
        assertTrue(Engine.POSTGRES.isFixedSystemSchema("pg_catalog"))
        assertTrue(Engine.MYSQL.isFixedSystemSchema("INFORMATION_SCHEMA"), "MySQL folds")
        assertFalse(Engine.POSTGRES.isFixedSystemSchema("PG_CATALOG"), "Postgres matches exactly")
    }

    @Test fun `Postgres non-system schema does not match`() {
        assertFalse(Engine.POSTGRES.isSystemSchema("public"))
        assertFalse(Engine.POSTGRES.isSystemSchema("app"))
    }

    @Test fun `MySQL function catalog is the pinned native list with or without a push`() {
        val natives = MysqlNativeFunctions.forVersion("8.0.44")
        val unpushed = Engine.MYSQL.functionCatalog(null, "8.0.44")!!
        assertEquals(natives, unpushed.builtinFunctionsList)
        val pushed = functionCatalog {
            builtinFunctions.add("invented_native")
            udfSchemas.add(schemaFunctions { schema = "app"; names.add("add_tax") })
            loadableFunctions.add("fnv_64")
        }
        val filled = Engine.MYSQL.functionCatalog(pushed, "8.0.44")!!
        assertEquals(natives, filled.builtinFunctionsList, "a pushed MySQL builtin claim is replaced, never trusted")
        assertEquals(pushed.udfSchemasList, filled.udfSchemasList)
        assertEquals(pushed.loadableFunctionsList, filled.loadableFunctionsList)
    }

    @Test fun `Postgres function catalog is absent without a push and gains the grammar functions with one`() {
        assertNull(Engine.POSTGRES.functionCatalog(null, "16.4"))
        val pushed = functionCatalog {
            builtinFunctions.add("abs")
            systemFunctionSchemas.add(schemaFunctions { schema = "pg_catalog"; names.add("abs") })
            systemFunctionSchemas.add(schemaFunctions { schema = "information_schema"; names.add("_pg_expandarray") })
            systemFunctionSchemas.add(schemaFunctions { schema = "pg_catalog"; names.add("lower") })
            udfSchemas.add(schemaFunctions { schema = "public"; names.add("add_tax") })
        }
        val filled = Engine.POSTGRES.functionCatalog(pushed, "16.4")!!
        assertEquals(listOf("abs") + PostgresGrammarFunctions.names, filled.builtinFunctionsList)
        val bySchema = filled.systemFunctionSchemasList.groupBy { it.schema }
        assertEquals(1, bySchema.getValue("pg_catalog").size, "duplicate pg_catalog entries fold into one")
        assertEquals(
            listOf("abs", "lower") + PostgresGrammarFunctions.names,
            bySchema.getValue("pg_catalog").single().namesList,
        )
        assertEquals(listOf("_pg_expandarray"), bySchema.getValue("information_schema").single().namesList)
        assertEquals(pushed.udfSchemasList, filled.udfSchemasList)
    }

    @Test fun `functionCatalog fails closed on an unspecified engine`() {
        assertFailsWith<IllegalStateException> { Engine.ENGINE_UNSPECIFIED.functionCatalog(FunctionCatalog.getDefaultInstance(), null) }
    }
}
