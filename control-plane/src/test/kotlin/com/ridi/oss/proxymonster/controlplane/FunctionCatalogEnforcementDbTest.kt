package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.analyzer.pb.schemaFunctions
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.SharedMySql
import com.ridi.oss.proxymonster.controlplane.support.PerConnectionCatalogFixture
import com.ridi.oss.proxymonster.controlplane.support.pushTestCatalog
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.storedRoutines
import com.ridi.oss.proxymonster.controlplane.support.storedSnapshot
import com.ridi.oss.proxymonster.analyzer.pb.CatalogSnapshot
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.schemaFragmentPush
import com.ridi.oss.proxymonster.analyzer.pb.catalogSnapshot
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class FunctionCatalogEnforcementDbTest {
    @Test
    fun `mysql held connection uses its own routines and live classifications without global columns`() = runBlocking {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        SharedMySql.executeAdmin("CREATE FUNCTION `${fx.datasource.dbName}`.catalog_identity(v BIGINT) RETURNS BIGINT DETERMINISTIC RETURN v")
        val fixture = PerConnectionCatalogFixture(fx)
        val core = fixture.core
        val ds = fixture.datasource
        val opened = fixture.openAndPush()
        assertTrue("catalog_identity" in core.datasourceStore.storedRoutines(ds.id).getValue(ds.dbName))
        fx.cedarPolicyStore.create(CedarPolicyInput(
            name = "catalog-function-read",
            cedarSrc = """permit(principal in Role::"analyst", action == Action::"result.read.unmasked", resource == Function::"${ds.name}/${ds.dbName}.catalog_identity");""",
        ), updatedBy = "test")
        // The held connection decides against its own fragments: the stored snapshot can go away entirely.
        core.datasourceStore.storePushedCatalog(
            ds.id, ds.defaultSchemas, ds.mysqlLowerCaseTableNames, ds.engineVersion!!,
            CatalogSnapshot.getDefaultInstance(), ds.effectiveCatalog,
        )
        assertTrue(core.datasourceStore.catalog(ds.id).columns.isEmpty())
        // A call may run DDL inside its body, so every verdict on a function call carries a refetch of the
        // held schemas; answer it the way the proxy does after an unchanged hash probe.
        suspend fun decide(connectionId: com.google.protobuf.ByteString, sql: String): DecisionContext {
            val verdict = assertIs<EnforcementOutcome.Verdict>(decideConnection(
                core, connectionId, "analyst@example.com", ds, sql, ds.defaultSchemas, "127.0.0.1:12345",
            ))
            for (refetch in verdict.afterStatement) {
                val held = core.connectionCatalog.find(connectionId)!!.held.getValue(namespace(ds.effectiveCatalog, refetch.schema))
                val ack = core.connectionCatalog.applyPush(
                    schemaFragmentPush {
                        this.connectionId = connectionId; datasourceName = ds.name; catalog = ds.effectiveCatalog; schema = refetch.schema
                        contentHash = held.hash.bytes; unchanged = true; backendGeneration = 1
                    },
                    ds,
                )
                assertIs<CatalogMutationResult.Applied>(ack)
            }
            return verdict.ctx
        }
        val masked = decide(opened.connectionId, "SELECT catalog_identity(id), ssn FROM users")
        assertEquals(EnfAction.MASK, masked.action, masked.detail)
        assertEquals(listOf(1), masked.masks.map { it.ordinal })
        core.datasourceStore.deleteClassification(ds.id, ds.dbName, "users", "ssn", ds.effectiveCatalog)
        val clear = decide(opened.connectionId, "SELECT catalog_identity(id), ssn FROM users")
        assertEquals(EnfAction.ALLOW, clear.action, clear.detail)
        val udfCall = assertIs<EnforcementOutcome.Verdict>(decideConnection(
            core, opened.connectionId, "analyst@example.com", ds, "SELECT catalog_identity(id) FROM users", ds.defaultSchemas, "127.0.0.1:12345",
        ))
        assertEquals(ds.defaultSchemas, udfCall.afterStatement.map { it.schema }, "a UDF call refetches")
        core.connectionCatalog.applyPush(
            schemaFragmentPush {
                connectionId = opened.connectionId; datasourceName = ds.name; catalog = ds.effectiveCatalog; schema = ds.defaultSchemas.single()
                contentHash = core.connectionCatalog.find(opened.connectionId)!!.held.getValue(namespace(ds.effectiveCatalog, ds.defaultSchemas.single())).hash.bytes
                unchanged = true; backendGeneration = 1
            },
            ds,
        )
        // Same columns, no routines: the call fails closed on the inventory alone, not on a missing table.
        // Opened last (its routine-less push becomes authoritative and would mark `opened` stale) and after
        // the stored catalog is restored, which is where the fixture reads columns from.
        fx.datasourceStore.pushTestCatalog(ds, fx.targetJdbcUrl, fx.targetUser, fx.targetPassword)
        val bare = fixture.openAndPush(withRoutines = false)
        val plain = decide(bare.connectionId, "SELECT id FROM users")
        assertEquals(EnfAction.ALLOW, plain.action, "the table itself is held: ${plain.detail}")
        val absent = decide(bare.connectionId, "SELECT catalog_identity(id) FROM users")
        assertEquals(EnfAction.DENY, absent.action, absent.detail)
    }

    @Test
    fun `mysql routines never become natives and the pinned natives stay`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        val ds = fx.datasource
        fx.datasourceStore.storePushedCatalog(
            ds.id, ds.defaultSchemas, ds.mysqlLowerCaseTableNames, ds.engineVersion!!,
            catalogSnapshot {
                columns.addAll(fx.datasourceStore.storedSnapshot(ds.id).columnsList)
                routines.add(schemaFunctions { schema = ds.dbName; names.add("invented_native") })
            },
            ds.effectiveCatalog,
        )
        val catalog = fx.datasourceStore.catalog(ds.id)
        val (_, analyzer) = analyzerAndCatalogIndex(ds, catalog, emptyList(), ds.defaultSchemas)
        val lower = analyzer.analyze("SELECT LOWER(region) FROM users")
        assertTrue(lower.resolved, lower.detail)
        assertTrue("lower" in lower.functionsList, lower.toString())
        assertTrue(lower.resultReadsList.filter { it.hasFunction() }.all { it.function.builtin })
        val invented = analyzer.analyze("SELECT invented_native(region) FROM users")
        assertTrue(invented.resolved, invented.detail)
        assertTrue(invented.resultReadsList.any { it.hasFunction() && !it.function.builtin }, invented.toString())
    }

    @Test
    fun `postgres grammar functions supplement the stored inventory through analysis and disclosure`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.postgres()
        val catalog = fx.datasourceStore.catalog(fx.datasource.id)
        assertFalse("coalesce" in fx.datasourceStore.storedRoutines(fx.datasource.id).getValue("pg_catalog"), "coalesce has no pg_proc row")
        assertTrue("coalesce" in catalog.functions.builtinFunctionsList, "the grammar functions join pg_catalog on read")
        val (_, analyzer) = analyzerAndCatalogIndex(
            fx.datasource, catalog, emptyList(), fx.datasource.defaultSchemas,
        )
        val facts = analyzer.analyze("SELECT COALESCE(region, 'unknown') FROM users")
        assertTrue(facts.resolved, facts.detail)
        assertTrue("pg_catalog.coalesce" in facts.functionsList, facts.toString())
        assertEquals(emptyList(), protectedPredicateLiterals(
            fx.datasource, "SELECT LOWER(region) FROM users WHERE id = 1", catalog,
        ))
        assertEquals(listOf("${fx.datasource.dbName}.public.users.ssn"), protectedPredicateLiterals(
            fx.datasource, "SELECT LOWER(region) FROM users WHERE ssn = 'secret'", catalog,
        ))
    }
}
