package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.SharedMySql
import com.ridi.oss.proxymonster.controlplane.support.pushTestCatalog
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.analyzer.pb.CatalogSnapshot
import com.ridi.oss.proxymonster.grpc.EnfAction
import kotlin.test.Test
import kotlin.test.assertEquals

class FunctionCatalogRolloutDbTest {
    /** Store a snapshot with no columns and no routines: MySQL keeps its pinned natives, PostgreSQL keeps only the grammar functions. */
    private fun clearFunctions(fx: EnforcementFixture) {
        val ds = fx.datasource
        fx.datasourceStore.storePushedCatalog(
            ds.id, ds.defaultSchemas, ds.mysqlLowerCaseTableNames, ds.engineVersion!!, CatalogSnapshot.getDefaultInstance(),
        )
    }

    @Test
    fun `rollout mysql abs permits with absent function inventory`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        clearFunctions(fx)
        val decision = fx.decide("SELECT abs(1)")
        assertEquals(EnfAction.ALLOW, decision.action, decision.detail)
    }

    @Test
    fun `rollout postgres abs permits with pushed function inventory`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.postgres()
        val decision = fx.decide("SELECT abs(1)")
        assertEquals(EnfAction.ALLOW, decision.action, decision.detail)
    }

    @Test
    fun `activation mysql stored udf requires a function grant and fresh inventory`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.mysql()
        val ds = fx.datasource
        SharedMySql.executeAdmin("CREATE FUNCTION `${ds.dbName}`.rollout_identity(v BIGINT) RETURNS BIGINT DETERMINISTIC RETURN v")
        try {
            fx.datasourceStore.pushTestCatalog(ds, fx.targetJdbcUrl, fx.targetUser, fx.targetPassword)
            val sql = "SELECT rollout_identity(1)"
            val denied = fx.decide(sql)
            assertEquals(EnfAction.DENY, denied.action, denied.detail)
            fx.cedarPolicyStore.create(CedarPolicyInput(
                name = "rollout-function-read",
                cedarSrc = """permit(principal in Role::"analyst", action == Action::"result.read.unmasked", resource == Function::"${ds.name}/${ds.dbName}.rollout_identity");""",
            ), updatedBy = "test")
            val allowed = fx.decide(sql)
            assertEquals(EnfAction.ALLOW, allowed.action, allowed.detail)
            clearFunctions(fx)
            val absent = fx.decide(sql)
            assertEquals(EnfAction.DENY, absent.action, absent.detail)
        } finally {
            SharedMySql.executeAdmin("DROP FUNCTION `${ds.dbName}`.rollout_identity")
        }
    }

    @Test
    fun `activation postgres absent function inventory denies abs`() {
        requireDockerOrSkip()
        val fx = EnforcementFixture.postgres()
        clearFunctions(fx)
        val decision = fx.decide("SELECT abs(1)")
        assertEquals(EnfAction.DENY, decision.action, decision.detail)
    }
}
