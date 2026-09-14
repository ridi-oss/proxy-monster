package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.analyzer.pb.CatalogSnapshot
import com.ridi.oss.proxymonster.grpc.EnfAction
import kotlin.test.Test
import kotlin.test.assertEquals

class FunctionCatalogRolloutDbTest {
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
}
