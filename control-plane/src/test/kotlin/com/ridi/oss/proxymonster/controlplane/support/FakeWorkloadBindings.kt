package com.ridi.oss.proxymonster.controlplane.support

import com.ridi.oss.proxymonster.controlplane.CpGoBridgeConfig
import com.ridi.oss.proxymonster.cpgo.DeleteBindingRequest
import com.ridi.oss.proxymonster.cpgo.DeleteBindingResponse
import com.ridi.oss.proxymonster.cpgo.ListBindingsRequest
import com.ridi.oss.proxymonster.cpgo.ListBindingsResponse
import com.ridi.oss.proxymonster.cpgo.WorkloadBinding
import com.ridi.oss.proxymonster.cpgo.WorkloadBindingInput
import com.ridi.oss.proxymonster.cpgo.WorkloadBindingsGrpcKt
import com.ridi.oss.proxymonster.cpgo.WriteBindingRequest
import com.ridi.oss.proxymonster.cpgo.listBindingsResponse
import com.ridi.oss.proxymonster.cpgo.workloadBinding
import io.grpc.Server
import io.grpc.Status
import io.grpc.StatusException
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

internal class FakeWorkloadBindings : AutoCloseable {
    private val bindings = ConcurrentHashMap<String, WorkloadBinding>()
    private val ids = AtomicLong()

    private val server: Server = NettyServerBuilder.forAddress(InetSocketAddress("127.0.0.1", 0))
        .addService(
            object : WorkloadBindingsGrpcKt.WorkloadBindingsCoroutineImplBase() {
                override suspend fun listBindings(request: ListBindingsRequest): ListBindingsResponse =
                    listBindingsResponse { bindings.addAll(this@FakeWorkloadBindings.bindings.values.sortedBy { it.name }) }

                override suspend fun createBinding(request: WriteBindingRequest): WorkloadBinding =
                    store(request.binding, ids.incrementAndGet())

                override suspend fun updateBinding(request: WriteBindingRequest): WorkloadBinding =
                    store(request.binding, bindings[request.binding.name]?.id ?: throw StatusException(Status.NOT_FOUND))

                override suspend fun deleteBinding(request: DeleteBindingRequest): DeleteBindingResponse {
                    bindings.remove(request.name) ?: throw StatusException(Status.NOT_FOUND)
                    return DeleteBindingResponse.getDefaultInstance()
                }
            },
        )
        .build()
        .start()

    val config = CpGoBridgeConfig("127.0.0.1:${server.port}", "internal-token")

    private fun store(input: WorkloadBindingInput, bindingId: Long): WorkloadBinding = workloadBinding {
        id = bindingId
        name = input.name
        issuer = input.issuer
        subject = input.subject
        principal = if (input.hasPrincipal()) input.principal else "svc:${input.name}"
        purposes.addAll(input.purposesList)
        mcpScopes.addAll(input.mcpScopesList)
        conditions.putAll(input.conditionsMap)
        ttlSeconds = if (input.hasTtlSeconds()) input.ttlSeconds else 900
        enabled = !input.hasEnabled() || input.enabled
        createdAt = "2026-01-01T00:00:00Z"
        updatedAt = "2026-01-01T00:00:00Z"
    }.also { bindings[it.name] = it }

    override fun close() {
        server.shutdownNow()
    }
}
