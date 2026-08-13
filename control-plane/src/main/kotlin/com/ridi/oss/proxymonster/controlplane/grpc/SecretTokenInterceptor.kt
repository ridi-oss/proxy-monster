package com.ridi.oss.proxymonster.controlplane.grpc

import com.ridi.oss.proxymonster.controlplane.constantTimeEquals
import com.ridi.oss.proxymonster.grpc.WireMetadata
import io.grpc.Contexts
import io.grpc.Metadata
import io.grpc.ServerCall
import io.grpc.ServerCallHandler
import io.grpc.ServerInterceptor
import io.grpc.Status

/**
 * Gate on the proxy's transport secret (`x-pm-secret-token`, docs/datasource-registration.md).
 *
 * When an [expected] shared secret is configured, every call must present a constant-time-matching
 * token or it is closed `UNAUTHENTICATED` before reaching a handler, fail-closed. When [expected] is null (local dev, no secret set) the gate is
 * open. Either way the presented token is stashed on the gRPC [io.grpc.Context] via
 * [WireMetadata.SECRET_TOKEN_CTX] so handlers can resolve a per-datasource secret later.
 */
class SecretTokenInterceptor(private val expected: String?) : ServerInterceptor {
    override fun <ReqT, RespT> interceptCall(
        call: ServerCall<ReqT, RespT>,
        headers: Metadata,
        next: ServerCallHandler<ReqT, RespT>,
    ): ServerCall.Listener<ReqT> {
        val presented = headers.get(WireMetadata.SECRET_TOKEN_KEY)
        if (expected != null && !constantTimeEquals(presented, expected)) {
            call.close(
                Status.UNAUTHENTICATED.withDescription("missing or invalid x-pm-secret-token"),
                Metadata(),
            )
            return object : ServerCall.Listener<ReqT>() {}
        }
        val ctx = io.grpc.Context.current().withValue(WireMetadata.SECRET_TOKEN_CTX, presented)
        return Contexts.interceptCall(ctx, call, headers, next)
    }
}
