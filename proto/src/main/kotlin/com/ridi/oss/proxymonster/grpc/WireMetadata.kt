package com.ridi.oss.proxymonster.grpc

import io.grpc.Context
import io.grpc.Metadata

/**
 * Shared gRPC metadata contract for the proxy<->control-plane channel
 * (docs/datasource-registration.md). Lives in :proto because it is part of the wire contract the
 * server (:control-plane) enforces; the client is the Go `goproxy` data plane, which carries the
 * same header names in goproxy/cp/client.go.
 */
object WireMetadata {
    /**
     * Transport auth header: the proxy's shared secret (`PM_SECRET_TOKEN`), attached to every call.
     * This authenticates the *proxy* to the control-plane; it is distinct from the end-user wire
     * token carried in [DecisionRequest.token]/[OpenConnectionRequest.token], which authenticates the
     * DB *client* and is re-resolved server-side per query.
     */
    val SECRET_TOKEN_KEY: Metadata.Key<String> =
        Metadata.Key.of("x-pm-secret-token", Metadata.ASCII_STRING_MARSHALLER)

    /** Server-side handle: the extracted secret token, exposed to handlers via the gRPC [Context]. */
    val SECRET_TOKEN_CTX: Context.Key<String> = Context.key("pm-secret-token")
}
