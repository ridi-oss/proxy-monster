package com.ridi.oss.proxymonster.controlplane.source

import java.time.Instant

/** The message names the method, path, and status, never a header or token. */
sealed class GitHubException(message: String) : Exception(message) {
    class Unauthorized(message: String) : GitHubException(message)

    class Forbidden(message: String) : GitHubException(message)

    class NotFound(message: String) : GitHubException(message)

    class RateLimited(message: String, val resetAt: Instant?) : GitHubException(message)

    class Unprocessable(message: String) : GitHubException(message)

    class Server(message: String, val status: Int) : GitHubException(message)

    class Graphql(message: String, val types: List<String>) : GitHubException(message)
}
