package com.ridi.oss.proxymonster.controlplane.source

import com.google.protobuf.Timestamp
import com.ridi.oss.proxymonster.controlplane.GitHubConfig
import com.ridi.oss.proxymonster.controlplane.GitHubIdentityResolver
import com.ridi.oss.proxymonster.cpgo.GitHubError
import com.ridi.oss.proxymonster.cpgo.branchRulesRequest
import com.ridi.oss.proxymonster.cpgo.GitHubSourceGrpcKt.GitHubSourceCoroutineStub
import com.ridi.oss.proxymonster.cpgo.compareCommitsRequest
import com.ridi.oss.proxymonster.cpgo.dismissReviewRequest
import com.ridi.oss.proxymonster.cpgo.identityRequest
import com.ridi.oss.proxymonster.cpgo.postCheckRequest
import com.ridi.oss.proxymonster.cpgo.postCommentRequest
import com.ridi.oss.proxymonster.cpgo.readFileRequest
import com.ridi.oss.proxymonster.cpgo.readPullRequestsRequest
import com.ridi.oss.proxymonster.cpgo.repo
import io.grpc.Channel
import io.grpc.StatusException
import io.grpc.protobuf.StatusProto
import java.time.Instant
import com.ridi.oss.proxymonster.cpgo.CheckConclusion as CheckConclusionPb
import com.ridi.oss.proxymonster.cpgo.CheckStatus as CheckStatusPb
import com.ridi.oss.proxymonster.cpgo.PullRequest as PullRequestPb
import com.ridi.oss.proxymonster.cpgo.RateLimit as RateLimitPb
import com.ridi.oss.proxymonster.cpgo.SourceUser as SourceUserPb

/**
 * A [SourceAdapter] whose GitHub calls cp-go makes as the GitHub App, through the GitHubSource bridge service.
 * Mapping a GitHub user to a principal stays here: cp-go returns GitHub's facts and [config]'s resolvers match them.
 */
class GitHubAdapter(
    private val config: GitHubConfig,
    private val directory: PrincipalDirectory,
    channel: Channel,
) : SourceAdapter {
    private val stub = GitHubSourceCoroutineStub(channel)

    @Volatile
    override var rateLimit: RateLimit? = null
        private set

    override suspend fun readPullRequests(repo: Repo, numbers: List<Int>): Map<Int, PullRequest> {
        if (numbers.isEmpty()) return emptyMap()
        val out = call {
            stub.readPullRequests(
                readPullRequestsRequest {
                    this.repo = repo.pb()
                    this.numbers += numbers
                },
            )
        }
        note(if (out.hasRateLimit()) out.rateLimit else null)
        return out.pullRequestsMap.mapValues { (_, pr) -> pr.model() }
    }

    override suspend fun readFile(repo: Repo, ref: String, path: String): ByteArray = call {
        stub.readFile(
            readFileRequest {
                this.repo = repo.pb()
                this.ref = ref
                this.path = path
            },
        )
    }.content.toByteArray()

    override suspend fun compareCommits(repo: Repo, base: String, head: String): CommitRelation = CommitRelation.valueOf(
        call {
            stub.compareCommits(
                compareCommitsRequest {
                    this.repo = repo.pb()
                    this.base = base
                    this.head = head
                },
            )
        }.relation.name,
    )

    override suspend fun branchRules(repo: Repo, branch: String): BranchRules = call {
        stub.readBranchRules(
            branchRulesRequest {
                this.repo = repo.pb()
                this.branch = branch
            },
        )
    }.let { BranchRules(it.contextsList.toSet(), it.strict, it.threadResolution, it.mergeMethodsList.toSet(), it.uncheckedList) }

    override suspend fun postCheck(
        repo: Repo,
        headSha: String,
        name: String,
        status: CheckStatus,
        conclusion: CheckConclusion?,
        title: String,
        summary: String,
    ) {
        require(status != CheckStatus.COMPLETED || conclusion != null) { "a completed check needs a conclusion" }
        call {
            stub.postCheck(
                postCheckRequest {
                    this.repo = repo.pb()
                    this.headSha = headSha
                    this.name = name
                    this.status = CheckStatusPb.valueOf(status.name)
                    conclusion?.let { this.conclusion = CheckConclusionPb.valueOf(it.name) }
                    this.title = title
                    this.summary = summary
                },
            )
        }
    }

    override suspend fun dismissReview(repo: Repo, pr: Int, reviewId: String, message: String) {
        call {
            stub.dismissReview(
                dismissReviewRequest {
                    this.repo = repo.pb()
                    this.pr = pr
                    this.reviewId = reviewId
                    this.message = message
                },
            )
        }
    }

    override suspend fun postComment(repo: Repo, pr: Int, body: String) {
        call { stub.postComment(postCommentRequest { this.repo = repo.pb(); this.pr = pr; this.body = body }) }
    }

    override suspend fun upsertComment(repo: Repo, pr: Int, marker: String, body: String) {
        call {
            stub.postComment(
                postCommentRequest {
                    this.repo = repo.pb()
                    this.pr = pr
                    this.marker = marker
                    this.body = body
                },
            )
        }
    }

    override suspend fun resolveUser(
        org: String,
        user: SourceUser,
        role: MappingRole,
        commitEmails: List<String>,
    ): String? {
        val asked = identityRequest {
            this.org = org
            this.login = user.login
        }
        for (resolver in config.identity) {
            val principal = when (resolver) {
                GitHubIdentityResolver.EXTERNAL_IDENTITY -> {
                    val out = call { stub.externalIdentity(asked) }
                    note(if (out.hasRateLimit()) out.rateLimit else null)
                    if (out.hasNameId()) directory.activePrincipal(out.nameId) else null
                }
                GitHubIdentityResolver.VERIFIED_EMAIL -> {
                    val out = call { stub.verifiedEmails(asked) }
                    note(if (out.hasRateLimit()) out.rateLimit else null)
                    uniquePrincipalByEmail(out.emailsList)
                }
                GitHubIdentityResolver.COMMIT_EMAIL ->
                    if (role == MappingRole.REVIEWER) null else uniquePrincipalByEmail(commitEmails)
            }
            if (principal != null) return principal
        }
        return null
    }

    override suspend fun emailOf(org: String, user: SourceUser): String? {
        val asked = identityRequest {
            this.org = org
            this.login = user.login
        }
        for (resolver in config.identity) {
            val email = when (resolver) {
                GitHubIdentityResolver.EXTERNAL_IDENTITY -> call { stub.externalIdentity(asked) }.let { out ->
                    note(if (out.hasRateLimit()) out.rateLimit else null)
                    out.nameId.takeIf { out.hasNameId() && '@' in it }
                }
                GitHubIdentityResolver.VERIFIED_EMAIL -> call { stub.verifiedEmails(asked) }.let { out ->
                    note(if (out.hasRateLimit()) out.rateLimit else null)
                    out.emailsList.map { it.trim() }.filter { it.isNotEmpty() }.distinct().singleOrNull()
                }
                GitHubIdentityResolver.COMMIT_EMAIL -> null
            }
            if (email != null) return email
        }
        return null
    }

    private fun uniquePrincipalByEmail(emails: List<String>): String? =
        emails.map { it.trim() }.filter { it.isNotEmpty() }.distinct()
            .mapNotNull { directory.activePrincipalByEmail(it) }
            .distinct()
            .singleOrNull()

    private fun note(limit: RateLimitPb?) {
        if (limit != null) rateLimit = RateLimit(limit.remaining, limit.resetAt.instant())
    }

    /** A GitHub failure cp-go reports becomes its [GitHubException]; any other failure stays an error. */
    private suspend fun <T> call(block: suspend () -> T): T = try {
        block()
    } catch (e: StatusException) {
        val detail = StatusProto.fromThrowable(e)?.detailsList?.firstOrNull { it.`is`(GitHubError::class.java) }
            ?.unpack(GitHubError::class.java)
            ?: throw IllegalStateException("cp-go GitHub bridge: ${e.status.code}: ${e.status.description}", e)
        throw when (detail.kind) {
            GitHubError.Kind.UNAUTHORIZED -> GitHubException.Unauthorized(detail.message)
            GitHubError.Kind.FORBIDDEN -> GitHubException.Forbidden(detail.message)
            GitHubError.Kind.NOT_FOUND -> GitHubException.NotFound(detail.message)
            GitHubError.Kind.RATE_LIMITED ->
                GitHubException.RateLimited(detail.message, if (detail.hasResetAt()) detail.resetAt.instant() else null)
            GitHubError.Kind.UNPROCESSABLE -> GitHubException.Unprocessable(detail.message)
            GitHubError.Kind.SERVER -> GitHubException.Server(detail.message, detail.status)
            GitHubError.Kind.GRAPHQL -> GitHubException.Graphql(detail.message, emptyList())
            else -> IllegalStateException(detail.message)
        }
    }

    private companion object {
        fun Repo.pb() = repo {
            owner = this@pb.owner
            name = this@pb.name
        }

        fun Timestamp.instant(): Instant = Instant.ofEpochSecond(seconds, nanos.toLong())

        fun SourceUserPb.model() = SourceUser(id, login)

        fun PullRequestPb.model() = PullRequest(
            number = number,
            open = open,
            draft = draft,
            mergeable = mergeable,
            mergeState = mergeState,
            reviewDecision = reviewDecision.ifEmpty { null },
            unresolvedThreads = unresolvedThreads,
            canBeRebased = canBeRebased,
            merged = merged,
            mergedAt = if (hasMergedAt()) mergedAt.instant() else null,
            mergedBy = if (hasMergedBy()) mergedBy.model() else null,
            mergeCommit = if (hasMergeCommit()) mergeCommit else null,
            headSha = headSha,
            baseRef = baseRef,
            author = if (hasAuthor()) author.model() else null,
            autoMerge = if (hasAutoMerge()) {
                AutoMerge(
                    if (autoMerge.hasEnabledBy()) autoMerge.enabledBy.model() else null,
                    if (autoMerge.hasEnabledAt()) autoMerge.enabledAt.instant() else null,
                    autoMerge.mergeMethod.ifEmpty { null },
                )
            } else {
                null
            },
            reviews = reviewsList.map {
                Review(
                    id = it.id,
                    reviewer = if (it.hasReviewer()) it.reviewer.model() else null,
                    state = ReviewState.valueOf(it.state.name),
                    submittedAt = if (it.hasSubmittedAt()) it.submittedAt.instant() else null,
                    url = it.url,
                    commit = if (it.hasCommit()) it.commit else null,
                )
            },
            checks = if (hasChecks()) {
                checks.checksList.map {
                    Check(
                        it.name,
                        it.required,
                        CheckStatus.valueOf(it.status.name),
                        if (it.conclusion == CheckConclusionPb.CHECK_CONCLUSION_UNSPECIFIED) null else CheckConclusion.valueOf(it.conclusion.name),
                        it.own,
                    )
                }
            } else {
                null
            },
            files = filesList.map { ChangedFile(it.path, FileChange.valueOf(it.change.name)) },
            commits = commitsList.map {
                CommitAuthor(
                    if (it.hasUserId()) it.userId else null, if (it.hasEmail()) it.email else null, it.merge,
                    if (it.hasLogin()) it.login else null,
                )
            },
        )
    }
}
