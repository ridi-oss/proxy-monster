package com.ridi.oss.proxymonster.controlplane.source

import java.time.Instant

data class Repo(val owner: String, val name: String) {
    val fullName: String get() = "$owner/$name"

    companion object {
        private val FULL_NAME = Regex("""^[^/\s]+/[^/\s]+$""")

        /** `owner/name`, or null when it is not exactly that. */
        fun parse(fullName: String): Repo? =
            if (FULL_NAME.matches(fullName)) Repo(fullName.substringBefore('/'), fullName.substringAfter('/')) else null
    }
}

/** [id] is the source's stable numeric user id; a login can be renamed and reused. */
data class SourceUser(val id: String, val login: String)

enum class FileChange { ADDED, DELETED, MODIFIED, RENAMED, COPIED, CHANGED }

enum class ReviewState { APPROVED, CHANGES_REQUESTED, COMMENTED, DISMISSED, PENDING }

enum class CheckStatus { QUEUED, IN_PROGRESS, COMPLETED }

enum class CheckConclusion { SUCCESS, NEUTRAL, SKIPPED, FAILURE, CANCELLED, TIMED_OUT, ACTION_REQUIRED, STALE }

data class Review(
    val id: String,
    val reviewer: SourceUser?,
    val state: ReviewState,
    val submittedAt: Instant?,
    val url: String,
    /** The commit the review was submitted on; null when that commit is gone from the pull request. */
    val commit: String? = null,
)

data class Check(val name: String, val required: Boolean, val status: CheckStatus, val conclusion: CheckConclusion?)

data class ChangedFile(val path: String, val change: FileChange)

data class CommitAuthor(val userId: String?, val email: String?, val merge: Boolean)

data class AutoMerge(val enabledBy: SourceUser?, val enabledAt: Instant?)

/** How a head commit relates to a base commit: AHEAD and IDENTICAL mean the head contains the base. */
enum class CommitRelation { AHEAD, IDENTICAL, BEHIND, DIVERGED }

data class PullRequest(
    val number: Int,
    val open: Boolean,
    val draft: Boolean = false,
    val merged: Boolean,
    val mergedAt: Instant?,
    /** The merge commit once [merged]. */
    val mergeCommit: String? = null,
    val headSha: String,
    val baseRef: String,
    val author: SourceUser?,
    val autoMerge: AutoMerge?,
    val reviews: List<Review>,
    /** Null when the head commit's rollup could not be read. */
    val checks: List<Check>?,
    val files: List<ChangedFile>,
    val commits: List<CommitAuthor> = emptyList(),
) {
    /** The emails of [user]'s own non-merge commits. */
    fun commitEmailsBy(user: SourceUser): List<String> =
        commits.filter { !it.merge && it.userId == user.id }
            .mapNotNull { it.email?.trim()?.takeIf(String::isNotEmpty) }
            .distinct()
}

data class RateLimit(val remaining: Int, val resetAt: Instant)

enum class MappingRole { REQUESTER, REVIEWER }

interface SourceAdapter {
    /** From the last API response that reported it; null before the first call. */
    val rateLimit: RateLimit?

    /** A pull request that does not exist is absent from the result. */
    suspend fun readPullRequests(repo: Repo, numbers: List<Int>): Map<Int, PullRequest>

    suspend fun readFile(repo: Repo, ref: String, path: String): ByteArray

    suspend fun compareCommits(repo: Repo, base: String, head: String): CommitRelation

    /** The status contexts [branch]'s rulesets and branch protection require. */
    suspend fun requiredChecks(repo: Repo, branch: String): Set<String>

    suspend fun postCheck(
        repo: Repo,
        headSha: String,
        name: String,
        status: CheckStatus,
        conclusion: CheckConclusion?,
        title: String,
        summary: String,
    )

    suspend fun dismissReview(repo: Repo, pr: Int, reviewId: String, message: String)

    suspend fun postComment(repo: Repo, pr: Int, body: String)

    /** Edits this app's comment carrying [marker], or posts a new one. */
    suspend fun upsertComment(repo: Repo, pr: Int, marker: String, body: String)

    /** The active principal [user] maps to, or null when no configured resolver matches. */
    suspend fun resolveUser(
        org: String,
        user: SourceUser,
        role: MappingRole,
        commitEmails: List<String> = emptyList(),
    ): String?
}
