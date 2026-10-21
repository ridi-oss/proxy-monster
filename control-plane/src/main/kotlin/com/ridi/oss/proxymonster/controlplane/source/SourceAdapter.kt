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

/** [mergeMethod] is GitHub's MERGE, SQUASH or REBASE. */
data class AutoMerge(val enabledBy: SourceUser?, val enabledAt: Instant?, val mergeMethod: String? = null)

/** What a base branch requires of a pull request before it merges. */
data class BranchRules(
    val contexts: Set<String> = emptySet(),
    /** The head must contain the base branch. */
    val strict: Boolean = false,
    val threadResolution: Boolean = false,
    /** Empty allows every method; otherwise lowercase GitHub names (merge, squash, rebase). */
    val mergeMethods: Set<String> = emptySet(),
    /** Rule types that can block a merge and that the flow does not evaluate. */
    val unchecked: List<String> = emptyList(),
)

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
    /** GitHub's MergeableState, MergeStateStatus and PullRequestReviewDecision; no decision when none is required. */
    val mergeable: String = "MERGEABLE",
    val mergeState: String = "CLEAN",
    val reviewDecision: String? = null,
    val unresolvedThreads: Int = 0,
    val canBeRebased: Boolean = true,
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

    suspend fun branchRules(repo: Repo, branch: String): BranchRules

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
