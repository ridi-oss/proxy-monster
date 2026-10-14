// Package github acts as the control plane's GitHub App: it signs the App's JWTs with a PEM key or
// AWS KMS, keeps installation tokens, and makes the REST and GraphQL calls the SQL-from-GitHub flow
// needs. The Kotlin control plane reaches it through Handler.
package github

import "time"

// The JSON shapes match the Kotlin control plane's source package, enum values included.

type Repo struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

type User struct {
	ID    string `json:"id"`
	Login string `json:"login"`
}

type Review struct {
	ID          string     `json:"id"`
	Reviewer    *User      `json:"reviewer"`
	State       string     `json:"state"`
	SubmittedAt *time.Time `json:"submittedAt"`
	URL         string     `json:"url"`
	Commit      *string    `json:"commit"`
}

type Check struct {
	Name       string  `json:"name"`
	Required   bool    `json:"required"`
	Status     string  `json:"status"`
	Conclusion *string `json:"conclusion"`
}

type ChangedFile struct {
	Path   string `json:"path"`
	Change string `json:"change"`
}

type CommitAuthor struct {
	UserID *string `json:"userId"`
	Email  *string `json:"email"`
	Merge  bool    `json:"merge"`
}

type AutoMerge struct {
	EnabledBy *User      `json:"enabledBy"`
	EnabledAt *time.Time `json:"enabledAt"`
}

type PullRequest struct {
	Number      int            `json:"number"`
	Open        bool           `json:"open"`
	Merged      bool           `json:"merged"`
	MergedAt    *time.Time     `json:"mergedAt"`
	MergeCommit *string        `json:"mergeCommit"`
	HeadSHA     string         `json:"headSha"`
	BaseRef     string         `json:"baseRef"`
	Author      *User          `json:"author"`
	AutoMerge   *AutoMerge     `json:"autoMerge"`
	Reviews     []Review       `json:"reviews"`
	Checks      []Check        `json:"checks"` // nil when the head commit's rollup could not be read
	Files       []ChangedFile  `json:"files"`
	Commits     []CommitAuthor `json:"commits"`
}

type RateLimit struct {
	Remaining int       `json:"remaining"`
	ResetAt   time.Time `json:"resetAt"`
}

// Relation is how a head commit relates to a base commit.
type Relation string

const (
	Ahead     Relation = "AHEAD"
	Identical Relation = "IDENTICAL"
	Behind    Relation = "BEHIND"
	Diverged  Relation = "DIVERGED"
)

const (
	CheckQueued     = "QUEUED"
	CheckInProgress = "IN_PROGRESS"
	CheckCompleted  = "COMPLETED"
)
