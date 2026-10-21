package github

import "time"

// Kind classifies a failed GitHub call; the Kotlin control plane maps each to its own exception.
type Kind string

const (
	Unauthorized  Kind = "unauthorized"
	Forbidden     Kind = "forbidden"
	NotFound      Kind = "not_found"
	RateLimited   Kind = "rate_limited"
	Unprocessable Kind = "unprocessable"
	Server        Kind = "server"
	GraphQL       Kind = "graphql"
	// Internal is a failure other than a GitHub response, such as a body this client cannot read.
	Internal Kind = "internal"
)

// Error is a failed GitHub call. Message names the method, path, and status, never a header or token.
type Error struct {
	Kind    Kind       `json:"kind"`
	Message string     `json:"message"`
	Status  int        `json:"status,omitempty"`
	ResetAt *time.Time `json:"resetAt,omitempty"`
}

func (e *Error) Error() string { return e.Message }
