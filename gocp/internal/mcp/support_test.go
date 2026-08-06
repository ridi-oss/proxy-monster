package mcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// Test doubles for the seams A11 §2/§3 resolve through.
//
// They exist so the GATE and AUTHORIZER suites can run with no database at all: the four gates and the
// two-stage authorizer are pure decision logic over a token lookup, a deactivation read, a role
// resolution and a Cedar call, and standing up Postgres to assert "a foreign Origin is 403" would make
// the security suite slower and no more truthful.
//
// The DB-backed suite (mcp_server_db_test.go) uses the REAL stores for everything these fake, because
// what it asserts — rollback, idempotency rows, audit outcomes — is only observable in the rows.
// ---------------------------------------------------------------------------------------------

// rolesFunc adapts a function to [Roles].
type rolesFunc func(principal string) ([]string, error)

func (f rolesFunc) Resolve(_ context.Context, principal string) ([]string, error) {
	return f(principal)
}

// cedarFunc adapts a function to [Cedar].
type cedarFunc func(principal string, roles []string, action authz.AuthzAction, resource authz.AuthzResource, ctx authz.AuthzContext) authz.AuthzDecision

func (f cedarFunc) AuthorizeAs(principal string, roles []string, action authz.AuthzAction, resource authz.AuthzResource, ctx authz.AuthzContext) authz.AuthzDecision {
	return f(principal, roles, action, resource, ctx)
}

// tokensFunc adapts a function to [TokenResolver].
type tokensFunc func(token, resource string) (*AccessIdentity, error)

func (f tokensFunc) ResolveAccess(_ context.Context, token, resource string) (*AccessIdentity, error) {
	return f(token, resource)
}

// deactivationsFunc adapts a function to [Deactivations].
type deactivationsFunc func(principal string) (bool, error)

func (f deactivationsFunc) IsDeactivated(_ context.Context, principal string) (bool, error) {
	return f(principal)
}

// recordingAudit is an in-memory [AuditWriter]. It records the EVENTS rather than counting calls,
// because every assertion about the MCP audit trail is about a field of the row — the outcome string,
// the sorted roles, the datasource scope — and a counter would pass while all three were wrong.
type recordingAudit struct {
	events []types.AuditEvent
	// failOn makes Insert/InsertOn fail for a matching statement, which is how the
	// audit-rollback property is provoked without a database trigger in the unit suite.
	failOn string
}

func (a *recordingAudit) Insert(_ context.Context, rec types.AuditEvent) (int64, error) {
	if a.failOn != "" && rec.Statement == a.failOn {
		return 0, errors.New("forced audit failure")
	}
	a.events = append(a.events, rec)
	return int64(len(a.events)), nil
}

func (a *recordingAudit) InsertOn(ctx context.Context, _ store.Queryer, rec types.AuditEvent) (int64, error) {
	return a.Insert(ctx, rec)
}

// outcomes returns the `outcome` column of every recorded row, in order — the exact projection
// `McpServerDbTest` selects.
func (a *recordingAudit) outcomes() []string {
	out := []string{}
	for _, e := range a.events {
		if e.Outcome != nil {
			out = append(out, *e.Outcome)
		}
	}
	return out
}

// countingVersions is a [PolicyVersions] that records how many times INV-A11-12's post-commit bump
// fired. A bool would not do: the invariant is that a REPLAY bumps ZERO extra times, which is a
// difference between 1 and 2.
type countingVersions struct{ bumps int }

func (v *countingVersions) Bump() { v.bumps++ }

// newRequest builds a bare request carrying one Authorization header, for [bearerToken].
func newRequest(authorization string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	return r
}

// asError is errors.As with the target inferred, so a call site reads as an assertion.
func asError[T error](err error, target *T) bool { return errors.As(err, target) }
