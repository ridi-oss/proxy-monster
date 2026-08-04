//go:build depspin

// This file is never built (no build configuration defines `depspin`) and exists only so that
// `go mod tidy` — which loads packages under ALL build constraints — keeps a library version settled
// before the code that uses it lands.
//
// go.work resolves ONE version per module across the whole workspace, and `mise run verify` /
// `mise run test-go` both run in workspace mode. So an unpinned `go get` here does not just affect the
// control plane: it rebuilds goproxy, auditmon, pmon and the rest against the new version. pgx is
// pinned to goproxy's existing require for exactly that reason (latest is v5.10.0):
//
//   - github.com/jackc/pgx/v5 v5.7.1 — D3, matching goproxy/go.mod. Native pgxpool, not database/sql:
//     *pgconn.PgError.Code is the direct port of SQLException.sqlState, which is what keeps
//     "23505 matched, 23503 deliberately NOT matched" that narrow.
//
// cedar-go NO LONGER NEEDS PINNING HERE — internal/authz imports it for real, so go.mod carries it as
// a direct require. D5 pins it EXACT (v1.8.0, not a range) and the two required mappings are
// implemented and tested: errors-first in internal/authz/errors_first_test.go, the two-stage IP check
// in internal/authz/ip_test.go.
//
// DELETE THIS FILE once internal/store imports pgx for real.
package controlplane

import (
	_ "github.com/jackc/pgx/v5"
)
