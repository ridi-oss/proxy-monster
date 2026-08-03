package audit

import (
	"context"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/authz"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// The /api/audit limit bounds — `(limit?.toIntOrNull() ?: 100).coerceIn(1, 500)`.
const (
	// DefaultLimit is used when `limit` is absent OR unparseable.
	DefaultLimit = 100
	// MinLimit is coerceIn's floor. `?limit=0` and `?limit=-1` both read 1 row, they do not error and
	// they do not read zero.
	MinLimit = 1
	// MaxLimit is coerceIn's ceiling and the only cap on how much of the log one request can pull.
	MaxLimit = 500
)

// CoerceLimit ports the /api/audit limit rule exactly: `?limit=` absent or unparseable ⇒ 100, then
// clamped into [1, 500].
//
// present is how the HTTP layer says "the query parameter was there at all"; Kotlin's
// `queryParameters["limit"]` is null when absent, and null and "not a number" take the same branch, so
// the two are folded here for the caller's convenience rather than modelled separately.
//
// Three edges, all of them reachable from a URL and all listed as coverage gaps in 08-audit.md §4:
//
//   - `?limit=0` and `?limit=-1` clamp UP to 1. Neither errors.
//   - `?limit=501` clamps DOWN to 500.
//   - `?limit=abc` and `?limit=3000000000` are BOTH "not an Int" and fall back to 100 — the second
//     because Kotlin's toIntOrNull is 32-bit. See parseKotlinInt; using strconv.Atoi here would
//     answer 500 for that URL instead of 100.
func CoerceLimit(raw string, present bool) int {
	limit := DefaultLimit
	if present {
		if v, ok := parseKotlinInt(raw); ok {
			limit = v
		}
	}
	if limit < MinLimit {
		return MinLimit
	}
	if limit > MaxLimit {
		return MaxLimit
	}
	return limit
}

// Reader is the store half of AuditRoutes.kt: the VISIBILITY MODEL for the two read routes, with the
// HTTP mechanics (requireApi, session resolution, id parsing, response encoding) left to A1.
//
// It exists as its own type rather than as two free functions because the two invariants that make
// audit reads safe are properties of the RETURN SHAPE, not of the SQL:
//
// 🔒 INV-A8-6 — [Reader.Detail] returns (nil, nil) for BOTH "no such row" and "you may not see this
// row". The caller is structurally unable to tell them apart, so it cannot leak existence by
// answering differently. The Kotlin achieves this by routing both to respondAuditNotFound(); modelling
// it as one nil return is the same guarantee enforced by the type system instead of by discipline.
//
// 🔒 INV-A8-7 — [Reader.List] on a DENIED collection read returns the caller's OWN rows. It does not
// error and it must not be "improved" into a 403: own rows always, the whole log by grant, is the
// two-tier contract the console is built on.
type Reader struct {
	// Store is the audit store the two routes read through.
	Store *Store
	// Authz evaluates AUDIT_READ. Never consulted when AuthDebug is set.
	Authz *authz.Authz
	// AuthDebug is Config.authDebug — PM_AUTH_DEBUG, the dev bypass.
	//
	// 🔒 INV-A8-8 — it short-circuits BEFORE any session resolution, mirroring requireApi. Both methods
	// therefore IGNORE their principal argument when it is set, and the caller need not have resolved a
	// session at all. INV-A2-16's framing applies: the bypass never SKIPS Cedar, it prevents Cedar from
	// being REACHED — no policy is evaluated and no role is looked up.
	AuthDebug bool
}

// List is GET /api/audit, from the limit onwards. `limit` must already be through [CoerceLimit].
//
// AuthDebug ⇒ the whole log, with no authorization and no session. Otherwise ONE AUDIT_READ check on
// AuthzResource.AuditLog decides between the whole log and the caller's own rows (INV-A8-7).
//
// 🔒 Exactly one authorization per call, whatever the row count — AuditReadRoutesDbTest cases 2 and 5
// assert the role-source lookup count is 1 for both an ordinary principal and an auditor, i.e. the
// collection check is per-REQUEST and never per-row. Anything that authorizes per row here would turn
// a 500-row feed into 500 Cedar evaluations and would also, silently, change the answer.
//
// ctx carries the AuthzContext (network zones, channel, requester_ip, derived tags), which is NOT
// decoration: AuditReadRoutesDbTest case 7 pins an ip-gated audit.read grant, so dropping actx would
// stop an in-range caller from reading the collection at all.
func (r *Reader) List(ctx context.Context, limit int, principal string, actx authz.AuthzContext) ([]types.AuditEvent, error) {
	if r.AuthDebug {
		return r.Store.Recent(ctx, limit)
	}
	decision := r.Authz.Authorize(principal, authz.ActionAuditRead, authz.ResourceAuditLog{}, actx)
	if decision.Allowed {
		return r.Store.Recent(ctx, limit)
	}
	return r.Store.RecentForPrincipal(ctx, limit, principal)
}

// Detail is GET /api/audit/{id}, from the resolved id onwards.
//
// Returns (nil, nil) when the caller must be told "audit record not found" — which is BOTH the missing
// row and the denied row (INV-A8-6). A non-nil error is an infrastructure failure, never a verdict.
//
// 🔒 The lookup happens BEFORE the authorization and a miss returns without consulting Cedar at all:
// AuditReadRoutesDbTest case 2 asserts zero role lookups for a nonexistent id, so the ORDER is itself
// observable — an implementation that authorized first would burn a Cedar evaluation per probe and,
// worse, would make the two cases distinguishable by timing.
//
// AuthDebug still resolves the row first, then short-circuits: the debug bypass changes who may see a
// record, never whether it exists.
func (r *Reader) Detail(ctx context.Context, id int64, principal string, actx authz.AuthzContext) (*types.AuditEvent, error) {
	record, err := r.Store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, nil
	}
	if r.AuthDebug {
		return record, nil
	}
	// The resource carries the record's OWNER, which is what lets the shipped `audit.read-own` policy
	// (V8__seed.sql -4) compare resource.principal == principal.
	decision := r.Authz.Authorize(principal, authz.ActionAuditRead, authz.ResourceAuditRecord{Principal: record.Principal}, actx)
	if !decision.Allowed {
		return nil, nil
	}
	return record, nil
}
