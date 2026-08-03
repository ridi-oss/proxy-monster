// Package identity is A3's identity core: server-side role resolution ([RoleResolver], the port of
// `RoleResolver.kt`, 94 LOC) and the reads of `Users.kt`'s `UserGroupStore` that every other area
// gates on.
//
// Area doc: plans/proxy-monster-go-port/03-identity-scim.md.
//
// # Why this package matters more than its size
//
// [RoleResolver.Resolve] is **the sole source of truth for effective roles**. A2 wires it in as
// `RoleSource { p -> roleResolver.resolve(p) }` (ControlPlaneCore.kt:34), so A6 INV-A6-7 and EVERY
// Cedar decision in the system read this and nothing else. A caller cannot assert an arbitrary
// `baseRoles` and have it honoured — the resolution is server-side, from the control-plane store, or
// it does not happen.
//
// [UserGroupStore.IsDeactivated] is, per 03-identity-scim.md:533, "the most widely depended-on
// predicate in the area": A4 (DaemonSession.kt:655, Datasources.kt:739), A6 (Query.kt:361,1130),
// A7 (Approvals.kt:800), A10 (grpc/ControlPlaneGrpcService.kt:123) and A3 itself.
//
// # Scope of THIS increment
//
// Ported: RoleResolver in full (DirectRoles / Resolve / HasActiveAssignee), EffectiveRoles, and the
// UserGroupStore subset those and their consumers need — IsDeactivated in both forms, and
// RolesForPrincipal.
//
// NOT ported yet, and each belongs to A3 as well:
//
//   - TODO(A3): the rest of `UserGroupStore` — the plain user/group reads, `provisionFromOidc`, the
//     SCIM upserts, and the six principal-mutating writes with their `lockCurrentPrincipal` /
//     `deactivatePrincipalTombstone` / `releaseTombstone` ordering. **Get that ordering right when
//     it lands; it is the whole security property** (03-identity-scim.md §"Principal-mutating
//     writes").
//   - TODO(A3): `isSystemGroup(id[, c])`, the SYSTEM predicate the SCIM PUT/PATCH/DELETE routes and
//     A11's `rejectSystem` call. ⚠️ F34 — `V8__seed.sql:48-58` seeds SEVEN `source=SYSTEM` groups,
//     and every guard must key on the COLUMN, never on the string `"system:admin"`. The role-side
//     half of that invariant is already pinned in internal/policy's IsSystemRole tests.
//   - TODO(A3): `Deprovision.kt`'s `revokeActiveCredentials` / `revokeActiveCredentialsTx` (they
//     need A4's TokenStore + PrincipalSessionStore and A6's AccessStore) and
//     `mintForActivePrincipalLocked`. The last one needs nothing outside this package plus
//     store.InTx / store.AdvisoryLockPrincipal, which already exist — it is
//     `inTx { c -> c.advisoryLockPrincipal(p); if (isDeactivated(p, c)) null else mint(c) }`, and
//     [UserGroupStore.IsDeactivatedOn] exists precisely so its check runs on the transaction holding
//     the lock (INV-A3-7).
//   - TODO(A3): the SCIM routes (`Scim.kt`), a later increment.
//
// # Where EffectiveRoles lives, and why here
//
// In the Kotlin, `effectiveRoles(baseRoles, grantRoles, groupRoles)` is a top-level function in
// `Query.kt:197` — i.e. A6, not A3 — kept separate purely so the union stays unit-testable
// (`EffectiveRolesTest`, 4 cases, no DB). 09-policies.md §Note and 06-query-decision.md §
// "effectiveRoles" both say so explicitly.
//
// The Go port puts [EffectiveRoles] HERE, and the reason is dependency direction: [RoleResolver] is
// its sole production caller, so hosting it in A6's package would make internal/identity import the
// query package — the exact inversion of how the two relate. A6 will import THIS package anyway
// (for IsDeactivated at Query.kt:361,1130 and for Resolve), so `identity.EffectiveRoles(...)` costs
// A6 nothing. It is a pure function with no dependencies; if A6's package would rather own it, move
// it — the tests move with it unchanged.
//
// # Ordering is observable — Resolve does not return a Go map
//
// Kotlin's `(baseRoles + grantRoles + groupRoles).toSet()` produces a LinkedHashSet, which preserves
// FIRST-OCCURRENCE order, and `Query.kt:366` immediately does `roles.toList()` into the decision
// DTO's `effectiveRoles: List<String>` — which is rendered into the audit record and returned to
// web/ and to gRPC. So the order is on the wire.
//
// A Go `map[string]struct{}` would randomise it and produce audit diff churn during differential
// conformance. [EffectiveRoles] and [RoleResolver.Resolve] therefore return an order-preserving,
// deduplicated []string. Treat it as a set; do not sort it.
//
// # Fail-closed, four times over
//
// 🔒 INV-A3-9 — deprovisioning short-circuits ALL role sources. [RoleResolver.Resolve] returns the
// empty set for a deactivated principal regardless of any direct `principal_role` assignment, group
// membership, or JIT grant. `directRoles` and `listGrants` are keyed on the principal STRING and are
// independent of `app_user` entirely, so dropping the short-circuit would leave a deprovisioned user
// holding every direct and JIT role.
//
// 🔒 INV-A3-10 — "no `app_user` row" is NOT "deactivated". A purely local `principal_role`-only
// identity, never synced into the directory, keeps its direct roles: there is nothing to deactivate.
// Inverting this to fail-closed-on-absence would break every local-only operator identity and every
// wire token minted before a directory row existed.
//
// 🔒 INV-A3-15 — [UserGroupStore.RolesForPrincipal] fails closed on its own: INNER JOINs from
// `app_user` plus `AND u.active` mean an unknown or inactive principal yields zero rows. That is
// belt-and-braces behind INV-A3-9 — the GROUP source is guarded twice, the direct and JIT sources
// only once.
//
// 🔒 INV-A3-13 — readiness must agree with Resolve, arm for arm. [RoleResolver.HasActiveAssignee] is
// a SECOND, independent implementation of the same three-way union, in one SQL statement. Two
// implementations of one predicate is a drift risk and the mirrored test is the only thing holding
// them together; resolver_db_test.go ports all thirteen assertion points.
//
// # Reproduced defect
//
// ⚠️ INV-A3-11 / F31 — **Resolve is NOT transactional.** Its four reads (IsDeactivated, DirectRoles,
// the JIT grants, RolesForPrincipal) run on four separate pooled connections with no transaction, so
// a deactivation committing mid-resolve yields a torn view: roles read before the flip and
// `isDeactivated` read after it, or the reverse. Contrast A2's INV-A2-10, which takes ONE role
// snapshot and threads it through both passes — that invariant protects the CONSUMER; nothing
// protects Resolve itself.
//
// It is untested in the Kotlin and REPRODUCED here: wrapping the four reads in one transaction would
// close the window and is a behaviour change on the hottest read path in the system
// (03-identity-scim.md Q4). That is a deliberate decision for after cutover, not a side effect of
// the port.
package identity
