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
// # Scope
//
// Ported: `RoleResolver.kt` in full (DirectRoles / Resolve / HasActiveAssignee) and EffectiveRoles;
// all of `Users.kt`'s `UserGroupStore` except the two symbols listed below — the plain user/group
// reads, the group/member/role-map writes, the six PRINCIPAL-MUTATING writes with their
// `lockCurrentPrincipal` / `releaseTombstone` / `deactivatePrincipalTombstone` ordering
// (usergroupwrites.go), and the SCIM upsert/replace family (scimstore.go); `Deprovision.kt`'s
// `revokeActiveCredentials` / `revokeActiveCredentialsTx` (deprovision.go); and the whole of
// `Scim.kt` — DTOs, the PATCH validator, the discovery documents and the fifteen routes.
//
// The route table: fourteen admin routes in routes.go (`/api/users**`, `/api/groups**`, all
// `admin.identity`) and fifteen SCIM routes in scimroutes.go (`/api/scim/v2/**`, bearer + TLS). Both
// groups expose `Register(mux *http.ServeMux)`; internal/app mounts them.
//
// NOT ported, and each belongs to A3:
//
//   - TODO(A3/A14): `provisionFromOidc`, which delegates entirely to A14's
//     `auth/OidcDirectoryProvisioner`. 🔒 INV-A3-30's reserved-`system:` gate lives in
//     `OidcGroupMapping.resolve`, in that other module — do not lose it at the module seam.
//   - TODO(A3/A4): `mintForActivePrincipalLocked` is hosted in internal/token with its own relocation
//     TODO. It is behaviourally complete where it is; moving it (and A4's call sites) is a deliberate
//     move, not a side effect of this change.
//
// F27's OMIT set — `groupIdsForUser`, `findGroupIdByName`, `ensureGroupByName`, `insertReturningId`,
// `role` / `roleExists` — is genuinely dropped: no call path in main OR test, so no observable
// behaviour. The fixture-live half (`setUserActive`, `findUserByExternalId` /
// `findGroupByExternalId`, the 4-arg `deleteUser`) IS reproduced, because OMIT never means "delete
// and move on" for a symbol a test still calls.
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
