// Package policy is A9 — the CRUD layer over the three tables the authz model's *inputs* live in:
// named roles (`app_role`), direct principal→role assignments (`principal_role`), and the
// mask-function registry (`mask_fn`). It is the Go port of `Policies.kt` (242 LOC).
//
// Area doc: plans/proxy-monster-go-port/09-policies.md.
//
// # What this package is NOT
//
// Despite the Kotlin filename this owns no Cedar policy. Decision *rules* are A2
// (`authz/CedarPolicyStore.kt` → internal/authz); this package stores the *vocabulary* those rules
// refer to. The two are deliberately distinct.
//
// `effectiveRoles` is not here either — it is a pure union that lives in `Query.kt:197` (A6), and
// `RoleResolver` is A3. Both are in internal/identity in the Go port; see that package's doc.go for
// where EffectiveRoles ended up and why.
//
// The 11 HTTP routes (`Route.policyRoutes`) are NOT ported here. Every one of them delegates to
// `PolicyManagementService` (A11) and catches `ManagementException`; porting the routes without A11
// would mean inventing the service layer that owns the SYSTEM-immutability guards. See TODOs below.
//
// # Zero inherited test coverage
//
// 09-policies.md §4 is explicit and it changes how this package is verified: **there are no Kotlin
// tests to port.** No test file HTTP-calls `/api/roles`, `/api/role-assignments` or `/api/mask-fns`,
// and there is no `PolicyStoreTest`. `PolicyStore` appears in ~36 Kotlin test files exclusively as a
// *fixture*. So 1:1 test migration — the method the rest of this port runs on — has nothing to
// migrate here (00-INDEX.md F10).
//
// Everything in store_db_test.go is therefore NEW, written against §1–§3 of the area doc as the sole
// specification. It covers what §4.3 asks for on the store side: the role / assignment / mask-fn
// CRUD, isSystemRole against SYSTEM-sourced groups (all seven, not just `system:admin` — F34), and
// the `ON CONFLICT` idempotency of createAssignment.
//
// # The method pairs
//
// Every Kotlin method comes in two forms: a `dataSource.connection.use { … }` wrapper and a
// `(…, c: Connection)` overload for composing into a caller's transaction. Go has no overloading, so
// the pair is spelled:
//
//	ListRoles(ctx)                       — runs on the store's own handle
//	ListRolesOn(ctx, c, …)               — runs on the CALLER's handle (pgx.Tx, pool, conn)
//
// 09-policies.md §2 says to keep the pair, and it is right for a reason beyond fixture count: the
// `On` form is what lets a directory mutation and its policy write commit in ONE transaction, which
// is the same property INV-A3-6 rests on elsewhere.
//
// ⚠️ The pair is NOT universal, and the gaps are reproduced rather than filled in:
// `deleteAssignment(principal, roleId, c)` has only the connection form in the Kotlin (A11's
// `replaceDirectRoles` calls it under the advisory lock), so DeleteAssignmentByPrincipalRoleOn has
// no own-handle twin here either. Adding one would be a new API, not a port.
//
// # Reproduced defects
//
// ⚠️ **F8 — createAssignment is O(n).** `Policies.kt:98` finds the row it just inserted with
// `listAssignments(null, null, c).first { it.id == id }`: it loads EVERY assignment in the table to
// locate one. `getAssignment(id, c)` already exists and is exact. REPRODUCE, per the binding port
// policy (00-INDEX.md:375) — inefficiency is explicitly not grounds for OMIT, and the two paths are
// not identical (`listAssignments` joins and orders; `.first {}` throws where a miss would otherwise
// be null). See CreateAssignmentOn.
//
// 🔒 **INV-A9-1 — "system role" is DERIVED, not a column.** A role is a system role iff at least one
// group with `source = 'SYSTEM'` grants it. There is no `app_role.is_system` flag and adding one
// changes the semantics: a role becomes, or stops being, a system role as `group_role` mappings
// change. See IsSystemRoleOn.
//
// 🔒 **INV-A9-2 — the assignment upsert is an idempotency idiom, not an update.**
// `ON CONFLICT (principal, role_id) DO UPDATE SET principal=EXCLUDED.principal RETURNING id` is a
// deliberate no-op write whose only purpose is to make `RETURNING id` fire on conflict. `DO NOTHING`
// returns no row, which would leave the caller with nothing to return. See CreateAssignmentOn.
//
// # Duplication is reproduced too
//
// The five private JDBC helpers (`Connection.query`, `queryOne`, `insertReturningId`, `exec`,
// `execUpdate`) exist in THREE Kotlin copies — here, in `CedarPolicyStore` and in `Users.kt` — and
// 09-policies.md:95-98 dispositions all three as REPRODUCE. So this package keeps its own private
// copies rather than exporting a shared query helper: collapsing three call paths into one is a
// refactor, and the port policy says do it after cutover when the diff is reviewable.
//
// ⚠️ Note the name collision the area doc flags: `Policies.kt`'s `Connection.insertReturningId` is
// LIVE (ported here), `CedarPolicyStore`'s private one is dead (F2) and `Users.kt:878`'s is dead
// (F80). Same name, three different dispositions — do not "unify" them.
//
// # Language-forced shape changes
//
// These are mechanical, and each one is noted at its site:
//
//   - JDBC's positional `?` becomes pgx's `$1…$n`. In ListAssignmentsOn the numbering is DYNAMIC
//     (the WHERE clause is built conditionally), which is the single most dangerous line in the
//     package: a mis-numbered argument is a silent wrong-value bug, not a compile error.
//   - Kotlin `T?` returns become `*T`; `null` is `nil`.
//   - Kotlin throws; Go returns `error`. Two non-local exits become errors rather than panics:
//     `getRole(id, c)!!` after an insert (Kotlin: NullPointerException) and `.first { … }` in
//     createAssignment (Kotlin: NoSuchElementException). Both are unreachable absent a concurrent
//     delete, and both stay loud.
//   - `description: String? = null` is serialized under `explicitNulls = false` (INV-A1-4), so a
//     null description is ABSENT from the JSON, not `null`. That is `*string` + `omitempty`.
//
// # TODOs
//
// TODO(A11): the 11 routes and `PolicyManagementService`. The routes are pure delegation, but the
// service owns the guards: `isSystemRole` is called at `ManagementServices.kt:362,370,382,389`, each
// throwing `role.system_immutable`, and NOTHING TESTS IT (00-INDEX.md F19 — the largest untested
// surface in the control plane, and it contains security guards). Whoever ports A11 must also carry
// INV-A9-3 (`GET /api/roles` is deliberately `requireApi`, not `requireAdmin` — two non-admin web
// surfaces consume it for JIT elevation) and INV-A9-4 (`GET /api/role-assignments` answers a
// malformed `roleId` with `[]`, not `400 common.bad_id`).
//
// TODO(A5): `mask_fn.kind` is free-form TEXT at this layer; the mask semantics live in
// `engine/probe/Masks.kt` (and, in Go, goproxy/engine/masking.go). 09-policies.md Q4 is open —
// nothing here validates that an admin-created `kind` is one the engine can apply.
//
// TODO(dbtest): internal/dbtest/seed.go writes `app_role`, `principal_role` and `mask_fn` with its
// own INSERT statements because this package did not exist when the harness was built (its
// TODO(A9)). Re-point Seed.Role / Seed.AssignRole / Seed.MaskFn at this store and delete that SQL —
// a fixture that keeps its own INSERTs is a second, silently diverging definition of a valid row.
package policy
