# A9 — Roles, Role Assignments, Mask Functions

File: `Policies.kt` (242). Fully read. Tables: `app_role`, `principal_role`,
`mask_fn`, plus reads of `group_role` / `app_group` (V1, V3).

⚠️ **This area has ZERO dedicated test coverage.** See §4 — it is the largest
untested surface in the control-plane, and that changes how Step 3 should treat
it.

## Purpose

CRUD over the three tables the authz model's _inputs_ live in: named roles,
direct principal→role assignments, and the mask-function registry. Despite the
filename this owns no Cedar policy — that is A2 (`authz/CedarPolicyStore.kt`).
The two are distinct: A2 stores decision _rules_, A9 stores the _vocabulary_
they refer to.

Note `effectiveRoles(baseRoles, grantRoles, groupRoles)` is **not** here — it
lives in `Query.kt:197` (A6), and `RoleResolver` is A3.

---

## 1. Wire contract

| DTO                   | Fields                                                              |
| --------------------- | ------------------------------------------------------------------- |
| `Role`                | `id: Long`, `name: String`, `description: String? = null`           |
| `RoleInput`           | `name: String`, `description: String? = null`                       |
| `RoleAssignment`      | `id: Long`, `principal: String`, `roleId: Long`, `roleName: String` |
| `RoleAssignmentInput` | `principal: String`, `roleId: Long`                                 |
| `MaskFn`              | `id: Long`, `name: String`, `kind: String`                          |
| `MaskFnInput`         | `name: String`, `kind: String`                                      |

`RoleAssignment.roleName` is denormalized from the join — the UI shows the name,
so every read joins `app_role`.

---

## 2. `PolicyStore` · class

`class PolicyStore(internal val dataSource: DataSource)`. Every method comes in
two forms: a `dataSource.connection.use { … }` wrapper and a
`(…, c: Connection)` overload for composing into a caller's transaction. The Go
port should keep the pair — ~36 test files use the connection form as a fixture.

### Roles — `app_role`

| Method                  | SQL                                                                                                                              |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `listRoles()`           | `SELECT id, name, description FROM app_role ORDER BY name`                                                                       |
| `getRole(id)`           | `WHERE id=?`                                                                                                                     |
| `getRoleByName(name)`   | `WHERE name=?`                                                                                                                   |
| `createRole(input)`     | `INSERT … RETURNING id`, then `getRole(id, c)!!`                                                                                 |
| `updateRole(id, input)` | `getRole(id, c) == null ⇒ null`; else `UPDATE app_role SET name=?, description=?`, re-read                                       |
| `deleteRole(id)`        | `DELETE … WHERE id=?`, returns `rows > 0`                                                                                        |
| `isSystemRole(id)`      | `SELECT EXISTS(SELECT 1 FROM group_role gr JOIN app_group g ON g.id = gr.group_id WHERE gr.role_id = ? AND g.source = 'SYSTEM')` |

🔒 **INV-A9-1 — "system role" is derived, not a column.** A role is a system
role iff it is granted by at least one group whose `source = 'SYSTEM'`. There is
no `app_role.is_system` flag. A Go port that adds one changes the semantics: a
role becomes/stops being system as group mappings change.

⚠️ `isSystemRole` is declared here but **no call site exists in `Policies.kt`**
— the guard is enforced by `PolicyManagementService` (A11). Confirm when
specifying A11 that it is actually called on `updateRole`/`deleteRole`; if not,
system roles are mutable through the API. **Flagged as a possible live gap, not
just a port question** — see §5 Q1.

### Assignments — `principal_role`

| Method                                   | Behavior                                                                                                                                                 |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `listAssignments(principal?, roleId?)`   | dynamic `WHERE 1=1` + optional `AND pr.principal = ?` / `AND pr.role_id = ?`, `ORDER BY pr.principal, r.name`; joins `app_role` for `role_name`          |
| `getAssignment(id)`                      | same join, `WHERE pr.id = ?`                                                                                                                             |
| `createAssignment(input)`                | `INSERT INTO principal_role (principal, role_id) VALUES (?, ?) ON CONFLICT (principal, role_id) DO UPDATE SET principal=EXCLUDED.principal RETURNING id` |
| `deleteAssignment(id)`                   | `DELETE … WHERE id=?`                                                                                                                                    |
| `deleteAssignment(principal, roleId, c)` | `DELETE … WHERE principal=? AND role_id=?`                                                                                                               |

**INV-A9-2 — the upsert is an idempotency idiom, not a real update.**
`DO UPDATE SET principal=EXCLUDED.principal` is a deliberate no-op write whose
only purpose is to make `RETURNING id` fire on conflict (a plain `DO NOTHING`
returns no row). So re-assigning an existing (principal, role) pair returns the
**existing** id instead of failing. Go's `pgx` reproduces this verbatim; do not
"simplify" it to `DO NOTHING`, which would return zero rows and NPE the caller.

⚠️ **Inefficiency — REPRODUCE (F8):** `createAssignment` finds its result via
`listAssignments(null, null, c).first { it.id == id }` — it loads **every**
assignment in the table to locate one row. Correct but O(n).
`getAssignment(id, c)` already exists, is exact, and is the obvious swap — but
inefficiency is explicitly not grounds for OMIT, and the two paths are not
identical (`listAssignments` joins `app_role` and orders, `.first {}` throws
where a miss would otherwise be null), so the swap is a behaviour change however
small. Port the O(n) lookup with a comment naming F8; make the swap a separate
PR against the working Go service.

### Mask functions — `mask_fn`

`listMaskFns` / `getMaskFn(id)` / `getMaskFnByName(name)` / `createMaskFn` /
`updateMaskFn` / `deleteMaskFn` — the same shape as roles (`ORDER BY name`,
`RETURNING id`, update returns null when absent, delete returns `rows > 0`).

`kind` is a free-form `String` at this layer; the mask semantics live in
`engine/probe/Masks.kt`.

### Private JDBC helpers

`ResultSet.toRole()`, `ResultSet.toMaskFn()`, `Connection.query`,
`Connection.queryOne`, `Connection.insertReturningId`, `Connection.exec`,
`Connection.execUpdate`. This idiom (extension functions on `Connection`) recurs
across `CedarPolicyStore` and `Users.kt` — **three copies, and all three are
REPRODUCE (`09-policies.md:95-98`)**. Factoring one small shared query helper is
the right end-state, but duplication is explicitly not grounds for OMIT and
collapsing three call paths into one is a refactor; do it after cutover, when
the diff is reviewable. ⚠️ Note the name collision flagged in A3:
`Policies.kt`'s `Connection.insertReturningId` is live, `CedarPolicyStore`'s
private one is dead (F2) and `Users.kt:878`'s is dead (F80) — same name, three
different dispositions.

---

## 3. Routes — 11 endpoints

All delegate to `PolicyManagementService` (A11) and catch `ManagementException`
⇒ `respondManagementError(e)`. Unparseable id ⇒ `400 ApiError("common.bad_id")`.

| Method | Path                         | Gate                | Success |
| ------ | ---------------------------- | ------------------- | ------- |
| GET    | `/api/roles`                 | **`requireApi`** ⚠️ | 200     |
| POST   | `/api/roles`                 | `ADMIN_POLICIES`    | **201** |
| PUT    | `/api/roles/{id}`            | `ADMIN_POLICIES`    | 200     |
| DELETE | `/api/roles/{id}`            | `ADMIN_POLICIES`    | **204** |
| GET    | `/api/role-assignments`      | `ADMIN_IDENTITY`    | 200     |
| POST   | `/api/role-assignments`      | `ADMIN_IDENTITY`    | **201** |
| DELETE | `/api/role-assignments/{id}` | `ADMIN_IDENTITY`    | **204** |
| GET    | `/api/mask-fns`              | `ADMIN_POLICIES`    | 200     |
| POST   | `/api/mask-fns`              | `ADMIN_POLICIES`    | **201** |
| PUT    | `/api/mask-fns/{id}`         | `ADMIN_POLICIES`    | 200     |
| DELETE | `/api/mask-fns/{id}`         | `ADMIN_POLICIES`    | **204** |

🔒 **INV-A9-3 — `GET /api/roles` is `requireApi`, not `requireAdmin`, and this
is DELIBERATE.** Any authenticated session can list every role name and
description, while every other route here is admin-gated (`GET /api/mask-fns`
_is_ `ADMIN_POLICIES`).

**Verified reason:** `web/src/lib/hooks.ts:131`'s `useRoles()` is consumed by
two **non-admin** surfaces — `components/query/request-access-dialog.tsx:58` and
`components/workflows/role-request-composer.tsx:51` — where an ordinary user
picks the role **R** to request elevation to. Tightening this to `requireAdmin`
breaks JIT elevation for every non-admin user, which is the product.

The MCP asymmetry is correct too: A11's `list_roles` tool requires
`ADMIN_POLICIES` because it is an admin _management_ tool. Two gates over the
same data because there are two callers with different legitimate needs.

**Port action: preserve both gates exactly, and add the doc comment this route
is missing** — the absence of one is why it read as a gap. (Originally filed as
index finding F5; closed as by-design.)

⚠️ **INV-A9-4 — `GET /api/role-assignments` returns `[]` for a malformed
`roleId`,** rather than `400 common.bad_id` like every other id-taking route:

```kotlin
if (roleIdRaw != null && roleId == null) return@get call.respond(emptyList<RoleAssignment>())
```

An inconsistency in the wire contract. `web/` may depend on it. Replicate, flag,
do not "fix" during the port.

Two route-level quirks worth noting for a faithful port:

- `PUT /api/mask-fns/{id}` calls `call.receive()` **inline as an argument**
  (`management.updateMaskFn(id, call.receive())`) rather than binding it first,
  unlike `PUT /api/roles/{id}`. Same behaviour, but the deserialization error
  surfaces from a different point in the handler.
- `GET /api/roles` and `GET /api/mask-fns` are written as single-line handlers
  with `;` separators; purely stylistic.

---

## 4. Test inventory — **0 dedicated cases**

Verified by search: no test file HTTP-calls `/api/roles`,
`/api/role-assignments`, or `/api/mask-fns`, and there is no `PolicyStoreTest`.
`PolicyStore` appears in **~36 test files** — exclusively as a _fixture_
(constructing roles and assignments so some other area's test has an authz
vocabulary to work against), never as the subject.

What that means concretely:

| Surface                                     | Direct coverage | Indirect coverage                        |
| ------------------------------------------- | --------------- | ---------------------------------------- |
| `PolicyStore` role/assignment CRUD          | none            | happy-path create/read, via ~36 fixtures |
| `PolicyStore` mask-fn CRUD                  | none            | some, via A6 masking suites              |
| `isSystemRole`                              | **none**        | none found                               |
| All 11 routes                               | **none**        | none                                     |
| INV-A9-3 (`requireApi` on `GET /api/roles`) | **none**        | none                                     |
| INV-A9-4 (`[]` on bad `roleId`)             | **none**        | none                                     |

So for A9 the ported Kotlin tests provide **no** regression signal. Practical
consequences:

1. **A9 cannot be validated by 1:1 test migration** — there is nothing to
   migrate. It is the one area where Step 3's plan does not apply.
2. The area's contract is therefore only what §1–§3 above records. That makes
   this document, rather than a test suite, the sole specification — worth extra
   review.
3. Step 3 should **write new tests** here: 11 route tests (gate + status +
   shape), `isSystemRole` against a SYSTEM-sourced group, the `ON CONFLICT`
   idempotency of `createAssignment`, and the two flagged inconsistencies
   (INV-A9-3, INV-A9-4) so they become deliberate rather than incidental.
4. Because the fixture usage is so wide, a `PolicyStore` behaviour change breaks
   ~36 suites in ways that will look like _those_ areas failing. **Port
   `PolicyStore` early and exactly**, before the areas that depend on it.

---

## 5. Open questions

| #      | Question                                                                                                                                                                                                                                                                                                |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ~~Q1~~ | **ANSWERED — yes.** `isSystemRole` is called in `ManagementServices.kt:362` (`updateRole(id)`), `:370` (`updateRole(name)`), `:382` (`deleteRole(id)`), `:389` (`deleteRole(name, c)`), each throwing `role.system_immutable`. System roles are protected. ⚠️ But nothing **tests** it — see index F19. |
| ~~Q2~~ | **ANSWERED — deliberate.** See INV-A9-3 above; two non-admin `web/` surfaces depend on it.                                                                                                                                                                                                              |
| Q3     | Does `web/` rely on `GET /api/role-assignments` returning `[]` rather than 400 for a bad `roleId` (INV-A9-4)?                                                                                                                                                                                           |
| Q4     | `mask_fn.kind` is free-form here but presumably constrained by `engine/probe/Masks.kt`. Is there validation anywhere, or can an admin create a mask fn with a `kind` the engine cannot apply?                                                                                                           |
