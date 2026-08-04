// Package management is A11 §8's `ManagementServices.kt` — the TRANSPORT-NEUTRAL service layer that
// both the REST admin routes and the MCP tools call, and the only place the SYSTEM-immutability
// guards live.
//
// Area doc: plans/proxy-monster-go-port/11-mcp-oauth-management.md §8.
//
// # Why it is its own layer
//
// A management service cannot reach an HTTP status, an English sentence, or an MCP envelope. It
// returns a [Error] carrying only a dot-namespaced [types.ApiError] code plus params, and the edge
// decides what that becomes — 400/404/409/502 over HTTP via httpapi.RespondManagementError, or a
// localized MCP error over JSON-RPC. That is INV-A1-13 in structural form, and it is what lets ONE
// implementation of "delete this role" serve two transports without either of them re-deciding
// whether a system role is deletable.
//
// # 🔴 Where the three services actually live, and why they are not all in this file
//
// A11 §8 declares three services. Two of them are here. The third is not, and the split is forced,
// not stylistic:
//
//   - [DatasourceService] — `DatasourceManagementService`. Here.
//   - [IdentityService] — `IdentityManagementService`. Here, because it composes internal/identity's
//     `UserGroupStore` with internal/policy's `PolicyStore`, so it cannot live in either.
//   - [PolicyService] — `PolicyManagementService`. It is an ALIAS for policy.PolicyManagement, which
//     already existed when this package was written: A1's `/auth/debug` could not be built without
//     `replaceDirectRoles`, so that method (and [Error] itself) landed in internal/policy first, and
//     internal/policy/management.go states the rule in as many words — "EXTEND [PolicyManagement]; do
//     not declare a second service type, and do not declare a second [ManagementError]". Go can only
//     define a method in the package that declares the receiver's type, so the name-keyed half of
//     `PolicyManagementService` had to be added to internal/policy
//     (internal/policy/management_named.go). The alias here exists so a caller still imports ONE
//     package for all three services and cannot end up with two spellings of the same type.
//
// [Error] and [CedarValidationError] are likewise aliases, for the same reason and with the same
// effect: `errors.As(err, &me)` where `me *management.Error` matches an error returned by
// internal/policy, because they are the same type, not two structurally identical ones.
//
// # The three SYSTEM guards, and why they are three
//
// 🔒 INV-A11-32 — the Kotlin protects `source = 'SYSTEM'` groups with THREE different mechanisms, and
// all three are reproduced rather than unified:
//
//   - `rejectSystem(group)` — a plain `isSystemGroup(id)` read with NO row lock. Guards update/delete
//     group and add/remove member.
//   - `lockMutableGroup(id)` — `SELECT source FROM app_group WHERE id = ? FOR UPDATE`. Guards
//     addGroupRole / removeGroupRole.
//   - `setGroupRoles` — its own inline `SELECT id, source … FOR UPDATE` keyed on the NAME.
//
// The two `FOR UPDATE` variants exist so a concurrent transaction cannot flip `source` between the
// check and the mutation. `rejectSystem` has no lock, which means the group-update and membership
// paths CAN in principle race a `source` flip. That asymmetry is 11-mcp-oauth-management.md Q4 and it
// is REPRODUCED: adding a lock would be a fix during a port, and the port policy is that
// inefficiency, duplication and inconsistency are reproduced, never tidied.
//
// 🔒 INV-A11-30 (F6, resolved) — the role-side guard, `isSystemRole` on updateRole/deleteRole in all
// four overloads, lives in internal/policy alongside the rest of `PolicyManagementService`.
//
// # 🔒 The invariant most likely to pass single-threaded and corrupt under load
//
// `replaceDirectRoles` takes the per-principal advisory lock FIRST. `inTx` alone is not enough: at
// READ COMMITTED a list-delete-insert is a read-modify-write, so two concurrent replacements each
// delete only the ids THEY listed and then insert their own — committing the UNION rather than either
// caller's set. See policy.PolicyManagement.ReplaceDirectRolesOn, and
// TestReplaceDirectRolesUnderConcurrencyCommitsOneCallersSetNotTheUnion, which runs the race.
//
// # Test posture — everything here is NEW
//
// `ManagementServices.kt` is 732 LOC with ZERO Kotlin tests (00-INDEX.md F19 — "the largest untested
// surface in the control-plane", and unlike the other untested surfaces it contains security guards).
// There is nothing to migrate 1:1, so every case in this package's suites was written against §8 of
// the area doc.
package management
