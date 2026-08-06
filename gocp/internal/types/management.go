package types

// ---------------------------------------------------------------------------------------------
// The two transport-neutral management types, declared in the LEAF package.
//
// 🔴 WHY THEY ARE HERE AND NOT IN internal/policy, WHERE THEY WERE FIRST WRITTEN.
//
// `ManagementException` and `DeleteResult` are `management/ManagementServices.kt`'s (A11), and A11's
// Go home is internal/management. internal/policy declared them first only because A1's `/auth/debug`
// needed `replaceDirectRoles` before internal/management existed, and internal/management then
// ALIASED them (`type Error = policy.ManagementError`) so that one type carries two names and a
// cross-package `errors.As` still matches.
//
// A5's route group is the third package that has to name them: `datasource.Management` — the
// hand-written interface `*management.DatasourceService` satisfies structurally — declares
// `ClearColumnClassificationByID(...) (DeleteResult, error)`, and interface satisfaction is by TYPE
// IDENTITY, so it must name the same declaration. Naming it as `policy.DeleteResult` gave
// internal/datasource an import of internal/policy, and that closed a cycle through the DB test
// harness:
//
//	audit  (internal test) → dbtest → datasource → policy → audit
//	policy (internal test) → dbtest → datasource → policy
//
// — `go build` was clean and `go vet ./...` / `go test ./...` were not, because the edge only exists
// once a `_test.go` in package `audit` (or `policy`) pulls in internal/dbtest, which needs
// internal/datasource for its fixture.
//
// Moving the two declarations to this leaf package removes the datasource→policy edge without moving
// a single method or changing a single wire shape: internal/policy and internal/management both keep
// their names as ALIASES, so `policy.ManagementError`, `management.Error`, `policy.DeleteResult` and
// `management.DeleteResult` all remain THE SAME TYPE as `types.ManagementError` / `types.DeleteResult`
// and every existing `errors.As` and every interface satisfaction is unchanged.
//
// This is a Go import-graph constraint with no Kotlin counterpart (the JVM has no package cycle rule
// of this kind), so it is a mechanical relocation, not a port decision.
// ---------------------------------------------------------------------------------------------

// ManagementError is `class ManagementException(val error: ApiError) : RuntimeException(error.code)`
// (ManagementServices.kt:47) — "a transport-neutral management failure represented only by a stable
// API code and parameters".
//
// 🔒 TRANSPORT-NEUTRAL IS THE POINT, and it is INV-A1-13 in structural form: a management service
// cannot reach an HTTP status or an English sentence, only a dot-namespaced code the web looks up.
// The status is chosen at the edge — see httpapi.RespondManagementError, which reproduces
// `respondManagementError`'s four-arm switch on exactly this code.
//
// Kotlin throws; Go returns. Every caller therefore matches it with errors.As rather than a type
// switch on a panic, and a caller that forgets ends up returning it as a plain error — which the
// route layer answers as 500 common.fallback, i.e. fails visibly rather than leaking the code with
// the wrong status.
type ManagementError struct{ Err ApiError }

// Error is `RuntimeException(error.code)` — the code, never the params, so a log line carrying the
// error string cannot leak an interpolated resource name into a place that is not the wire.
func (e *ManagementError) Error() string { return e.Err.Code }

// DeleteResult is `@Serializable data class DeleteResult(val deleted: Boolean)`
// (ManagementServices.kt:53) — the body every NAME-KEYED management delete returns.
//
// ⚠️ `deleted: false` is a SUCCESS. A name-keyed delete that matched no row still commits and still
// answers 200 with this body; only the paths that resolve the row first can 404.
type DeleteResult struct {
	Deleted bool `json:"deleted"`
}
