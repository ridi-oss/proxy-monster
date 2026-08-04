package management

import (
	"strings"

	"github.com/ridi-oss/proxy-monster/gocp/internal/policy"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// Error is `class ManagementException(val error: ApiError) : RuntimeException(error.code)`
// (ManagementServices.kt:47) — "a transport-neutral management failure represented only by a stable
// API code and parameters".
//
// 🔴 IT IS AN ALIAS, NOT A NEW TYPE. internal/policy declared it first (A1's `/auth/debug` needed
// `replaceDirectRoles` before A11 existed) and instructs in as many words: "do not declare a second
// [ManagementError]". An alias is the only construction that keeps that literally true across a
// package boundary — `errors.As(err, &me)` with `me *management.Error` matches an error built by
// internal/policy, because there is one type with two names. A structurally identical second struct
// would compile, pass every unit test, and then silently fail every cross-package errors.As at the
// route layer.
type Error = policy.ManagementError

// CedarValidationError is `class CedarValidationManagementException(val errors: List<String>)`
// (ManagementServices.kt:50) — the ONE management failure that does not carry an ApiError, because
// its WIRE BODY is `{errors: [...]}`, a bare map. It preserves the validator's raw error array
// verbatim: the policy editor renders the Cedar compiler's output one line at a time, and folding it
// into an ApiError param would both lose the array and put compiler prose into a field the web treats
// as an i18n interpolation.
//
// Also an alias — see [Error].
type CedarValidationError = policy.CedarValidationError

// Fail builds a [Error] from a code and params. params may be nil for a code that carries none.
func Fail(code string, params map[string]string) *Error {
	return &Error{Err: types.ApiError{Code: code, Params: params}}
}

// Required is `private fun required(field: String, value: String)` (ManagementServices.kt:716):
// blank ⇒ `common.field_required{fields: <field>}`. It returns the failure rather than throwing, so
// a caller writes `if err := Required("name", name); err != nil { return err }`.
//
// ⚠️ The param key is `fields`, PLURAL, while exactly one field name is ever put in it. That is the
// Kotlin's and it is wire-visible — `web/` interpolates `{fields}` into a localized sentence — so it
// is reproduced rather than corrected.
//
// Kotlin's `String.isBlank()` is "empty or all whitespace" over Character.isWhitespace;
// strings.TrimSpace's set is unicode.IsSpace, which differs on a handful of exotic code points
// (Character.isWhitespace excludes NBSP, unicode.IsSpace includes it). Narrower in the rejecting
// direction and unreachable for any field this guards, matching internal/policy's own note on the
// same helper.
func Required(field, value string) error {
	if strings.TrimSpace(value) != "" {
		return nil
	}
	return Fail("common.field_required", map[string]string{"fields": field})
}

// NotFound is `private fun notFound(resource: String): Nothing` (ManagementServices.kt:720) —
// `common.not_found{resource: <resource>}`, which httpapi.RespondManagementError answers 404.
//
// ⚠️ `resource` is a per-call-site LITERAL and is NOT the route path: the user routes pass
// `unique("principal", …)` but `notFound("user")`, and `replaceDirectRoles` passes the interpolated
// `"role '<name>'"` rather than `"role"`. The literals are wire-visible, because `web/` interpolates
// `{resource}` into a localized sentence. See [ResourceGroup] and friends.
func NotFound(resource string) *Error {
	return Fail("common.not_found", map[string]string{"resource": resource})
}

// AlreadyExists is the value form of `unique`'s 23505 arm:
// `common.already_exists{resource, name?}`, with `name` OMITTED when nil — `buildMap { put("resource",
// resource); name?.let { put("name", it) } }` (ManagementServices.kt:728).
//
// ⚠️ Note where it lands: `common.already_exists` is NOT an arm of `respondManagementError`'s switch,
// so it answers **400**, not the 409 a route responding with types.AlreadyExists directly would give.
func AlreadyExists(resource string, name *string) *Error {
	params := map[string]string{"resource": resource}
	if name != nil {
		params["name"] = *name
	}
	return Fail("common.already_exists", params)
}

// Unique is `private inline fun <T> unique(resource: String, name: String?, block: () -> T): T`
// (ManagementServices.kt:723) as a translation of an already-returned error rather than a wrapper
// around a block — Kotlin catches, Go inspects.
//
// SQLSTATE 23505 ⇒ [AlreadyExists]; anything else passes through UNTOUCHED, including 23503
// (foreign-key violation), which reaches StatusPages as 500 common.fallback. That omission is F29
// and store.IsUniqueViolation documents why adding a 23503 arm would change an observable status.
//
// The usual shape at a call site:
//
//	created, err := s.store.CreateGroupOn(ctx, tx, input)
//	if err != nil {
//	    return AppGroup{}, Unique(err, ResourceGroup, &input.Name)
//	}
func Unique(err error, resource string, name *string) error {
	if err == nil {
		return nil
	}
	if store.IsUniqueViolation(err) {
		return AlreadyExists(resource, name)
	}
	return err
}

// The `resource` literals this package passes to [NotFound] and [Unique].
//
// A3's are QUOTED in the spec set (03-identity-scim.md) and are reproduced exactly, including the
// mismatch on users: a 404 says `user` while a duplicate says `principal`. That is not a typo to fix
// — `unique("principal", input.principal)` and `notFound("user")` are two different call sites in
// ManagementServices.kt:531-534 and the strings reach the console as different i18n keys.
const (
	// ResourceUser is `notFound("user")` — ManagementServices.kt:523.
	ResourceUser = "user"
	// ResourcePrincipal is `unique("principal", …)` — ManagementServices.kt:532. NOT "user".
	ResourcePrincipal = "principal"
	// ResourceGroup is `notFound("group")` / `unique("group", …)` — ManagementServices.kt:524,588.
	ResourceGroup = "group"
	// ResourceDatasource is `notFound("datasource")` — ManagementServices.kt:202.
	ResourceDatasource = "datasource"
	// ResourceTable is `notFound("table")` — ManagementServices.kt:99, for a table the live
	// introspection returned nothing for.
	ResourceTable = "table"
	// ResourceRole is `notFound("role")` — ManagementServices.kt:694, in setGroupRoles.
	ResourceRole = "role"
)

// The A11 §8 codes that are not `common.*`. Declared as constants because each is asserted by a test
// and read by httpapi.RespondManagementError's switch, and a typo in one is a silent 400.
const (
	// CodeGroupSystemImmutable is 🔒 INV-A11-32's verdict — 409 at the edge.
	CodeGroupSystemImmutable = "group.system_immutable"
	// CodeReservedTag is 🔒 INV-A11-28's verdict, carrying the offending tag as `{tag}` — 400.
	CodeReservedTag = "datasource.reserved_tag"
	// CodeSchemaRequired is INV-A11-29's verdict: a null schema with no resolvable default — 400.
	CodeSchemaRequired = "datasource.schema_required"
	// CodeTableIntrospectionFailed carries `{detail}` and is the one A11 code answered **502**.
	CodeTableIntrospectionFailed = "datasource.table_introspection_failed"
)

// DeleteResult is `@Serializable data class DeleteResult(val deleted: Boolean)`
// (ManagementServices.kt:53) — the body every name-keyed management delete returns.
//
// It is a BODY, not a status: a delete that matched nothing is `{"deleted": false}` with a 2xx from
// the routes that return it, which is why several callers discard it entirely.
//
// An alias, for the same reason [Error] is — the name-keyed policy methods that return it are
// declared in internal/policy (Go method ownership), so the type has to be declared there too or the
// two packages would return two incompatible structs of the same shape.
type DeleteResult = policy.DeleteResult
