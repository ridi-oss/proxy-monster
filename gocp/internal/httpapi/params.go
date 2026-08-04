package httpapi

import (
	"net/http"
	"strconv"
)

// IDParam is `suspend fun ApplicationCall.idParam(): Long? = parameters["id"]?.toLongOrNull()`
// (Datasources.kt:707), used by eight route files.
//
// Nil is the ONE failure value, covering both "no {id} in the pattern" and "present but not a Long" —
// which is why every call site is `id := IDParam(r); if id == nil { … types.BadID() … }`, the direct
// analogue of `val id = call.idParam() ?: return@get call.badId()`.
//
// The accepted set matches `String.toLongOrNull()` deliberately:
//   - base 10 only, so `0x10` and `010` (as octal) are rejected exactly as Kotlin rejects them;
//   - a leading `+` or `-` is accepted by both (`-1` parses, then finds no row, then 404s — the
//     Kotlin does the same, and turning it into a 400 would be a fix, not a port);
//   - an empty segment is rejected by both;
//   - NO whitespace tolerance in either, so ` 1` is nil.
//
// ⚠️ strconv.ParseInt's underscore handling (`1_000`) is base-0 only, and this passes base 10, so it
// rejects underscores exactly as Kotlin does. Passing 0 for the base here would silently widen the
// accepted set.
func IDParam(r *http.Request) *int64 {
	return NamedIDParam(r, "id")
}

// NamedIDParam is `parameters["<name>"]?.toLongOrNull()` for the four other wildcard names the route
// table uses — `{taskId}`, `{sessionId}`, `{userId}`, `{roleId}` (03-identity-scim.md:230: "{userId}
// / {roleId} are parsed the same way").
//
// [IDParam] is the `{id}` alias because that is 55 of the 60-odd uses and reads better at a call site.
func NamedIDParam(r *http.Request, name string) *int64 {
	raw := r.PathValue(name)
	if raw == "" {
		return nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return nil
	}
	return &v
}
