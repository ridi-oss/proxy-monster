package types

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// 01-bootstrap.md §3's table, asserted as a table: helper -> status, code, params.
//
// 🔒 INV-A1-13 — no English prose on the wire. Every code here is a stable dot-namespaced i18n key
// the web looks up directly, and every one must exist in every locale under web/messages/<locale>/.
// 00-INDEX.md contract #11: there is no automated completeness check, so adding a code is only half
// the change.
func TestErrorHelpers(t *testing.T) {
	tests := []struct {
		name   string
		got    ErrorResponse
		status int
		code   string
		params map[string]string
	}{
		{
			name: "badId", got: BadID(),
			status: http.StatusBadRequest, code: "common.bad_id", params: nil,
		},
		{
			name: "notFound", got: NotFound("datasource"),
			status: http.StatusNotFound, code: "common.not_found",
			params: map[string]string{"resource": "datasource"},
		},
		{
			// vararg joined with ", " — comma AND space (ApiErrors.kt's explicit joinToString(", ")).
			name: "fieldRequired multiple", got: FieldRequired("name", "url", "engine"),
			status: http.StatusBadRequest, code: "common.field_required",
			params: map[string]string{"fields": "name, url, engine"},
		},
		{
			name: "fieldRequired single", got: FieldRequired("name"),
			status: http.StatusBadRequest, code: "common.field_required",
			params: map[string]string{"fields": "name"},
		},
		{
			// No fields at all is reachable in Kotlin (vararg with zero args) and joins to "".
			name: "fieldRequired none", got: FieldRequired(),
			status: http.StatusBadRequest, code: "common.field_required",
			params: map[string]string{"fields": ""},
		},
		{
			name: "alreadyExists without name", got: AlreadyExists("group", nil),
			status: http.StatusConflict, code: "common.already_exists",
			params: map[string]string{"resource": "group"},
		},
		{
			name: "alreadyExists with name", got: AlreadyExists("group", Ptr("analysts")),
			status: http.StatusConflict, code: "common.already_exists",
			params: map[string]string{"resource": "group", "name": "analysts"},
		},
		{
			name: "unauthenticated", got: Unauthenticated(),
			status: http.StatusUnauthorized, code: "common.unauthenticated", params: nil,
		},
		{
			name: "invalidToken without kind", got: InvalidToken(nil),
			status: http.StatusUnauthorized, code: "common.invalid_token", params: nil,
		},
		{
			name: "invalidToken with kind", got: InvalidToken(Ptr("bearer")),
			status: http.StatusUnauthorized, code: "common.invalid_token",
			params: map[string]string{"kind": "bearer"},
		},
		{
			name: "fallback", got: Fallback(),
			status: http.StatusInternalServerError, code: "common.fallback", params: nil,
		},
		{
			name: "forbidden without detail", got: Forbidden(nil),
			status: http.StatusForbidden, code: "common.forbidden", params: nil,
		},
		{
			name: "forbidden with detail", got: Forbidden(Ptr("no policy permits task.approve")),
			status: http.StatusForbidden, code: "common.forbidden",
			params: map[string]string{"detail": "no policy permits task.approve"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got.Status != tc.status {
				t.Errorf("status = %d, want %d", tc.got.Status, tc.status)
			}
			if tc.got.Body.Code != tc.code {
				t.Errorf("code = %q, want %q", tc.got.Body.Code, tc.code)
			}
			if len(tc.got.Body.Params) != len(tc.params) {
				t.Errorf("params = %v, want %v", tc.got.Body.Params, tc.params)
			}
			for k, v := range tc.params {
				if tc.got.Body.Params[k] != v {
					t.Errorf("params[%q] = %q, want %q", k, tc.got.Body.Params[k], v)
				}
			}
			// 🔒 INV-A1-13: the code is a dot-namespaced key, never a sentence.
			if !strings.HasPrefix(tc.got.Body.Code, "common.") || strings.ContainsAny(tc.got.Body.Code, " ") {
				t.Errorf("code %q is not a dot-namespaced common.* key", tc.got.Body.Code)
			}
		})
	}
}

// 🔒 INV-A1-4 applied to a MAP: Kotlin's `params: Map<String,String> = emptyMap()` is a defaulted
// non-null field, so encodeDefaults = true always emits it — as {} at minimum. Go's nil map marshals
// as null, a different shape. The normalisation lives in MarshalJSON so a bare struct literal cannot
// get it wrong.
func TestApiErrorParamsNeverMarshalAsNull(t *testing.T) {
	tests := []struct {
		name string
		in   ApiError
		want string
	}{
		{"nil map from a bare literal", ApiError{Code: "common.bad_id"}, `{"code":"common.bad_id","params":{}}`},
		{"explicit empty map", ApiError{Code: "common.fallback", Params: map[string]string{}}, `{"code":"common.fallback","params":{}}`},
		{
			"populated", ApiError{Code: "common.not_found", Params: map[string]string{"resource": "role"}},
			`{"code":"common.not_found","params":{"resource":"role"}}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := MarshalWire(tc.in)
			if err != nil {
				t.Fatalf("MarshalWire: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("shape drifted.\n got: %s\nwant: %s", got, tc.want)
			}
			if strings.Contains(string(got), "null") {
				t.Errorf("ApiError emitted a null: %s", got)
			}
		})
	}
}

// Every helper's body must survive the same rule, including the five that build a nil params map.
func TestErrorHelperBodiesMarshalWithParamsObject(t *testing.T) {
	for _, e := range []ErrorResponse{
		BadID(), NotFound("role"), FieldRequired("name"), AlreadyExists("group", nil),
		AlreadyExists("group", Ptr("analysts")), Unauthenticated(), InvalidToken(nil),
		InvalidToken(Ptr("ingest")), Fallback(), Forbidden(nil), Forbidden(Ptr("denied")),
	} {
		got, err := MarshalWire(e.Body)
		if err != nil {
			t.Fatalf("MarshalWire(%s): %v", e.Body.Code, err)
		}
		if strings.Contains(string(got), "null") {
			t.Errorf("%s emitted a null: %s", e.Body.Code, got)
		}
		if !strings.Contains(string(got), `"params":`) {
			t.Errorf("%s omitted params entirely: %s", e.Body.Code, got)
		}
		// Two keys and only two: the envelope is {code, params}.
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(got, &keys); err != nil {
			t.Fatalf("re-decode: %v", err)
		}
		if len(keys) != 2 {
			t.Errorf("%s emitted %d keys, want 2 (code, params)", e.Body.Code, len(keys))
		}
	}
}

// code has no Kotlin default, so a body without it fails to decode rather than yielding code "".
func TestApiErrorUnmarshal(t *testing.T) {
	var e ApiError
	if err := json.Unmarshal([]byte(`{"params":{"resource":"role"}}`), &e); err == nil {
		t.Error("Unmarshal accepted a body with no code, want an error")
	}
	// params defaults to an empty map, never nil, so a caller can index it without a check.
	if err := json.Unmarshal([]byte(`{"code":"common.bad_id"}`), &e); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if e.Params == nil {
		t.Error("params decoded as nil, want an empty map (Kotlin emptyMap())")
	}
	if len(e.Params) != 0 {
		t.Errorf("params = %v, want empty", e.Params)
	}
	// ignoreUnknownKeys = true.
	if err := json.Unmarshal([]byte(`{"code":"x","params":{},"httpStatus":418}`), &e); err != nil {
		t.Fatalf("Unmarshal rejected an unknown key: %v", err)
	}
}

func TestApiErrorRoundTrip(t *testing.T) {
	original := AlreadyExists("group", Ptr("analysts")).Body
	encoded, err := MarshalWire(original)
	if err != nil {
		t.Fatalf("MarshalWire: %v", err)
	}
	var decoded ApiError
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(original, decoded) {
		t.Errorf("round trip lost data.\noriginal: %+v\n decoded: %+v", original, decoded)
	}
}

// ErrorResponse.Error() carries status + code + params and NO prose. INV-A1-13 governs the wire and
// this string never reaches it, but an English sentence here is how prose leaks into a log line, a
// gRPC status or an MCP payload later.
func TestErrorResponseError(t *testing.T) {
	if got, want := BadID().Error(), "400 common.bad_id"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if got, want := NotFound("role").Error(), "404 common.not_found {resource=role}"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	// Params are sorted, so the string does not depend on Go's map iteration order. Run it enough
	// times that an unsorted implementation would be caught.
	e := AlreadyExists("group", Ptr("analysts"))
	const want = "409 common.already_exists {name=analysts, resource=group}"
	for range 100 {
		if got := e.Error(); got != want {
			t.Fatalf("Error() = %q, want %q", got, want)
		}
	}
	// It satisfies the error interface, which is the point of having it.
	var err error = Forbidden(Ptr("denied"))
	if err.Error() != "403 common.forbidden {detail=denied}" {
		t.Errorf("Error() = %q", err.Error())
	}
}

func TestErrorResponseRespond(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := NotFound("audit record").Respond(rec); err != nil {
		t.Fatalf("Respond: %v", err)
	}
	res := rec.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	const want = `{"code":"common.not_found","params":{"resource":"audit record"}}`
	if string(body) != want {
		t.Errorf("body = %s, want %s", body, want)
	}
}

// RespondError is the seam for the route-specific <feature>.* codes that have no helper.
func TestRespondError(t *testing.T) {
	rec := httptest.NewRecorder()
	err := RespondError(rec, http.StatusUnprocessableEntity, "datasource.unreachable",
		map[string]string{"name": "warehouse"})
	if err != nil {
		t.Fatalf("RespondError: %v", err)
	}
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422", rec.Code)
	}
	const want = `{"code":"datasource.unreachable","params":{"name":"warehouse"}}`
	if rec.Body.String() != want {
		t.Errorf("body = %s, want %s", rec.Body.String(), want)
	}

	// A nil params map still produces {}.
	rec = httptest.NewRecorder()
	if err := RespondError(rec, http.StatusBadRequest, "query.too_long", nil); err != nil {
		t.Fatalf("RespondError: %v", err)
	}
	if rec.Body.String() != `{"code":"query.too_long","params":{}}` {
		t.Errorf("body = %s", rec.Body.String())
	}
}
