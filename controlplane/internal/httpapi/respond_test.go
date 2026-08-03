package httpapi

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// ContentNegotiation, reduced to its two halves — `install(ContentNegotiation) { json(appJson) }`
// (App.kt:452). The plugin itself has nothing to negotiate (one converter, one media type, and the
// Kotlin never varies on Accept), so what has to be pinned is the appJson CONFIG surviving:
// INV-A1-4's `encodeDefaults = true` + `explicitNulls = false`, plus kotlinx's non-escaping of
// `<`, `>` and `&`.

// silentLogger is quietLogger's logger half, for the cases that do not inspect the log.
func silentLogger() *slog.Logger { l, _ := quietLogger(); return l }

// 🔒 INV-A1-4. Naive encoding/json gives the OPPOSITE of all three rules, so a body that ever
// bypassed types.MarshalWire would ship `null` where the console expects `[]`, an explicit `null`
// where the MCP SDK's Zod schemas require an ABSENT key, and `<` where kotlinx emits `<`.
func TestRespondJSONGoesThroughMarshalWireNotEncodingJSON(t *testing.T) {
	type body struct {
		Rows    []string `json:"rows"`
		Comment string   `json:"comment"`
		Absent  *string  `json:"absent,omitempty"`
	}

	rec := httptest.NewRecorder()
	if err := RespondJSON(rec, http.StatusOK, body{Rows: []string{}, Comment: `a < b && c > d`}); err != nil {
		t.Fatalf("RespondJSON: %v", err)
	}

	got := rec.Body.String()
	want := `{"rows":[],"comment":"a < b && c > d"}`
	if got != want {
		t.Errorf("body = %s\nwant %s", got, want)
	}
	// The escape sequences are BUILT rather than written as literals, for the same reason
	// conformance's jsonUnicodeEscape is: a literal escape in a source file is itself subject to
	// being reinterpreted between an editor, a template and a diff, and this assertion's whole job is
	// to be exact about those six characters.
	for _, c := range []byte{'<', '>', '&'} {
		escape := string([]byte{'\\', 'u', '0', '0', "0123456789abcdef"[c>>4], "0123456789abcdef"[c&0x0F]})
		if strings.Contains(got, escape) {
			t.Errorf("body carries the HTML escape %s for %q; kotlinx emits these characters raw",
				escape, string(c))
		}
	}
	// A response body has no trailing newline — json.Encoder.Encode's is stripped inside MarshalWire.
	if strings.HasSuffix(got, "\n") {
		t.Error("body ends in a newline; a response body has none")
	}
}

func TestRespondJSONWritesTheStatusAndContentType(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := RespondJSON(rec, http.StatusAccepted, map[string]string{"status": "accepted"}); err != nil {
		t.Fatalf("RespondJSON: %v", err)
	}
	assertStatus(t, rec, http.StatusAccepted, "explicit status")
	// Ktor's `withCharsetIfNeeded` appends `; charset=UTF-8` only for a `text` type, so
	// `application/json` goes out bare. See ContentTypeJSON's Unverified note.
	if ct := rec.Header().Get("Content-Type"); ct != ContentTypeJSON {
		t.Errorf("Content-Type = %q, want %q", ct, ContentTypeJSON)
	}
}

// The three error responders write the same envelopes the gates and StatusPages produce, so a route
// that reaches for one of them cannot drift from the plumbing.
func TestErrorRespondersWriteTheirEnvelopes(t *testing.T) {
	t.Run("ApiError", func(t *testing.T) {
		rec := httptest.NewRecorder()
		if err := RespondAPIError(rec, types.NotFound("datasource")); err != nil {
			t.Fatalf("RespondAPIError: %v", err)
		}
		assertStatus(t, rec, http.StatusNotFound, "notFound")
		if got, want := rec.Body.String(), `{"code":"common.not_found","params":{"resource":"datasource"}}`; got != want {
			t.Errorf("body = %s, want %s", got, want)
		}
	})

	t.Run("OAuthError", func(t *testing.T) {
		rec := httptest.NewRecorder()
		if err := RespondOAuthError(rec, types.OAuthServerError()); err != nil {
			t.Fatalf("RespondOAuthError: %v", err)
		}
		assertStatus(t, rec, http.StatusInternalServerError, "server_error")
		if got, want := rec.Body.String(), `{"error":"server_error"}`; got != want {
			t.Errorf("body = %s, want %s — error_description is ABSENT, never null", got, want)
		}
	})

	// 🔒 INV-A1-13's one exemption: English prose on the wire, because the consumer is an IdP with no
	// locale to look a code up in.
	t.Run("ScimError", func(t *testing.T) {
		rec := httptest.NewRecorder()
		if err := RespondScimError(rec, http.StatusNotImplemented, NewScimError("501", scimNotConfiguredDetail)); err != nil {
			t.Fatalf("RespondScimError: %v", err)
		}
		assertStatus(t, rec, http.StatusNotImplemented, "scim 501")
		want := `{"schemas":["` + ScimErrorSchema + `"],"status":"501","detail":"SCIM provisioning is not configured"}`
		if got := rec.Body.String(); got != want {
			t.Errorf("body = %s\nwant %s", got, want)
		}
	})
}

// The Kotlin default is `listOf(SCIM_ERROR_SCHEMA)`, NOT emptyList(), so a nil slice must become the
// ONE-ELEMENT default rather than `[]`. An IdP that receives `"schemas": []` cannot tell what it is
// holding, and every construction site in the port writes `ScimError{Status: …}` without it.
func TestScimErrorDefaultsSchemasToTheURNNotAnEmptyList(t *testing.T) {
	raw, err := types.MarshalWire(ScimError{Status: "409"})
	if err != nil {
		t.Fatalf("MarshalWire: %v", err)
	}
	want := `{"schemas":["` + ScimErrorSchema + `"],"status":"409"}`
	if string(raw) != want {
		t.Errorf("bytes = %s\nwant %s", raw, want)
	}
}

// ---------------------------------------------------------------------------------------------
// Receive — `call.receive<T>()` with appJson
// ---------------------------------------------------------------------------------------------

// `ignoreUnknownKeys = true` is encoding/json's default, so a client sending a field the port does
// not know must not fail the decode. A rejection here would break every rolling deploy where the
// console ships a new field before the server does.
func TestReceiveIgnoresUnknownKeys(t *testing.T) {
	var dst struct {
		Name string `json:"name"`
	}
	r := httptest.NewRequest(http.MethodPost, "/api/tokens",
		strings.NewReader(`{"name":"ci-runner","somethingNewTheConsoleSends":42}`))

	if err := Receive(r, &dst); err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if dst.Name != "ci-runner" {
		t.Errorf("name = %q, want ci-runner", dst.Name)
	}
}

// A decode failure is RETURNED, never responded to: the caller chooses the code, because the
// Kotlin's choice differs per route (400 common.field_required, 400 <feature>.invalid_request, and a
// bare 400 in a few places). Collapsing them in the helper would flatten a distinction the web
// depends on.
func TestReceiveReturnsTheDecodeErrorRatherThanAnswering(t *testing.T) {
	var dst struct {
		Name string `json:"name"`
	}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/tokens", strings.NewReader(`{"name":`))

	if err := Receive(r, &dst); err == nil {
		t.Fatal("Receive must return the decode error")
	}
	if rec.Body.Len() != 0 || rec.Code != http.StatusOK {
		t.Error("Receive wrote to the response; choosing the status is the caller's job")
	}
}

// The size cap is a PORT ADDITION, not a Kotlin behaviour: Netty caps a request body long before a
// control-plane handler sees it, and net/http has no equivalent, so leaving it out would be a silent
// widening rather than a faithful port. A hostile gigabyte must not be buffered.
func TestReceiveIsBoundedByMaxRequestBodyBytes(t *testing.T) {
	var dst struct {
		Name string `json:"name"`
	}
	// Valid JSON, but its string value alone exceeds the cap — so the reader is cut mid-token and the
	// decoder sees a truncated document rather than allocating the whole thing.
	oversized := `{"name":"` + strings.Repeat("a", MaxRequestBodyBytes) + `"}`
	r := httptest.NewRequest(http.MethodPost, "/api/tokens", strings.NewReader(oversized))

	if err := Receive(r, &dst); err == nil {
		t.Fatalf("a %d-byte body decoded successfully; the %d-byte cap is not applied",
			len(oversized), MaxRequestBodyBytes)
	}
}

// A body just under the cap still decodes — the bound must not be so tight that a legitimate policy
// source or catalog fragment (kilobytes, but occasionally large) is rejected.
func TestReceiveAcceptsABodyUnderTheCap(t *testing.T) {
	var dst struct {
		Name string `json:"name"`
	}
	value := strings.Repeat("a", 1<<20) // 1 MiB, comfortably under 8 MiB
	r := httptest.NewRequest(http.MethodPost, "/api/tokens", strings.NewReader(`{"name":"`+value+`"}`))

	if err := Receive(r, &dst); err != nil {
		t.Fatalf("Receive on a 1 MiB body: %v", err)
	}
	if len(dst.Name) != len(value) {
		t.Errorf("decoded %d bytes, want %d", len(dst.Name), len(value))
	}
}
