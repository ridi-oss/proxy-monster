package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// idParam() — Datasources.kt:707, `parameters["id"]?.toLongOrNull()`, used by eight route files.
//
// The accepted set IS the contract: every one of the ~60 call sites reads
// `id := IDParam(r); if id == nil { badId() }`, so anything this function accepts becomes a lookup
// and anything it rejects becomes a 400. Widening it (base 0, whitespace tolerance) turns inputs the
// Kotlin 400s into database round trips; narrowing it turns 404s into 400s.

// 🔒 The accepted set is `String.toLongOrNull()`'s, NOT strconv.ParseInt's defaults. The two differ
// in exactly the places a careless port gets wrong: base-0 prefixes and underscores.
func TestIDParamAcceptsExactlyWhatToLongOrNullAccepts(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want *int64
	}{
		// Accepted by both.
		{"1", ptr64(1)},
		{"0", ptr64(0)},
		{"9223372036854775807", ptr64(9223372036854775807)}, // Long.MAX_VALUE
		{"-9223372036854775808", ptr64(-9223372036854775808)},
		// A leading sign parses in both. `-1` then finds no row and 404s — the Kotlin does the same,
		// and turning it into a 400 here would be a fix, not a port.
		{"-1", ptr64(-1)},
		{"+7", ptr64(7)},

		// Rejected by both.
		{"", nil},
		{"9223372036854775808", nil}, // Long.MAX_VALUE + 1 overflows in both
		{"abc", nil},
		{"1.0", nil},
		{"1e3", nil},

		// ⚠️ The four that separate toLongOrNull from a base-0 ParseInt. Passing 0 for the base would
		// silently accept all four.
		{"0x10", nil},
		{"0b11", nil},
		{"0o17", nil},
		{"1_000", nil},

		// `010` is DECIMAL TEN in Kotlin, not octal eight. Base 10 gives the same; base 0 would give 8,
		// which is a wrong ROW rather than a rejection — the worst of the three outcomes.
		{"010", ptr64(10)},

		// No whitespace tolerance in either.
		{" 1", nil},
		{"1 ", nil},
		{"\t1", nil},
	} {
		t.Run("id="+tc.raw, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/probe", nil)
			r.SetPathValue("id", tc.raw)
			got := IDParam(r)
			switch {
			case tc.want == nil && got != nil:
				t.Errorf("IDParam(%q) = %d, want nil", tc.raw, *got)
			case tc.want != nil && got == nil:
				t.Errorf("IDParam(%q) = nil, want %d", tc.raw, *tc.want)
			case tc.want != nil && got != nil && *got != *tc.want:
				t.Errorf("IDParam(%q) = %d, want %d", tc.raw, *got, *tc.want)
			}
		})
	}
}

// Nil is the ONE failure value and it covers "no {id} in the pattern" as well as "present but not a
// Long" — which is why every call site is a single `if id == nil` branch.
func TestIDParamIsNilWhenThePatternHasNoIDWildcard(t *testing.T) {
	if got := IDParam(httptest.NewRequest(http.MethodGet, "/api/datasources", nil)); got != nil {
		t.Errorf("IDParam = %d for a request with no {id} in its pattern, want nil", *got)
	}
}

// The four other wildcard names the route table uses. 03-identity-scim.md:230: "{userId} / {roleId}
// are parsed the same way."
func TestNamedIDParamReadsTheOtherWildcards(t *testing.T) {
	for _, name := range []string{"taskId", "sessionId", "userId", "roleId"} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/probe", nil)
			r.SetPathValue(name, "42")
			got := NamedIDParam(r, name)
			if got == nil || *got != 42 {
				t.Fatalf("NamedIDParam(%q) = %v, want 42", name, got)
			}
			// A wildcard the pattern does not declare reads as absent, not as the {id} one.
			if other := NamedIDParam(r, "id"); other != nil {
				t.Errorf("NamedIDParam(id) = %d, want nil — wildcards must not bleed", *other)
			}
		})
	}
}

// The realistic path: through a real ServeMux pattern, which is where PathValue gets populated in
// production. Guards against the params helper and the router disagreeing about wildcard names.
func TestIDParamThroughARealServeMuxPattern(t *testing.T) {
	var seen *int64
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/datasources/{id}", func(w http.ResponseWriter, r *http.Request) {
		seen = IDParam(r)
		w.WriteHeader(http.StatusOK)
	})

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/datasources/17", nil))
	if seen == nil || *seen != 17 {
		t.Fatalf("IDParam through the mux = %v, want 17", seen)
	}

	seen = nil
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/datasources/nope", nil))
	if seen != nil {
		t.Errorf("IDParam through the mux = %d for a non-numeric segment, want nil", *seen)
	}
}

func ptr64(v int64) *int64 { return &v }
