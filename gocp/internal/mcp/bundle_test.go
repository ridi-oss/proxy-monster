package mcp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// A11 §5 / D11 — the four resource bundles. All NEW: the Kotlin's only assertion about them is
// `McpServerDbTest` case 4's `assertContains(create_role's description, "역할")`.
// ---------------------------------------------------------------------------------------------

// errorCodes is every ApiError code this area can emit into `localizedError`. Assembled by hand from
// the raise sites rather than from the bundle, so a code with no message FAILS instead of the test
// quietly shrinking to whatever the bundle happens to contain.
var errorCodes = []string{
	// raised in this package
	"mcp.insufficient_scope", "mcp.idempotency_conflict", "mcp.invalid_request", "mcp.internal_error",
	"common.forbidden", "common.field_required", "common.not_found",
	// raised by internal/management and reaching the MCP edge unchanged
	"common.already_exists",
	"datasource.reserved_tag", "datasource.schema_required", "datasource.table_introspection_failed",
	"group.system_immutable", "role.system_immutable",
	"policy.reserved_name", "policy.system_immutable",
	// emitted by the interceptor rather than by localizedError, but present in the bundle
	"mcp.invalid_host", "mcp.invalid_origin",
}

// TestEveryErrorCodeHasBothLocales is the precondition [bundleString]'s "no parent-bundle fallback"
// simplification rests on.
//
// 🔒 INV-A11-15 ships BOTH locales inline on every error, so a code missing from `mcp_errors_ko` is
// not a cosmetic gap: [Routes.localizedError] returns an error, the SDK answers a JSON-RPC protocol
// failure, and the client sees nothing about what it actually did wrong.
func TestEveryErrorCodeHasBothLocales(t *testing.T) {
	for _, code := range errorCodes {
		for _, locale := range []Locale{LocaleEnglish, LocaleKorean} {
			msg, err := bundleString("mcp_errors", locale, code)
			if err != nil {
				t.Errorf("mcp_errors_%s is missing %q", locale, code)
				continue
			}
			if msg == "" {
				t.Errorf("mcp_errors_%s[%q] is empty", locale, code)
			}
		}
	}
}

// TestEveryToolHasADescriptionInBothLocales — 🔒 the description is ON THE MCP WIRE, so a missing key
// fails the whole `tools/list`, not just one tool: [Routes.newServer] returns the error and the
// request dies.
func TestEveryToolHasADescriptionInBothLocales(t *testing.T) {
	for _, c := range Entries {
		for _, locale := range []Locale{LocaleEnglish, LocaleKorean} {
			desc, err := toolDescription(c.ToolName, locale)
			if err != nil {
				t.Errorf("mcp_tools_%s is missing %q", locale, c.ToolName)
				continue
			}
			if isBlank(desc) {
				t.Errorf("mcp_tools_%s[%q] is blank", locale, c.ToolName)
			}
		}
	}
	// `McpServerDbTest` case 4's own assertion, kept: the Korean description of create_role must
	// actually be Korean.
	ko, err := toolDescription("create_role", LocaleKorean)
	if err != nil {
		t.Fatalf("create_role ko: %v", err)
	}
	if want := "역할"; !contains(ko, want) {
		t.Errorf("create_role ko = %q, want it to contain %q", ko, want)
	}
}

// TestBundlesAreByteIdenticalToTheKotlinResources is D11's "keep the 6 files byte-for-byte".
//
// 🔒 It compares BYTES, not parsed keys. `mcp_tools` text is wire-visible, so a reworded description
// is a wire change; keeping the files identical is also what makes them diffable against the Kotlin
// during cutover.
//
// It FAILS rather than skips when the Kotlin tree cannot be found — the same posture internal/dbtest
// takes about Docker. A silently skipped byte-identity check is how the two copies drift.
func TestBundlesAreByteIdenticalToTheKotlinResources(t *testing.T) {
	kotlin := findKotlinResources(t)
	for _, name := range []string{
		"mcp_errors_en.properties", "mcp_errors_ko.properties",
		"mcp_tools_en.properties", "mcp_tools_ko.properties",
	} {
		want, err := os.ReadFile(filepath.Join(kotlin, name))
		if err != nil {
			t.Fatalf("reading the Kotlin %s: %v", name, err)
		}
		got, err := bundleFS.ReadFile("resources/" + name)
		if err != nil {
			t.Fatalf("reading the embedded %s: %v", name, err)
		}
		if string(got) != string(want) {
			t.Errorf("%s differs from the Kotlin resource (%d vs %d bytes)", name, len(got), len(want))
		}
	}
}

// findKotlinResources walks up from the working directory looking for the Kotlin control plane's
// resource directory, the way internal/dbtest locates db-support.json — 00-INDEX.md F9 flags a fixed
// `../../` path into another module as a cutover hazard.
func findKotlinResources(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		candidate := filepath.Join(dir, "control-plane", "src", "main", "resources")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find control-plane/src/main/resources above the working directory — " +
				"the byte-identity check cannot run, and skipping it is how the two copies drift")
		}
		dir = parent
	}
}

func TestMessageInterpolationIsANaiveSequentialReplace(t *testing.T) {
	cases := []struct {
		name   string
		err    types.ApiError
		locale Locale
		want   string
	}{
		{
			"a single named param",
			types.ApiError{Code: "common.not_found", Params: map[string]string{"resource": "datasource"}},
			LocaleEnglish, "No such datasource.",
		},
		{
			"the Korean bundle interpolates the same key",
			types.ApiError{Code: "common.not_found", Params: map[string]string{"resource": "datasource"}},
			LocaleKorean, "datasource 항목을 찾을 수 없습니다.",
		},
		{
			// ⚠️ REPRODUCED QUIRK: no param, no substitution — the placeholder is rendered LITERALLY.
			// `common.forbidden` with no `detail` really does say "Forbidden: {detail}" on the wire.
			"a missing param leaves the placeholder in the message",
			types.ApiError{Code: "common.forbidden"},
			LocaleEnglish, "Forbidden: {detail}",
		},
		{
			"an unused param is ignored",
			types.ApiError{Code: "mcp.internal_error", Params: map[string]string{"nope": "x"}},
			LocaleEnglish, "The MCP operation failed.",
		},
		{
			"the scope param reaches the insufficient-scope message",
			types.ApiError{Code: "mcp.insufficient_scope", Params: map[string]string{"scope": ScopePoliciesWrite}},
			LocaleEnglish, "The OAuth token does not include the required scope: mcp:policies:write.",
		},
		{
			"the reserved-tag message quotes the offending tag",
			types.ApiError{Code: "datasource.reserved_tag", Params: map[string]string{"tag": "system:pii"}},
			LocaleEnglish, `The tag "system:pii" is reserved for system classification.`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := messageFor(c.err, c.locale)
			if err != nil {
				t.Fatalf("messageFor: %v", err)
			}
			if got != c.want {
				t.Errorf("messageFor = %q, want %q", got, c.want)
			}
		})
	}
}

// TestAnUnknownCodeIsAnErrorNotAFallbackString pins the MissingResourceException analogue.
//
// 🔒 A fallback ("return the code") would ship a nonsense message on a 200 and hide the real bug — an
// ApiError code no bundle localizes — behind a plausible-looking response.
func TestAnUnknownCodeIsAnErrorNotAFallbackString(t *testing.T) {
	_, err := messageFor(types.ApiError{Code: "totally.unknown"}, LocaleEnglish)
	if !errors.Is(err, errMissingBundleKey) {
		t.Fatalf("messageFor(unknown) = %v, want errMissingBundleKey", err)
	}
}

// TestRequestLocaleIsAPrefixTestNotContentNegotiation pins all three reproduced quirks.
func TestRequestLocaleIsAPrefixTestNotContentNegotiation(t *testing.T) {
	cases := []struct {
		header string
		want   Locale
	}{
		{"", LocaleEnglish},
		{"ko", LocaleKorean},
		{"KO-kr", LocaleKorean},
		{"ko-KR,en;q=0.9", LocaleKorean},
		// ⚠️ A client that lists Korean SECOND gets English, whatever the q-weights say.
		{"en,ko;q=0.9", LocaleEnglish},
		// ⚠️ Any header starting "ko" is Korean, including nonsense.
		{"korean-nonsense", LocaleKorean},
		{"en-GB", LocaleEnglish},
		{"*", LocaleEnglish},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		if c.header != "" {
			r.Header.Set("Accept-Language", c.header)
		}
		if got := requestLocale(r); got != c.want {
			t.Errorf("requestLocale(%q) = %q, want %q", c.header, got, c.want)
		}
	}
}

// TestThePropertiesReaderTakesTheValueVerbatimAfterTheFirstEquals pins the reader's three rules
// against inputs the shipped bundles do not contain but a future edit might.
func TestThePropertiesReaderTakesTheValueVerbatimAfterTheFirstEquals(t *testing.T) {
	got := parseProperties([]byte(
		"# a comment\n" +
			"\n" +
			"  # an indented comment\n" +
			"a.b=plain\n" +
			"with.equals=lhs=rhs\n" +
			"  spaced.key  =value with trailing space \n" +
			"no.equals.line\n" +
			"empty.value=\n"))
	want := map[string]string{
		"a.b":         "plain",
		"with.equals": "lhs=rhs",
		"spaced.key":  "value with trailing space ",
		"empty.value": "",
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("parsed[%q] = %q, want %q", k, got[k], v)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
