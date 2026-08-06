package mcp

import (
	"bufio"
	"bytes"
	"embed"
	"fmt"
	"net/http"
	"strings"

	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// A11 §5 — the two JVM `ResourceBundle`s, as an embed.FS (D11).
//
// 🔒 INV-A11-15 — MCP errors ship BOTH locales inline (`message_en` AND `message_ko`), unlike REST,
// which returns a bare code for `web/` to look up (INV-A1-13). An MCP client has no message catalog,
// so the server resolves both. That is why this file exists at all.
//
// D11 (99-library-decisions.md §9) chose embed.FS + a hand-written reader over go-i18n or x/text, and
// the deciding fact is the placeholder syntax: these files use NAMED `{resource}` placeholders, not
// MessageFormat's `{0}` and not go-i18n's `{{.Name}}`. Rewriting 128 lines into a library's syntax
// would be a WIRE CHANGE dressed up as a refactor, because `mcp_tools` text is the tool description
// every MCP client displays.
//
// 🔴 The four files under resources/ are BYTE-FOR-BYTE COPIES of
// control-plane/src/main/resources/mcp_{errors,tools}_{en,ko}.properties (verified by sha256 when
// copied, and re-asserted by TestBundlesAreByteIdenticalToTheKotlinResources where the Kotlin tree is
// reachable). Keeping them identical is what makes them diffable during cutover.
// ---------------------------------------------------------------------------------------------

//go:embed resources/mcp_errors_en.properties resources/mcp_errors_ko.properties
//go:embed resources/mcp_tools_en.properties resources/mcp_tools_ko.properties
var bundleFS embed.FS

// Locale is the two-value subset of `java.util.Locale` this area uses: `Locale.ENGLISH` and
// `Locale.KOREAN`, the only two `messageFor`/`toolDescription` are ever called with.
//
// It is NOT a general locale type. `requestLocale` maps every Accept-Language that is not a `ko`
// prefix onto English, so there is no third value to represent and no negotiation to do.
type Locale string

const (
	// LocaleEnglish is `Locale.ENGLISH` — the default for every request that does not ask for Korean.
	LocaleEnglish Locale = "en"
	// LocaleKorean is `Locale.KOREAN`.
	LocaleKorean Locale = "ko"
)

// bundles holds the four parsed catalogs, keyed by base name then locale. Parsed once at package
// init: a malformed embedded bundle is a programming error, not a runtime condition, and
// ResourceBundle.getBundle would likewise fail on first use.
var bundles = map[string]map[Locale]map[string]string{
	"mcp_errors": {
		LocaleEnglish: mustBundle("resources/mcp_errors_en.properties"),
		LocaleKorean:  mustBundle("resources/mcp_errors_ko.properties"),
	},
	"mcp_tools": {
		LocaleEnglish: mustBundle("resources/mcp_tools_en.properties"),
		LocaleKorean:  mustBundle("resources/mcp_tools_ko.properties"),
	},
}

func mustBundle(name string) map[string]string {
	raw, err := bundleFS.ReadFile(name)
	if err != nil {
		panic(fmt.Sprintf("mcp: embedded bundle %s: %v", name, err))
	}
	return parseProperties(raw)
}

// parseProperties is the `.properties` reader D11 sizes at "~30 lines of key=value".
//
// It is deliberately NOT a full java.util.Properties implementation. The six control-plane bundles
// were verified free of backslash escapes and `\uXXXX` sequences (99-library-decisions.md §9:
// "`grep -c '\\\\'` → 0 on all six; `grep -l '\\u'` → none"), and they are raw UTF-8 rather than
// Latin-1 — so continuation lines, `\:`/`\=` escapes, `!` comments and `:`-separated keys are all
// unreachable and implementing them would be untested code on a wire-visible path.
//
// What IS handled, because it is what the files contain: `key=value` at the first `=`, with the value
// taken VERBATIM to end of line (no trimming — a trailing space would be part of the message, and
// Properties keeps it too), blank lines skipped, and `#` comments skipped.
func parseProperties(raw []byte) map[string]string {
	out := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	// A message line is short, but the default 64 KiB token limit is left in place rather than raised:
	// a bundle line longer than that is a corrupted file, and silently truncating one would ship a
	// half message to every MCP client.
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		eq := strings.IndexByte(trimmed, '=')
		if eq < 0 {
			continue
		}
		out[strings.TrimRight(trimmed[:eq], " \t")] = trimmed[eq+1:]
	}
	return out
}

// errMissingBundleKey is the Go stand-in for `java.util.MissingResourceException`, which
// `ResourceBundle.getString` throws for an unknown key.
//
// 🔒 It is an ERROR RETURN, not a fallback string, because the Kotlin's throw is observable: it
// escapes `localizedError`, which runs INSIDE the tool handler's catch chain but is itself outside any
// further try, so the exception leaves the handler and the SDK turns it into a JSON-RPC protocol
// error rather than a tool result. A port that substituted the key for a missing message would answer
// 200 with a nonsense message where the Kotlin answers a protocol error — and would hide the real bug,
// which is an ApiError code that no bundle localizes.
var errMissingBundleKey = fmt.Errorf("mcp: missing resource-bundle key")

// bundleString is `ResourceBundle.getBundle(base, locale).getString(key)`.
//
// ⚠️ NO PARENT-BUNDLE FALLBACK. The JVM would fall back `mcp_errors_ko` → `mcp_errors_<default>` →
// `mcp_errors` (the base file) for a key missing from the Korean bundle. There is no base
// `mcp_errors.properties` in the repo (verified: the resources directory holds only the `_en`/`_ko`
// pairs), so on the JVM a key present in `_en` and missing from `_ko` falls through to the JVM
// DEFAULT LOCALE's bundle and then throws — i.e. its behaviour depends on the container's locale.
// Both bundles carry all 18 keys today and TestEveryErrorCodeHasBothLocales keeps it that way, which
// is the only reason this simplification is safe. Recorded rather than emulated: emulating it would
// mean reproducing `Locale.getDefault()` sensitivity, which is a JVM artifact.
func bundleString(base string, locale Locale, key string) (string, error) {
	catalog, ok := bundles[base][locale]
	if !ok {
		return "", fmt.Errorf("%w: no bundle %s_%s", errMissingBundleKey, base, locale)
	}
	value, ok := catalog[key]
	if !ok {
		return "", fmt.Errorf("%w: %s_%s has no key %q", errMissingBundleKey, base, locale, key)
	}
	return value, nil
}

// messageFor is `private fun messageFor(error: ApiError, locale: Locale): String`:
//
//	var message = bundle.getString(error.code)
//	error.params.forEach { (key, value) -> message = message.replace("{$key}", value) }
//
// ⚠️ It is a naive sequential `String.replace`, not a template engine, and three of its properties are
// observable:
//
//   - A `{param}` with no matching key stays in the message LITERALLY. `common.forbidden` interpolated
//     without a `detail` param renders "Forbidden: {detail}".
//   - A param the message does not mention is silently unused.
//   - The replacement is done IN MAP ITERATION ORDER, so a value that itself contains `{other}` can be
//     re-substituted by a later param. Unreachable with today's params (none contains a brace) and
//     reproduced by doing the same thing rather than by pre-scanning.
//
// ⚠️ Go's map iteration order is RANDOM where Kotlin's LinkedHashMap is insertion-ordered. That only
// matters for the third property above, which no current message can trigger; the keys are iterated
// SORTED here so the order is at least deterministic and a future divergence is reproducible rather
// than flaky.
func messageFor(e types.ApiError, locale Locale) (string, error) {
	message, err := bundleString("mcp_errors", locale, e.Code)
	if err != nil {
		return "", err
	}
	for _, key := range sortedKeys(e.Params) {
		message = strings.ReplaceAll(message, "{"+key+"}", e.Params[key])
	}
	return message, nil
}

// toolDescription is `private fun toolDescription(toolName, locale)` — `mcp_tools`'s entry for the
// tool.
//
// 🔒 The returned text is ON THE MCP WIRE: it is `Tool.description`, which every client displays and
// every model reads. Q5 records it as part of the tool contract, which is why the bundle files are
// carried byte-for-byte rather than reworded.
//
// A missing key throws MissingResourceException on the JVM — during `createMcpServer`, i.e. while
// BUILDING the per-request server, before any tool runs. Here the error is returned and the caller
// fails the request the same way.
func toolDescription(toolName string, locale Locale) (string, error) {
	return bundleString("mcp_tools", locale, toolName)
}

// requestLocale is `private fun requestLocale(call)`:
//
//	if (call.request.headers[AcceptLanguage]?.lowercase(Locale.ROOT)?.startsWith("ko") == true)
//	    Locale.KOREAN else Locale.ENGLISH
//
// ⚠️ It is a PREFIX TEST ON THE RAW HEADER, not RFC 4647 language-range negotiation. Three consequences
// are reproduced verbatim because they are observable:
//
//   - `ko-KR,en;q=0.9` is Korean (prefix match), and so is `korean-nonsense`.
//   - `en,ko;q=0.9` is ENGLISH — a client that lists Korean second gets English, whatever the weights
//     say.
//   - Only the FIRST header instance matters in Ktor (`headers[name]`), unlike the trusted-edge
//     resolvers a few lines away, which deliberately take the LAST. Go's Header.Get is also the first
//     instance, so this one lines up for free.
//
// `lowercase(Locale.ROOT)` is locale-independent lowering; strings.ToLower is too. The Turkish-dotless-I
// hazard that makes `lowercase()` without an explicit locale dangerous on the JVM does not arise for
// the two ASCII letters compared here.
func requestLocale(r *http.Request) Locale {
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Accept-Language")), "ko") {
		return LocaleKorean
	}
	return LocaleEnglish
}
