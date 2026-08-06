package mcp

import (
	"slices"
	"sort"
	"strings"
	"unicode/utf16"
)

// ---------------------------------------------------------------------------------------------
// A11 §4 — `canonicalJson`, the idempotency request-hash preimage.
//
//	private fun canonicalJson(element: JsonElement): String = when (element) {
//	    is JsonObject -> element.entries.sortedBy { it.key }.joinToString(",", "{", "}") { (key, value) ->
//	        mcpJson.encodeToString(JsonPrimitive(key)) + ":" + canonicalJson(value)
//	    }
//	    is JsonArray -> element.joinToString(",", "[", "]", transform = ::canonicalJson)
//	    else -> element.toString()
//	}
//
// 🔒 THIS IS A COMPATIBILITY CONTRACT, NOT AN INTERNAL DETAIL. Its output is sha256'd into
// `mcp_mutation_idempotency.request_hash`. A Go port that renders one byte differently turns every
// row a running Kotlin instance already wrote into a spurious `mcp.idempotency_conflict` — INV-A11-11
// says "replaying a key with DIFFERENT arguments is a CONFLICT", and the client cannot tell a real
// conflict from a serializer disagreement. Area doc §11 Q2 asks whether byte-compatibility is
// required or a cutover truncation is acceptable; until that is answered, it is reproduced.
//
// Three things had to be written by hand rather than taken from encoding/json, and each is a real
// difference rather than a preference:
//
//  1. NUMBERS ARE RAW SOURCE TEXT. `1.50`, `1e5` and `-0` stay themselves. See [argValue]'s `lit`.
//  2. STRING ESCAPING IS KOTLINX'S, NOT GO'S. They still disagree on U+2028/U+2029 — see [quoteKotlinx].
//  3. KEY ORDER IS JAVA'S `String.compareTo`, i.e. UTF-16 CODE-UNIT order, not UTF-8 byte order.
// ---------------------------------------------------------------------------------------------

// canonicalJSON is `canonicalJson`.
func canonicalJSON(v argValue) string {
	var b strings.Builder
	writeCanonical(&b, v)
	return b.String()
}

func writeCanonical(b *strings.Builder, v argValue) {
	switch v.kind {
	case argObject:
		keys := make([]string, 0, len(v.obj))
		for k := range v.obj {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return compareUTF16(keys[i], keys[j]) < 0 })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			quoteKotlinx(b, k)
			b.WriteByte(':')
			writeCanonical(b, v.obj[k])
		}
		b.WriteByte('}')
	case argArray:
		b.WriteByte('[')
		for i := range v.arr {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonical(b, v.arr[i])
		}
		b.WriteByte(']')
	case argString:
		// `JsonLiteral.toString()` for isString == true is `printQuoted(body)`.
		quoteKotlinx(b, v.str)
	default:
		// A non-string literal's `toString()` is its raw body: the number token as it was parsed, or
		// `true`/`false`, or `null` for JsonNull.
		b.WriteString(v.lit)
	}
}

// compareUTF16 is `java.lang.String.compareTo`, which is what Kotlin's `sortedBy { it.key }` uses on
// String keys: a lexicographic comparison of UTF-16 CODE UNITS.
//
// ⚠️ This is NOT the same as Go's byte-wise string comparison. UTF-8 byte order equals code-point
// order; UTF-16 code-unit order does not, because a supplementary character (U+10000 and above) is
// encoded as a surrogate pair beginning at 0xD800, which sorts BELOW the BMP private-use and CJK
// compatibility range U+E000-U+FFFF. So Java orders "" AFTER "\U0001F600" while Go's `<` orders
// it before.
//
// Reachable, if narrowly: `validateArguments` restricts the TOP-LEVEL keys to schemaFor's ASCII
// property names, but nothing constrains the keys of a NESTED object a client passes as an argument
// value, and canonicalJson recurses into it before the tool ever inspects its type. Cheap to get
// right, and this is a hash input.
func compareUTF16(a, b string) int {
	if a == b {
		return 0
	}
	// Fast path: neither string leaves the BMP, so UTF-16 order and UTF-8 order agree.
	if isBMPOnly(a) && isBMPOnly(b) {
		return strings.Compare(a, b)
	}
	return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
}

func isBMPOnly(s string) bool {
	for _, r := range s {
		if r > 0xFFFF {
			return false
		}
	}
	return true
}

// quoteKotlinx is kotlinx.serialization's `printQuoted` — the exact function behind both
// `mcpJson.encodeToString(JsonPrimitive(key))` and a string `JsonPrimitive.toString()`.
//
// Its escape table (kotlinx `StringOps.kt`, `ESCAPE_STRINGS`) is 93 entries long, so ONLY code units
// below 93 are ever escaped:
//
//	0x00-0x1F  -> \u00xx, LOWERCASE hex, except the five with short forms
//	0x08 \b    0x09 \t    0x0A \n    0x0C \f    0x0D \r
//	0x22 "     -> \"
//	0x5C \     -> \\
//
// ⚠️ MEASURED THIS SESSION against go1.26.4's encoding/json, not assumed:
//
//	input    kotlinx   json.Marshal   json+SetEscapeHTML(false)
//	U+0008   \b         \b             \b        agree
//	U+000C   \f         \f             \f        agree
//	U+0001   \u0001     \u0001         \u0001    agree
//	U+007F   raw       raw            raw       agree
//	U+2028   raw        \u2028         \u2028    🔴 DIFFER
//	U+2029   raw        \u2029         \u2029    🔴 DIFFER
//	<        raw        \u003c         raw       differ unless HTML escaping is off
//
// So the stdlib is closer than it once was — historically Go emitted \u0008 / \u000c for the
// first two — but U+2028/U+2029 alone are enough to make json.Marshal unusable here, and a client
// can put either in any string argument. TestGoStdlibStillDisagreesOnTheLineSeparators is the control
// that keeps this table honest.
//
// 🔒 The deeper reason to own the table rather than track the stdlib: this output is a STORED HASH
// PREIMAGE. A future Go release that changed one escape form would silently re-hash every argument
// set and turn live idempotency rows into conflicts, with nothing in this repo changing. Pinning the
// table makes the hash a property of THIS code.
//
// Invalid UTF-8 in a Go string would be written through byte-for-byte here, where Go's encoder
// substitutes U+FFFD. Unreachable: every string in the tree came out of encoding/json's decoder,
// which already performed that substitution, so the two agree by the time this runs.
func quoteKotlinx(b *strings.Builder, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\b':
			b.WriteString(`\b`)
		case c == '\t':
			b.WriteString(`\t`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\f':
			b.WriteString(`\f`)
		case c == '\r':
			b.WriteString(`\r`)
		case c < 0x20:
			b.WriteString(`\u00`)
			const hex = "0123456789abcdef"
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0xF])
		default:
			// Everything at or above 0x20 is emitted verbatim, one BYTE at a time. Iterating bytes
			// rather than runes is deliberate and correct: the table only reaches index 92, so no
			// multi-byte sequence can contain an escapable unit (UTF-8 continuation bytes are all
			// >= 0x80), and copying bytes keeps any already-decoded text intact.
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
}
