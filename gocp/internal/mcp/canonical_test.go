package mcp

import (
	"encoding/json"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
)

// ---------------------------------------------------------------------------------------------
// A11 §4 — `canonicalJson`, the idempotency request-hash preimage.
//
// 🔴 ALL NEW. 11-mcp-oauth-management.md §9 lists "the canonicalJson hash stability (INV-A11-11's
// compatibility contract)" among the things NOTHING tests, and §11 Q2 asks whether the Go port must be
// byte-compatible. Until Q2 is answered "no", every case below is a wire contract: its output is
// sha256'd into `mcp_mutation_idempotency.request_hash`, and a one-byte difference turns every row a
// running Kotlin instance already wrote into a spurious `mcp.idempotency_conflict`.
// ---------------------------------------------------------------------------------------------

// mustArgs parses a JSON object the way the tool dispatcher does.
func mustArgs(t *testing.T, raw string) argValue {
	t.Helper()
	v, err := parseArguments(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("parseArguments(%s): %v", raw, err)
	}
	return v
}

func TestCanonicalJSONSortsObjectKeysAndPreservesArrayOrder(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty object", `{}`, `{}`},
		{"keys are sorted, not insertion-ordered", `{"z":1,"a":2,"m":3}`, `{"a":2,"m":3,"z":1}`},
		{"arrays keep their order", `{"tags":["c","a","b"]}`, `{"tags":["c","a","b"]}`},
		{"nested objects sort too", `{"o":{"b":1,"a":2}}`, `{"o":{"a":2,"b":1}}`},
		{"arrays of objects", `{"a":[{"y":1,"x":2}]}`, `{"a":[{"x":2,"y":1}]}`},
		{"null is a literal", `{"a":null}`, `{"a":null}`},
		{"booleans", `{"a":true,"b":false}`, `{"a":true,"b":false}`},
		{"empty array", `{"a":[]}`, `{"a":[]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := canonicalJSON(mustArgs(t, c.in)); got != c.want {
				t.Errorf("canonicalJSON = %s, want %s", got, c.want)
			}
		})
	}
}

// TestCanonicalJSONKeepsANumbersSourceText is the single most likely silent hash break.
//
// 🔒 kotlinx's `JsonPrimitive.toString()` on a parsed number returns the RAW TOKEN. A Go port that
// decoded into float64 — which `map[string]any` does by default — would render `1.50` as `1.5`,
// `1e5` as `100000` and `-0` as `0`, and every one of those is a different sha256.
func TestCanonicalJSONKeepsANumbersSourceText(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"n":1.50}`, `{"n":1.50}`},
		{`{"n":1e5}`, `{"n":1e5}`},
		{`{"n":1E5}`, `{"n":1E5}`},
		{`{"n":-0}`, `{"n":-0}`},
		{`{"n":0.10}`, `{"n":0.10}`},
		{`{"n":10000000000000000000000}`, `{"n":10000000000000000000000}`},
		{`{"n":1.0000000000000000000001}`, `{"n":1.0000000000000000000001}`},
	}
	for _, c := range cases {
		if got := canonicalJSON(mustArgs(t, c.in)); got != c.want {
			t.Errorf("canonicalJSON(%s) = %s, want %s", c.in, got, c.want)
		}
	}
}

// TestStringEscapingIsKotlinxsNotGos pins the four inputs where encoding/json and kotlinx disagree,
// plus the three where Go's HTML escaping would differ if SetEscapeHTML(false) were forgotten.
//
// 🔒 Each row is a hash difference. `\b` alone is enough to make a stored `request_hash` unmatchable.
func TestStringEscapingIsKotlinxsNotGos(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"backspace uses the short form, not \\u0008", "\b", `"\b"`},
		{"form feed uses the short form, not \\u000c", "\f", `"\f"`},
		{"tab", "\t", `"\t"`},
		{"newline", "\n", `"\n"`},
		{"carriage return", "\r", `"\r"`},
		{"quote", `"`, `"\""`},
		{"backslash", `\`, `"\\"`},
		{"another control character is \\u00xx in LOWERCASE hex", "\x01", `"\u0001"`},
		{"0x1f is the last escaped code unit", "\x1f", `"\u001f"`},
		{"U+2028 is emitted RAW; encoding/json escapes it", " ", "\" \""},
		{"U+2029 is emitted RAW", " ", "\" \""},
		{"DEL is not escaped", "\x7f", "\"\x7f\""},
		{"< is not HTML-escaped", "<", `"<"`},
		{"> is not HTML-escaped", ">", `">"`},
		{"& is not HTML-escaped", "&", `"&"`},
		{"/ is not escaped", "/", `"/"`},
		{"non-ASCII is emitted as UTF-8", "역할", `"역할"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := argValue{kind: argString, str: c.in}
			var got string
			func() {
				defer func() {}()
				got = canonicalJSON(argValue{kind: argObject, obj: map[string]argValue{"k": v}})
			}()
			want := `{"k":` + c.want + `}`
			if got != want {
				t.Errorf("canonicalJSON = %q, want %q", got, want)
			}
		})
	}
}

// TestGoStdlibStillDisagreesOnTheLineSeparators is the CONTROL for the case above: without it, a
// reader cannot tell whether the hand-rolled quoter is necessary or just a longer way of writing
// json.Marshal.
//
// 🔴 IT ALREADY EARNED ITS KEEP. An earlier revision of this file asserted that go1.26.4 disagreed
// with kotlinx on \\b and \\f as well; running the control showed the stdlib now emits both short forms,
// so the comment on [quoteKotlinx] was corrected against measurement rather than left as folklore.
// What REMAINS different is U+2028 and U+2029, which encoding/json escapes and kotlinx emits raw.
//
// If the stdlib ever agrees on those too, this fails and somebody gets to delete [quoteKotlinx]
// deliberately — which is still the wrong move while the output is a stored hash preimage, but it
// should be a decision rather than a drift.
func TestGoStdlibStillDisagreesOnTheLineSeparators(t *testing.T) {
	for _, in := range []string{"\u2028", "\u2029"} {
		stdlib, err := json.Marshal(in) // HTML escaping is irrelevant for these two.
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		ours := canonicalJSON(argValue{kind: argString, str: in})
		if string(stdlib) == ours {
			t.Errorf("encoding/json and quoteKotlinx now AGREE on %q (%s) — "+
				"re-check whether the hand-rolled quoter is still needed", in, ours)
		}
	}
	// The other direction, also measured: the five short forms and the \\u00xx fallback DO agree today,
	// so the table below is not what makes those cases pass — owning it is what stops a future stdlib
	// change from moving the hash.
	for _, in := range []string{"\b", "\f", "\t", "\n", "\r", "\x01", "\x7f"} {
		stdlib, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if ours := canonicalJSON(argValue{kind: argString, str: in}); string(stdlib) != ours {
			t.Logf("note: encoding/json and quoteKotlinx disagree on %q (stdlib %s, ours %s)", in, stdlib, ours)
		}
	}
}

// TestObjectKeysSortByUTF16CodeUnitNotUTF8Byte pins the third hand-written piece.
//
// Java's `String.compareTo` compares UTF-16 CODE UNITS, so a supplementary character (encoded as a
// surrogate pair starting at 0xD800) sorts BELOW the BMP range U+E000-U+FFFF. Go's `<` on strings
// compares UTF-8 bytes, which is code-point order, and puts it above.
func TestObjectKeysSortByUTF16CodeUnitNotUTF8Byte(t *testing.T) {
	const bmp = ""             // BMP private use
	const astral = "\U0001F600" // 😀, a surrogate pair in UTF-16
	obj := argValue{kind: argObject, obj: map[string]argValue{
		bmp:    {kind: argLiteral, lit: "1"},
		astral: {kind: argLiteral, lit: "2"},
	}}
	got := canonicalJSON(obj)
	want := `{"` + astral + `":2,"` + bmp + `":1}`
	if got != want {
		t.Errorf("canonicalJSON = %q, want %q (UTF-16 order puts the surrogate pair first)", got, want)
	}
	// The CONTROL: plain Go string comparison would order them the other way, so the test above is
	// actually exercising compareUTF16 rather than agreeing with the default by luck.
	if !(bmp < astral) {
		t.Fatal("premise broke: UTF-8 byte order was expected to put the BMP key FIRST, " +
			"which is what makes the UTF-16 ordering above a real difference rather than a coincidence")
	}
	if compareUTF16(astral, bmp) >= 0 {
		t.Error("compareUTF16 did not put the surrogate pair first")
	}
}

// TestTheHashPreimageForARepresentativeMutation is a GOLDEN VALUE.
//
// It is not a cross-check against the Kotlin (no JVM on this box — `gradle not found`), so it does not
// prove byte-compatibility with a running Kotlin instance. What it does prove is that the preimage is
// STABLE: any future edit to canonicalJson, to the escape table, or to number handling changes this
// string and fails here rather than silently invalidating stored idempotency rows.
//
//	TODO(A11): during cutover, run the Kotlin's canonicalJson over the same arguments and confirm the
//	two hashes match. That is the only thing that closes §11 Q2.
func TestTheHashPreimageForARepresentativeMutation(t *testing.T) {
	args := mustArgs(t, `{
		"idempotencyKey": "must-not-appear",
		"datasource": "warehouse",
		"schema": null,
		"table": "users",
		"column": "rrn",
		"tags": ["pii", "kr-rrn"],
		"maskFnName": "last4",
		"enabled": true,
		"count": 1.50
	}`)
	preimage := canonicalJSON(args.without("idempotencyKey"))
	const want = `{"column":"rrn","count":1.50,"datasource":"warehouse","enabled":true,` +
		`"maskFnName":"last4","schema":null,"table":"users","tags":["pii","kr-rrn"]}`
	if preimage != want {
		t.Fatalf("preimage =\n  %s\nwant\n  %s", preimage, want)
	}
	// 🔒 The idempotency key itself is EXCLUDED from the hash — that is what lets the same arguments
	// under a different key be a fresh call rather than a conflict.
	if contains(preimage, "must-not-appear") {
		t.Error("the idempotency key leaked into its own request hash")
	}
	got := session.SHA256Hex(preimage)
	const wantHash = "aca2b7fbd92a6a8c034a39cf96c0170ea14bc9c21f1dd6e45d5380e3bec8fa9e"
	if got != wantHash {
		t.Errorf("request hash = %s\nwant          %s\n(if this changed deliberately, every stored "+
			"mcp_mutation_idempotency row becomes a spurious conflict — see INV-A11-11)", got, wantHash)
	}
}

// TestTheSameArgumentsInADifferentOrderHashTheSame is the property the sort exists for: a client that
// serialises its arguments in a different key order must REPLAY, not CONFLICT.
func TestTheSameArgumentsInADifferentOrderHashTheSame(t *testing.T) {
	a := canonicalJSON(mustArgs(t, `{"name":"r","description":"d","enabled":true}`))
	b := canonicalJSON(mustArgs(t, `{"enabled":true,"name":"r","description":"d"}`))
	if a != b {
		t.Errorf("key order changed the preimage:\n  %s\n  %s", a, b)
	}
}

// TestADifferentValueHashesDifferently is INV-A11-11's other half — the reason the hash is stored at
// all. Without it, replaying a key with changed arguments would silently return the OLD response.
func TestADifferentValueHashesDifferently(t *testing.T) {
	a := session.SHA256Hex(canonicalJSON(mustArgs(t, `{"name":"r","description":"created once"}`)))
	b := session.SHA256Hex(canonicalJSON(mustArgs(t, `{"name":"r","description":"different input"}`)))
	if a == b {
		t.Error("two different argument sets hashed identically")
	}
}
