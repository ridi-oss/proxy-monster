package engine

import (
	"strings"
	"unicode"
	"unicode/utf16"

	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
)

// Deterministic value masking. The control plane calls this when a stored result set is viewed (an
// approval result): the saved result never replays through the wire proxy, so the control plane applies
// the column masks itself. The data-plane proxy has its own byte-identical Go implementation
// (goproxy/engine/masking.go) for inline wire result-set rewriting.
//
// 🔒 INV-A13-5 — the control-plane and wire implementations MUST produce identical output for the same
// (value, kind). The same stored cell is rendered by the proxy on the live path and by the control plane
// on the stored-result view path (A7). A divergence means the same task shows different values depending
// on how it is read — and the wire path is the one whose output was never persisted, so the discrepancy
// is unreconstructable after the fact.
//
// This file is a deliberate transcription of goproxy/engine/masking.go, not a fresh derivation. 13-engine
// .md §1.1 recommends importing that file instead; the import is barred by Go's internal/ rule (its
// ColumnMask is goproxy/internal/pb.ColumnMask). masking_test.go carries goproxy's 11-row table verbatim
// so the twins cannot drift silently.

// MaskBinding is the result of binding: masks keyed by result-set column INDEX, plus every input mask
// that could not be placed. The mask type is the proto ColumnMask used AS the data class (13-engine.md
// §3.3 — "proto types are safe beyond the gRPC boundary", engine/build.gradle.kts:19-21), so there is no
// hand-written mirror type to port.
type MaskBinding struct {
	ByIndex map[int]string
	Unbound []*pb.ColumnMask
}

// AllBound reports whether every mask bound to a live result column — the caller's fail-closed test.
func (b MaskBinding) AllBound() bool { return len(b.Unbound) == 0 }

// BindMasks binds mask specs to result-set column indexes BY OUTPUT POSITION (the ordinal the analyzer
// assigned), shared by the control plane and both wire proxies.
//
// 🔒 INV-A13-6 — binding is BY OUTPUT POSITION, NEVER by column name. Masks.kt:11-13 states the reason:
// "Position is immune to alias/case/EXPR$0 name mismatch — name binding was the fail-open bug." A port
// that reintroduces a name lookup reintroduces a known leak.
//
// 🔒 INV-A13-7 — an ABSENT ordinal NEVER binds; it is reported unbound. The presence check runs BEFORE
// the range test, because proto3's implicit zero would otherwise place a malformed or omitted mask on
// result column 0 — masking a column that needed no mask and leaving the intended one cleartext. ⚠️ In Go
// this is the single easiest mistake in the whole area: mask.GetOrdinal() returns 0 for nil, so this code
// tests mask.Ordinal != nil and dereferences the pointer, exactly as goproxy/engine/masking.go:13-14
// warns.
//
// 🔒 INV-A13-8 — an OUT-OF-RANGE ordinal is reported unbound, and the caller MUST fail closed ("every
// required mask must bind, else DENY"). BindMasks itself denies nothing; it only reports. Both consumers
// honour it: A7's view gate 7 (!allBound ⇒ "required view mask could not be bound") and the proxy's
// NewRowMasker returning nil.
//
// INV-A13-9 — duplicate ordinals: FIRST wins, and the loser is NOT reported unbound. It is neither
// applied nor surfaced in Unbound, so AllBound stays true. Consistent with A6, whose mask-binding loop is
// itself first-wins, so a duplicate should never reach here in practice.
func BindMasks(masks []*pb.ColumnMask, resultColumnCount int) MaskBinding {
	// Kotlin's byIndex is a LinkedHashMap and its unbound an empty ArrayList; Go's are a plain map (no
	// consumer iterates byIndex in order — A7 looks up byIndex[index] per column) and a nil slice (both
	// sides only ask isEmpty/len == 0). Neither shape difference is behavioural.
	byIndex := make(map[int]string)
	var unbound []*pb.ColumnMask
	for _, mask := range masks {
		if mask.Ordinal != nil && int(*mask.Ordinal) >= 0 && int(*mask.Ordinal) < resultColumnCount {
			ordinal := int(*mask.Ordinal)
			if _, exists := byIndex[ordinal]; !exists {
				byIndex[ordinal] = mask.GetKind()
			}
		} else {
			unbound = append(unbound, mask)
		}
	}
	return MaskBinding{ByIndex: byIndex, Unbound: unbound}
}

// ApplyMaskKind returns the masked rendering of an already-stringified cell value, or nil for a full
// redaction. Ports probe/Masking.kt Masking.apply. Total: it never panics.
//
// 🔒 INV-A13-1 — it returns nil for EXACTLY TWO inputs: a nil value, and kind "NULL". Therefore a caller
// must branch on the KIND, never on the result: collapsing this to `ApplyMaskKind(v, kind) ?? v` would
// fall a NULL-redacted cell back to the CLEARTEXT value. That is the whole reason A7's view path
// (INV-A7-15) null-checks the kind. The same pattern is duplicated in the enforcement harness, so a port
// that "fixes" one must fix both.
//
// 🔒 INV-A13-2 — an UNRECOGNIZED kind masks fully ("****"), never passes cleartext through. F21/F79:
// mask_fn.kind is a bare TEXT column with NO CHECK constraint (V2__catalog.sql:67-71 documents the four
// values in a comment only), and an admin creating a mask fn through POST /api/mask-fns can store any
// string — so the default arm is REACHABLE IN PRODUCTION, not defensive. It is a SECURITY DEFAULT, kept
// and pinned by a test. A6 compounds this: its mask-binding loop uses `kind = maskKinds[fn] ?: "FIXED"`,
// so a MISSING mask-fn row also yields a real transform rather than an error.
//
// 🔒 INV-A13-3 — LAST_N on a value of ≤ 4 units reveals NOTHING. Without the guard, repeat(len-4) would
// be a negative repeat (a Kotlin exception, a Go panic) or, worse, a rewrite that emitted the whole short
// value. Short PII (a 4-digit PIN, a 2-character name) is exactly the case where revealing "the last
// four" is revealing everything.
//
// INV-A13-4 — FORMAT_PRESERVING is defined on UTF-16 CODE UNITS with JDK Character.isLetterOrDigit(char)
// semantics. Kotlin String length, takeLast and Char mapping all operate on UTF-16 code units, so this
// deliberately does NOT use Go rune counts: a naive `len([]rune(v))` changes the mask length of any value
// containing an astral character. Consequence, deliberate and pinned: a SUPPLEMENTARY letter (e.g. U+10400
// DESERET) arrives as two surrogate halves, neither of which is a letter, so it passes through UNMASKED.
// Over-revealing in an exotic case, accepted, and observable — do not "fix" it silently.
func ApplyMaskKind(value *string, kind string) *string {
	if value == nil || kind == "NULL" {
		return nil
	}
	var masked string
	switch kind {
	case "FIXED":
		masked = "####" // literal, four hashes, independent of input length
	case "LAST_N":
		units := utf16.Encode([]rune(*value))
		const visible = 4
		if len(units) <= visible {
			masked = strings.Repeat("*", len(units))
		} else {
			masked = strings.Repeat("*", len(units)-visible) + string(utf16.Decode(units[len(units)-visible:]))
		}
	case "FORMAT_PRESERVING":
		units := utf16.Encode([]rune(*value))
		for i, unit := range units {
			if isKotlinCharLetterOrDigit(rune(unit)) {
				units[i] = '*'
			}
		}
		masked = string(utf16.Decode(units))
	default:
		masked = "****" // INV-A13-2: fail-closed on an unknown mask kind — reachable, not dead
	}
	return &masked
}

// isKotlinCharLetterOrDigit mirrors JDK 24 Character.isLetterOrDigit(char). Go uses Unicode 15 tables
// while JDK 24 uses Unicode 16, whose eight new BMP letters must also be masked. Supplementary letters
// are represented by surrogate halves in Kotlin Char iteration and therefore intentionally remain
// unclassified here.
//
// ⚠️ The Unicode-table patch is a maintenance trap the port INHERITS, not one it escapes. Once the JVM
// side is gone, "JDK 24 Character.isLetterOrDigit" stops being the definition of correct — but the stored
// cleartext of every already-masked approval result is re-masked LIVE on every read (INV-A7-3), so a
// semantics change silently changes what a viewer sees for an old task. The port keeps the hardcoded set
// and treats "what does letter-or-digit mean" as a FROZEN PRODUCT DECISION, not a library version detail
// (13-engine.md Q1).
func isKotlinCharLetterOrDigit(r rune) bool {
	if r > 0xffff {
		return false
	}
	if unicode.IsLetter(r) || unicode.IsDigit(r) {
		return true
	}
	switch r {
	case 0x1c89, 0x1c8a, 0xa7cb, 0xa7cc, 0xa7cd, 0xa7da, 0xa7db, 0xa7dc:
		return true
	default:
		return false
	}
}

// takeUTF16 is Kotlin's String.take(n) — the first n UTF-16 CODE UNITS, not the first n runes. Used by
// the analyzer facade's fail-closed detail truncation, where Kotlin's `.take(150)` counts code units
// while the Go probe's own truncateDetail counts runes (F28).
//
// A cut that lands between the two halves of a surrogate pair leaves an unpaired half, which
// utf16.Decode renders as U+FFFD — Kotlin would keep the lone surrogate. That difference is unobservable
// through the only consumer (the detail string reaches the wire as opaque diagnostic text) and Go strings
// cannot hold an unpaired surrogate at all.
func takeUTF16(s string, n int) string {
	units := utf16.Encode([]rune(s))
	if len(units) <= n {
		return s
	}
	return string(utf16.Decode(units[:n]))
}
