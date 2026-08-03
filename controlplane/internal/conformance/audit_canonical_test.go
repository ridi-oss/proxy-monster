package conformance

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/ridi-oss/proxy-monster/auditmon/canon"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/audit"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// ============================================================================================
// CONTRACT 1 — the audit canonical bytes.
//
// ORACLE: control-plane/src/test/resources/atrail/canonical-golden.json — the fixture the KOTLIN CI
// replays (control-plane's AuditCanonicalGoldenTest) and that auditmon/canon/canonical_test.go:90
// already replays from Go. Its README.md is the format spec; every structural rule asserted below is
// quoted from it.
//
// This is the ONE place the two languages are provably identical, so the assertion is worth having in
// triplicate. What THIS copy adds over the two that exist:
//
//   - internal/audit/canon_test.go replays the fixture through types.AuditEvent → ToCanon and checks
//     the resulting HASHES. A hash agreeing proves the whole preimage agrees, but tells you NOTHING
//     about which rule broke when it does not. TestCanonicalFieldEncodingMatchesTheSpec below DECODES
//     the canonical bytes with an independent parser written from the README's field table, so a
//     drift reports "field 11 (maskedColumns) is out of order" instead of "hash mismatch".
//   - the parser is deliberately NOT built on canon's writer. Asserting a writer against itself is
//     circular; asserting it against a reader transcribed from the prose spec is not.
// ============================================================================================

type goldenCase struct {
	Name         string           `json:"name"`
	ID           int64            `json:"id"`
	PrevHashHex  string           `json:"prevHashHex"`
	Event        types.AuditEvent `json:"event"`
	CanonicalHex string           `json:"canonicalHex"`
	RowHashHex   string           `json:"rowHashHex"`
}

type goldenFixture struct {
	DomainSep    string       `json:"domainSep"`
	ChainVersion uint32       `json:"chainVersion"`
	Cases        []goldenCase `json:"cases"`
}

func loadGolden(t *testing.T) goldenFixture {
	t.Helper()
	path := goldenFixturePath(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden fixture %s: %v", path, err)
	}
	var fx goldenFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal golden fixture %s: %v", path, err)
	}
	// The fixture is decoded into types.AuditEvent, the WIRE type — not into a test-local mirror of
	// canon.AuditEvent. That is deliberate: it means types.AuditEvent.UnmarshalJSON (required fields,
	// defaulted lists, the validated Decision) is on the path from Kotlin's bytes to Go's hash, which
	// is the path production actually takes on /api/ingest/decision.
	if len(fx.Cases) != 6 {
		t.Fatalf("fixture has %d cases, want 6 — the fixture changed, which is a coordinated cross-language format change", len(fx.Cases))
	}
	return fx
}

// tsMicrosOf is the store's timestamp reduction: parse the ISO-8601 instant, truncate to micros
// (INV-A8-2 — Postgres timestamptz is microsecond-precision and the hashed value must be the stored
// value), then convert to epoch micros.
func tsMicrosOf(t *testing.T, ev types.AuditEvent) int64 {
	t.Helper()
	if ev.TS == nil {
		t.Fatal("fixture case has no ts")
	}
	parsed, err := audit.ParseInstant(*ev.TS)
	if err != nil {
		t.Fatalf("parse ts %q: %v", *ev.TS, err)
	}
	return audit.EpochMicros(audit.TruncateToMicros(parsed))
}

// TestGoldenCanonicalBytesAndRowHashes is the byte-for-byte cross-language assertion: the exact
// canonical preimage AND the exact SHA-256 row hash for all six vectors, through internal/audit's
// wire-type conversion.
//
// If this fails, the Go control plane would write chain rows the Kotlin verifier — and auditmon —
// read as TAMPERED. There is no benign version of this failing.
func TestGoldenCanonicalBytesAndRowHashes(t *testing.T) {
	fx := loadGolden(t)

	if fx.DomainSep != string(canon.DomainSep) {
		t.Fatalf("domainSep = %q, want %q", fx.DomainSep, canon.DomainSep)
	}
	if fx.ChainVersion != audit.ChainVersion {
		t.Fatalf("chainVersion = %d, want %d", fx.ChainVersion, audit.ChainVersion)
	}

	for _, c := range fx.Cases {
		t.Run(c.Name, func(t *testing.T) {
			tsMicros := tsMicrosOf(t, c.Event)

			gotCanon := audit.Canonical(c.Event, tsMicros)
			if got := hex.EncodeToString(gotCanon); got != c.CanonicalHex {
				t.Errorf("canonical bytes:\n got  %s\n want %s", got, c.CanonicalHex)
			}

			prev, err := hex.DecodeString(c.PrevHashHex)
			if err != nil {
				t.Fatalf("decode prevHashHex: %v", err)
			}
			rowHash, err := audit.RowHash(c.ID, c.Event, tsMicros, prev)
			if err != nil {
				t.Fatalf("RowHash: %v", err)
			}
			if got := hex.EncodeToString(rowHash); got != c.RowHashHex {
				t.Errorf("row hash:\n got  %s\n want %s", got, c.RowHashHex)
			}
		})
	}
}

// TestDomainSeparatorAndChainVersionAppearExactlyOnce pins the README's "DOMAIN_SEP and chain_version
// occur exactly once in either byte stream".
//
// The domain separator is what stops an audit-event hash from being replayable as any other SHA-256
// construction in the system; emitting it twice (a plausible refactor artifact when the row-hash
// preimage is built by wrapping the canonical bytes rather than by re-encoding) changes every hash
// while still "looking domain-separated".
func TestDomainSeparatorAndChainVersionAppearExactlyOnce(t *testing.T) {
	fx := loadGolden(t)
	var version [4]byte
	binary.BigEndian.PutUint32(version[:], fx.ChainVersion)

	for _, c := range fx.Cases {
		t.Run(c.Name, func(t *testing.T) {
			b := audit.Canonical(c.Event, tsMicrosOf(t, c.Event))

			if !bytes.HasPrefix(b, canon.DomainSep) {
				t.Fatalf("canonical bytes do not start with the domain separator %q", canon.DomainSep)
			}
			if n := bytes.Count(b, canon.DomainSep); n != 1 {
				t.Errorf("domain separator appears %d times, want exactly 1", n)
			}
			if got := b[len(canon.DomainSep) : len(canon.DomainSep)+4]; !bytes.Equal(got, version[:]) {
				t.Errorf("chain version bytes = %x, want %x (u32be of %d)", got, version, fx.ChainVersion)
			}
		})
	}
}

// ---- an independent decoder for the canonical field block ----------------------------------
//
// Transcribed from control-plane/src/test/resources/atrail/README.md "## Fields", NOT from
// canon.writeFields. A non-null string is u32be(len)||UTF-8; a null scalar is FF FF FF FF with no
// payload; a signed int64 is u32be(8)||i64be; an array is u32be(count) then each element as
// u32be(len)||UTF-8.

const nullMarker uint32 = 0xFFFFFFFF

type canonReader struct {
	b   []byte
	pos int
	t   *testing.T
}

func (r *canonReader) u32(what string) uint32 {
	r.t.Helper()
	if r.pos+4 > len(r.b) {
		r.t.Fatalf("truncated stream reading %s at offset %d", what, r.pos)
	}
	v := binary.BigEndian.Uint32(r.b[r.pos : r.pos+4])
	r.pos += 4
	return v
}

func (r *canonReader) bytesN(n int, what string) []byte {
	r.t.Helper()
	if r.pos+n > len(r.b) {
		r.t.Fatalf("truncated stream reading %d bytes of %s at offset %d", n, what, r.pos)
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v
}

func (r *canonReader) str(what string) string {
	r.t.Helper()
	n := r.u32(what + ".len")
	if n == nullMarker {
		r.t.Fatalf("%s: non-nullable string carries the null marker", what)
	}
	return string(r.bytesN(int(n), what))
}

// nullableStr returns nil for the FF FF FF FF marker — the encoding's only way to say "absent".
func (r *canonReader) nullableStr(what string) *string {
	r.t.Helper()
	n := r.u32(what + ".len")
	if n == nullMarker {
		return nil
	}
	s := string(r.bytesN(int(n), what))
	return &s
}

func (r *canonReader) i64(what string) int64 {
	r.t.Helper()
	if n := r.u32(what + ".len"); n != 8 {
		r.t.Fatalf("%s: int64 length prefix = %d, want 8", what, n)
	}
	return int64(binary.BigEndian.Uint64(r.bytesN(8, what)))
}

func (r *canonReader) nullableI64(what string) *int64 {
	r.t.Helper()
	save := r.pos
	if n := r.u32(what + ".len"); n == nullMarker {
		return nil
	}
	r.pos = save
	v := r.i64(what)
	return &v
}

func (r *canonReader) array(what string) []string {
	r.t.Helper()
	n := r.u32(what + ".count")
	if n == nullMarker {
		r.t.Fatalf("%s: an array carries the null marker — Kotlin's List<String> is non-null, [] is the only empty", what)
	}
	out := make([]string, 0, n)
	for i := uint32(0); i < n; i++ {
		out = append(out, r.str(fmt.Sprintf("%s[%d]", what, i)))
	}
	return out
}

// decodedFields is the 22-field block, in the README's declared order.
type decodedFields struct {
	Kind               string
	TSMicros           int64
	Principal          string
	Roles              []string
	Datasource         string
	ClientAddr         *string
	Statement          string
	Decision           string
	FailedStage        *string
	EffectiveNamespace []string
	MaskedColumns      []string
	PIITouched         []string
	LatencyMs          int64
	Detail             *string
	Channel            *string
	ContextTags        []string
	AuthzAction        *string
	AuthzResource      *string
	Outcome            *string
	RowsReturned       *int64
	BytesReturned      *int64
	DecisionID         *int64
}

// decodeCanonical parses DomainSep || u32be(chainVersion) || fields(event) and requires the stream to
// be fully consumed. A trailing byte means the writer emitted something the spec does not describe.
func decodeCanonical(t *testing.T, b []byte) decodedFields {
	t.Helper()
	if !bytes.HasPrefix(b, canon.DomainSep) {
		t.Fatalf("canonical bytes do not start with %q", canon.DomainSep)
	}
	r := &canonReader{b: b, pos: len(canon.DomainSep), t: t}
	if v := r.u32("chainVersion"); v != audit.ChainVersion {
		t.Fatalf("chainVersion = %d, want %d", v, audit.ChainVersion)
	}
	f := decodedFields{
		Kind:               r.str("1.kind"),
		TSMicros:           r.i64("2.ts"),
		Principal:          r.str("3.principal"),
		Roles:              r.array("4.roles"),
		Datasource:         r.str("5.datasource"),
		ClientAddr:         r.nullableStr("6.clientAddr"),
		Statement:          r.str("7.statement"),
		Decision:           r.str("8.decision"),
		FailedStage:        r.nullableStr("9.failedStage"),
		EffectiveNamespace: r.array("10.effectiveNamespace"),
		MaskedColumns:      r.array("11.maskedColumns"),
		PIITouched:         r.array("12.piiTouched"),
		LatencyMs:          r.i64("13.latencyMs"),
		Detail:             r.nullableStr("14.detail"),
		Channel:            r.nullableStr("15.channel"),
		ContextTags:        r.array("16.contextTags"),
		AuthzAction:        r.nullableStr("17.authzAction"),
		AuthzResource:      r.nullableStr("18.authzResource"),
		Outcome:            r.nullableStr("19.outcome"),
		RowsReturned:       r.nullableI64("20.rowsReturned"),
		BytesReturned:      r.nullableI64("21.bytesReturned"),
		DecisionID:         r.nullableI64("22.decisionId"),
	}
	if r.pos != len(b) {
		t.Fatalf("canonical stream has %d trailing byte(s) after field 22 (decisionId)", len(b)-r.pos)
	}
	return f
}

// TestCanonicalFieldEncodingMatchesTheSpec decodes every golden vector with the independent parser and
// checks each of the 22 fields against the event it came from.
//
// This is the assertion that NAMES the broken rule. A swapped maskedColumns/piiTouched pair, a
// nullable emitted as an empty string instead of the marker, an int64 written without its length
// prefix — all of them are one hash mismatch to the golden test above and a precise field-level
// failure here.
func TestCanonicalFieldEncodingMatchesTheSpec(t *testing.T) {
	fx := loadGolden(t)
	for _, c := range fx.Cases {
		t.Run(c.Name, func(t *testing.T) {
			tsMicros := tsMicrosOf(t, c.Event)
			got := decodeCanonical(t, audit.Canonical(c.Event, tsMicros))

			eqStr(t, "1.kind", got.Kind, c.Event.Kind)
			if got.TSMicros != tsMicros {
				t.Errorf("2.ts = %d, want %d", got.TSMicros, tsMicros)
			}
			eqStr(t, "3.principal", got.Principal, c.Event.Principal)
			eqSortedSet(t, "4.roles", got.Roles, c.Event.Roles)
			eqStr(t, "5.datasource", got.Datasource, c.Event.Datasource)
			eqStrPtr(t, "6.clientAddr", got.ClientAddr, c.Event.ClientAddr)
			eqStr(t, "7.statement", got.Statement, c.Event.Statement)
			eqStr(t, "8.decision", got.Decision, string(c.Event.Decision))
			eqStrPtr(t, "9.failedStage", got.FailedStage, c.Event.FailedStage)
			// 🔒 INV-A8-5, the ORDERED half: effectiveNamespace is a LIST and keeps input order.
			eqOrderedList(t, "10.effectiveNamespace", got.EffectiveNamespace, c.Event.EffectiveNamespace)
			eqSortedSet(t, "11.maskedColumns", got.MaskedColumns, c.Event.MaskedColumns)
			eqSortedSet(t, "12.piiTouched", got.PIITouched, c.Event.PIITouched)
			if got.LatencyMs != c.Event.LatencyMs {
				t.Errorf("13.latencyMs = %d, want %d", got.LatencyMs, c.Event.LatencyMs)
			}
			eqStrPtr(t, "14.detail", got.Detail, c.Event.Detail)
			eqStrPtr(t, "15.channel", got.Channel, c.Event.Channel)
			eqSortedSet(t, "16.contextTags", got.ContextTags, c.Event.ContextTags)
			eqStrPtr(t, "17.authzAction", got.AuthzAction, c.Event.AuthzAction)
			eqStrPtr(t, "18.authzResource", got.AuthzResource, c.Event.AuthzResource)
			eqStrPtr(t, "19.outcome", got.Outcome, c.Event.Outcome)
			eqI64Ptr(t, "20.rowsReturned", got.RowsReturned, c.Event.RowsReturned)
			eqI64Ptr(t, "21.bytesReturned", got.BytesReturned, c.Event.BytesReturned)
			eqI64Ptr(t, "22.decisionId", got.DecisionID, c.Event.DecisionID)
		})
	}
}

// TestNullScalarsUseTheFourByteMarker asserts the 0xFFFFFFFF null marker directly on the wire, rather
// than inferring it from a decode.
//
// The `minimal-null-and-empty` vector has all nine nullable scalars absent and all five arrays empty,
// which is exactly the discrimination that matters: a null scalar is `ffffffff` (four bytes, NO
// payload) while an empty array is `00000000` (a zero COUNT). Encoding a null as an empty string
// (`00000000`) would produce a stream the Kotlin verifier rejects, and both look like "four zero-ish
// bytes" to a careless reader.
func TestNullScalarsUseTheFourByteMarker(t *testing.T) {
	fx := loadGolden(t)
	var minimal *goldenCase
	for i := range fx.Cases {
		if fx.Cases[i].Name == "minimal-null-and-empty" {
			minimal = &fx.Cases[i]
		}
	}
	if minimal == nil {
		t.Fatal("fixture no longer carries the minimal-null-and-empty vector")
	}

	b := audit.Canonical(minimal.Event, tsMicrosOf(t, minimal.Event))

	// The field table has exactly TEN nullable scalars — clientAddr(6), failedStage(9), detail(14),
	// channel(15), authzAction(17), authzResource(18), outcome(19), rowsReturned(20),
	// bytesReturned(21), decisionId(22) — and this vector leaves every one of them absent, so the
	// marker must appear exactly ten times and nowhere else.
	const nullableScalars = 10
	if n := bytes.Count(b, []byte{0xFF, 0xFF, 0xFF, 0xFF}); n != nullableScalars {
		t.Errorf("null marker ffffffff appears %d times, want %d "+
			"(clientAddr, failedStage, detail, channel, authzAction, authzResource, outcome, "+
			"rowsReturned, bytesReturned, decisionId — all absent in this vector)", n, nullableScalars)
	}

	// And the decode must agree that every one of them is nil, not "".
	got := decodeCanonical(t, b)
	for name, p := range map[string]*string{
		"clientAddr": got.ClientAddr, "failedStage": got.FailedStage, "detail": got.Detail,
		"channel": got.Channel, "authzAction": got.AuthzAction, "authzResource": got.AuthzResource,
		"outcome": got.Outcome,
	} {
		if p != nil {
			t.Errorf("%s decoded as %q, want the null marker", name, *p)
		}
	}
	for name, p := range map[string]*int64{
		"rowsReturned": got.RowsReturned, "bytesReturned": got.BytesReturned, "decisionId": got.DecisionID,
	} {
		if p != nil {
			t.Errorf("%s decoded as %d, want the null marker", name, *p)
		}
	}

	// An EMPTY array is a zero count, not a marker — the other half of the discrimination.
	for name, a := range map[string][]string{
		"roles": got.Roles, "effectiveNamespace": got.EffectiveNamespace,
		"maskedColumns": got.MaskedColumns, "piiTouched": got.PIITouched, "contextTags": got.ContextTags,
	} {
		if len(a) != 0 {
			t.Errorf("%s decoded as %v, want empty", name, a)
		}
	}
}

// TestInvA85SortRulesAreProvenByTheGoldenBytes is INV-A8-5, asserted where it is actually decidable.
//
// 🔒 INV-A8-5 — roles / maskedColumns / piiTouched / contextTags sort ascending by UNSIGNED UTF-8
// byte order with duplicates preserved; effectiveNamespace preserves INPUT order.
//
// Both halves need input whose sorted order DIFFERS from its input order, or the assertion is vacuous.
// The fixture supplies exactly that, and this test refuses to run on input that does not:
//
//   - `unicode-korean-and-emoji` roles are ["분석가", "emoji-🧪"]. UTF-8 'e' is 0x65 and '분' is
//     0xEC…, so sorted order REVERSES the input. That is the sorted half, and it is simultaneously
//     the UNSIGNED half: Java's `byte` is SIGNED, so a naive signed comparator would read 0xEC as
//     -20 and sort '분석가' FIRST. The golden bytes say otherwise.
//   - the SAME vector's effectiveNamespace is ["카탈로그", "스키마"] — EC B9 B4… before EC 8A A4… —
//     which is NOT sorted, so the golden bytes prove input order is preserved.
//   - `full-unsorted-sets-duplicate-and-ordered-namespace` adds duplicate preservation
//     (["alpha","alpha"] survives as two elements) and a second unsigned probe, "é" (C3 A9) after
//     "zeta" (7A…).
func TestInvA85SortRulesAreProvenByTheGoldenBytes(t *testing.T) {
	fx := loadGolden(t)
	byName := map[string]goldenCase{}
	for _, c := range fx.Cases {
		byName[c.Name] = c
	}

	unicode, ok := byName["unicode-korean-and-emoji"]
	if !ok {
		t.Fatal("fixture no longer carries the unicode-korean-and-emoji vector, which is what makes INV-A8-5 decidable")
	}
	// Guard against the vector being edited into something that cannot discriminate.
	if isByteSorted(unicode.Event.Roles) {
		t.Fatal("the unicode vector's roles are already sorted — the sorted half of INV-A8-5 would be vacuous")
	}
	if isByteSorted(unicode.Event.EffectiveNamespace) {
		t.Fatal("the unicode vector's effectiveNamespace is already sorted — the ordered half of INV-A8-5 would be vacuous")
	}

	got := decodeCanonical(t, audit.Canonical(unicode.Event, tsMicrosOf(t, unicode.Event)))

	if !isByteSorted(got.Roles) {
		t.Errorf("INV-A8-5: roles came out %v, which is not ascending by unsigned UTF-8 bytes", got.Roles)
	}
	eqOrderedList(t, "effectiveNamespace (INV-A8-5, ordered half)", got.EffectiveNamespace, unicode.Event.EffectiveNamespace)

	full, ok := byName["full-unsorted-sets-duplicate-and-ordered-namespace"]
	if !ok {
		t.Fatal("fixture no longer carries the full-unsorted-sets vector")
	}
	gotFull := decodeCanonical(t, audit.Canonical(full.Event, tsMicrosOf(t, full.Event)))
	for name, a := range map[string][]string{
		"roles": gotFull.Roles, "maskedColumns": gotFull.MaskedColumns,
		"piiTouched": gotFull.PIITouched, "contextTags": gotFull.ContextTags,
	} {
		if !isByteSorted(a) {
			t.Errorf("INV-A8-5: %s came out %v, which is not ascending by unsigned UTF-8 bytes", name, a)
		}
	}
	// Duplicates preserved: input roles has "alpha" twice, so the output must too.
	if len(gotFull.Roles) != len(full.Event.Roles) {
		t.Errorf("INV-A8-5: roles length %d != input length %d — duplicates must be PRESERVED, not deduped",
			len(gotFull.Roles), len(full.Event.Roles))
	}
}

// isByteSorted reports whether a is non-descending under bytes.Compare, which IS Kotlin's
// UNSIGNED_UTF8_COMPARATOR: Go compares bytes as uint8, Java's `byte` is int8, and that difference is
// the entire content of the "unsigned" in INV-A8-5.
func isByteSorted(a []string) bool {
	for i := 1; i < len(a); i++ {
		if bytes.Compare([]byte(a[i-1]), []byte(a[i])) > 0 {
			return false
		}
	}
	return true
}

func eqStr(t *testing.T, what, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %q, want %q", what, got, want)
	}
}

func eqStrPtr(t *testing.T, what string, got, want *string) {
	t.Helper()
	switch {
	case got == nil && want == nil:
	case got == nil:
		t.Errorf("%s = null, want %q", what, *want)
	case want == nil:
		t.Errorf("%s = %q, want null", what, *got)
	case *got != *want:
		t.Errorf("%s = %q, want %q", what, *got, *want)
	}
}

func eqI64Ptr(t *testing.T, what string, got, want *int64) {
	t.Helper()
	switch {
	case got == nil && want == nil:
	case got == nil:
		t.Errorf("%s = null, want %d", what, *want)
	case want == nil:
		t.Errorf("%s = %d, want null", what, *got)
	case *got != *want:
		t.Errorf("%s = %d, want %d", what, *got, *want)
	}
}

// eqOrderedList requires element-for-element equality IN ORDER.
func eqOrderedList(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s = %v, want %v (length)", what, got, want)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s = %v, want %v (element %d)", what, got, want, i)
			return
		}
	}
}

// eqSortedSet requires the same MULTISET (duplicates preserved) in unsigned-byte-sorted order.
func eqSortedSet(t *testing.T, what string, got, want []string) {
	t.Helper()
	sorted := append([]string(nil), want...)
	byteSort(sorted)
	eqOrderedList(t, what, got, sorted)
}

func byteSort(a []string) {
	// Insertion sort, stable, tiny inputs — written out rather than pulled from sort so the COMPARATOR
	// is visibly bytes.Compare and not a locale- or rune-aware alternative.
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && bytes.Compare([]byte(a[j-1]), []byte(a[j])) > 0; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}
