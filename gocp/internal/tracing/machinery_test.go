package tracing

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The checker's whole value is that it FAILS on a bad marker. A checker nobody has seen fail is just
// as unfalsifiable as the coverage it is meant to measure, so this file drives the two halves of the
// machinery — identity resolution and marker attachment — over synthetic input and asserts that each
// rejection actually fires.

func TestResolveAcceptsAnExactIdentityAndAnIdentityPlusNote(t *testing.T) {
	inv, err := LoadInventory()
	if err != nil {
		t.Fatalf("load inventory: %v", err)
	}
	const bare = "AuthzTest.kt#system-admin is allowed on admin actions"
	// This one has an em dash INSIDE the case name — the reason Resolve cannot use " — " as a
	// delimiter and resolves by longest inventory prefix instead.
	const dashed = "AuthzTest.kt#no roles is denied on admin actions — the 'admin = any session' hole stays closed"

	for _, tc := range []struct {
		payload, wantID, wantNote string
	}{
		{bare, bare, ""},
		{bare + " — pure Cedar half", bare, "pure Cedar half"},
		{bare + "   ", bare, ""},
		{dashed, dashed, ""},
		{dashed + " — and the note survives the second em dash", dashed, "and the note survives the second em dash"},
	} {
		id, note, ok := inv.Resolve(tc.payload)
		if !ok {
			t.Errorf("Resolve(%q) = not ok, want ok", tc.payload)
			continue
		}
		if id != tc.wantID {
			t.Errorf("Resolve(%q) identity = %q, want %q", tc.payload, id, tc.wantID)
		}
		if note != tc.wantNote {
			t.Errorf("Resolve(%q) note = %q, want %q", tc.payload, note, tc.wantNote)
		}
	}
}

func TestResolveRejectsEveryShapeOfWrongIdentity(t *testing.T) {
	inv, err := LoadInventory()
	if err != nil {
		t.Fatalf("load inventory: %v", err)
	}
	for _, payload := range []string{
		"",
		"AuthzTest.kt#system-admin is allowed on admin action",                      // dropped an 's'
		"AuthzTest.kt#SYSTEM-ADMIN is allowed on admin actions",                     // wrong case
		"AuthzTest.kt#system-admin is allowed on admin actions extra",               // no space-delimited note, longer name
		"AuthzTest.kt# system-admin is allowed on admin actions",                    // stray leading space
		"AuthzTests.kt#system-admin is allowed on admin actions",                    // wrong suite
		"AuthzTest#system-admin is allowed on admin actions",                        // missing .kt
		"system-admin is allowed on admin actions",                                  // no suite at all
		"EnforcementDbTest.kt#IN subquery oracle is denied",                         // class prefix omitted
		"EnforcementDbTest.kt#EnforcementSqliteDbTest.IN subquery oracle is denied", // invented class
		"ColumnAuthzTest.kt#system-admin is allowed on admin actions",               // right name, wrong suite
	} {
		if id, _, ok := inv.Resolve(payload); ok {
			t.Errorf("Resolve(%q) resolved to %q — a marker that cites a case which does not exist "+
				"must be rejected, because it reads as coverage", payload, id)
		}
	}
	// "extra" above is the one worth being explicit about: it must NOT silently truncate to the
	// shorter real case, which would invent a mapping the author did not write.
}

func TestResolveSuggestsTheIntendedIdentity(t *testing.T) {
	inv, err := LoadInventory()
	if err != nil {
		t.Fatalf("load inventory: %v", err)
	}
	got := inv.SuggestFor("AuthzTest.kt#system-admin is allowed on admin action", 3)
	want := "AuthzTest.kt#system-admin is allowed on admin actions"
	for _, g := range got {
		if g == want {
			return
		}
	}
	t.Errorf("SuggestFor did not offer %q; got %v", want, got)
}

// writeGo drops a synthetic _test.go into a temp dir and scans it.
func scanSynthetic(t *testing.T, body string) []Marker {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "synthetic_test.go")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	ms, err := scanFile(p, "synthetic_test.go")
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	return ms
}

func TestMarkerAttachment(t *testing.T) {
	const src = `package p

import "testing"

// KT-OMIT: file level marker — allowed unattached
// KT: file level port claim — must NOT attach to anything

// TestDoc is documented.
// KT: doc attached
func TestDoc(t *testing.T) {
	// KT: body attached
	t.Run("sub one", func(t *testing.T) {})

	// KT: above a subtest
	t.Run("sub two", func(t *testing.T) {})
}

// KT: separated by a blank line, so NOT a doc comment

func TestBlankLineBetween(t *testing.T) {}

// KT: sits above a helper, not a test
func helper() {}

func TestSubtestViaFixture(t *testing.T) {
	// KT: fixture subtest
	fx.subtest(t, "fixture sub", func(t *testing.T) {})
}
`
	got := scanSynthetic(t, src)
	type want struct {
		kind    Kind
		payload string
		owner   string
		subtest string
	}
	wants := []want{
		{KindOmit, "file level marker — allowed unattached", "", ""},
		{KindPort, "file level port claim — must NOT attach to anything", "", ""},
		{KindPort, "doc attached", "TestDoc", ""},
		{KindPort, "body attached", "TestDoc", "sub one"},
		{KindPort, "above a subtest", "TestDoc", "sub two"},
		{KindPort, "separated by a blank line, so NOT a doc comment", "", ""},
		{KindPort, "sits above a helper, not a test", "", ""},
		{KindPort, "fixture subtest", "TestSubtestViaFixture", "fixture sub"},
	}
	if len(got) != len(wants) {
		t.Fatalf("found %d markers, want %d: %+v", len(got), len(wants), got)
	}
	for i, w := range wants {
		g := got[i]
		if g.Kind != w.kind || g.Payload != w.payload || g.Owner != w.owner || g.Subtest != w.subtest {
			t.Errorf("marker %d = {%s %q owner=%q subtest=%q}, want {%s %q owner=%q subtest=%q}",
				i, g.Kind, g.Payload, g.Owner, g.Subtest, w.kind, w.payload, w.owner, w.subtest)
		}
	}
}

func TestMarkerKindsAreRecognised(t *testing.T) {
	const src = `package p

import "testing"

// KT: one
// KT-OMIT: two — reason
// KT-DEFER: three — reason
// KT-OMITTED: not a marker
// KTX: not a marker
// no marker here at all

func TestStringLiteral(t *testing.T) {
	x := "KT: inside a string literal, not a comment"
	_ = x
}
`
	got := scanSynthetic(t, src)
	if len(got) != 3 {
		t.Fatalf("found %d markers, want 3: %+v", len(got), got)
	}
	for i, want := range []Kind{KindPort, KindOmit, KindDefer} {
		if got[i].Kind != want {
			t.Errorf("marker %d kind = %s, want %s", i, got[i].Kind, want)
		}
	}
}

// TestTargetDistinguishesSubtests is the duplicate-detection key: two subtests of one function are two
// tests (both addressable with -run), so the same identity on each is a split, not a copy-paste.
func TestTargetDistinguishesSubtests(t *testing.T) {
	a := Marker{Owner: "TestX", Subtest: "one"}
	b := Marker{Owner: "TestX", Subtest: "two"}
	c := Marker{Owner: "TestX"}
	if a.Target() == b.Target() {
		t.Errorf("subtests collapsed to one target: %q", a.Target())
	}
	if c.Target() != "TestX" || a.Target() != "TestX/one" {
		t.Errorf("Target() = %q / %q, want %q / %q", c.Target(), a.Target(), "TestX", "TestX/one")
	}
}

// TestEveryMarkerLineIsOneLine guards the documented limitation that an identity may not be wrapped:
// the parser reads to end of line, so a wrapped identity silently becomes a truncated one — which
// Resolve then rejects. Assert the rejection rather than trusting the doc.
func TestEveryMarkerLineIsOneLine(t *testing.T) {
	inv, err := LoadInventory()
	if err != nil {
		t.Fatalf("load inventory: %v", err)
	}
	const wrapped = "AuditCanonicalGoldenTest.kt#canonical bytes and row hashes match the cross-language" // continued on the next comment line
	if _, _, ok := inv.Resolve(wrapped); ok {
		t.Error("a wrapped (truncated) identity resolved — it must be rejected so the wrap is visible")
	}
	full := wrapped + " golden vectors"
	if _, _, ok := inv.Resolve(full); !ok {
		t.Errorf("the unwrapped identity %q does not resolve", full)
	}
	if !strings.HasPrefix(full, wrapped) {
		t.Fatal("test setup is wrong")
	}
}
