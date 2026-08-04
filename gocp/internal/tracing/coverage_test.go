package tracing

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ================================================================================================
// THE RATCHET
//
// minMappedCases is the number of Kotlin cases that carried a KT: marker when this file was last
// updated. The checker fails if the real number drops below it, so coverage can only go UP.
//
// It deliberately does NOT start at 903. Demanding 100% today would make `go test ./...` red for the
// whole remaining port and the check would be disabled within a day; a ratchet that is actually green
// is worth more than an aspiration that is not.
//
// TO RAISE IT: add markers, run
//
//	go test ./internal/tracing -run Coverage -v
//
// read the "mapped" total off the summary, put that number here, and commit the two together. Never
// lower it. If a legitimate change removes a Go test (and so unmaps a case), the case must gain a
// KT-DEFER: marker in the same commit — accountedCases below is what stops a deletion from quietly
// looking like progress.
//
// Set KT_COVERAGE_REQUIRE_FULL=1 to demand all 903 instead; that is the switch to flip on the day the
// port claims completeness, and the one CI should flip to prove it.
// ⚠️ LOWERED 893 → 890 BY A REBASE, which is the one case the "never lower it" rule above does not
// cover. The rule guards against a coverage REGRESSION — a Go test deleted without a KT-DEFER in its
// place. This was the DENOMINATOR moving: rebasing onto main brought 26 upstream commits, the inventory
// went 903 → 929 cases, and three cases the port had mapped were DELETED upstream (two by #78 "a tag is
// a tag", one by RoleDiscoveryTest's rework). A marker cannot cite a case that no longer exists, so the
// three markers were removed and the reasoning left as prose at each site.
//
// Nothing became less covered. The port is now measurably BEHIND main by a known amount — 39 unmapped
// cases against 929 — and that gap, not this number, is the thing to close.
const minMappedCases = 890

// minAccountedCases is mapped + KT-OMIT + KT-DEFER. Same ratchet, one level weaker: it counts cases
// somebody has made a decision about, so deleting a marker outright is caught even when the deleter
// swaps a KT: for a KT-DEFER:.
const minAccountedCases = 900

const requireFullEnv = "KT_COVERAGE_REQUIRE_FULL"

// ================================================================================================

type coverage struct {
	inv       *Inventory
	markers   []Marker
	byCase    map[string][]Marker // identity -> valid KT: markers
	omitted   map[string][]Marker
	deferred  map[string][]Marker
	problems  []string
	modRoot   string
	numMapped int
}

func analyse(t *testing.T) *coverage {
	t.Helper()
	inv, err := LoadInventory()
	if err != nil {
		t.Fatalf("load inventory: %v", err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root, err := FindModuleRoot(wd)
	if err != nil {
		t.Fatalf("find module root: %v", err)
	}
	markers, err := ScanModule(root)
	if err != nil {
		t.Fatalf("scan module for markers: %v", err)
	}

	c := &coverage{
		inv:      inv,
		markers:  markers,
		byCase:   map[string][]Marker{},
		omitted:  map[string][]Marker{},
		deferred: map[string][]Marker{},
		modRoot:  root,
	}

	// seen[identity][target] -> the first marker that claimed it, for duplicate detection.
	seen := map[string]map[string]Marker{}

	for _, m := range markers {
		identity, note, ok := inv.Resolve(m.Payload)
		if !ok {
			sugg := inv.SuggestFor(m.Payload, 3)
			msg := fmt.Sprintf(
				"%s: %s marker names a case that is NOT in %s:\n      cited: %q",
				m.Loc(), m.Kind, InventoryFile, m.Payload)
			if len(sugg) > 0 {
				msg += "\n      did you mean:"
				for _, s := range sugg {
					msg += "\n        " + s
				}
			}
			c.problems = append(c.problems, msg)
			continue
		}
		switch m.Kind {
		case KindOmit, KindDefer:
			if strings.TrimSpace(note) == "" {
				c.problems = append(c.problems, fmt.Sprintf(
					"%s: %s needs a reason after the identity — %q states no reason. "+
						"An unexplained non-coverage is indistinguishable from a forgotten one.",
					m.Loc(), m.Kind, identity))
				continue
			}
			if m.Kind == KindOmit {
				c.omitted[identity] = append(c.omitted[identity], m)
			} else {
				c.deferred[identity] = append(c.deferred[identity], m)
			}
		case KindPort:
			if m.Owner == "" {
				c.problems = append(c.problems, fmt.Sprintf(
					"%s: KT: marker is not attached to a Go test (%q). A coverage claim has to name a "+
						"test: put the marker in the doc comment DIRECTLY above a func Test..., or inside "+
						"the test body. Use KT-OMIT:/KT-DEFER: for a file-level statement.",
					m.Loc(), identity))
				continue
			}
			if seen[identity] == nil {
				seen[identity] = map[string]Marker{}
			}
			if prev, dup := seen[identity][m.Target()]; dup {
				c.problems = append(c.problems, fmt.Sprintf(
					"%s: duplicate mapping — %q is already claimed by the SAME Go test %s at %s. "+
						"Two DIFFERENT Go tests splitting one Kotlin case is legitimate; the same one "+
						"claiming it twice is a copy-paste.",
					m.Loc(), identity, m.Target(), prev.Loc()))
				continue
			}
			seen[identity][m.Target()] = m
			c.byCase[identity] = append(c.byCase[identity], m)
		}
	}

	// A case cannot be both covered and deliberately uncovered.
	for identity := range c.byCase {
		for _, kind := range []map[string][]Marker{c.omitted, c.deferred} {
			if ms, both := kind[identity]; both {
				c.problems = append(c.problems, fmt.Sprintf(
					"%s: %q is marked %s here but also carries a KT: coverage claim at %s. Pick one — "+
						"either it is ported or it is not.",
					ms[0].Loc(), identity, ms[0].Kind, c.byCase[identity][0].Loc()))
			}
		}
	}

	c.numMapped = len(c.byCase)
	return c
}

func (c *coverage) accounted() int {
	set := map[string]bool{}
	for k := range c.byCase {
		set[k] = true
	}
	for k := range c.omitted {
		set[k] = true
	}
	for k := range c.deferred {
		set[k] = true
	}
	return len(set)
}

// markerLines is how many marker COMMENTS exist, which is less than len(c.markers) whenever a marker
// sits in a shared contract helper: ScanModule emits one Marker per test that reaches it, so 8 lines in
// runSchemaThreadingContract become 16 mappings across the two engine tests.
func (c *coverage) markerLines() int {
	seen := map[string]bool{}
	for _, m := range c.markers {
		seen[m.Loc()] = true
	}
	return len(seen)
}

func (c *coverage) status(identity string) string {
	switch {
	case len(c.byCase[identity]) > 0:
		return "mapped"
	case len(c.omitted[identity]) > 0:
		return "omit"
	case len(c.deferred[identity]) > 0:
		return "defer"
	default:
		return "UNMAPPED"
	}
}

// TestCoverageMarkersAreValid is the un-gated half of the checker: every one of these is a defect in
// the BOOKKEEPING, not a gap in coverage, and a wrong mapping is worse than a missing one because it
// reads as coverage. None of it is behind the ratchet.
func TestCoverageMarkersAreValid(t *testing.T) {
	c := analyse(t)
	if len(c.problems) == 0 {
		t.Logf("%d markers, all valid", len(c.markers))
		return
	}
	sort.Strings(c.problems)
	t.Errorf("%d invalid marker(s):\n\n  %s\n", len(c.problems), strings.Join(c.problems, "\n\n  "))
}

// TestCoverageRatchet is the gated half: it does not demand 100%, it demands NOT LESS THAN LAST TIME.
func TestCoverageRatchet(t *testing.T) {
	c := analyse(t)
	total := len(c.inv.Cases)
	mapped, acct := c.numMapped, c.accounted()

	pct := func(n int) string { return fmt.Sprintf("%.1f%%", 100*float64(n)/float64(total)) }
	t.Logf("Kotlin cases %d · mapped %d (%s) · accounted %d (%s) · %d marker lines → %d mappings · ratchet %d",
		total, mapped, pct(mapped), acct, pct(acct), c.markerLines(), len(c.markers), minMappedCases)

	if os.Getenv(requireFullEnv) != "" {
		if mapped+len(c.omitted)+len(c.deferred) < total {
			t.Errorf("%s is set: every one of the %d Kotlin cases must carry a KT:, KT-OMIT: or "+
				"KT-DEFER: marker, but %d do not. Run with -v for the list.",
				requireFullEnv, total, total-acct)
		}
	}
	if mapped < minMappedCases {
		t.Errorf("COVERAGE WENT DOWN: %d Kotlin cases carry a KT: marker, the ratchet in "+
			"coverage_test.go is %d. Either restore the mapping, or — if the Go test was legitimately "+
			"removed — give the case a KT-DEFER: marker saying so. Do not lower the ratchet.",
			mapped, minMappedCases)
	}
	if acct < minAccountedCases {
		t.Errorf("ACCOUNTED WENT DOWN: %d cases carry any marker, the ratchet is %d.",
			acct, minAccountedCases)
	}
	if mapped > minMappedCases {
		t.Logf("ratchet is stale and can be raised: minMappedCases = %d (currently %d)", mapped, minMappedCases)
	}
}

// TestCoverageReport prints the human report. `go test ./internal/tracing -run Coverage -v` is the
// command; it never fails, so it stays readable while the port is in flight.
func TestCoverageReport(t *testing.T) {
	c := analyse(t)
	if !testing.Verbose() {
		t.Skip("run with -v for the per-suite table and the unmapped list")
	}
	total := len(c.inv.Cases)

	type row struct {
		suite                               string
		cases, mapped, omit, defr, unmapped int
	}
	var rows []row
	for _, s := range c.inv.Suites() {
		r := row{suite: s}
		for _, cs := range c.inv.CasesIn(s) {
			r.cases++
			switch c.status(cs.Identity) {
			case "mapped":
				r.mapped++
			case "omit":
				r.omit++
			case "defer":
				r.defr++
			default:
				r.unmapped++
			}
		}
		rows = append(rows, r)
	}
	// Biggest holes first — the point of the table is to show where the work is.
	sort.SliceStable(rows, func(a, b int) bool {
		if rows[a].unmapped != rows[b].unmapped {
			return rows[a].unmapped > rows[b].unmapped
		}
		return rows[a].suite < rows[b].suite
	})

	var b strings.Builder
	fmt.Fprintf(&b, "\n=== KOTLIN → GO TEST TRACEABILITY ==============================================\n")
	fmt.Fprintf(&b, "inventory : %s (%d cases, %d suites)\n", InventoryFile, total, len(c.inv.Suites()))
	fmt.Fprintf(&b, "module    : %s\n", c.modRoot)
	fmt.Fprintf(&b, "markers   : %d lines → %d mappings (%d KT:, %d KT-OMIT:, %d KT-DEFER:)\n",
		c.markerLines(), len(c.markers),
		countKind(c.markers, KindPort), countKind(c.markers, KindOmit), countKind(c.markers, KindDefer))
	fmt.Fprintf(&b, "MAPPED    : %d / %d  (%.1f%%)   ratchet %d\n",
		c.numMapped, total, 100*float64(c.numMapped)/float64(total), minMappedCases)
	fmt.Fprintf(&b, "UNMAPPED  : %d\n\n", total-c.accounted())

	fmt.Fprintf(&b, "%-52s %6s %6s %5s %5s %8s\n", "SUITE", "CASES", "MAPPED", "OMIT", "DEFER", "UNMAPPED")
	fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 87))
	for _, r := range rows {
		flag := ""
		if r.unmapped == 0 {
			flag = "  ✓"
		}
		fmt.Fprintf(&b, "%-52s %6d %6d %5d %5d %8d%s\n", r.suite, r.cases, r.mapped, r.omit, r.defr, r.unmapped, flag)
	}
	fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 87))
	fmt.Fprintf(&b, "%-52s %6d %6d %5d %5d %8d\n", "TOTAL", total, c.numMapped, len(c.omitted), len(c.deferred), total-c.accounted())

	fmt.Fprintf(&b, "\n--- FULL UNMAPPED LIST (%d) ----------------------------------------------------\n", total-c.accounted())
	for _, r := range rows {
		if r.unmapped == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n%s  (%d of %d unmapped)\n", r.suite, r.unmapped, r.cases)
		for _, cs := range c.inv.CasesIn(r.suite) {
			if c.status(cs.Identity) == "UNMAPPED" {
				fmt.Fprintf(&b, "  %s\n", cs.Name)
			}
		}
	}
	fmt.Fprintf(&b, "\n=== end ========================================================================\n")
	fmt.Print(b.String())
}

func countKind(ms []Marker, k Kind) int {
	n := 0
	for _, m := range ms {
		if m.Kind == k {
			n++
		}
	}
	return n
}

// TestNoIdentityIsAPrefixOfAnother pins the invariant that makes Inventory.Resolve unambiguous: a
// marker's payload is `<identity> <note>`, and the identity is recovered by longest inventory prefix.
// If some case name were ever a prefix of another (plus a space), `#A — x` could mean either "case A
// with note x" or "case A — x", and the checker would silently pick one. Better to fail here.
func TestNoIdentityIsAPrefixOfAnother(t *testing.T) {
	inv, err := LoadInventory()
	if err != nil {
		t.Fatalf("load inventory: %v", err)
	}
	bySuite := map[string][]Case{}
	for _, c := range inv.Cases {
		bySuite[c.Suite] = append(bySuite[c.Suite], c)
	}
	for suite, cases := range bySuite {
		for _, a := range cases {
			for _, b := range cases {
				if a.Identity == b.Identity {
					continue
				}
				if strings.HasPrefix(b.Identity, a.Identity+" ") {
					t.Errorf("%s: %q is a prefix of %q — marker resolution is now ambiguous. "+
						"Switch Resolve to a delimiter that neither name contains.", suite, a.Name, b.Name)
				}
			}
		}
	}
}

// TestInventoryMatchesTheKotlinTree re-derives the totals straight from the Kotlin sources, so the
// inventory cannot drift from the thing it claims to enumerate. The per-file counts use the ONE
// authoritative form:
//
//	grep -rhoE '@Test\b' --include='*.kt' <path> | wc -l
//
// reimplemented here as regexp `@Test\b` over the file bytes, which is the same thing.
func TestInventoryMatchesTheKotlinTree(t *testing.T) {
	inv, err := LoadInventory()
	if err != nil {
		t.Fatalf("load inventory: %v", err)
	}
	wd, _ := os.Getwd()
	modRoot, err := FindModuleRoot(wd)
	if err != nil {
		t.Fatalf("find module root: %v", err)
	}
	repoRoot := filepath.Dir(modRoot)
	trees := []string{
		filepath.Join(repoRoot, "control-plane", "src", "test", "kotlin", "com", "ridi", "oss", "proxymonster"),
		filepath.Join(repoRoot, "engine", "src", "test", "kotlin", "com", "ridi", "oss", "proxymonster"),
	}
	for _, tr := range trees {
		if _, err := os.Stat(tr); err != nil {
			t.Skipf("Kotlin tree not checked out next to the module (%s): this cross-check only runs "+
				"in the port worktree, where control-plane/ and engine/ are siblings of gocp/. "+
				"The inventory itself is still enforced by the other tests in this package.", tr)
		}
	}

	testRe := regexp.MustCompile(`@Test\b`)
	perFile := map[string]int{}
	files := 0
	total := 0
	for _, tr := range trees {
		err := filepath.Walk(tr, func(path string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() || !strings.HasSuffix(path, ".kt") {
				return err
			}
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			files++
			n := len(testRe.FindAll(b, -1))
			if n > 0 {
				perFile[filepath.Base(path)] = n
				total += n
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", tr, err)
		}
	}

	if total != len(inv.Cases) {
		t.Errorf("Kotlin tree has %d @Test cases, %s has %d lines — regenerate the inventory",
			total, InventoryFile, len(inv.Cases))
	}
	if len(perFile) != len(inv.Suites()) {
		t.Errorf("Kotlin tree has %d suite files with cases (%d .kt files total), %s covers %d",
			len(perFile), files, InventoryFile, len(inv.Suites()))
	}
	for suite, want := range perFile {
		if got := len(inv.CasesIn(suite)); got != want {
			t.Errorf("%s: Kotlin has %d @Test, inventory has %d", suite, want, got)
		}
	}
	for _, suite := range inv.Suites() {
		if _, ok := perFile[suite]; !ok {
			t.Errorf("%s: in the inventory but has no @Test in the Kotlin tree (renamed or deleted?)", suite)
		}
	}
	t.Logf("cross-checked: %d cases across %d suite files (%d .kt files scanned)", total, len(perFile), files)
}
