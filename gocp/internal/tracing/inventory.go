package tracing

import (
	"bufio"
	"embed"
	"fmt"
	"sort"
	"strings"
)

//go:embed kotlin_cases.txt
var inventoryFS embed.FS

// InventoryFile is the name of the embedded inventory, for error messages.
const InventoryFile = "kotlin_cases.txt"

// Case is one Kotlin @Test case.
type Case struct {
	// Identity is the whole line as it appears in kotlin_cases.txt, e.g.
	// "EnforcementDbTest.kt#EnforcementMysqlDbTest.IN subquery oracle is denied". It is what a KT:
	// marker must cite.
	Identity string
	// Suite is the Kotlin file's basename including ".kt".
	Suite string
	// Name is everything after the "#": the case name, prefixed with "<DeclaringClass>." in the
	// multi-class files. See the package doc.
	Name string
	// Line is the 1-based line number in kotlin_cases.txt.
	Line int
}

// Inventory is the authoritative set of Kotlin cases, indexed for marker resolution.
type Inventory struct {
	Cases []Case // in file order (which is sorted by identity)

	byIdentity map[string]Case
	bySuite    map[string][]Case
	suites     []string // sorted
}

// LoadInventory parses the embedded kotlin_cases.txt.
//
// Blank lines and lines starting with "//" are ignored so the file can carry a provenance header if a
// later increment wants one; today it carries none, which keeps `wc -l kotlin_cases.txt` == 903 an
// honest one-command check.
func LoadInventory() (*Inventory, error) {
	raw, err := inventoryFS.ReadFile(InventoryFile)
	if err != nil {
		return nil, fmt.Errorf("read embedded %s: %w", InventoryFile, err)
	}
	inv := &Inventory{
		byIdentity: map[string]Case{},
		bySuite:    map[string][]Case{},
	}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		if line != strings.TrimSpace(line) {
			return nil, fmt.Errorf("%s:%d: leading or trailing whitespace — case names are verbatim, so whitespace is significant and must not be introduced here", InventoryFile, lineNo)
		}
		suite, name, ok := strings.Cut(line, "#")
		if !ok {
			return nil, fmt.Errorf("%s:%d: no '#' separator in %q", InventoryFile, lineNo, line)
		}
		if !strings.HasSuffix(suite, ".kt") {
			return nil, fmt.Errorf("%s:%d: suite %q does not end in .kt", InventoryFile, lineNo, suite)
		}
		if name == "" {
			return nil, fmt.Errorf("%s:%d: empty case name in %q", InventoryFile, lineNo, line)
		}
		if prev, dup := inv.byIdentity[line]; dup {
			return nil, fmt.Errorf("%s:%d: duplicate identity %q (first seen at line %d) — the inventory must be 1:1 with the Kotlin cases", InventoryFile, lineNo, line, prev.Line)
		}
		c := Case{Identity: line, Suite: suite, Name: name, Line: lineNo}
		inv.Cases = append(inv.Cases, c)
		inv.byIdentity[line] = c
		inv.bySuite[suite] = append(inv.bySuite[suite], c)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", InventoryFile, err)
	}
	for s := range inv.bySuite {
		inv.suites = append(inv.suites, s)
	}
	sort.Strings(inv.suites)
	return inv, nil
}

// Suites returns the suite file basenames, sorted.
func (i *Inventory) Suites() []string { return i.suites }

// CasesIn returns the cases of one suite, in inventory order.
func (i *Inventory) CasesIn(suite string) []Case { return i.bySuite[suite] }

// Has reports whether identity is exactly an inventory line.
func (i *Inventory) Has(identity string) bool {
	_, ok := i.byIdentity[identity]
	return ok
}

// NoteSeparators introduce the optional free-form note after a marker's identity. An em dash is the
// convention; " -- " is accepted for keyboards that make one awkward.
//
// A separator is REQUIRED, and that is the point. Without one, `#…on admin actions extra` would
// resolve to `#…on admin actions` with the note "extra" — silently mapping a typo to a real case,
// which is the one failure mode worse than a gap. With one, the typo does not resolve and the checker
// says so.
var NoteSeparators = []string{" — ", " -- "}

// Resolve turns a marker's payload into a case identity plus the note that followed it.
//
// The payload is `<identity>` or `<identity> — <note>`. The identity is found by LONGEST inventory
// prefix within the cited suite rather than by splitting on the separator, because 40 of the 903 case
// names contain " — " themselves and would otherwise be truncated at their own em dash. Longest-prefix
// is unambiguous exactly because no inventory identity is a prefix of another —
// TestNoIdentityIsAPrefixOfAnother pins that, and fails if a future Kotlin case breaks it.
//
// ok is false when nothing resolves, which is the typo case and must be a hard failure: a marker naming
// a case that does not exist reads as coverage while covering nothing.
func (i *Inventory) Resolve(payload string) (identity, note string, ok bool) {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return "", "", false
	}
	// Fast path: the whole payload is an identity, no note.
	if i.Has(payload) {
		return payload, "", true
	}
	suite, _, cut := strings.Cut(payload, "#")
	if !cut {
		return "", "", false
	}
	best, bestNote := "", ""
	for _, c := range i.bySuite[suite] {
		if !strings.HasPrefix(payload, c.Identity) || len(c.Identity) <= len(best) {
			continue
		}
		rest := payload[len(c.Identity):]
		for _, sep := range NoteSeparators {
			if strings.HasPrefix(rest, sep) {
				best, bestNote = c.Identity, strings.TrimSpace(rest[len(sep):])
				break
			}
		}
	}
	if best == "" {
		return "", "", false
	}
	return best, bestNote, true
}

// SuggestFor returns up to n inventory identities a mistyped payload probably meant, so the checker's
// failure message is actionable instead of just "unknown".
func (i *Inventory) SuggestFor(payload string, n int) []string {
	payload = strings.TrimSpace(payload)
	suite, name, _ := strings.Cut(payload, "#")
	cands := i.bySuite[suite]
	if len(cands) == 0 {
		// Wrong suite name: fall back to any suite whose basename shares the payload's prefix.
		for _, s := range i.suites {
			if strings.EqualFold(s, suite) || strings.HasPrefix(strings.ToLower(s), strings.ToLower(strings.TrimSuffix(suite, ".kt"))) {
				cands = append(cands, i.bySuite[s]...)
			}
		}
	}
	type scored struct {
		id string
		n  int
	}
	var out []scored
	lname := strings.ToLower(name)
	for _, c := range cands {
		out = append(out, scored{c.Identity, commonPrefixLen(strings.ToLower(c.Name), lname)})
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].n > out[b].n })
	var ids []string
	for _, s := range out {
		if len(ids) >= n {
			break
		}
		ids = append(ids, s.id)
	}
	return ids
}

func commonPrefixLen(a, b string) int {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return n
}
