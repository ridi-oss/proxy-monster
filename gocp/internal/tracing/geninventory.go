//go:build ignore

// geninventory regenerates kotlin_cases.txt from the Kotlin test tree.
//
//	go run ./internal/tracing/geninventory.go            # from gocp/, writes internal/tracing/kotlin_cases.txt
//	go run ./internal/tracing/geninventory.go -check     # exit 1 if the checked-in file is stale
//
// The inventory is the denominator of every coverage number the checker reports, so it has to be
// DERIVED rather than hand-maintained: the Kotlin suite grows, and an inventory that silently lags
// makes coverage look better than it is — the one failure mode this whole convention exists to prevent.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// roots are the Kotlin test trees, relative to the repository root.
var roots = []string{
	"control-plane/src/test/kotlin/com/ridi/oss/proxymonster",
	"engine/src/test/kotlin/com/ridi/oss/proxymonster",
}

var (
	// testAnno matches @Test but NOT @TestInstance / @TestFactory: the trailing boundary is the
	// whole point, and `grep -c @Test` over-counting for exactly this reason is why the count is
	// pinned here rather than in a shell one-liner.
	testAnno = regexp.MustCompile(`@Test\b`)
	// backticked is Kotlin's spaces-in-identifiers form, which nearly every case uses.
	backticked = regexp.MustCompile("`([^`]+)`")
	// plainFun covers the handful written as ordinary camelCase identifiers.
	plainFun = regexp.MustCompile(`^\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:private\s+|internal\s+|inner\s+)*fun\s+([A-Za-z_]\w*)\s*\(`)
	// className tracks the enclosing class, used only to disambiguate a name that repeats inside
	// one file (two test classes in one file, each declaring the same case name).
	className = regexp.MustCompile(`^\s*(?:private\s+|internal\s+|abstract\s+|open\s+|sealed\s+)*class\s+(\w+)`)
)

type entry struct{ file, class, name string }

func main() {
	check := flag.Bool("check", false, "verify the checked-in inventory is current instead of rewriting it")
	flag.Parse()

	root, err := repoRoot()
	if err != nil {
		fail(err)
	}

	var entries []entry
	for _, r := range roots {
		dir := filepath.Join(root, r)
		if _, err := os.Stat(dir); err != nil {
			fail(fmt.Errorf("test root %s: %w", r, err))
		}
		err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".kt") {
				return err
			}
			found, err := scan(p)
			if err != nil {
				return err
			}
			entries = append(entries, found...)
			return nil
		})
		if err != nil {
			fail(err)
		}
	}

	lines := identities(entries)
	sort.Strings(lines)
	out := strings.Join(lines, "\n") + "\n"

	dest := filepath.Join(root, "gocp", "internal", "tracing", "kotlin_cases.txt")
	if *check {
		cur, err := os.ReadFile(dest)
		if err != nil {
			fail(err)
		}
		if string(cur) != out {
			fmt.Fprintf(os.Stderr,
				"kotlin_cases.txt is stale: checked in %d cases, the Kotlin tree has %d.\n"+
					"Regenerate with: go run ./internal/tracing/geninventory.go\n",
				strings.Count(string(cur), "\n"), len(lines))
			os.Exit(1)
		}
		fmt.Printf("kotlin_cases.txt is current: %d cases\n", len(lines))
		return
	}
	if err := os.WriteFile(dest, []byte(out), 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("wrote %d cases to %s\n", len(lines), dest)
}

// scan pulls every @Test case out of one Kotlin file.
//
// A case is the first `fun` following the annotation, which may sit on the same line
// (`@Test fun `x`()`) or on any following line — @Test and the declaration are sometimes separated by
// further annotations, so the search runs forward rather than assuming the very next line.
func scan(path string) ([]entry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	base := filepath.Base(path)
	lines := strings.Split(string(raw), "\n")

	var out []entry
	class := ""
	for i, line := range lines {
		if m := className.FindStringSubmatch(line); m != nil {
			class = m[1]
		}
		if !testAnno.MatchString(line) {
			continue
		}
		if name, ok := funName(line); ok {
			out = append(out, entry{base, class, name})
			continue
		}
		for j := i + 1; j < len(lines) && j <= i+6; j++ {
			if name, ok := funName(lines[j]); ok {
				out = append(out, entry{base, class, name})
				break
			}
		}
	}
	return out, nil
}

// funName reads the case name off a declaration line, backticked or plain.
func funName(line string) (string, bool) {
	if !strings.Contains(line, "fun ") && !strings.Contains(line, "fun\t") {
		return "", false
	}
	if m := backticked.FindStringSubmatch(line); m != nil {
		return m[1], true
	}
	if m := plainFun.FindStringSubmatch(line); m != nil {
		return m[1], true
	}
	return "", false
}

// identities renders one line per case, qualifying with the class ONLY where a bare
// File.kt#name would be ambiguous. Keeping the common case unqualified is what lets a marker
// be written the way the Kotlin reads.
func identities(entries []entry) []string {
	seen := map[string]int{}
	for _, e := range entries {
		seen[e.file+"#"+e.name]++
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if seen[e.file+"#"+e.name] > 1 {
			out = append(out, e.file+"#"+e.class+"."+e.name)
			continue
		}
		out = append(out, e.file+"#"+e.name)
	}
	return out
}

// repoRoot walks up from the working directory to the directory holding both the Kotlin tree and gocp.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "gocp", "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no repository root above the working directory (looked for gocp/go.mod)")
		}
		dir = parent
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "geninventory:", err)
	os.Exit(1)
}
