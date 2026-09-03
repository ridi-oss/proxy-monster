package dbtest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// dbSupportFile is the repo-root file that declares every supported database version and the image
// each is tested against. db-support.json's own header calls it "the ONE place the set is declared".
const dbSupportFile = "db-support.json"

// DbSupport is db-support.json, decoded.
type DbSupport struct {
	// Target engines are the databases the proxy brokers queries TO.
	Target []DbSupportEntry `json:"target"`
	// Storage engines are what the control plane keeps its own state in. PostgreSQL only.
	Storage []DbSupportEntry `json:"storage"`
}

// DbSupportEntry is one declared version: the engine, the series support is claimed at, and the
// floating image pin within that series.
type DbSupportEntry struct {
	Engine string `json:"engine"`
	Series string `json:"series"`
	Image  string `json:"image"`
}

// LoadDbSupport reads db-support.json by walking UP from the working directory.
//
// The walk is deliberate. F9 (00-INDEX.md:188) records that auditmon reads a control-plane fixture
// through a hardcoded `../../control-plane/src/test/...` path that BREAKS AT CUTOVER; a fixed
// `../../../db-support.json` here would be the same defect, and it would break on the ordinary
// `go test ./internal/dbtest` vs `go test ./...` difference too, because the working directory is the
// package's. Walking up finds the file from any depth and from either invocation.
func LoadDbSupport() (DbSupport, string, error) {
	path, err := findUpwards(dbSupportFile)
	if err != nil {
		return DbSupport{}, "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return DbSupport{}, path, fmt.Errorf("read %s: %w", path, err)
	}
	var out DbSupport
	if err := json.Unmarshal(raw, &out); err != nil {
		return DbSupport{}, path, fmt.Errorf("parse %s: %w", path, err)
	}
	return out, path, nil
}

func findUpwards(name string) (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(dir, name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("%s not found in any parent of the working directory", name)
		}
		dir = parent
	}
}

// NewestSeries returns the newest declared series for an engine in a list, comparing numerically
// component by component ("8.4" > "8.0", "17" > "16" — and "10" > "9", which a string comparison gets
// backwards).
func NewestSeries(entries []DbSupportEntry, engine string) (DbSupportEntry, bool) {
	var best DbSupportEntry
	var found bool
	for _, e := range entries {
		if e.Engine != engine {
			continue
		}
		if !found || compareSeries(e.Series, best.Series) > 0 {
			best, found = e, true
		}
	}
	return best, found
}

// compareSeries orders two dotted-numeric series. A non-numeric component sorts as 0, which is safe
// here: the guard's job is to notice a NEW series being added, and a malformed one shows up as the
// default no longer matching rather than as a silent pass.
func compareSeries(a, b string) int {
	as, bs := splitSeries(a), splitSeries(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func splitSeries(s string) []int {
	var out []int
	cur, has := 0, false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] >= '0' && s[i] <= '9':
			cur, has = cur*10+int(s[i]-'0'), true
		case s[i] == '.':
			out, cur, has = append(out, cur), 0, false
		default:
			return append(out, cur)
		}
	}
	if has || len(out) == 0 {
		out = append(out, cur)
	}
	return out
}
