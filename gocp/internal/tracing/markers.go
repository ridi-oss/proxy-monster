package tracing

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Kind is which of the three markers a line carries.
type Kind string

const (
	KindPort  Kind = "KT"       // a claim of coverage
	KindOmit  Kind = "KT-OMIT"  // deliberately not ported, with a reason
	KindDefer Kind = "KT-DEFER" // blocked, with what it is blocked on
)

// Marker is one KT:/KT-OMIT:/KT-DEFER: line found in a *_test.go file.
type Marker struct {
	Kind    Kind
	Payload string // the raw text after the colon, identity + optional note
	File    string // module-relative
	Line    int    // 1-based
	Owner   string // enclosing or documented TEST function; "" when unattached
	Subtest string // the t.Run / subtest name the marker sits directly above; "" when none
}

// Loc renders "file:line" for error messages.
func (m Marker) Loc() string { return fmt.Sprintf("%s:%d", m.File, m.Line) }

// Target is the Go test a marker maps to. A subtest is a distinct test: `go test -run
// 'TestEnforcementPostgresDb/IN subquery oracle is denied'` addresses it on its own. Duplicate
// detection keys on this, so the same identity on two SUBTESTS of one function is a split (allowed)
// while the same identity twice in one block is a copy-paste (rejected).
func (m Marker) Target() string {
	if m.Subtest == "" {
		return m.Owner
	}
	return m.Owner + "/" + m.Subtest
}

var (
	markerRe = regexp.MustCompile(`\bKT(-OMIT|-DEFER)?:[ \t]*(.*)$`)
	testFunc = regexp.MustCompile(`^(Test|Benchmark|Fuzz|Example)`)
)

// subtestLookahead is how many lines below a marker a t.Run may sit and still be named by it. The
// conventional placement is the very next line; the slack covers an intervening comment.
const subtestLookahead = 4

// FindModuleRoot walks up from dir until it finds go.mod.
func FindModuleRoot(dir string) (string, error) {
	d, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", fmt.Errorf("no go.mod at or above %s", dir)
		}
		d = parent
	}
}

// ScanModule collects every marker in every *_test.go under root, in (file, line) order.
//
// internal/tracing is skipped on purpose: this package's own doc and self-tests quote example markers,
// and a checker that counted its own examples as coverage would be exactly the unfalsifiable thing it
// exists to prevent.
func ScanModule(root string) ([]Marker, error) {
	var out []Marker
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules", "testdata":
				return fs.SkipDir
			}
			if rel, rerr := filepath.Rel(root, path); rerr == nil && rel == filepath.Join("internal", "tracing") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		ms, ferr := scanFile(path, filepath.ToSlash(rel))
		if ferr != nil {
			return ferr
		}
		out = append(out, ms...)
		return nil
	})
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].File != out[b].File {
			return out[a].File < out[b].File
		}
		return out[a].Line < out[b].Line
	})
	return out, err
}

// scanFile parses one *_test.go and returns its markers.
//
// It uses go/ast rather than a line scan because every interesting attachment question is a question
// the parser already answers exactly: "is this comment the func's doc comment" is ast.FuncDecl.Doc,
// and "is this marker inside that func" is a position range. A line scan gets one-line function
// bodies, raw string literals containing a brace at column 0, and `KT:` inside a string literal all
// wrong — and a checker that miscounts is worse than no checker.
func scanFile(path, rel string) ([]Marker, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", rel, err)
	}

	// Which comment groups are the doc comment of a TEST function.
	docOwner := map[*ast.CommentGroup]string{}
	var funcs []*ast.FuncDecl
	callers := map[string][]string{} // callee name -> the funcs that call it, in this file
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		funcs = append(funcs, fn)
		if fn.Doc != nil && fn.Recv == nil && testFunc.MatchString(fn.Name.Name) {
			docOwner[fn.Doc] = fn.Name.Name
		}
		if fn.Recv != nil || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok {
					callers[id.Name] = append(callers[id.Name], fn.Name.Name)
				}
			}
			return true
		})
	}

	var out []Marker
	for _, grp := range f.Comments {
		for _, c := range grp.List {
			m := markerRe.FindStringSubmatch(c.Text)
			if m == nil {
				continue
			}
			kind := KindPort
			switch m[1] {
			case "-OMIT":
				kind = KindOmit
			case "-DEFER":
				kind = KindDefer
			}
			pos := fset.Position(c.Slash)
			enclosing, body := enclosingFunc(funcs, c.Slash)
			owners := []string{""}
			switch {
			case enclosing == nil: // not inside any body: is this group a test func's doc comment?
				owners = []string{docOwner[grp]}
			case isTestFunc(enclosing):
				owners = []string{enclosing.Name.Name}
			default:
				// A shared contract helper. Attribute the marker to every test that reaches it —
				// see reachingTests.
				if ts := reachingTests(callers, enclosing.Name.Name); len(ts) > 0 {
					owners = ts
				}
			}
			for _, owner := range owners {
				out = append(out, Marker{
					Kind:    kind,
					Payload: strings.TrimSpace(m[2]),
					File:    rel,
					Line:    pos.Line,
					Owner:   owner,
					Subtest: subtestBelow(fset, body, pos.Line),
				})
			}
		}
	}
	return out, nil
}

func isTestFunc(fn *ast.FuncDecl) bool {
	return fn.Recv == nil && testFunc.MatchString(fn.Name.Name)
}

// enclosingFunc returns the function declaration whose body contains pos, and that body.
func enclosingFunc(funcs []*ast.FuncDecl, pos token.Pos) (*ast.FuncDecl, *ast.BlockStmt) {
	for _, fn := range funcs {
		if fn.Body != nil && pos >= fn.Body.Pos() && pos <= fn.Body.End() {
			return fn, fn.Body
		}
	}
	return nil, nil
}

// reachingTests walks the file's call graph backwards from a helper to every test function that
// reaches it, so a marker inside a SHARED CONTRACT counts once per test that runs it.
//
// This is not a convenience — it is the shape the Kotlin itself uses. SchemaThreadingDbTest.kt declares
// an abstract SchemaThreadingDbContract whose 8 @Test cases run once per concrete subclass, one per
// engine. Go has no inheritance, so the port makes the contract a function that the two engine tests
// call; a marker in there is genuinely ported by BOTH, which is the legitimate "several Go tests split
// one Kotlin case" cardinality. Naming only the helper would map the case to something `go test -run`
// cannot address; refusing it would force a third, duplicate test the Kotlin does not have.
func reachingTests(callers map[string][]string, helper string) []string {
	found := map[string]bool{}
	seen := map[string]bool{helper: true}
	queue := []string{helper}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, c := range callers[cur] {
			if seen[c] {
				continue
			}
			seen[c] = true
			if testFunc.MatchString(c) {
				found[c] = true
				continue // a test is a root; do not walk past it
			}
			queue = append(queue, c)
		}
	}
	out := make([]string, 0, len(found))
	for t := range found {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// subtestBelow names the t.Run / fx.subtest the marker sits directly above, so that the conventional
// placement
//
//	// KT: <identity>
//	t.Run("<the kotlin case name>", func(t *testing.T) {
//
// enriches the report with the subtest. It looks FORWARD only: the nearest PRECEDING t.Run is the
// previous subtest, and attributing a marker to that would be worse than reporting no subtest at all.
func subtestBelow(fset *token.FileSet, body *ast.BlockStmt, markerLine int) string {
	if body == nil {
		return ""
	}
	best, bestLine := "", 0
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Run" && sel.Sel.Name != "subtest") {
			return true
		}
		line := fset.Position(call.Pos()).Line
		if line < markerLine || line > markerLine+subtestLookahead {
			return true
		}
		for _, a := range call.Args {
			lit, ok := a.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				continue
			}
			if best == "" || line < bestLine {
				best, bestLine = s, line
			}
			break
		}
		return true
	})
	return best
}
