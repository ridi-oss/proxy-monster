package authz

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"sync"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// PolicySource is one enabled policy row — the port of Kotlin's Pair<Long, String> that
// CedarPolicyStore.enabledSources() returns (id, cedar_src), ORDER BY id.
type PolicySource struct {
	ID  int64
	Src string
}

// PolicyStore is the narrow slice of CedarPolicyStore that CedarEngine actually needs.
//
// Declared here rather than imported so the authz decision path does not depend on the store package.
// The Kotlin constructor takes the whole CedarPolicyStore but calls exactly these two methods
// (CedarEngine.kt:155).
//
// TODO(A2): CedarPolicyStore itself — policy CRUD with validate-on-write, the origin guards under a row
// lock (INV-A2-20), enable-revalidates (INV-A2-21) and the SYSTEM-toggle sentinel audit row
// (INV-A2-22) — is a later increment. See 02-authz.md §8.
type PolicyStore interface {
	// EnabledSources returns (id, cedar_src) for enabled = true, ORDER BY id — a stable order.
	EnabledSources() []PolicySource
	// StateVersion is bumped only AFTER a mutation commits (INV-A2-19).
	StateVersion() int64
}

// CedarEngine is the live authorization engine: the current ENABLED policy set, cached and rebuilt only
// when the store's state version changes. Ported from CedarEngine.kt:154-217.
//
// The column path calls Authorize O(N = touched columns) per query, so re-parsing every enabled policy
// on every call would not be cheap — the cache is a correctness-neutral performance requirement that
// CedarEngineCacheTest pins at O(1) rebuilds per query.
type CedarEngine struct {
	sources func() []PolicySource
	version func() int64
	schema  *CedarSchema

	// Kotlin uses @Volatile fields plus @Synchronized on the rebuild. One mutex covering both the
	// rebuild and the read is the Go equivalent and is what guarantees INV-A2-18's "concurrent callers
	// never observe a torn cache" — an atomic.Pointer to an immutable snapshot would work equally well
	// but buys nothing at this call rate.
	mu             sync.Mutex
	cachedVersion  int64
	cachedPolicies *cedar.PolicySet
	cachedVocab    []string
	buildCount     int
	evalCount      int
}

// NewCedarEngineFromSources is CedarEngine(policySources: List<Pair<Long,String>>) — a FIXED, in-memory
// policy set with no store, no DataSource and no DB, for unit tests that want a real engine without
// touching JDBC. Its version supplier is a constant 0, so the policy set is built once and never
// invalidated (correct: the list is immutable for the lifetime of the engine).
func NewCedarEngineFromSources(sources []PolicySource) (*CedarEngine, error) {
	fixed := append([]PolicySource(nil), sources...)
	return newCedarEngine(func() []PolicySource { return fixed }, func() int64 { return 0 }, DefaultSchema)
}

// NewCedarEngine is CedarEngine(policyStore: CedarPolicyStore) — the production constructor. Polls
// StateVersion() on every Authorize and rebuilds from EnabledSources() only when it has moved.
func NewCedarEngine(store PolicyStore) (*CedarEngine, error) {
	return newCedarEngine(store.EnabledSources, store.StateVersion, DefaultSchema)
}

func newCedarEngine(sources func() []PolicySource, version func() int64, schema *CedarSchema) (*CedarEngine, error) {
	e := &CedarEngine{
		sources:       sources,
		version:       version,
		schema:        schema,
		cachedVersion: math.MinInt64, // Long.MIN_VALUE sentinel: guarantees a first-use build
	}

	// 🔒 INV-A2-17 — FAIL FAST AT CONSTRUCTION. Validate EVERY source; any failure aborts. Cedar would
	// otherwise silently refuse to load a malformed policy and effectively deny everything for it — a
	// disabled security control that looks like a working one. CedarEngine.kt:166-174.
	//
	// The Kotlin throws IllegalStateException from `check`; Go returns the error, and the message shape
	// is reproduced exactly (including the polic{y|ies} pluralisation) because
	// ChannelContextAuthzTest case 4 and TagResolutionTest case 6 assert construction FAILS, and an
	// operator reads this string when boot aborts.
	var parts []string
	for _, s := range sources() {
		if errs := schema.Validate(s.Src); len(errs) > 0 {
			parts = append(parts, "policy #"+strconv.FormatInt(s.ID, 10)+": "+strings.Join(errs, ", "))
		}
	}
	if len(parts) > 0 {
		noun := "policies"
		if len(parts) == 1 {
			noun = "policy"
		}
		return nil, errors.New("authz: enabled cedar " + noun +
			" failed schema validation at startup: " + strings.Join(parts, "; "))
	}
	return e, nil
}

// snapshot ports rebuildIfStale + policySet + contextTagVocabulary (CedarEngine.kt:179-204).
//
// 🔒 INV-A2-18 — the policy set and the tag vocabulary rebuild ATOMICALLY, so they can never disagree,
// and concurrent callers never observe a torn cache. Returning both from one locked region is what
// enforces that; splitting it into two accessors would reintroduce the tear.
//
// Kotlin's Policy(src, "policy-$id") THROWS if a source no longer parses, and that exception propagates
// out of isAuthorized. Go returns it instead — see the note on Authorize.
func (e *CedarEngine) snapshot() (*cedar.PolicySet, []string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	v := e.version()
	if e.cachedPolicies != nil && v == e.cachedVersion {
		return e.cachedPolicies, e.cachedVocab, nil
	}

	srcs := e.sources()
	ps := cedar.NewPolicySet()
	var vocab []string
	seen := map[string]bool{}
	for _, s := range srcs {
		var p cedar.Policy
		if err := p.UnmarshalCedar([]byte(s.Src)); err != nil {
			// Unreachable through the API: every path that enables a row validates it first
			// (INV-A2-21), and Validate performs the same parse. Reaching here means the `policy` table
			// was edited out of band. Fail closed and do NOT publish a partial policy set — silently
			// dropping a forbid is the one outcome that must never happen.
			return nil, nil, errors.New("authz: enabled cedar policy #" +
				strconv.FormatInt(s.ID, 10) + " failed to parse: " + err.Error())
		}
		// 🔴 W2 — the POLICY-LOAD half of the multi-statement reject. W2 requires the statement-count
		// check "in the Go validate AND in the policy-load path", and this is that path.
		//
		// UnmarshalCedar above ACCEPTS `permit(…); forbid(…);` and silently keeps statement 1, so without
		// this guard an enabled row whose second statement is a forbid loses that forbid at load time —
		// the security control is gone and nothing reports it. Construction (INV-A2-17) and every
		// enable/create/update path validate first, so this is only reachable when the `policy` table is
		// edited out of band; that is exactly the case W2 is about. Kotlin's own rebuild uses the same
		// single-named-policy constructor (Policy(src, "policy-$id"), CedarEngine.kt:184) that the Rust
		// core REJECTS a two-statement source through, so failing here is the faithful behaviour as well
		// as the safe one — the Kotlin throws out of isAuthorized, the port denies through branch 1a.
		if n, cerr := statementCount(s.Src); cerr == nil && n != 1 {
			return nil, nil, errors.New("authz: enabled cedar policy #" + strconv.FormatInt(s.ID, 10) +
				" must contain exactly one statement, found " + strconv.Itoa(n))
		}
		ps.Add(cedar.PolicyID("policy-"+strconv.FormatInt(s.ID, 10)), &p)
		for _, n := range ExtractContextTagNames(s.Src) {
			if !seen[n] {
				seen[n] = true
				vocab = append(vocab, n)
			}
		}
	}

	e.cachedPolicies = ps
	e.cachedVocab = vocab
	e.cachedVersion = v
	e.buildCount++
	return ps, vocab, nil
}

// ContextTagVocabulary is every tag name the enabled rules target via a context.tag::<name> action —
// DERIVED, not predefined (docs/authz-context.md). Empty when no tag rule is enabled, which is what
// makes pass-1 a no-op for the common deployment. Cached with the policy set.
func (e *CedarEngine) ContextTagVocabulary() ([]string, error) {
	_, vocab, err := e.snapshot()
	return vocab, err
}

// Authorize is CedarEngine.isAuthorized (CedarEngine.kt:206-213).
//
// Returns cedar-go's (Decision, Diagnostic) pair plus an error for the rebuild failure the Kotlin
// signals by throwing. Callers must run the result through toAuthzDecision or allowedByCedar — never
// read `decision` on its own. See the ERRORS-FIRST note on toAuthzDecision.
func (e *CedarEngine) Authorize(
	principal, action, resource types.EntityUID,
	entities types.EntityMap,
	context types.Record,
) (types.Decision, types.Diagnostic, error) {
	ps, _, err := e.snapshot()
	if err != nil {
		return false, types.Diagnostic{}, err
	}
	e.mu.Lock()
	e.evalCount++
	e.mu.Unlock()
	d, diag := cedar.Authorize(ps, entities, types.Request{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   context,
	})
	return d, diag, nil
}

// Validate parses and validates a single candidate policy against the schema — CedarEngine.kt:216.
func (e *CedarEngine) Validate(cedarSrc string) []string { return e.schema.Validate(cedarSrc) }

// Schema exposes the bundled schema (its Text backs GET /api/policies/schema).
func (e *CedarEngine) Schema() *CedarSchema { return e.schema }

// BuildCount is how many times the PolicySet has actually rebuilt.
//
// 02-authz.md §7 is explicit that this must exist: cedar-java's @JvmField internal buildCount "exists
// solely for CedarEngineCacheTest's O(1)-per-query assertion. The Go port needs an equivalent
// observable counter or that test cannot be ported."
func (e *CedarEngine) BuildCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.buildCount
}

// EvalCount is how many Cedar decisions have been evaluated.
//
// ADDITION (no Kotlin counterpart), on the same footing as BuildCount and for the same reason: the
// only way to assert TagResolutionTest case 3's "an empty vocabulary short-circuits to no tags WITH NO
// isAuthorized CALL MADE" is an observable evaluation counter. Without it the test degrades to
// asserting an empty result, which an implementation that evaluated and denied would also pass.
func (e *CedarEngine) EvalCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.evalCount
}
