package authz

import (
	"sync"
	"testing"

	"github.com/cedar-policy/cedar-go/types"
)

// The store-independent half of CedarEngineCacheTest.kt (02-authz.md §10 classifies both its cases as
// DB). The DB half — that a real setEnabled/delete bumps stateVersion and invalidates — belongs with
// the later store increment; what is testable NOW is the version GATING itself, via a fake PolicyStore.
//
// TODO(A2): CedarEngineCacheTest's two cases against a real CedarPolicyStore + Postgres — see D13.

// fakeStore is the narrow PolicyStore CedarEngine consumes, with a version the test drives by hand.
type fakeStore struct {
	mu      sync.Mutex
	sources []PolicySource
	version int64
	reads   int
}

func (s *fakeStore) EnabledSources() []PolicySource {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	return append([]PolicySource(nil), s.sources...)
}

func (s *fakeStore) StateVersion() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version
}

func (s *fakeStore) mutate(sources []PolicySource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources = sources
	s.version++ // INV-A2-19: bumped only AFTER the mutation commits
}

func decide(t *testing.T, a *Authz, principal string, roles []string) AuthzDecision {
	t.Helper()
	return a.AuthorizeDatasourceAction(principal, roles, ActionDatasourceConnect, "acme-pg", AuthzContext{}, nil)
}

// TestEngineRebuildsOnlyWhenStoreStateChanges is CedarEngineCacheTest case 2's assertion —
// "isAuthorized only rebuilds the PolicySet when store state changes — O(1) per query" — which is
// exactly why 02-authz.md §7 requires an observable BuildCount in the port.
func TestEngineRebuildsOnlyWhenStoreStateChanges(t *testing.T) {
	store := &fakeStore{sources: []PolicySource{
		{ID: 1, Src: `permit(principal in Role::"analyst", action == Action::"datasource.connect", resource in Datasource::"acme-pg");`},
	}}
	e, err := NewCedarEngine(store)
	if err != nil {
		t.Fatal(err)
	}
	a := New(e, store, stubRoles(nil))

	if e.BuildCount() != 0 {
		t.Fatalf("BuildCount before the first decision = %d, want 0 (the sentinel forces a first-use build, not an eager one)", e.BuildCount())
	}
	for range 20 {
		assertAllow(t, decide(t, a, "alice", []string{"analyst"}), "granted role")
	}
	if got := e.BuildCount(); got != 1 {
		t.Errorf("BuildCount after 20 decisions = %d, want 1 — the PolicySet must be rebuilt only on a version change", got)
	}
}

// TestEngineInvalidatesOnVersionBump is CedarEngineCacheTest case 1 — "disable invalidates the cache;
// re-enable and delete both take effect on the next call".
func TestEngineInvalidatesOnVersionBump(t *testing.T) {
	grant := PolicySource{ID: 1, Src: `permit(principal in Role::"analyst", action == Action::"datasource.connect", resource in Datasource::"acme-pg");`}
	store := &fakeStore{sources: []PolicySource{grant}}
	e, err := NewCedarEngine(store)
	if err != nil {
		t.Fatal(err)
	}
	a := New(e, store, stubRoles(nil))

	assertAllow(t, decide(t, a, "alice", []string{"analyst"}), "before disable")

	store.mutate(nil) // the row is disabled
	assertDeny(t, decide(t, a, "alice", []string{"analyst"}), "after disable")
	if got := e.BuildCount(); got != 2 {
		t.Errorf("BuildCount = %d, want 2 (one per version change)", got)
	}

	store.mutate([]PolicySource{grant}) // re-enabled
	assertAllow(t, decide(t, a, "alice", []string{"analyst"}), "after re-enable")
}

// TestVocabularyRebuildsAtomicallyWithThePolicySet — 🔒 INV-A2-18. The policy set and the tag
// vocabulary rebuild TOGETHER, so they can never disagree. A vocabulary that lagged the policy set
// would either evaluate a tag action no rule targets (harmless) or MISS a tag rule that is now enabled
// (a silently un-earned tag, i.e. a grant that never applies).
func TestVocabularyRebuildsAtomicallyWithThePolicySet(t *testing.T) {
	store := &fakeStore{sources: []PolicySource{
		{ID: 1, Src: `permit(principal, action == Action::"datasource.connect", resource);`},
	}}
	e, err := NewCedarEngine(store)
	if err != nil {
		t.Fatal(err)
	}
	vocab, err := e.ContextTagVocabulary()
	if err != nil || len(vocab) != 0 {
		t.Fatalf("vocabulary = %v (err %v), want empty", vocab, err)
	}

	store.mutate([]PolicySource{
		{ID: 1, Src: `permit(principal, action == Action::"datasource.connect", resource);`},
		{ID: 2, Src: cidrTagRule[1]},
	})
	vocab, err = e.ContextTagVocabulary()
	if err != nil {
		t.Fatal(err)
	}
	assertStrings(t, vocab, []string{"trusted-network"}, "vocabulary after the tag rule is enabled")
	if got := e.BuildCount(); got != 2 {
		t.Errorf("BuildCount = %d, want 2 — the vocabulary must rebuild WITH the policy set, not separately", got)
	}
}

// TestConcurrentDecisionsNeverTearTheCache covers 02-authz.md §10's named coverage gap: "concurrent
// rebuildIfStale (the @Synchronized / torn-cache guarantee)". Meaningful under `go test -race`.
func TestConcurrentDecisionsNeverTearTheCache(t *testing.T) {
	grant := PolicySource{ID: 1, Src: `permit(principal in Role::"analyst", action == Action::"datasource.connect", resource in Datasource::"acme-pg");`}
	store := &fakeStore{sources: []PolicySource{grant}}
	e, err := NewCedarEngine(store)
	if err != nil {
		t.Fatal(err)
	}
	a := New(e, store, stubRoles(nil))

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				// Either verdict is legitimate here — the store is being mutated concurrently. What must
				// never happen is a torn read, a data race, or a panic.
				_ = decide(t, a, "alice", []string{"analyst"})
				_, _ = e.ContextTagVocabulary()
			}
		}()
	}
	for range 20 {
		store.mutate([]PolicySource{grant})
	}
	wg.Wait()
}

// TestEngineConstructionValidatesEveryEnabledSource — 🔒 INV-A2-17, including the polic{y|ies}
// pluralisation an operator reads when boot aborts.
func TestEngineConstructionValidatesEveryEnabledSource(t *testing.T) {
	_, err := NewCedarEngineFromSources([]PolicySource{
		{ID: 7, Src: `permit(principal, action == Action::"totally.unknown", resource);`},
	})
	if err == nil {
		t.Fatal("construction must fail on a policy referencing an unknown action")
	}
	if want := "authz: enabled cedar policy failed schema validation at startup: policy #7: "; err.Error()[:len(want)] != want {
		t.Errorf("error = %q, want prefix %q", err.Error(), want)
	}

	_, err = NewCedarEngineFromSources([]PolicySource{
		{ID: 7, Src: `permit(principal, action == Action::"totally.unknown", resource);`},
		{ID: 8, Src: `this is not cedar at all`},
	})
	if err == nil {
		t.Fatal("construction must fail")
	}
	if want := "authz: enabled cedar policies failed schema validation at startup: "; err.Error()[:len(want)] != want {
		t.Errorf("error = %q, want the PLURAL prefix %q", err.Error(), want)
	}
}

// TestNetworkZonesIsAlwaysPresent — §6 step 1. The key is emitted even when empty.
//
// And the spike's third "surprise", which is easy to get wrong in the other direction:
// schema.cedarschema:114-119 declares network_zones OPTIONAL, so an UNGUARDED read still fails strict
// validation even though ToCedarMap always emits it. Both halves are asserted.
func TestNetworkZonesIsAlwaysPresent(t *testing.T) {
	empty := AuthzContext{}.ToCedarMap(true)
	v, ok := empty.Get("network_zones")
	if !ok {
		t.Fatal("network_zones must ALWAYS be present, empty set if none")
	}
	if s, isSet := v.(types.Set); !isSet || s.Len() != 0 {
		t.Errorf("network_zones = %v, want an empty Set", v)
	}

	assertInvalid(t, `permit(principal, action == Action::"datasource.connect", resource) when { context.network_zones.contains("office") };`)
	assertValid(t, `permit(principal, action == Action::"datasource.connect", resource) when { context has network_zones && context.network_zones.contains("office") };`)

	// And the guarded rule genuinely fires.
	a := authzFor(t, map[int64]string{
		1: `permit(principal, action == Action::"datasource.connect", resource) when { context has network_zones && context.network_zones.contains("office") };`,
	}, nil)
	assertAllow(t, a.AuthorizeDatasourceAction("alice", nil, ActionDatasourceConnect, "acme-pg",
		AuthzContext{NetworkZones: []string{"office"}}, nil), "network_zones=[office]")
	assertDeny(t, a.AuthorizeDatasourceAction("alice", nil, ActionDatasourceConnect, "acme-pg",
		AuthzContext{}, nil), "network_zones empty")
}
