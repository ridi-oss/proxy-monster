package spi

import "testing"

func TestAuthorizerCachesCatalogWithNamespace(t *testing.T) {
	decider := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	query := NewAuthorizer(decider)
	catalog := "one"
	probes := 0
	input := AuthzInput{ProbeSession: func() (SessionObservation, error) {
		probes++
		return SessionObservation{CurrentCatalog: catalog, Namespace: []string{"schema"}}, nil
	}}
	query.Authorize(input)
	catalog = "two"
	query.Authorize(input)
	if decider.lastReq.Session.CurrentCatalog != "one" || probes != 1 {
		t.Fatal("catalog was not cached with namespace")
	}
	query.MarkNamespaceDirty()
	query.Authorize(input)
	if decider.lastReq.Session.CurrentCatalog != "two" || probes != 2 {
		t.Fatal("dirty namespace did not refresh catalog")
	}
}
