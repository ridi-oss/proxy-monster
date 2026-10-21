package spi

import (
	"testing"
)

func TestAuthorizerCachesCatalogWithNamespace(t *testing.T) {
	decider := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	authz := NewAuthorizer(decider, "", nil)
	catalog := "one"
	probes := 0
	input := AuthzInput{ProbeSession: func() (SessionObservation, error) {
		probes++
		return SessionObservation{CurrentCatalog: catalog, Namespace: []string{"schema"}}, nil
	}}
	authz.Authorize(input)
	catalog = "two"
	authz.Authorize(input)
	if decider.lastReq.Session.CurrentCatalog != "one" || probes != 1 {
		t.Fatal("catalog was not cached with namespace")
	}
	authz.MarkNamespaceDirty()
	authz.Authorize(input)
	if decider.lastReq.Session.CurrentCatalog != "two" || probes != 2 {
		t.Fatal("dirty namespace did not refresh catalog")
	}
}
