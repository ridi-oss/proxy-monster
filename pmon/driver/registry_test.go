package driver

import "testing"

func TestRegistryRejectsInvalidRegistration(t *testing.T) {
	for _, test := range []struct {
		name      string
		providers []Provider
	}{
		{"empty engine", []Provider{{}}},
		{"duplicate engine", []Provider{{Engine: "test"}, {Engine: "test"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid registry did not panic")
				}
			}()
			NewRegistry(test.providers...)
		})
	}
}

func TestRegistryDoesNotExposeItsRegistrations(t *testing.T) {
	input := []Provider{{Engine: "test", UnavailableReason: "unsupported"}}
	registry := NewRegistry(input...)
	input[0].UnavailableReason = "changed input"
	provider, ok := registry.Lookup("test")
	if !ok || provider.UnavailableReason != "unsupported" {
		t.Fatalf("lookup = %+v, %v", provider, ok)
	}
	provider.UnavailableReason = "changed result"
	if got := registry.UnavailableReason(Endpoint{Engine: "test"}); got != "unsupported" {
		t.Fatalf("reason = %q", got)
	}
	if _, ok := registry.Lookup("other"); ok {
		t.Fatal("unknown engine resolved to a provider")
	}
}
