package driver

import (
	"context"
	"errors"
	"net"
	"testing"
)

type namedProvider string

func (p namedProvider) Engine() string                                      { return string(p) }
func (namedProvider) FormatConnectionString(Format, Target, Options) string { return "" }
func (namedProvider) UnavailableReason(Endpoint) string                     { return "unsupported" }
func (namedProvider) RouteKey(Endpoint) string                              { return "" }
func (namedProvider) Serve(context.Context, net.Listener, ResolveSession) error {
	return errors.New("unsupported")
}

func TestRegistryRejectsInvalidRegistration(t *testing.T) {
	for _, test := range []struct {
		name      string
		providers []Provider
	}{
		{"empty engine", []Provider{namedProvider("")}},
		{"duplicate engine", []Provider{namedProvider("test"), namedProvider("test")}},
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

func TestRegistryLooksUpByEngine(t *testing.T) {
	registry := NewRegistry(namedProvider("test"))
	if provider, ok := registry.Lookup("test"); !ok || provider.Engine() != "test" {
		t.Fatalf("lookup = %v, %v", provider, ok)
	}
	if _, ok := registry.Lookup("other"); ok {
		t.Fatal("unknown engine resolved to a provider")
	}
	if got := registry.UnavailableReason(Endpoint{Engine: "test"}); got != "unsupported" {
		t.Fatalf("reason = %q", got)
	}
	if got := registry.UnavailableReason(Endpoint{Engine: "other", AdvertiseAddr: "proxy:1"}); got != `engine "other" not brokered` {
		t.Fatalf("reason = %q", got)
	}
}
