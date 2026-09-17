package driver

import "fmt"

// Registry is the immutable set of providers the daemon was built with, keyed by engine name.
type Registry struct {
	providers map[string]Provider
}

// NewRegistry panics on an empty or duplicate engine; a bad composition root is a build error, not a
// runtime condition.
func NewRegistry(providers ...Provider) *Registry {
	r := &Registry{providers: make(map[string]Provider, len(providers))}
	for _, provider := range providers {
		engine := provider.Engine()
		if engine == "" {
			panic("provider engine is empty")
		}
		if _, exists := r.providers[engine]; exists {
			panic(fmt.Sprintf("duplicate provider engine %q", engine))
		}
		r.providers[engine] = provider
	}
	return r
}

func (r *Registry) Lookup(engine string) (Provider, bool) {
	provider, ok := r.providers[engine]
	return provider, ok
}

// UnavailableReason says why the endpoint has no local listener, or "" when its provider can broker it.
func (r *Registry) UnavailableReason(endpoint Endpoint) string {
	if provider, ok := r.Lookup(endpoint.Engine); ok {
		return provider.UnavailableReason(endpoint)
	}
	if endpoint.AdvertiseAddr == "" {
		return "no advertised proxy address"
	}
	return fmt.Sprintf("engine %q not brokered", endpoint.Engine)
}
