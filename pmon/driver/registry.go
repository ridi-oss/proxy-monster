package driver

import "fmt"

type Registry struct {
	providers map[string]Provider
}

func NewRegistry(providers ...Provider) *Registry {
	r := &Registry{providers: make(map[string]Provider, len(providers))}
	for _, provider := range providers {
		if provider.Engine == "" {
			panic("provider engine is empty")
		}
		if _, exists := r.providers[provider.Engine]; exists {
			panic(fmt.Sprintf("duplicate provider engine %q", provider.Engine))
		}
		r.providers[provider.Engine] = provider
	}
	return r
}

func (r *Registry) Lookup(engine string) (Provider, bool) {
	provider, ok := r.providers[engine]
	return provider, ok
}

func (r *Registry) UnavailableReason(endpoint Endpoint) string {
	provider, ok := r.Lookup(endpoint.Engine)
	if ok {
		if provider.Broker != nil {
			return provider.Broker.UnavailableReason(endpoint)
		}
		if provider.UnavailableReason != "" {
			return provider.UnavailableReason
		}
	}
	if endpoint.AdvertiseAddr == "" {
		return "no advertised proxy address"
	}
	return fmt.Sprintf("engine %q not brokered", endpoint.Engine)
}
