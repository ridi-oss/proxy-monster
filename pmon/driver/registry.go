package driver

import (
	"fmt"
	"slices"
)

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
		if provider.Renderer != nil {
			if provider.DefaultFormat == "" || !slices.Contains(provider.SupportedFormats, provider.DefaultFormat) {
				panic(fmt.Sprintf("provider %q has no supported default format", provider.Engine))
			}
		} else if len(provider.SupportedFormats) != 0 || provider.DefaultFormat != "" {
			panic(fmt.Sprintf("provider %q declares formats without a renderer", provider.Engine))
		}
		for i, format := range provider.SupportedFormats {
			if format == "" || slices.Contains(provider.SupportedFormats[:i], format) {
				panic(fmt.Sprintf("provider %q has an empty or duplicate format", provider.Engine))
			}
		}
		provider.SupportedFormats = slices.Clone(provider.SupportedFormats)
		r.providers[provider.Engine] = provider
	}
	return r
}

func (r *Registry) Lookup(engine string) (Provider, bool) {
	provider, ok := r.providers[engine]
	provider.SupportedFormats = slices.Clone(provider.SupportedFormats)
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
