package driver

import "testing"

type testFormats struct {
	namedProvider
	formats  []Format
	fallback Format
}

func (p testFormats) SupportedFormats() []Format { return p.formats }
func (p testFormats) DefaultFormat() Format      { return p.fallback }

func TestRegistryValidatesFormatCapabilities(t *testing.T) {
	for _, provider := range []testFormats{
		{namedProvider: "test"},
		{namedProvider: "test", fallback: URL, formats: []Format{CLI}},
		{namedProvider: "test", fallback: URL, formats: []Format{URL, URL}},
		{namedProvider: "test", fallback: URL, formats: []Format{URL, ""}},
	} {
		t.Run(string(provider.fallback), func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid format capabilities were accepted")
				}
			}()
			NewRegistry(provider)
		})
	}
	if _, ok := NewRegistry(testFormats{namedProvider: "test", fallback: CLI, formats: []Format{CLI, URL}}).Lookup("test"); !ok {
		t.Fatal("valid format capabilities were rejected")
	}
}
