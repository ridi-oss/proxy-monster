package driver

import "testing"

type testRenderer struct{}

func (testRenderer) Render(format Format, _ Target, _ Options) string { return string(format) }

func TestRegistryValidatesFormatCapabilities(t *testing.T) {
	for _, provider := range []Provider{
		{Engine: "test", Renderer: testRenderer{}},
		{Engine: "test", Renderer: testRenderer{}, DefaultFormat: URL, SupportedFormats: []Format{CLI}},
		{Engine: "test", Renderer: testRenderer{}, DefaultFormat: URL, SupportedFormats: []Format{URL, URL}},
		{Engine: "test", Renderer: testRenderer{}, DefaultFormat: URL, SupportedFormats: []Format{URL, ""}},
		{Engine: "test", DefaultFormat: URL, SupportedFormats: []Format{URL}},
	} {
		t.Run(string(provider.DefaultFormat), func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid format capabilities were accepted")
				}
			}()
			NewRegistry(provider)
		})
	}
}

func TestRegistryClonesFormatCapabilities(t *testing.T) {
	input := Provider{Engine: "test", Renderer: testRenderer{}, DefaultFormat: CLI, SupportedFormats: []Format{CLI, URL}}
	registry := NewRegistry(input)
	input.SupportedFormats[0] = JDBC
	first, _ := registry.Lookup("test")
	if first.DefaultFormat != CLI || first.SupportedFormats[0] != CLI {
		t.Fatalf("registry shares the input slice: %+v", first)
	}
	first.SupportedFormats[0] = GoDSN
	second, _ := registry.Lookup("test")
	if second.SupportedFormats[0] != CLI {
		t.Fatalf("registry shares the returned slice: %+v", second)
	}
}
