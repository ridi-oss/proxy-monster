package spi

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
)

type engineProvider struct{ engine *engines.Engine }

func (p engineProvider) Engine() *engines.Engine                 { return p.engine }
func (p engineProvider) OpenTarget(TargetConfig) (Target, error) { return nil, nil }

func TestNewRegistryRejectsUnknownAndDuplicateEngines(t *testing.T) {
	copied := *engines.MySQL
	for name, rows := range map[string][]Provider{
		"nil engine":       {engineProvider{}},
		"unknown engine":   {engineProvider{&engines.Engine{WireName: "oracle"}}},
		"copied engine":    {engineProvider{&copied}},
		"duplicate engine": {engineProvider{engines.MySQL}, engineProvider{engines.MySQL}},
	} {
		if _, err := NewRegistry(rows...); err == nil {
			t.Errorf("%s: NewRegistry = nil error", name)
		}
	}
}
