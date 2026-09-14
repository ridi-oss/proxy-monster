package spi

import (
	"reflect"
	"testing"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

type testProvider struct{ definition Definition }

func (p testProvider) Definition() Definition            { return p.definition }
func (testProvider) Configure(LookupEnv) (Target, error) { return nil, nil }

func TestRegistryUsesProviderNames(t *testing.T) {
	provider := testProvider{Definition{Name: "remote", Engine: enginepb.Engine_MYSQL}}
	registry, err := NewRegistry(provider)
	if err != nil {
		t.Fatal(err)
	}
	got, err := registry.For("remote")
	if err != nil || got != provider {
		t.Fatalf("For(remote) = %v, %v", got, err)
	}
	if _, err := registry.For("mysql"); err == nil {
		t.Fatal("an unregistered engine name was accepted")
	}
	names := registry.Names()
	names[0] = "changed"
	if !reflect.DeepEqual(registry.Names(), []string{"remote"}) {
		t.Fatal("Names exposed the registry's mutable slice")
	}
}

func TestRegistryRejectsInvalidDefinitions(t *testing.T) {
	valid := testProvider{Definition{Name: "mysql", Engine: enginepb.Engine_MYSQL}}
	for _, test := range []struct {
		name      string
		providers []Provider
	}{
		{"nil", []Provider{nil}},
		{"duplicate", []Provider{valid, valid}},
		{"blank name", []Provider{testProvider{Definition{Engine: enginepb.Engine_MYSQL}}}},
		{"noncanonical name", []Provider{testProvider{Definition{Name: "MySQL", Engine: enginepb.Engine_MYSQL}}}},
		{"whitespace", []Provider{testProvider{Definition{Name: "mysql ", Engine: enginepb.Engine_MYSQL}}}},
		{"unspecified engine", []Provider{testProvider{Definition{Name: "mysql"}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewRegistry(test.providers...); err == nil {
				t.Fatal("invalid registry was accepted")
			}
		})
	}
}
