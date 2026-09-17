package driver

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestConnectionInfoPresenceAndClone(t *testing.T) {
	for _, input := range []string{
		`{"name":"test"}`,
		`{"name":"test","connectionInfo":null}`,
		`{"name":"test","connectionInfo":{"endpoint":"","properties":null}}`,
		`{"name":"test","connectionInfo":{"endpoint":"https://proxy.example/","properties":{"region":"us-east-1","future":"preserved"}}}`,
	} {
		var endpoint Endpoint
		if err := json.Unmarshal([]byte(input), &endpoint); err != nil {
			t.Fatal(err)
		}
		clone := endpoint.Clone()
		if !reflect.DeepEqual(endpoint, clone) {
			t.Fatalf("clone changed presence or metadata: %#v, %#v", endpoint, clone)
		}
		if endpoint.ConnectionInfo == nil {
			continue
		}
		if endpoint.ConnectionInfo == clone.ConnectionInfo {
			t.Fatal("clone shares the connection metadata pointer")
		}
		clone.ConnectionInfo.Endpoint = "https://other.example/"
		if endpoint.ConnectionInfo.Endpoint == clone.ConnectionInfo.Endpoint {
			t.Fatal("clone changed the original endpoint")
		}
		if clone.ConnectionInfo.Properties != nil {
			clone.ConnectionInfo.Properties["future"] = "changed"
			if endpoint.ConnectionInfo.Properties["future"] != "preserved" {
				t.Fatal("clone changed the original properties")
			}
		}
	}
}
