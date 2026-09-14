package daemon

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

func TestConnectionInfoSurvivesDiscoveryStatusAndSession(t *testing.T) {
	metadata := &driver.ConnectionInfo{Endpoint: "https://proxy.example/", Properties: map[string]string{"region": "us-east-1", "future": "preserved"}}
	broker := httpBroker{started: make(chan servingBroker, 1)}
	registry := driver.NewRegistry(driver.Provider{Engine: "test-http", Broker: broker})
	d, cp := startProviderDaemon(t, registry, []Datasource{{Name: "test", Engine: "test-http", AdvertiseAddr: "proxy.example:443", ConnectionInfo: metadata}})
	running := awaitBroker(t, broker.started)
	assertMetadata := func(info *driver.ConnectionInfo) {
		t.Helper()
		if info == nil || info.Endpoint != metadata.Endpoint || info.Properties["region"] != "us-east-1" || info.Properties["future"] != "preserved" {
			t.Fatalf("metadata lost or changed: %+v", info)
		}
	}
	status := d.Status()
	assertMetadata(status.Datasources[0].ConnectionInfo)
	status.Datasources[0].ConnectionInfo.Endpoint = "https://mutated.example/"
	status.Datasources[0].ConnectionInfo.Properties["region"] = "mutated"
	assertMetadata(d.Status().Datasources[0].ConnectionInfo)
	endpoint, _, ok := running.resolve()
	if !ok {
		t.Fatal("session unavailable")
	}
	assertMetadata(endpoint.ConnectionInfo)
	endpoint.ConnectionInfo.Endpoint = "https://mutated.example/"
	endpoint.ConnectionInfo.Properties["future"] = "mutated"
	endpoint, _, ok = running.resolve()
	if !ok {
		t.Fatal("session unavailable after mutating prior snapshot")
	}
	assertMetadata(endpoint.ConnectionInfo)
	wire, err := json.Marshal(d.Status())
	if err != nil {
		t.Fatal(err)
	}
	var decoded control.Status
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	assertMetadata(decoded.Datasources[0].ConnectionInfo)
	cp.datasources[0].ConnectionInfo = nil
	d.openListeners(context.Background())
	if d.Status().Datasources[0].ConnectionInfo != nil {
		t.Fatal("missing metadata became present after rediscovery")
	}
	cp.datasources[0].ConnectionInfo = &driver.ConnectionInfo{}
	d.openListeners(context.Background())
	if d.Status().Datasources[0].ConnectionInfo == nil {
		t.Fatal("present empty metadata became absent after rediscovery")
	}
}

func TestUnbrokeredConnectionInfoSnapshotIsIndependent(t *testing.T) {
	metadata := &driver.ConnectionInfo{Endpoint: "https://proxy.example/", Properties: map[string]string{"future": "preserved"}}
	d, _ := startProviderDaemon(t, driver.NewRegistry(), []Datasource{{Name: "test", Engine: "future", ConnectionInfo: metadata}})
	status := d.Status()
	if len(status.Datasources) != 1 || status.Datasources[0].Brokered || status.Datasources[0].ConnectionInfo == nil {
		t.Fatalf("unexpected status: %+v", status)
	}
	status.Datasources[0].ConnectionInfo.Properties["future"] = "mutated"
	if got := d.Status().Datasources[0].ConnectionInfo.Properties["future"]; got != "preserved" {
		t.Fatalf("unbrokered metadata changed through status: %q", got)
	}
}
