package cp

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

func TestDecideCarriesCatalogs(t *testing.T) {
	fake := &fakeControlPlane{}
	client := startFakeControlPlane(t, fake)
	result := client.Decide(engine.DecideRequest{Session: engine.SessionObservation{CurrentCatalog: "catalog"}, TempColumns: []engine.TempColumn{{Catalog: "catalog", Schema: "temp", Table: "t", Column: "c"}}})
	if result.IsErr() {
		t.Fatal(result.Err)
	}
	fake.mu.Lock()
	request := fake.decideReqs[0]
	fake.mu.Unlock()
	if request.GetCurrentCatalog() != "catalog" || request.TempColumns[0].GetCatalog() != "catalog" {
		t.Fatalf("catalog context = %v", request)
	}
}

func TestRefetchCatalogPresenceAndOwnership(t *testing.T) {
	command := refetch("schema", []byte("hash"))
	command.GetRefetch().Catalog = "catalog"
	mapped, err := refetchesFromWire([]*pb.ProxyCommand{command})
	if err != nil || mapped[0].GetCatalog() != "catalog" {
		t.Fatalf("commands = %v, %v", mapped, err)
	}
	command.GetRefetch().Catalog = "changed"
	if mapped[0].GetCatalog() != "catalog" {
		t.Fatal("mapped catalog aliases the wire command")
	}
	command.GetRefetch().Catalog = ""
	if _, err := refetchesFromWire([]*pb.ProxyCommand{command}); err == nil {
		t.Fatal("explicit blank catalog was accepted")
	}
}
