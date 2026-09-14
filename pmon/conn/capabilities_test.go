package conn

import (
	"reflect"
	"testing"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

func TestProviderFormatCapabilities(t *testing.T) {
	for _, engine := range []string{"mysql", "postgres"} {
		if got := DefaultFormat(engine); got != URL {
			t.Errorf("%s default = %q, want url", engine, got)
		}
		if got := SupportedFormats(engine); !reflect.DeepEqual(got, []Format{URL, JDBC, GoDSN, CLI}) {
			t.Errorf("%s formats = %v", engine, got)
		}
		if SupportsFormat(engine, "python") {
			t.Errorf("%s advertises an unsupported format", engine)
		}
	}
	if got := DefaultFormat("athena"); got != CLI {
		t.Fatalf("Athena default = %q, want cli", got)
	}
	for _, format := range []Format{CLI, URL, JDBC, "python", "node", "aws-config"} {
		if !SupportsFormat("athena", format) {
			t.Errorf("Athena does not advertise %q", format)
		}
	}
	if SupportsFormat("athena", GoDSN) || SupportsFormat("unknown", URL) || DefaultFormat("unknown") != "" {
		t.Fatal("capabilities advertise unsupported engine or format")
	}
	formats := SupportedFormats("athena")
	formats[0] = GoDSN
	if SupportsFormat("athena", GoDSN) {
		t.Fatal("caller changed the registered format slice")
	}
}

func TestAthenaPublicRenderingUsesConnectionInfo(t *testing.T) {
	target := Target{
		Name: "warehouse", Engine: "athena", Port: 32123, User: "alice", Password: "local-password",
		ConnectionInfo: &driver.ConnectionInfo{Properties: map[string]string{"region": "us-east-1"}},
	}
	if got := String(URL, target); got != "http://127.0.0.1:32123" {
		t.Fatalf("Athena endpoint = %q", got)
	}
	if got := String(GoDSN, target); got != "" {
		t.Fatalf("unsupported GoDSN rendered %q", got)
	}
}
