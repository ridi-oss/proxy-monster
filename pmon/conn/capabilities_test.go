package conn

import (
	"reflect"
	"testing"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

func TestProviderFormatCapabilities(t *testing.T) {
	for _, engine := range []string{"mysql", "postgres"} {
		if got := DefaultFormat(engine); got != driver.URL {
			t.Errorf("%s default = %q, want url", engine, got)
		}
		if got := SupportedFormats(engine); !reflect.DeepEqual(got, []driver.Format{driver.URL, driver.JDBC, driver.GoDSN, driver.CLI}) {
			t.Errorf("%s formats = %v", engine, got)
		}
		if SupportsFormat(engine, "python") {
			t.Errorf("%s advertises an unsupported format", engine)
		}
	}
	if SupportsFormat("unknown", driver.URL) || DefaultFormat("unknown") != "" {
		t.Fatal("capabilities advertise an unsupported engine")
	}
	formats := SupportedFormats("mysql")
	formats[0] = "python"
	if SupportsFormat("mysql", "python") {
		t.Fatal("caller changed the registered format slice")
	}
}
