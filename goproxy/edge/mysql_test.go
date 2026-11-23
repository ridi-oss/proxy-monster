package edge

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/goproxy/mysql"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

func TestMySQLGreetingMatchesTheDatasourceProxy(t *testing.T) {
	scramble, err := mysqlwire.Scramble()
	if err != nil {
		t.Fatal(err)
	}
	gotVersion, gotCaps, ok := parseMySQLGreeting(mysqlGreeting(1, scramble))
	if !ok {
		t.Fatal("edge greeting does not parse")
	}
	proxy := mysqlwire.ServerGreetingSSL(1, scramble, mysql.FrontendServerVersion, mysql.FrontendConnectWithDB)
	wantVersion, wantCaps, ok := parseMySQLGreeting(proxy)
	if !ok {
		t.Fatal("datasource proxy greeting does not parse")
	}
	if gotVersion != wantVersion {
		t.Fatalf("edge greeting version = %q, datasource proxy = %q", gotVersion, wantVersion)
	}
	if gotCaps != wantCaps {
		t.Fatalf("edge greeting capabilities = 0x%08x, datasource proxy = 0x%08x", gotCaps, wantCaps)
	}
}
