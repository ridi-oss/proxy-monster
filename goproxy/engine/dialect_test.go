package engine

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

func TestDialectIndexesEngines(t *testing.T) {
	for d, want := range map[Dialect]*engines.Engine{MySQL: engines.MySQL, Postgres: engines.Postgres, Athena: engines.Athena} {
		if d.Engine() != want {
			t.Errorf("%d.Engine() = %s, want %s", d, d.Engine().WireName, want.WireName)
		}
		if got, err := ParseDialect(want.WireName); err != nil || got != d {
			t.Errorf("ParseDialect(%q) = %v, %v; want %v", want.WireName, got, err, d)
		}
	}
	bad, err := ParseDialect("postgresql")
	if err == nil || bad.Valid() || bad.Engine().Proto != pb.Engine_ENGINE_UNSPECIFIED {
		t.Fatalf("ParseDialect(postgresql) = %v, %v", bad, err)
	}
}
