package migrations_test

import (
	"io/fs"
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/migrations"
)

// A skeleton smoke test, not a ported Kotlin test. //go:embed already makes an unmatched pattern a
// BUILD error, so what this adds is the count and the emptiness check: a truncated or half-copied
// migration set still compiles, and would then fail at boot against a real deployment's
// flyway_schema_history checksums rather than here.
func TestEmbeddedMigrationSetIsComplete(t *testing.T) {
	want := []string{
		"sql/V1__identity.sql",
		"sql/V2__catalog.sql",
		"sql/V3__policy.sql",
		"sql/V4__audit.sql",
		"sql/V5__tasks.sql",
		"sql/V6__sessions.sql",
		"sql/V7__tokens.sql",
		"sql/V8__seed.sql",
		"sql/V9__datasource_cert_chain.sql",
		"sql/V10__debug_requester_ip.sql",
	}

	for _, name := range want {
		b, err := migrations.FS.ReadFile(name)
		if err != nil {
			t.Errorf("%s: not embedded: %v", name, err)
			continue
		}
		if len(b) == 0 {
			t.Errorf("%s: embedded but empty", name)
		}
	}

	got, err := fs.Glob(migrations.FS, "sql/*.sql")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(got) != len(want) {
		t.Errorf("embedded %d migrations, want %d: %v", len(got), len(want), got)
	}
}
