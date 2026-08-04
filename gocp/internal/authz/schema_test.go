package authz

import (
	"strings"
	"testing"
)

// A skeleton smoke test, not a ported Kotlin test. It asserts only that the embedded schema is the
// real file and not a stub: the fifteen entity declarations 02-authz.md §1 enumerates, and the shared
// action-context shape whose ipaddr field drives the two-stage IP check (D5).
func TestEmbeddedCedarSchema(t *testing.T) {
	if len(SchemaSource) == 0 {
		t.Fatal("SchemaSource is empty")
	}

	for _, ent := range []string{
		"System", "Role", "Group", "Datasource", "Table", "Column", "Tag", "Function",
		"Utility", "User", "Request", "AccessGrant", "Token", "AuditRecord", "AuditLog",
	} {
		if !strings.Contains(SchemaSource, "entity "+ent) {
			t.Errorf("schema is missing `entity %s`", ent)
		}
	}

	// ipaddr is the only Cedar extension type used — no decimal, no datetime, no duration.
	if !strings.Contains(SchemaSource, "requester_ip") || !strings.Contains(SchemaSource, "ipaddr") {
		t.Error("schema is missing the requester_ip: ipaddr context field")
	}
	for _, unused := range []string{"decimal", "datetime", "duration"} {
		if strings.Contains(SchemaSource, unused) {
			t.Errorf("schema unexpectedly references the %q extension type; 02-authz.md §1 says ipaddr is the only one", unused)
		}
	}

	// Tag is a leaf entity type, not Cedar's entity-tags language feature.
	for _, kw := range []string{"getTag", "hasTag"} {
		if strings.Contains(SchemaSource, kw) {
			t.Errorf("schema uses %s; 02-authz.md §1 records that cedar-go needs no entity-tag support", kw)
		}
	}
}
