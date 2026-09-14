package probe

import (
	"sort"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

// Call-qualifier trust is quote-aware through the ENGINE-CATALOG resolver (opaque_functions
// preserves call qualifiers through NormalizeIdentifiers so the resolver folds them engine-true
// itself): an unquoted PG_CATALOG folds to the system schema and resolves Builtin, while a QUOTED
// "PG_CATALOG" is a DISTINCT case-sensitive user schema — absent from the catalog, the call is
// unresolvable and the statement fails closed. A blanket fold would hand a user schema a system
// builtin's pass.
func TestUpfrontFoldKeepsQualifierTrustQuoteAware(t *testing.T) {
	if f := postgresFacts(t, "SELECT PG_CATALOG.version()"); !f.GetResolved() ||
		len(f.GetFunctions()) != 1 || f.GetFunctions()[0] != "pg_catalog.version" {
		t.Errorf("unquoted PG_CATALOG must fold to the trusted system schema: %+v", f)
	}
	if f := postgresFacts(t, `SELECT "PG_CATALOG".version()`); f.GetResolved() {
		t.Errorf(`quoted "PG_CATALOG" is a distinct unknown schema and must fail closed: %+v`, f)
	}
	if f := postgresFacts(t, `SELECT "MySchema".fn()`); f.GetResolved() {
		t.Errorf(`quoted unknown user schema must fail closed: %+v`, f)
	}
}

// The fold must also reach the relation identities the control plane authorizes against: MySQL under
// lower_case_table_names=1 folds relation names, so an uppercase statement resolves and its scanned-table
// identity carries the folded spelling the catalog is keyed by.
func TestUpfrontFoldReachesRelationIdentities(t *testing.T) {
	mapping, _, err := schemaMappingFromProto("def", []*pb.Column{
		pbColumn("bom", "tb_user", "id", "BIGINT"),
	})
	if err != nil {
		t.Fatalf("build schema: %v", err)
	}
	facts := EmitFacts(
		"SELECT id FROM BOM.TB_USER",
		&pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.44", MysqlLowerCaseTableNames: proto.Int32(1)},
		mapping,
		nil,
		NamespaceConfig{Catalog: "def", SearchPath: []string{"bom"}},
	)
	if !facts.GetResolved() {
		t.Fatalf("lower_case_table_names=1 folds relation names, so this must resolve: %s", facts.GetDetail())
	}
	for _, src := range facts.GetSources() {
		if src.GetSchema() != "bom" || src.GetTable() != "tb_user" {
			t.Errorf("source carries %s.%s, want the folded bom.tb_user", src.GetSchema(), src.GetTable())
		}
	}
}

// The fold's whole point is an equivalence: two spellings the ENGINE calls the same must produce the
// same facts, and two it calls distinct must not. Asserted on the emitted source identity, which is what
// the control plane authorizes against.
//
// This guards OVER-reach specifically — a fold applied with the wrong dialect, or unconditionally, which
// would merge relations the engine keeps distinct (lctn=0 relation names, PostgreSQL quoted identifiers)
// and hand a query the wrong table's masks. It does NOT fail if the up-front fold is removed entirely:
// on a RESOLVED statement Qualify folds again in VALIDATE, so these facts come out identical either way.
// The under-reach direction is covered where it is actually observable — on the paths Qualify never
// completes: [TestSchemaQualifierCandidatesFoldToTheStoredSpelling] (candidates from a statement whose
// schema is absent) and [TestUpfrontFoldKeepsQualifierTrustQuoteAware] (a qualifier read before Qualify).
func TestUpfrontFoldRespectsEngineEquivalence(t *testing.T) {
	mysqlMapping, _, err := schemaMappingFromProto("def", []*pb.Column{
		pbColumn("bom", "tb_user", "id", "BIGINT"),
		pbColumn("bom", "tb_user", "email", "VARCHAR"),
	})
	if err != nil {
		t.Fatalf("build mysql schema: %v", err)
	}
	mysqlNs := NamespaceConfig{Catalog: "def", SearchPath: []string{"bom"}}
	mysqlFacts := func(t *testing.T, sql string, lctn int32) *pb.StatementFacts {
		t.Helper()
		return EmitFacts(sql, &pb.EngineConfig{
			Engine: pb.Engine_MYSQL, EngineVersion: "8.0.44",
			MysqlLowerCaseTableNames: proto.Int32(lctn),
		}, mysqlMapping, nil, mysqlNs)
	}

	// lower_case_table_names=1: relation names are case-insensitive, so the uppercase spelling is the
	// SAME relation and must resolve to the same source identity.
	folded := mysqlFacts(t, "SELECT id FROM BOM.TB_USER", 1)
	plain := mysqlFacts(t, "SELECT id FROM bom.tb_user", 1)
	if !folded.GetResolved() || !plain.GetResolved() {
		t.Fatalf("both spellings must resolve under lctn=1: %q / %q", folded.GetDetail(), plain.GetDetail())
	}
	if got, want := sourceKeys(folded), sourceKeys(plain); !equalStrings(got, want) {
		t.Errorf("lctn=1 treats these as one relation, so sources must match: %v vs %v", got, want)
	}

	// lower_case_table_names=0: table/db names are case-SENSITIVE, so BOM.TB_USER is a relation that
	// does not exist. Folding it would invent a resolution the target DB would reject.
	if sensitive := mysqlFacts(t, "SELECT id FROM BOM.TB_USER", 0); sensitive.GetResolved() {
		t.Errorf("lctn=0 is case-sensitive for relation names, so this must NOT resolve, got sources %v",
			sourceKeys(sensitive))
	}

	// A MySQL COLUMN is case-insensitive even under lctn=0, so the fold must still reach column names —
	// the case an lctn-gated relation fold would miss.
	upperCol := mysqlFacts(t, "SELECT ID FROM bom.tb_user", 0)
	lowerCol := mysqlFacts(t, "SELECT id FROM bom.tb_user", 0)
	if !upperCol.GetResolved() {
		t.Fatalf("a MySQL column is case-insensitive at every lctn mode: %s", upperCol.GetDetail())
	}
	if got, want := readKeys(upperCol), readKeys(lowerCol); !equalStrings(got, want) {
		t.Errorf("column case must not change the traced column: %v vs %v", got, want)
	}
}

// PostgreSQL folds unquoted identifiers at DDL time and keeps quoted ones verbatim, so a quoted and an
// unquoted relation of the same letters are genuinely TWO tables. Folding them together would merge two
// catalog rows into one key and mask (or expose) the wrong column.
func TestUpfrontFoldKeepsPostgresQuotedRelationsDistinct(t *testing.T) {
	mapping, _, err := schemaMappingFromProto("acme", []*pb.Column{
		pbColumn("public", "mixedcase", "id", "BIGINT"),
		pbColumn("public", "MixedCase", "id", "BIGINT"),
	})
	if err != nil {
		t.Fatalf("build schema: %v", err)
	}
	pg := &pb.EngineConfig{Engine: pb.Engine_POSTGRES, EngineVersion: "16.0"}
	ns := NamespaceConfig{Catalog: "acme", SearchPath: []string{"public"}}

	// Unquoted folds to the lowercase table; quoted resolves to the case-preserved one.
	unquoted := EmitFacts(`SELECT id FROM MixedCase`, pg, mapping, nil, ns)
	quoted := EmitFacts(`SELECT id FROM "MixedCase"`, pg, mapping, nil, ns)
	if !unquoted.GetResolved() || !quoted.GetResolved() {
		t.Fatalf("both relations exist: %q / %q", unquoted.GetDetail(), quoted.GetDetail())
	}
	if got, want := sourceKeys(unquoted), []string{"acme.public.mixedcase"}; !equalStrings(got, want) {
		t.Errorf("an unquoted PostgreSQL relation folds: got %v, want %v", got, want)
	}
	if got, want := sourceKeys(quoted), []string{"acme.public.MixedCase"}; !equalStrings(got, want) {
		t.Errorf("a quoted PostgreSQL relation keeps its case: got %v, want %v", got, want)
	}
}

func sourceKeys(facts *pb.StatementFacts) []string {
	out := make([]string, 0, len(facts.GetSources()))
	for _, src := range facts.GetSources() {
		out = append(out, src.GetCatalog()+"."+src.GetSchema()+"."+src.GetTable())
	}
	sort.Strings(out)
	return out
}

func readKeys(facts *pb.StatementFacts) []string {
	out := []string{}
	for _, grant := range facts.GetResultReads() {
		if col := grant.GetColumn(); col != nil {
			out = append(out, col.GetSchema()+"."+col.GetTable()+"."+col.GetColumn())
		}
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
