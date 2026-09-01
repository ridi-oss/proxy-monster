package probe

// The analyzer<->JVM FFM wire boundary (docs/statement-facts-contract.md): protobuf in,
// protobuf out on both directions of the call. AnalyzeStatementSafe is the entry point cmd/libsqlglot's
// AnalyzeStatement export calls; it is total (never panics, always returns a valid marshaled
// StatementFacts), the fail-closed contract the FFI boundary requires.

import (
	"fmt"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/sqlglot-go/schema"
	"google.golang.org/protobuf/proto"
)

// AnalyzeStatement decodes req's typed fields, runs Probe, and returns the response as a typed
// proto message — no (un)marshaling here. AnalyzeStatementSafe below owns the byte-buffer boundary.
func AnalyzeStatement(req *pb.AnalyzeRequest) (*pb.StatementFacts, error) {
	sch, err := schemaMappingFromProto(req.GetCatalog())
	if err != nil {
		return nil, err
	}
	namespace, err := namespaceConfigFromProto(req.GetNamespace())
	if err != nil {
		return nil, err
	}
	return EmitFacts(req.GetSql(), req.GetEngineConfig(), sch, namespace), nil
}

// AnalyzeStatementSafe is the total, panic-safe entry point for the c-shared / FFI boundary: decode
// reqBytes, run AnalyzeStatement, encode the response — ALWAYS returning a validly-encoded
// StatementFacts, never an error, never a panic escaping to the caller (which, across a cgo boundary,
// would crash the host process). Any internal error or panic becomes a fail-closed (resolved=false)
// result, the safe direction for a security probe.
func AnalyzeStatementSafe(reqBytes []byte) (out []byte) {
	defer func() {
		if r := recover(); r != nil {
			out = mustFailProto("LINEAGE", fmt.Sprintf("panic: %v", r))
		}
	}()
	var req pb.AnalyzeRequest
	if err := proto.Unmarshal(reqBytes, &req); err != nil {
		return mustFailProto("VALIDATE", fmt.Sprintf("invalid AnalyzeRequest: %v", err))
	}
	result, err := AnalyzeStatement(&req)
	if err != nil {
		return mustFailProto("VALIDATE", err.Error())
	}
	out, err = proto.Marshal(result)
	if err != nil {
		return marshalErrorFallback
	}
	return out
}

// SplitStatementsSafe is the panic-safe FFI entry point for the batch split: anything that goes wrong
// becomes an encoded ok=false, never a panic crossing into the JVM.
func SplitStatementsSafe(reqBytes []byte) (out []byte) {
	defer func() {
		if r := recover(); r != nil {
			out = splitFailure
		}
	}()
	var req pb.SplitRequest
	if err := proto.Unmarshal(reqBytes, &req); err != nil {
		return splitFailure
	}
	statements, ok := SplitStatements(req.GetSql(), req.GetEngineConfig())
	if !ok {
		return splitFailure
	}
	encoded, err := proto.Marshal(&pb.SplitResponse{Ok: true, Statements: statements})
	if err != nil {
		return splitFailure
	}
	return encoded
}

// The encoded fail-closed SplitResponse, computed once so the failure path never has to marshal.
var splitFailure = must(proto.Marshal(&pb.SplitResponse{Ok: false}))

// marshalErrorFallback is a statically-valid encoded fail-closed StatementFacts, computed once so
// mustFailProto never has to marshal twice on the (essentially unreachable) path where encoding the
// real failure result itself errors — proto.Marshal on a well-formed message practically never
// fails, unlike JSON's marshal-on-arbitrary-types risk, but the FFI boundary must still be total.
var marshalErrorFallback = must(proto.Marshal(unanalyzableFacts("LINEAGE", "marshal error")))

func mustFailProto(stage, detail string) []byte {
	b, err := proto.Marshal(unanalyzableFacts(stage, detail))
	if err != nil {
		return marshalErrorFallback
	}
	return b
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err) // only ever runs at init on a hardcoded literal message; a failure here is a build-time bug.
	}
	return b
}

func strPtr(s string) *string { return &s }

// schemaMappingFromProto builds a depth-3 schema.Mapping (catalog -> schema -> table -> column ->
// SQL type) from a flat ColumnSpec list — the Go-side half of the flat-catalog simplification: the
// JVM caller already holds a flat List<ColumnSpec> natively (CatalogApi.kt), so no tree-walking
// decoder is needed on either side, just this direct nested-Set build.
func schemaMappingFromProto(cols []*pb.ColumnSpec) (*schema.Mapping, error) {
	root := schema.NewMapping()
	for _, col := range cols {
		id := col.GetIdentity()
		if col.GetCatalog() == "" || id.GetSchema() == "" || id.GetTable() == "" || id.GetColumn() == "" {
			return nil, fmt.Errorf("catalog column entry is missing catalog/schema/table/column")
		}
		schemas := getOrNewMapping(root, col.GetCatalog())
		tables := getOrNewMapping(schemas, id.GetSchema())
		tableColumns := getOrNewMapping(tables, id.GetTable())
		if _, exists := tableColumns.Get(id.GetColumn()); exists {
			return nil, fmt.Errorf(
				"catalog contains duplicate column entry: %s.%s.%s.%s",
				col.GetCatalog(), id.GetSchema(), id.GetTable(), id.GetColumn(),
			)
		}
		tableColumns.Set(id.GetColumn(), col.GetDataType())
	}
	return root, nil
}

func getOrNewMapping(m *schema.Mapping, key string) *schema.Mapping {
	if existing, ok := m.Get(key); ok {
		if child, ok := existing.(*schema.Mapping); ok {
			return child
		}
	}
	child := schema.NewMapping()
	m.Set(key, child)
	return child
}

// namespaceConfigFromProto converts the wire Namespace into the NamespaceConfig Probe consumes.
// validateNamespace provides a comprehensive fail-fast duplicate of Probe's own validation, so no
// direct caller can bypass its invariants.
func namespaceConfigFromProto(ns *pb.Namespace) (NamespaceConfig, error) {
	if ns == nil {
		return NamespaceConfig{}, fmt.Errorf("namespace is required")
	}
	return validateNamespace(NamespaceConfig{
		Catalog:    ns.GetCatalog(),
		SearchPath: append([]string(nil), ns.GetSearchPath()...),
	})
}
