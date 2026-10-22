package engines

import (
	"bytes"
	"encoding/json"
	"fmt"

	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/schema"
)

func expressionsFor(expression exp.Expression, key string) []exp.Expression {
	if expression == nil {
		return nil
	}
	if node, ok := expression.(*exp.Node); ok {
		return node.ExpressionsFor(key)
	}
	value := expression.Arg(key)
	switch v := value.(type) {
	case []exp.Expression:
		return v
	case exp.Expression:
		if v == nil {
			return nil
		}
		return []exp.Expression{v}
	default:
		return nil
	}
}

func asExpression(value any) exp.Expression {
	if expression, ok := value.(exp.Expression); ok {
		return expression
	}
	return nil
}

func truthy(value any) bool {
	if value == nil {
		return false
	}
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return v != ""
	case []exp.Expression:
		return len(v) > 0
	case []any:
		return len(v) > 0
	}
	return true
}

func boolPtr(value bool) *bool { return &value }

func strPtr(s string) *string { return &s }

func stringSet(values ...string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		out[value] = true
	}
	return out
}

func addSet(dst map[string]bool, src map[string]bool) {
	for value := range src {
		dst[value] = true
	}
}

func subtractSet(base map[string]bool, remove map[string]bool) map[string]bool {
	out := map[string]bool{}
	for value := range base {
		if !remove[value] {
			out[value] = true
		}
	}
	return out
}

func sortedSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sortStrings(out)
	return out
}

func sortStrings(values []string) {
	if len(values) < 2 {
		return
	}
	for i := 1; i < len(values); i++ {
		value := values[i]
		j := i - 1
		for j >= 0 && values[j] > value {
			values[j+1] = values[j]
			j--
		}
		values[j+1] = value
	}
}

// validateNamespace checks the namespace: catalog and an ordered searchPath are required. Namespace
// resolution has no engine-specific settings — those live on EngineConfig and are validated by
// newSession instead. It returns namespace unchanged — folding the search path's identifiers is
// optimizer.Qualify's own job (via the dialect passed to it), not this function's.
func validateNamespace(namespace NamespaceConfig) (NamespaceConfig, error) {
	if namespace.Catalog == "" {
		return NamespaceConfig{}, fmt.Errorf("namespace catalog is required")
	}
	if len(namespace.SearchPath) == 0 {
		return NamespaceConfig{}, fmt.Errorf("namespace searchPath is required")
	}
	for _, name := range namespace.SearchPath {
		if name == "" {
			return NamespaceConfig{}, fmt.Errorf("namespace searchPath contains an empty schema")
		}
	}
	return namespace, nil
}

type columnID struct {
	table  tableID
	column string
}

// detectRenderCollisions fails closed if two distinct catalog/schema/table[/column] identities
// would render to the same dot-joined lineage key (e.g. catalog "a.b" + schema "c" vs. catalog "a"
// + schema "b.c", both -> "a.b.c") — a dot INSIDE a raw identifier making two different paths
// serialize identically. This is an artifact of PM's own key format, not a folding concern: it runs
// identically whether or not any identifier ever gets folded, and sqlglot-go stores a nested map and
// never dot-joins, so it can't own this. It operates on the RAW catalog exactly as introspected, with
// no dialect/mode awareness needed.
func detectRenderCollisions(sch *schema.Mapping) error {
	if sch == nil {
		return fmt.Errorf("schema mapping is required")
	}
	renderedTables := map[string]tableID{}
	renderedColumns := map[string]columnID{}
	for _, rawCatalog := range sch.Keys() {
		catalogValue, _ := sch.Get(rawCatalog)
		catalogMapping, ok := catalogValue.(*schema.Mapping)
		if !ok || catalogMapping == nil {
			return fmt.Errorf("catalog %q must map to schemas", rawCatalog)
		}
		if rawCatalog == "" {
			return fmt.Errorf("schema mapping contains an empty catalog")
		}
		for _, rawSchema := range catalogMapping.Keys() {
			schemaValue, _ := catalogMapping.Get(rawSchema)
			schemaMapping, ok := schemaValue.(*schema.Mapping)
			if !ok || schemaMapping == nil {
				return fmt.Errorf("schema %q.%q must map to tables", rawCatalog, rawSchema)
			}
			if rawSchema == "" {
				return fmt.Errorf("schema mapping contains an empty schema")
			}
			for _, rawTable := range schemaMapping.Keys() {
				tableValue, _ := schemaMapping.Get(rawTable)
				columnMapping, ok := tableValue.(*schema.Mapping)
				if !ok || columnMapping == nil {
					return fmt.Errorf("table %q.%q.%q must map to columns", rawCatalog, rawSchema, rawTable)
				}
				if rawTable == "" {
					return fmt.Errorf("schema mapping contains an empty table")
				}
				if columnMapping.Len() == 0 {
					return fmt.Errorf("table %q.%q.%q must have at least one column", rawCatalog, rawSchema, rawTable)
				}

				id := tableID{catalog: rawCatalog, schema: rawSchema, table: rawTable}
				rendered := id.String()
				if previous, exists := renderedTables[rendered]; exists && previous != id {
					return fmt.Errorf("table identities %v and %v both render as %q", previous, id, rendered)
				}
				renderedTables[rendered] = id

				for _, rawColumn := range columnMapping.Keys() {
					if rawColumn == "" {
						return fmt.Errorf("table %q contains an empty column", rendered)
					}
					cid := columnID{table: id, column: rawColumn}
					key := rendered + "." + rawColumn
					if previous, exists := renderedColumns[key]; exists && previous != cid {
						return fmt.Errorf("column identities %v and %v both render as %q", previous, cid, key)
					}
					renderedColumns[key] = cid
				}
			}
		}
	}
	return nil
}

func mappingToJSON(m *schema.Mapping) json.RawMessage {
	var buf bytes.Buffer
	writeMappingJSON(&buf, m)
	return json.RawMessage(buf.Bytes())
}

func writeMappingJSON(buf *bytes.Buffer, m *schema.Mapping) {
	buf.WriteByte('{')
	if m != nil {
		keys := m.Keys()
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeJSONScalar(buf, key)
			buf.WriteByte(':')
			value, _ := m.Get(key)
			writeJSONValue(buf, value)
		}
	}
	buf.WriteByte('}')
}

func writeJSONValue(buf *bytes.Buffer, value any) {
	switch v := value.(type) {
	case *schema.Mapping:
		writeMappingJSON(buf, v)
	default:
		writeJSONScalar(buf, v)
	}
}

func writeJSONScalar(buf *bytes.Buffer, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		encoded = []byte("null")
	}
	buf.Write(encoded)
}
