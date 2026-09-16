package probe

import (
	"reflect"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

// TestReturnedColumns locks the returned_columns fact: a base column is returned iff its value reaches the
// client through the result set, whatever projection arm carries it; a read-only position, a write payload,
// and an EXPLAIN return nothing; a write's RETURNING returns with no ordinals.
func TestReturnedColumns(t *testing.T) {
	engines := []struct {
		name, cat, sch string
		ec             *pb.EngineConfig
		ns             *pb.Namespace
	}{
		{"mysql", "def", "app", &pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(1)}, &pb.Namespace{Catalog: "def", SearchPath: []string{"app"}}},
		{"postgres", "acme", "public", &pb.EngineConfig{Engine: pb.Engine_POSTGRES}, &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}}},
	}
	for _, e := range engines {
		t.Run(e.name, func(t *testing.T) {
			catalog := snapshot([]*pb.Column{
				pbColumn(e.sch, "users", "id", "BIGINT"),
				pbColumn(e.sch, "users", "ssn", "VARCHAR"),
				pbColumn(e.sch, "users", "email", "VARCHAR"),
				pbColumn(e.sch, "orders", "id", "BIGINT"),
				pbColumn(e.sch, "orders", "amount", "BIGINT"),
			})
			key := func(table, col string) string { return e.cat + "." + e.sch + "." + table + "." + col }
			cases := []struct {
				sql   string
				want  map[string][]int32
				pg    bool
				mysql bool
			}{
				{sql: "SELECT ssn FROM users", want: map[string][]int32{key("users", "ssn"): {0}}},
				{sql: "SELECT * FROM users", want: map[string][]int32{key("users", "id"): {0}, key("users", "ssn"): {1}, key("users", "email"): {2}}},
				{sql: "SELECT max(ssn) FROM users", want: map[string][]int32{key("users", "ssn"): {0}}},
				{sql: "SELECT DISTINCT upper(ssn) FROM users", want: map[string][]int32{key("users", "ssn"): {0}}},
				{sql: "SELECT concat(ssn, email) FROM users", want: map[string][]int32{key("users", "ssn"): {0}, key("users", "email"): {0}}},
				{sql: "SELECT users FROM users", pg: true, want: map[string][]int32{key("users", "id"): {0}, key("users", "ssn"): {0}, key("users", "email"): {0}}},
				{sql: "SELECT to_jsonb(users) FROM users", want: map[string][]int32{key("users", "id"): {0}, key("users", "ssn"): {0}, key("users", "email"): {0}}, pg: true},
				{sql: "SELECT row_to_json(users.*) FROM users", want: map[string][]int32{key("users", "id"): {0}, key("users", "ssn"): {0}, key("users", "email"): {0}}, pg: true},
				{sql: "SELECT (users).ssn FROM users", want: map[string][]int32{key("users", "ssn"): {0}}, pg: true},
				{sql: "SELECT (SELECT id FROM users WHERE ssn IS NOT NULL LIMIT 1) FROM orders", want: map[string][]int32{key("users", "id"): {0}}},
				{sql: "SELECT (SELECT max(ssn) FROM users) FROM orders", want: map[string][]int32{key("users", "ssn"): {0}}},
				{sql: "SELECT sum(id) OVER (PARTITION BY ssn ORDER BY email) FROM users", want: map[string][]int32{key("users", "id"): {0}}},
				{sql: "SELECT JSON_OBJECT('ssn', ssn) FROM users", want: map[string][]int32{key("users", "ssn"): {0}}, mysql: true},
				{sql: "SELECT GROUP_CONCAT(id ORDER BY ssn) FROM users", want: map[string][]int32{key("users", "id"): {0}}, mysql: true},
				{sql: "SELECT string_agg(id::text, ',' ORDER BY ssn) FROM users", want: map[string][]int32{key("users", "id"): {0}}, pg: true},
				{sql: "SELECT u FROM users u", want: map[string][]int32{key("users", "id"): {0}, key("users", "ssn"): {0}, key("users", "email"): {0}}, pg: true},
				{sql: "SELECT 1 FROM users u WHERE u = u", want: map[string][]int32{}, pg: true},
				{sql: "SELECT id, email FROM users", want: map[string][]int32{key("users", "id"): {0}, key("users", "email"): {1}}},
				{sql: "SELECT id FROM users WHERE ssn IS NOT NULL", want: map[string][]int32{key("users", "id"): {0}}},
				{sql: "SELECT count(*) FROM users", want: map[string][]int32{}},
				{sql: "SELECT 1 FROM users ORDER BY ssn", want: map[string][]int32{}},
				{sql: "SELECT id FROM users UNION ALL SELECT amount FROM orders", want: map[string][]int32{key("users", "id"): {0}, key("orders", "amount"): {0}}},
				{sql: "INSERT INTO orders SELECT id, id FROM users", want: map[string][]int32{}},
				{sql: "EXPLAIN SELECT ssn FROM users", want: map[string][]int32{}},
				{sql: "UPDATE users SET id = id RETURNING ssn", want: map[string][]int32{key("users", "ssn"): {}}, pg: true},
				{sql: "UPDATE users SET id = id RETURNING (users).ssn", want: map[string][]int32{key("users", "ssn"): {}}, pg: true},
				{sql: "UPDATE users SET id = id RETURNING (SELECT count(*) FROM orders)", want: map[string][]int32{}, pg: true},
				{sql: "UPDATE users SET id = id RETURNING EXISTS(SELECT * FROM orders)", want: map[string][]int32{}, pg: true},
				{sql: "UPDATE users SET id = id RETURNING (SELECT ssn FROM users LIMIT 1)", want: map[string][]int32{key("users", "ssn"): {}}, pg: true},
				{sql: "UPDATE users SET id = id RETURNING to_jsonb(users)", want: map[string][]int32{key("users", "id"): {}, key("users", "ssn"): {}, key("users", "email"): {}}, pg: true},
				{sql: "UPDATE users SET id = id RETURNING *", want: map[string][]int32{key("users", "id"): {}, key("users", "ssn"): {}, key("users", "email"): {}}, pg: true},
				{sql: "DELETE FROM users RETURNING users.*", want: map[string][]int32{key("users", "id"): {}, key("users", "ssn"): {}, key("users", "email"): {}}, pg: true},
				{sql: "INSERT INTO users (id) VALUES (3) RETURNING *", want: map[string][]int32{key("users", "id"): {}, key("users", "ssn"): {}, key("users", "email"): {}}, pg: true},
				{sql: "DELETE FROM users RETURNING id, upper(email)", want: map[string][]int32{key("users", "id"): {}, key("users", "email"): {}}, pg: true},
			}
			for _, tc := range cases {
				if (tc.pg && e.name != "postgres") || (tc.mysql && e.name != "mysql") {
					continue
				}
				t.Run(tc.sql, func(t *testing.T) {
					facts := analyzeProto(t, &pb.AnalyzeRequest{Sql: tc.sql, EngineConfig: e.ec, Namespace: e.ns, Catalog: catalog})
					if !facts.Resolved {
						t.Fatalf("unresolved: %s", facts.Detail)
					}
					got := map[string][]int32{}
					for _, rc := range facts.ReturnedColumns {
						c := rc.Column
						k := c.Catalog + "." + c.Identity.Schema + "." + c.Identity.Table + "." + c.Identity.Column
						got[k] = append([]int32{}, rc.OutputOrdinals...)
					}
					if !reflect.DeepEqual(got, tc.want) {
						t.Errorf("returned = %v, want %v", got, tc.want)
					}
				})
			}
		})
	}
}
