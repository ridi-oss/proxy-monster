package relay

import (
	"reflect"
	"testing"

	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

type fakeDb struct {
	nsProbeSQL   string
	tempOverlay  bool
	tempProbeSQL string
}

func (f fakeDb) NamespaceProbeSQL() string   { return f.nsProbeSQL }
func (f fakeDb) SupportsTempOverlay() bool   { return f.tempOverlay }
func (f fakeDb) TempColumnsProbeSQL() string { return f.tempProbeSQL }
func (f fakeDb) HashSetupProbeSQL() string   { return "" }
func (f fakeDb) HashSetupColumns() int       { return 0 }
func (f fakeDb) SchemaHashSQL(string, [][]*string) (string, int, error) {
	return "hash", 1, nil
}
func (f fakeDb) SchemaHashFromRows([][]*string) ([]byte, bool, error) { return nil, false, nil }
func (f fakeDb) SchemaColumnsSQL(string) string                       { return "columns" }
func (f fakeDb) RoutinesSQL() string                                  { return "routines" }
func (f fakeDb) SchemaRoutinesSQL(string) string                      { return "routines" }
func (f fakeDb) LowerCaseTableNamesProbeSQL() string                  { return "" }
func (f fakeDb) FoldFunctionName(name string) string                  { return name }

func (f fakeDb) NormalizeColumns(_ int, columns []*analyzerpb.Column) []*analyzerpb.Column {
	return columns
}

var mysqlDb = fakeDb{nsProbeSQL: "SELECT DATABASE()"}
var pgDb = fakeDb{nsProbeSQL: "probe", tempOverlay: true, tempProbeSQL: "temps"}

func TestFragmentColumnsFromRowsStrict(t *testing.T) {
	str := func(s string) *string { return &s }
	valid := [][]*string{{str("app"), str("users"), str("id"), str("integer"), str("1"), str("NO"), str("db")}, {str("app"), str("users"), str("email"), str("text"), str("2"), str("YES"), str("db")}}
	got, err := FragmentColumnsFromRows(fakeDb{}, 0, "app", valid)
	if err != nil {
		t.Fatalf("FragmentColumnsFromRows: %v", err)
	}
	want := []*analyzerpb.Column{{Catalog: "db", Schema: "app", Table: "users", Column: "id", DataType: "integer", Ordinal: 1}, {Catalog: "db", Schema: "app", Table: "users", Column: "email", DataType: "text", Ordinal: 2, Nullable: true}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("columns = %+v, want %+v", got, want)
	}

	cases := []struct {
		name string
		rows [][]*string
	}{
		{"wrong width", [][]*string{{str("app")}}},
		{"nil field", [][]*string{{str("app"), nil, str("id"), str("int"), str("1"), str("NO"), str("db")}}},
		{"schema mismatch", [][]*string{{str("other"), str("t"), str("c"), str("int"), str("1"), str("NO"), str("db")}}},
		{"bad ordinal", [][]*string{{str("app"), str("t"), str("c"), str("int"), str("2147483648"), str("NO"), str("db")}}},
		{"bad nullable", [][]*string{{str("app"), str("t"), str("c"), str("int"), str("1"), str("TRUE"), str("db")}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := FragmentColumnsFromRows(fakeDb{}, 0, "app", tc.rows); err == nil {
				t.Fatal("FragmentColumnsFromRows succeeded, want strict error")
			}
		})
	}
}
