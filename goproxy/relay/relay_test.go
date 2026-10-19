package relay

import (
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
