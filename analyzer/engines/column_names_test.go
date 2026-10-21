package engines

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

func TestColumnNamesSafe(t *testing.T) {
	call := func(safe func([]byte) []byte, req *pb.ColumnNamesRequest) *pb.ColumnNamesResponse {
		in, _ := proto.Marshal(req)
		var out pb.ColumnNamesResponse
		if err := proto.Unmarshal(safe(in), &out); err != nil {
			t.Fatal(err)
		}
		return &out
	}
	typed := &pb.ColumnNamesRequest{Engine: pb.Engine_POSTGRES, Columns: []*pb.Column{{Catalog: "shop", Schema: "public", Table: "Users", Column: "SSN"}}}
	if got := call(ParseColumnsSafe, typed); got.GetError() != pb.ColumnNamesResponse_NONE || got.GetColumns()[0].GetTable() != "users" || got.GetColumns()[0].GetColumn() != "ssn" {
		t.Fatalf("parse: %v", got)
	}
	if got := call(IntrospectedColumnsSafe, typed); got.GetError() != pb.ColumnNamesResponse_NONE || got.GetColumns()[0].GetTable() != "Users" || got.GetColumns()[0].GetColumn() != "SSN" {
		t.Fatalf("introspected: %v", got)
	}
	mysql := &pb.ColumnNamesRequest{Engine: pb.Engine_MYSQL, Datasource: &pb.EngineDatasource{MysqlLowerCaseTableNames: proto.Int32(1)}, Columns: []*pb.Column{{Catalog: "def", Schema: "App", Table: "Users", Column: "SSN"}}}
	if got := call(IntrospectedColumnsSafe, mysql); got.GetError() != pb.ColumnNamesResponse_NONE || got.GetColumns()[0].GetSchema() != "app" || got.GetColumns()[0].GetTable() != "users" || got.GetColumns()[0].GetColumn() != "ssn" {
		t.Fatalf("introspected mysql: %v", got)
	}
	for _, bad := range []*pb.ColumnNamesRequest{
		{Engine: pb.Engine_ENGINE_UNSPECIFIED},
		{Engine: pb.Engine_MYSQL, Datasource: &pb.EngineDatasource{MysqlLowerCaseTableNames: proto.Int32(3)}},
		{Engine: pb.Engine_POSTGRES, Columns: []*pb.Column{{Table: "a b"}}},
	} {
		if call(ParseColumnsSafe, bad).GetError() == pb.ColumnNamesResponse_NONE {
			t.Errorf("parse: %v accepted", bad)
		}
	}
	for _, bad := range []*pb.ColumnNamesRequest{{Engine: pb.Engine_ENGINE_UNSPECIFIED}, {Engine: pb.Engine_MYSQL, Datasource: &pb.EngineDatasource{MysqlLowerCaseTableNames: proto.Int32(3)}}, {Engine: pb.Engine_MYSQL, Columns: []*pb.Column{{Schema: "App"}}}} {
		if call(IntrospectedColumnsSafe, bad).GetError() == pb.ColumnNamesResponse_NONE {
			t.Errorf("introspected: %v accepted", bad)
		}
	}
	for _, safe := range []func([]byte) []byte{ParseColumnsSafe, IntrospectedColumnsSafe} {
		if got := call(safe, &pb.ColumnNamesRequest{Engine: pb.Engine_MYSQL, Columns: mysql.Columns}); got.GetError() != pb.ColumnNamesResponse_DATASOURCE_REJECTED {
			t.Errorf("unreported mysql datasource: %v", got)
		}
		if call(safe, typed).GetError() != pb.ColumnNamesResponse_NONE {
			t.Error("postgres datasource rejected")
		}
		var garbage pb.ColumnNamesResponse
		if proto.Unmarshal(safe([]byte{0xff}), &garbage) != nil || garbage.GetError() != pb.ColumnNamesResponse_INVALID {
			t.Error("garbage accepted")
		}
	}
}
