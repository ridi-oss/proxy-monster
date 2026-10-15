package probe

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
	if got := call(ParseColumnsSafe, typed); !got.GetOk() || got.GetColumns()[0].GetTable() != "users" || got.GetColumns()[0].GetColumn() != "ssn" {
		t.Fatalf("parse: %v", got)
	}
	if got := call(IntrospectedColumnsSafe, typed); !got.GetOk() || got.GetColumns()[0].GetTable() != "Users" || got.GetColumns()[0].GetColumn() != "SSN" {
		t.Fatalf("introspected: %v", got)
	}
	mysql := &pb.ColumnNamesRequest{Engine: pb.Engine_MYSQL, MysqlLowerCaseTableNames: proto.Int32(1), Columns: []*pb.Column{{Catalog: "def", Schema: "App", Table: "Users", Column: "SSN"}}}
	if got := call(IntrospectedColumnsSafe, mysql); !got.GetOk() || got.GetColumns()[0].GetSchema() != "app" || got.GetColumns()[0].GetTable() != "users" || got.GetColumns()[0].GetColumn() != "ssn" {
		t.Fatalf("introspected mysql: %v", got)
	}
	for _, bad := range []*pb.ColumnNamesRequest{
		{Engine: pb.Engine_ENGINE_UNSPECIFIED},
		{Engine: pb.Engine_MYSQL, MysqlLowerCaseTableNames: proto.Int32(3)},
		{Engine: pb.Engine_POSTGRES, Columns: []*pb.Column{{Table: "a b"}}},
	} {
		if call(ParseColumnsSafe, bad).GetOk() {
			t.Errorf("parse: %v accepted", bad)
		}
	}
	for _, bad := range []*pb.ColumnNamesRequest{{Engine: pb.Engine_ENGINE_UNSPECIFIED}, {Engine: pb.Engine_MYSQL, MysqlLowerCaseTableNames: proto.Int32(3)}, {Engine: pb.Engine_MYSQL, Columns: []*pb.Column{{Schema: "App"}}}} {
		if call(IntrospectedColumnsSafe, bad).GetOk() {
			t.Errorf("introspected: %v accepted", bad)
		}
	}
	for _, safe := range []func([]byte) []byte{ParseColumnsSafe, IntrospectedColumnsSafe} {
		var garbage pb.ColumnNamesResponse
		if proto.Unmarshal(safe([]byte{0xff}), &garbage) != nil || garbage.GetOk() {
			t.Error("garbage accepted")
		}
	}
}
