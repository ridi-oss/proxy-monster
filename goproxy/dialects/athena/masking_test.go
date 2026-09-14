package athena

import (
	"bytes"
	"encoding/json"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"google.golang.org/protobuf/proto"
)

const maskPage = `{"ResultSet":{"ResultSetMetadata":{"ColumnInfo":[{"Name":"email","Label":"email","Type":"varchar"},{"Name":"count","Type":"bigint"}]},"Rows":[{"Data":[{"VarCharValue":"email"},{"VarCharValue":"count"}]},{"Data":[{"VarCharValue":"a@example.test"},{"VarCharValue":"12"}]},{"Data":[{},{"VarCharValue":"3"}]}],"FutureResult":true},"NextToken":"aws-page-token","FutureNumber":1.00}`

func TestMaskResultPageHeaderNullTypesAndNativeFields(t *testing.T) {
	masks := []*pb.ColumnMask{{Ordinal: proto.Int32(0), Kind: "FIXED"}, {Ordinal: proto.Int32(1), Kind: "FIXED"}}
	output, digest, err := MaskResultPage([]byte(maskPage), masks, proto.Int32(2), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != 32 || bytes.Contains(output, []byte("a@example.test")) || !bytes.Contains(output, []byte(`"FutureNumber":1.00`)) || !bytes.Contains(output, []byte(`"NextToken":"aws-page-token"`)) {
		t.Fatalf("bad masked page: %s", output)
	}
	var page struct {
		ResultSet struct {
			ResultSetMetadata struct{ ColumnInfo []struct{ Type string } }
			Rows              []struct{ Data []map[string]string }
		}
	}
	if err := json.Unmarshal(output, &page); err != nil {
		t.Fatal(err)
	}
	if page.ResultSet.Rows[0].Data[0]["VarCharValue"] != "email" || page.ResultSet.Rows[1].Data[0]["VarCharValue"] != "####" || page.ResultSet.Rows[2].Data[0]["VarCharValue"] != "" {
		t.Fatalf("bad header, mask, or null: %s", output)
	}
	if _, present := page.ResultSet.Rows[2].Data[0]["VarCharValue"]; present {
		t.Fatal("NULL became an empty string")
	}
	if page.ResultSet.ResultSetMetadata.ColumnInfo[1].Type != "varchar" {
		t.Fatal("masked numeric column retains numeric wire type")
	}
	later := bytes.Replace([]byte(maskPage), []byte(`{"VarCharValue":"email"}`), []byte(`{"VarCharValue":"secret"}`), 1)
	output, _, err = MaskResultPage(later, masks, proto.Int32(2), digest, false)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output, []byte("secret")) {
		t.Fatal("later page skipped its first data row")
	}
}

func TestMaskResultPageFailsClosedOnShape(t *testing.T) {
	masks := []*pb.ColumnMask{{Ordinal: proto.Int32(0), Kind: "FIXED"}}
	_, digest, err := MaskResultPage([]byte(maskPage), masks, proto.Int32(2), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		body   []byte
		masks  []*pb.ColumnMask
		width  *int32
		digest []byte
		first  bool
	}{
		{"width", []byte(maskPage), masks, proto.Int32(3), nil, true},
		{"missing ordinal", []byte(maskPage), []*pb.ColumnMask{{Kind: "FIXED"}}, nil, nil, true},
		{"nil mask", []byte(maskPage), []*pb.ColumnMask{nil}, nil, nil, true},
		{"out of range", []byte(maskPage), []*pb.ColumnMask{{Ordinal: proto.Int32(2), Kind: "FIXED"}}, nil, nil, true},
		{"metadata drift", bytes.Replace([]byte(maskPage), []byte(`"Type":"bigint"`), []byte(`"Type":"double"`), 1), masks, nil, digest, false},
		{"short row", bytes.Replace([]byte(maskPage), []byte(`{},{"VarCharValue":"3"}`), []byte(`{}`), 1), masks, nil, nil, true},
		{"missing header", bytes.Replace([]byte(maskPage), []byte(`"VarCharValue":"email"`), []byte(`"VarCharValue":"sensitive"`), 1), masks, nil, nil, true},
		{"json null", bytes.Replace([]byte(maskPage), []byte(`{},{"VarCharValue":"3"}`), []byte(`{"VarCharValue":null},{"VarCharValue":"3"}`), 1), masks, nil, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, _, err := MaskResultPage(tc.body, tc.masks, tc.width, tc.digest, tc.first)
			if err == nil || output != nil {
				t.Fatalf("unenforceable page accepted: %s", output)
			}
		})
	}
}

func TestLaterHeaderLikeDataIsMasked(t *testing.T) {
	output, _, err := MaskResultPage([]byte(maskPage), []*pb.ColumnMask{{Ordinal: proto.Int32(0), Kind: "FIXED"}}, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output, []byte(`"VarCharValue":"email"`)) {
		t.Fatal("a header-like value on a later page escaped masking")
	}
}
