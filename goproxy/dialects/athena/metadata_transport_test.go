package athena

import (
	"context"
	"io"
	"net/http"
	"testing"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

func TestNullTableParametersDoNotBreakMetadataReads(t *testing.T) {
	target := testTarget(t, func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch request.Header.Get("X-Amz-Target") {
		case "AmazonAthena.ListTableMetadata":
			_, _ = io.WriteString(w, `{"TableMetadataList":[{"Name":"events","TableType":"EXTERNAL_TABLE","Parameters":{"inputformat":null,"comment":"kept"},"Columns":[{"Name":"email","Type":"string"}]}]}`)
		case "AmazonAthena.GetTableMetadata":
			_, _ = io.WriteString(w, `{"TableMetadata":{"Name":"events","TableType":"EXTERNAL_TABLE","Parameters":{"serde.serialization.lib":null,"comment":"kept"},"Columns":[{"Name":"email","Type":"string"}]}}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	columns, err := target.readColumns(context.Background(), "AwsDataCatalog", "example")
	if err != nil || len(columns) != 1 {
		t.Fatalf("null parameter broke the listing: %v %v", columns, err)
	}
	detail, err := target.ReadTableDetail(context.Background(), &enginepb.TableRef{Schema: "example", Table: "events"})
	if err != nil || detail.Metadata.Comment == nil || *detail.Metadata.Comment != "kept" {
		t.Fatalf("null parameter broke the detail or dropped the comment: %+v %v", detail, err)
	}
}
