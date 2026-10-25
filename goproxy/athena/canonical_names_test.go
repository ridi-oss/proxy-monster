package athena

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena/types"
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

func TestMetadataNamesAreCanonical(t *testing.T) {
	target := testTarget(t, func(w http.ResponseWriter, request *http.Request) {
		var input map[string]string
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch request.Header.Get("X-Amz-Target") {
		case "AmazonAthena.GetWorkGroup":
			_, _ = io.WriteString(w, `{"WorkGroup":{"Configuration":{"EngineVersion":{"EffectiveEngineVersion":"Athena engine version 3"}}}}`)
		case "AmazonAthena.ListDatabases":
			_, _ = io.WriteString(w, `{"DatabaseList":[{"Name":"Sales"}]}`)
		case "AmazonAthena.ListTableMetadata":
			_, _ = io.WriteString(w, `{"TableMetadataList":[{"Name":"Orders","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"Email","Type":"string"}],"PartitionKeys":[{"Name":"Day","Type":"date"}]}]}`)
		case "AmazonAthena.GetTableMetadata":
			if input["CatalogName"] != "AwsDataCatalog" {
				t.Errorf("the configured catalog was not matched: %s", input["CatalogName"])
			}
			_, _ = io.WriteString(w, `{"TableMetadata":{"Name":"Orders","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"Email","Type":"string"}]}}`)
		default:
			t.Errorf("unexpected call %s", request.Header.Get("X-Amz-Target"))
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	target.config.database = "Sales"

	catalog, err := target.Introspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range catalog.Catalog.Columns {
		got = append(got, c.Catalog+"/"+c.Schema+"/"+c.Table+"/"+c.Column)
	}
	if len(got) != 2 || got[0] != "awsdatacatalog/sales/orders/email" || got[1] != "awsdatacatalog/sales/orders/day" {
		t.Fatalf("columns: %v", got)
	}
	if catalog.CurrentCatalog != "awsdatacatalog" || len(catalog.DefaultSchemas) != 1 || catalog.DefaultSchemas[0] != "sales" {
		t.Fatalf("namespace: %s %v", catalog.CurrentCatalog, catalog.DefaultSchemas)
	}

	detail, err := target.ReadTableDetail(context.Background(), &enginepb.ObjectRef{Catalog: "awsdatacatalog", Schema: "sales", Table: "orders"})
	if err != nil {
		t.Fatal(err)
	}
	if detail.Catalog != "awsdatacatalog" || detail.Schema != "sales" || detail.Table != "orders" || detail.Columns[0].Name != "email" {
		t.Fatalf("detail: %+v", detail)
	}
	if _, err := target.ReadTableDetail(context.Background(), &enginepb.ObjectRef{Catalog: "awsdatacatalog", Schema: "sales", Table: "Orders"}); err == nil {
		t.Fatal("a non-canonical table name matched")
	}
}

func TestColumnsDifferingOnlyInCaseAreDuplicates(t *testing.T) {
	table := types.TableMetadata{Name: aws.String("t"), Columns: []types.Column{
		{Name: aws.String("Email"), Type: aws.String("string")}, {Name: aws.String("EMAIL"), Type: aws.String("string")},
	}}
	if _, err := metadataColumns(table); err == nil {
		t.Fatal("columns that fold to one name were accepted")
	}
}
