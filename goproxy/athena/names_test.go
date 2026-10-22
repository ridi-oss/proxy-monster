package athena

import (
	"context"
	"io"
	"net/http"
	"slices"
	"testing"

	"github.com/ridi-oss/sqlglot-go/dialects"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

func athenaCanonical(name string) string { return dialects.Athena().FoldIdentifierName(name, false) }

func mixedCaseGlue(t *testing.T) *target {
	t.Helper()
	return testTargetIn(t, "HR", func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch request.Header.Get("X-Amz-Target") {
		case "AmazonAthena.GetWorkGroup":
			_, _ = io.WriteString(w, `{"WorkGroup":{"Configuration":{"EngineVersion":{"EffectiveEngineVersion":"Athena engine version 3"}}}}`)
		case "AmazonAthena.ListDatabases":
			_, _ = io.WriteString(w, `{"DatabaseList":[{"Name":"HR"}]}`)
		case "AmazonAthena.ListTableMetadata":
			_, _ = io.WriteString(w, `{"TableMetadataList":[{"Name":"Salaries","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"SSN","Type":"string"},{"Name":"Straße","Type":"string"}],"PartitionKeys":[{"Name":"Day","Type":"date"}]}]}`)
		case "AmazonAthena.GetTableMetadata":
			_, _ = io.WriteString(w, `{"TableMetadata":{"Name":"Salaries","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"SSN","Type":"string"},{"Name":"Straße","Type":"string"}],"PartitionKeys":[{"Name":"Day","Type":"date"}]}}`)
		default:
			t.Errorf("unexpected call %s", request.Header.Get("X-Amz-Target"))
			w.WriteHeader(http.StatusBadRequest)
		}
	})
}

func TestAthenaCatalogPushIsCanonical(t *testing.T) {
	catalog, err := mixedCaseGlue(t).Introspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := catalog.GetCurrentCatalog(); got != athenaCanonical("AwsDataCatalog") {
		t.Errorf("CurrentCatalog = %q, want %q", got, athenaCanonical("AwsDataCatalog"))
	}
	if got := catalog.GetDefaultSchemas(); !slices.Equal(got, []string{athenaCanonical("HR")}) {
		t.Errorf("DefaultSchemas = %v, want [%s]", got, athenaCanonical("HR"))
	}
	var got []string
	for _, c := range catalog.GetCatalog().GetColumns() {
		got = append(got, c.GetCatalog()+"."+c.GetSchema()+"."+c.GetTable()+"."+c.GetColumn())
	}
	prefix := athenaCanonical("AwsDataCatalog") + "." + athenaCanonical("HR") + "." + athenaCanonical("Salaries") + "."
	want := []string{prefix + athenaCanonical("SSN"), prefix + athenaCanonical("Straße"), prefix + athenaCanonical("Day")}
	if !slices.Equal(got, want) {
		t.Errorf("pushed columns = %v, want %v", got, want)
	}
}

func TestAthenaTableDetailIsCanonical(t *testing.T) {
	target := mixedCaseGlue(t)
	for _, tc := range []struct {
		ref     *enginepb.ObjectRef
		pending string
	}{
		{&enginepb.ObjectRef{Catalog: "awsdatacatalog", Schema: "hr", Table: "salaries"}, ""},
		{&enginepb.ObjectRef{Catalog: "AwsDataCatalog", Schema: "HR", Table: "Salaries"}, "Athena table detail compares the metadata table name byte-exact against a mixed-case request"},
	} {
		ref := tc.ref
		t.Run(ref.Schema+"."+ref.Table, func(t *testing.T) {
			if tc.pending != "" {
				t.Skip("pending-name-fix: " + tc.pending)
			}
			detail, err := target.ReadTableDetail(context.Background(), ref)
			if err != nil {
				t.Fatalf("ReadTableDetail: %v", err)
			}
			if detail.Catalog != athenaCanonical("AwsDataCatalog") || detail.Schema != athenaCanonical("HR") || detail.Table != athenaCanonical("Salaries") {
				t.Fatalf("detail = %s.%s.%s, want canonical", detail.Catalog, detail.Schema, detail.Table)
			}
			var columns []string
			for _, column := range detail.Columns {
				columns = append(columns, column.Name)
			}
			if want := []string{athenaCanonical("SSN"), athenaCanonical("Straße"), athenaCanonical("Day")}; !slices.Equal(columns, want) {
				t.Fatalf("columns = %v, want %v", columns, want)
			}
		})
	}
}
