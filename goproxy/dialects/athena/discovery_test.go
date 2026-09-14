package athena

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestCatalogDiscoveryCrawlsOnlyTheConfiguredCatalog(t *testing.T) {
	visited := make(map[string]bool)
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
			if input["CatalogName"] != "AwsDataCatalog" {
				t.Errorf("crawled a catalog outside the datasource scope: %s", input["CatalogName"])
			}
			_, _ = io.WriteString(w, `{"DatabaseList":[{"Name":"example"},{"Name":"archive"}]}`)
		case "AmazonAthena.ListTableMetadata":
			visited[input["CatalogName"]+"/"+input["DatabaseName"]] = true
			_, _ = io.WriteString(w, `{"TableMetadataList":[{"Name":"events","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"email","Type":"string"}]}]}`)
		default:
			t.Errorf("unexpected discovery call %s", request.Header.Get("X-Amz-Target"))
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	catalog, err := target.ReadCatalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Catalog.Columns) != 2 || len(visited) != 2 {
		t.Fatalf("incomplete discovery: %d columns, %d namespaces", len(catalog.Catalog.Columns), len(visited))
	}
	identities := make(map[string]bool)
	for _, column := range catalog.Catalog.Columns {
		identities[column.GetCatalog()+"/"+column.Schema+"/"+column.Table] = true
	}
	for _, expected := range []string{"awsdatacatalog/example/events", "awsdatacatalog/archive/events"} {
		if !identities[expected] {
			t.Errorf("missing qualified table %s", expected)
		}
	}
	if catalog.GetCurrentCatalog() != "awsdatacatalog" || len(catalog.DefaultSchemas) != 1 || catalog.DefaultSchemas[0] != "example" {
		t.Fatal("discovery changed connection defaults")
	}
}

func TestRepeatedMetadataTokenFailsInsteadOfReturningPartialCatalog(t *testing.T) {
	calls := 0
	target := testTarget(t, func(w http.ResponseWriter, request *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = io.WriteString(w, `{"TableMetadataList":[],"NextToken":"repeated"}`)
	})
	columns, err := target.readColumns(context.Background(), "external", "archive")
	if err == nil || columns != nil || calls != 2 {
		t.Fatalf("repeated token accepted: columns %v, err %v, calls %d", columns, err, calls)
	}
}

func TestCatalogCannotSilentlyFlattenOrOmitUnresolvedViews(t *testing.T) {
	target := testTarget(t, func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = io.WriteString(w, `{"TableMetadataList":[{"Name":"base","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"email","Type":"string"}]},{"Name":"view","TableType":"VIRTUAL_VIEW","Columns":[{"Name":"aliased_secret","Type":"string"}]},{"Name":"unknown","Columns":[{"Name":"value","Type":"string"}]}]}`)
	})
	columns, err := target.readColumns(context.Background(), "AwsDataCatalog", "example")
	if err == nil || columns != nil {
		t.Fatalf("unproved relation was flattened or silently omitted: %v, %v", columns, err)
	}
}

func TestConnectionMetadataUsesHTTPSWithoutExposingAWSProfile(t *testing.T) {
	target := testTarget(t, func(w http.ResponseWriter, request *http.Request) { t.Fatal("connection metadata made an AWS call") })
	target.config.advertise = "proxy.example:6443"
	target.config.profile = "private-profile"
	info := target.ConnectionInfo()
	if info.Endpoint != "https://proxy.example:6443" || info.Properties["catalog"] != "AwsDataCatalog" {
		t.Fatalf("bad connection metadata: %v", info)
	}
	if _, ok := info.Properties["profile"]; ok {
		t.Fatal("credential profile leaked into connection metadata")
	}
}
