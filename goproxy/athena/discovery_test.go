package athena

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"testing"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
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
	catalog, err := target.Introspect(context.Background())
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

func metadataTarget(t *testing.T, list string) *target {
	return testTarget(t, func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = io.WriteString(w, list)
	})
}

func TestCatalogReadsViewsGovernedAndUntypedPreCatalogTablesLikeTables(t *testing.T) {
	target := metadataTarget(t, `{"TableMetadataList":[{"Name":"base","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"email","Type":"string"}]},{"Name":"managed","TableType":"MANAGED_TABLE","Columns":[{"Name":"id","Type":"int"}]},{"Name":"recent","TableType":"VIRTUAL_VIEW","Columns":[{"Name":"email","Type":"string"},{"Name":"seen","Type":"date"}],"PartitionKeys":[{"Name":"day","Type":"string"}]},{"Name":"governed","TableType":"GOVERNED","Columns":[{"Name":"value","Type":"string"}]},{"Name":"crawled","Columns":[{"Name":"line","Type":"string"}]},{"Name":"empty_view","TableType":"VIRTUAL_VIEW"}]}`)
	columns, err := target.readColumns(context.Background(), "AwsDataCatalog", "example")
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, column := range columns {
		got = append(got, fmt.Sprintf("%s.%s:%d", column.Table, column.Column, column.Ordinal))
	}
	want := []string{"base.email:1", "managed.id:1", "recent.email:1", "recent.seen:2", "recent.day:3", "governed.value:1", "crawled.line:1"}
	if !slices.Equal(got, want) {
		t.Fatalf("catalog columns = %v, want %v", got, want)
	}
}

func TestCatalogFailsOnAnUnsupportedTableType(t *testing.T) {
	columns, err := metadataTarget(t, `{"TableMetadataList":[{"Name":"base","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"email","Type":"string"}]},{"Name":"snapshot","TableType":"MATERIALIZED_VIEW","Columns":[{"Name":"email","Type":"string"}]}]}`).readColumns(context.Background(), "AwsDataCatalog", "example")
	if err == nil || columns != nil {
		t.Fatalf("unsupported table type accepted: %v, %v", columns, err)
	}
}

func TestStatementOnACatalogedViewResolves(t *testing.T) {
	for name, tables := range map[string]string{
		"view":    `{"Name":"active_users","TableType":"VIRTUAL_VIEW","Columns":[{"Name":"email","Type":"string"}]}`,
		"no view": `{"Name":"users","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"email","Type":"string"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			target := testTarget(t, func(w http.ResponseWriter, request *http.Request) {
				w.Header().Set("Content-Type", "application/x-amz-json-1.1")
				switch request.Header.Get("X-Amz-Target") {
				case "AmazonAthena.GetWorkGroup":
					_, _ = io.WriteString(w, `{"WorkGroup":{}}`)
				case "AmazonAthena.ListDatabases":
					_, _ = io.WriteString(w, `{"DatabaseList":[{"Name":"example"}]}`)
				default:
					_, _ = io.WriteString(w, `{"TableMetadataList":[`+tables+`]}`)
				}
			})
			catalog, err := target.Introspect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			facts, err := engines.AnalyzeStatement(&enginepb.AnalyzeRequest{
				Sql:          "SELECT email FROM active_users",
				EngineConfig: &enginepb.EngineConfig{Engine: enginepb.Engine_ATHENA, Session: &enginepb.SessionObservation{Engine: &enginepb.SessionObservation_Athena{Athena: &enginepb.AthenaSqlContext{Workgroup: "primary"}}}},
				Namespace:    &enginepb.Namespace{Catalog: catalog.GetCurrentCatalog(), SearchPath: catalog.GetDefaultSchemas()},
				Catalog:      catalog.GetCatalog(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if facts.GetResolved() != (name == "view") {
				t.Fatalf("resolved = %v with %s in the catalog: %v", facts.GetResolved(), name, facts.GetFailureClass())
			}
		})
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
