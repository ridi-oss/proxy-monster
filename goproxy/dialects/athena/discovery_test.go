package athena

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
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
	columns, _, err := target.readColumns(context.Background(), "external", "archive")
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

func TestCatalogSkipsViewsAndUnknownTypesWithoutFlatteningTheirColumns(t *testing.T) {
	target := metadataTarget(t, `{"TableMetadataList":[{"Name":"base","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"email","Type":"string"}]},{"Name":"view","TableType":"VIRTUAL_VIEW","Columns":[{"Name":"aliased_secret","Type":"string"}]},{"Name":"unknown","Columns":[{"Name":"value","Type":"string"}]},{"Name":"managed","TableType":"MANAGED_TABLE","Columns":[{"Name":"id","Type":"int"}]}]}`)
	columns, skipped, err := target.readColumns(context.Background(), "AwsDataCatalog", "example")
	if err != nil {
		t.Fatal(err)
	}
	tables := []string{}
	for _, column := range columns {
		tables = append(tables, column.Table+"."+column.Column)
	}
	if !slices.Equal(tables, []string{"base.email", "managed.id"}) {
		t.Fatalf("catalog holds columns of an unproved relation: %v", tables)
	}
	if !slices.Equal(skipped, []skippedRelation{{"example", "view", "VIRTUAL_VIEW"}, {"example", "unknown", ""}}) {
		t.Fatalf("skipped relations not reported: %v", skipped)
	}
}

func TestCatalogStillRejectsMissingOrDuplicateRelationNames(t *testing.T) {
	for name, list := range map[string]string{
		"empty table name":      `{"TableMetadataList":[{"Name":"","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"email","Type":"string"}]}]}`,
		"empty view name":       `{"TableMetadataList":[{"Name":"","TableType":"VIRTUAL_VIEW"}]}`,
		"duplicate table":       `{"TableMetadataList":[{"Name":"base","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"email","Type":"string"}]},{"Name":"base","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"email","Type":"string"}]}]}`,
		"view shadows table":    `{"TableMetadataList":[{"Name":"base","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"email","Type":"string"}]},{"Name":"base","TableType":"VIRTUAL_VIEW"}]}`,
		"duplicate column name": `{"TableMetadataList":[{"Name":"base","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"email","Type":"string"}],"PartitionKeys":[{"Name":"email","Type":"string"}]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			columns, skipped, err := metadataTarget(t, list).readColumns(context.Background(), "AwsDataCatalog", "example")
			if err == nil || columns != nil || skipped != nil {
				t.Fatalf("invalid metadata accepted: %v, %v, %v", columns, skipped, err)
			}
		})
	}
}

func TestSkippedRelationLogIsOneBoundedLineCountedByType(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	skipped := make([]skippedRelation, skippedSampleSize*3)
	for i := range skipped {
		skipped[i] = skippedRelation{schema: "example", table: fmt.Sprintf("view_%d", i), kind: "VIRTUAL_VIEW"}
	}
	skipped[len(skipped)-1].kind = ""
	logSkippedRelations(logger, slog.LevelWarn, skipped)
	logSkippedRelations(logger, slog.LevelWarn, nil)

	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("want one line, got %d: %s", len(lines), logs.String())
	}
	var entry struct {
		Level  string         `json:"level"`
		Count  int            `json:"count"`
		Types  map[string]int `json:"types"`
		Sample []string       `json:"sample"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatal(err)
	}
	want := make([]string, skippedSampleSize)
	for i := range want {
		want[i] = skipped[i].schema + "." + skipped[i].table
	}
	if entry.Level != "WARN" || entry.Count != len(skipped) || !slices.Equal(entry.Sample, want) {
		t.Fatalf("log is not a bounded sample: %+v", entry)
	}
	if entry.Types["VIRTUAL_VIEW"] != len(skipped)-1 || entry.Types["(none)"] != 1 {
		t.Fatalf("log does not count skips by type: %v", entry.Types)
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

func TestSkippedViewsTravelAsUnprovedRelations(t *testing.T) {
	lists := map[string]string{
		"example": `{"TableMetadataList":[{"Name":"events","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"email","Type":"string"}]},{"Name":"recent","TableType":"VIRTUAL_VIEW"}]}`,
		"plain":   `{"TableMetadataList":[{"Name":"events","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"email","Type":"string"}]}]}`,
	}
	target := testTarget(t, func(w http.ResponseWriter, request *http.Request) {
		var input map[string]string
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch request.Header.Get("X-Amz-Target") {
		case "AmazonAthena.GetWorkGroup":
			_, _ = io.WriteString(w, `{"WorkGroup":{}}`)
		case "AmazonAthena.ListDatabases":
			_, _ = io.WriteString(w, `{"DatabaseList":[{"Name":"example"}]}`)
		default:
			_, _ = io.WriteString(w, lists[input["DatabaseName"]])
		}
	})
	catalog, err := target.Introspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	relations := catalog.Catalog.GetUnprovedRelations()
	if len(relations) != 1 || relations[0].GetCatalog() != "awsdatacatalog" || relations[0].GetSchema() != "example" || relations[0].GetTable() != "recent" {
		t.Fatalf("view is not an unproved relation: %v", relations)
	}

	var pushes []*pb.SchemaFragmentPush
	refetcher, err := target.newRefetcher([]byte("connection"), func(push *pb.SchemaFragmentPush) (uint64, error) {
		pushes = append(pushes, push)
		return 1, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, schema := range []string{"example", "plain"} {
		if err := refetcher.run(&pb.Refetch{Schema: schema, Catalog: "awsdatacatalog"}); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(pushes[0].GetUnprovedTables(), []string{"recent"}) || len(pushes[1].GetUnprovedTables()) != 0 {
		t.Fatalf("fragments do not carry unproved tables: %v / %v", pushes[0].GetUnprovedTables(), pushes[1].GetUnprovedTables())
	}
	if bytes.Equal(pushes[0].GetContentHash(), pushes[1].GetContentHash()) {
		t.Fatal("the content hash does not cover unproved tables")
	}
}
