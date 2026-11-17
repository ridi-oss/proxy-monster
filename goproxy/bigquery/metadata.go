package bigquery

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const metadataTimeout = 60 * time.Second

// bigquerySession folds BigQuery names, which depend on no target setting.
var bigquerySession, _ = engines.BigQuery.NewSession(nil)

// datasetName is what BigQuery allows in a dataset name, so a checked one is safe inside backticks.
var datasetName = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// informationSchema is one dataset's view: the region-wide one needs table access to every dataset in the location.
func (t *target) informationSchema(dataset, view string) (string, error) {
	if !datasetName.MatchString(dataset) {
		return "", fmt.Errorf("bigquery: invalid dataset name %q", dataset)
	}
	return fmt.Sprintf("`%s`.`%s`.INFORMATION_SCHEMA.%s", t.project, dataset, view), nil
}

// readColumns lists one dataset's columns; a STRUCT or ARRAY column is one row with its GoogleSQL type, such as
// STRUCT<email STRING, age INT64>.
func (t *target) readColumns(ctx context.Context, dataset string) ([]*enginepb.Column, error) {
	view, err := t.informationSchema(dataset, "COLUMNS")
	if err != nil {
		return nil, err
	}
	request := queryRequest{Query: "SELECT table_schema, table_name, column_name, data_type, ordinal_position, is_nullable FROM " +
		view + " WHERE is_hidden = 'NO'"}
	request.Query += " ORDER BY table_schema, table_name, ordinal_position"
	rows, err := t.queryRows(ctx, request)
	if err != nil {
		return nil, err
	}
	columns := make([]*enginepb.Column, 0, len(rows))
	for _, row := range rows {
		if len(row) != 6 || row[0] == nil || row[1] == nil || row[2] == nil || row[3] == nil || row[4] == nil {
			return nil, errors.New("bigquery: incomplete column metadata")
		}
		ordinal, err := strconv.ParseInt(*row[4], 10, 32)
		if err != nil {
			return nil, errors.New("bigquery: malformed column ordinal")
		}
		columns = append(columns, &enginepb.Column{
			Catalog: t.catalogIdentity(), Schema: *row[0], Table: *row[1], Column: *row[2], DataType: *row[3],
			Ordinal: int32(ordinal), Nullable: row[5] == nil || *row[5] != "NO",
		})
	}
	return bigquerySession.CanonicalColumns(columns), nil
}

// readRoutines lists one dataset's routine names as (dataset, name) rows.
func (t *target) readRoutines(ctx context.Context, dataset string) ([][]*string, error) {
	view, err := t.informationSchema(dataset, "ROUTINES")
	if err != nil {
		return nil, err
	}
	request := queryRequest{Query: "SELECT routine_schema, routine_name FROM " + view}
	request.Query += " ORDER BY routine_schema, routine_name"
	rows, err := t.queryRows(ctx, request)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if len(row) != 2 || row[0] == nil || row[1] == nil {
			return nil, errors.New("bigquery: incomplete routine metadata")
		}
	}
	return rows, nil
}

// introspectWorkers bounds the datasets read at once; each read is two metadata jobs.
const introspectWorkers = 8

// listDatasets names the datasets in the target's location that the credentials can see.
func (t *target) listDatasets(ctx context.Context) ([]string, error) {
	var names []string
	query := url.Values{"maxResults": {"1000"}}
	for {
		var page struct {
			Datasets []struct {
				DatasetReference struct {
					DatasetID string `json:"datasetId"`
				} `json:"datasetReference"`
				Location string `json:"location"`
			} `json:"datasets"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := t.call(ctx, http.MethodGet, projectPath(t.project)+"/datasets", query, nil, &page); err != nil {
			return nil, err
		}
		for _, dataset := range page.Datasets {
			if strings.EqualFold(dataset.Location, t.location) && datasetName.MatchString(dataset.DatasetReference.DatasetID) {
				names = append(names, dataset.DatasetReference.DatasetID)
			}
		}
		if page.NextPageToken == "" {
			return names, nil
		}
		query.Set("pageToken", page.NextPageToken)
	}
}

// Introspect reflects every dataset in the location through each dataset's own INFORMATION_SCHEMA, which needs
// no access beyond the datasets themselves. A listed dataset gone or unreadable by then is left out, so a
// statement naming it denies.
func (t *target) Introspect(ctx context.Context) (*pb.CatalogRequest, error) {
	datasets, err := t.listDatasets(ctx)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(datasets, t.dataset) {
		datasets = append(datasets, t.dataset)
	}
	type reflected struct {
		columns  []*enginepb.Column
		routines [][]*string
		err      error
	}
	results := make([]reflected, len(datasets))
	slots := make(chan struct{}, introspectWorkers)
	var wait sync.WaitGroup
	for i, dataset := range datasets {
		wait.Add(1)
		go func() {
			defer wait.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			columns, err := t.readColumns(ctx, dataset)
			var routines [][]*string
			if err == nil {
				routines, err = t.readRoutines(ctx, dataset)
			}
			var upstream *apiError
			if errors.As(err, &upstream) && (upstream.status == http.StatusNotFound || upstream.status == http.StatusForbidden) && dataset != t.dataset {
				columns, routines, err = nil, nil, nil
			}
			results[i] = reflected{columns, routines, err}
		}()
	}
	wait.Wait()
	var columns []*enginepb.Column
	var routines []*enginepb.SchemaFunctions
	for i, result := range results {
		if result.err != nil {
			return nil, fmt.Errorf("introspecting dataset %q: %w", datasets[i], result.err)
		}
		columns = append(columns, result.columns...)
		if len(result.routines) > 0 {
			schema := &enginepb.SchemaFunctions{Schema: *result.routines[0][0]}
			for _, row := range result.routines {
				schema.Names = append(schema.Names, bigquerySession.FunctionName(*row[1]).String())
			}
			routines = append(routines, schema)
		}
	}
	return &pb.CatalogRequest{
		CurrentCatalog: t.catalogIdentity(), DefaultSchemas: []string{t.dataset},
		Catalog: &enginepb.CatalogSnapshot{Columns: columns, Routines: routines},
	}, nil
}

// InspectSchema lists one dataset's columns and routines. The listing is the inspection, so its hash is
// always trusted; a dataset BigQuery does not know is an empty fragment.
func (t *target) InspectSchema(schema string, ifHashDiffers []byte) (*pb.SchemaFragmentPush, error) {
	ctx, cancel := context.WithTimeout(context.Background(), metadataTimeout)
	defer cancel()
	var columns []*enginepb.Column
	routines := []string{}
	if datasetName.MatchString(schema) {
		var err error
		columns, err = t.readColumns(ctx, schema)
		var rows [][]*string
		if err == nil {
			rows, err = t.readRoutines(ctx, schema)
		}
		var upstream *apiError
		switch {
		case errors.As(err, &upstream) && upstream.status == http.StatusNotFound:
			columns = nil
		case err != nil:
			return nil, fmt.Errorf("introspecting dataset %q: %w", schema, err)
		}
		for _, row := range rows {
			routines = append(routines, bigquerySession.FunctionName(*row[1]).String())
		}
	}
	hash, err := fragmentHash(columns, routines)
	if err != nil {
		return nil, err
	}
	if len(ifHashDiffers) > 0 && string(ifHashDiffers) == string(hash) {
		return &pb.SchemaFragmentPush{ContentHash: hash, Unchanged: true}, nil
	}
	return &pb.SchemaFragmentPush{ContentHash: hash, Columns: columns, Routines: routines}, nil
}

// RunCommand fails closed: BigQuery has no command besides Refetch.
func (t *target) RunCommand(*pb.ProxyCommand, *spi.SessionSnapshot) error {
	return relay.ErrUnknownCommand
}

func fragmentHash(columns []*enginepb.Column, routines []string) ([]byte, error) {
	rows := make([][]any, 0, len(columns))
	for _, column := range columns {
		rows = append(rows, []any{column.GetCatalog(), column.GetSchema(), column.GetTable(), column.GetColumn(), column.GetDataType(), column.GetOrdinal(), column.GetNullable()})
	}
	data, err := json.Marshal([]any{rows, routines})
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(data)
	return hash[:], nil
}

// ReadTableDetail reads a table's schema with tables.get; a RECORD column is one column of STRUCT type, as
// INFORMATION_SCHEMA.COLUMNS lists it.
func (t *target) ReadTableDetail(ctx context.Context, table *enginepb.ObjectRef) (*spi.TableDetail, error) {
	if table == nil || table.Table == "" || table.Schema == "" {
		return nil, errors.New("bigquery: table selector is incomplete")
	}
	project := table.Catalog
	if project == "" {
		project = t.project
	}
	var response struct {
		Description *string `json:"description"`
		Schema      struct {
			Fields []tableField `json:"fields"`
		} `json:"schema"`
	}
	path := projectPath(project) + "/datasets/" + url.PathEscape(table.Schema) + "/tables/" + url.PathEscape(table.Table)
	if err := t.call(ctx, http.MethodGet, path, nil, nil, &response); err != nil {
		return nil, err
	}
	detail := &spi.TableDetail{
		Catalog: engines.BigQuery.CatalogName(project).String(), Schema: table.Schema, Table: table.Table,
		Columns: []spi.TableDetailColumn{}, Indexes: []spi.TableIndex{}, ForeignKeys: []spi.TableRelation{}, ReferencedBy: []spi.TableRelation{},
		Metadata: spi.TableMetadata{Engine: "bigquery", Comment: response.Description},
	}
	for i, field := range response.Schema.Fields {
		if field.Name == "" || field.Type == "" {
			return nil, errors.New("bigquery: incomplete table schema")
		}
		detail.Columns = append(detail.Columns, spi.TableDetailColumn{
			Name: bigquerySession.CatalogColumnNames([]*enginepb.Column{{Column: field.Name}})[0].Column(), DataType: googleSQLType(field),
			Ordinal: i + 1, Nullable: field.Mode == "" || field.Mode == "NULLABLE", Comment: field.Description,
		})
	}
	return detail, nil
}

// legacyTypes are the REST schema's type names GoogleSQL spells differently.
var legacyTypes = map[string]string{"INTEGER": "INT64", "FLOAT": "FLOAT64", "BOOLEAN": "BOOL", "RECORD": "STRUCT"}

// googleSQLType spells a REST schema field as INFORMATION_SCHEMA.COLUMNS does: ARRAY<STRUCT<x INT64>>.
func googleSQLType(field tableField) string {
	kind := field.Type
	if spelled, ok := legacyTypes[kind]; ok {
		kind = spelled
	}
	if kind == "STRUCT" {
		members := make([]string, len(field.Fields))
		for i, member := range field.Fields {
			members[i] = member.Name + " " + googleSQLType(member)
		}
		kind = "STRUCT<" + strings.Join(members, ", ") + ">"
	}
	if field.Mode == "REPEATED" {
		return "ARRAY<" + kind + ">"
	}
	return kind
}
