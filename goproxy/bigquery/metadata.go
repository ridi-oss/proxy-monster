package bigquery

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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

// informationSchema is the region-scoped INFORMATION_SCHEMA view of the target's project, so one query lists
// every dataset in the location.
func (t *target) informationSchema(view string) string {
	return fmt.Sprintf("`%s`.`region-%s`.INFORMATION_SCHEMA.%s", t.project, strings.ToLower(t.location), view)
}

// readColumns lists the location's columns, or one dataset's; a STRUCT or ARRAY column is one row with its
// GoogleSQL type, such as STRUCT<email STRING, age INT64>.
func (t *target) readColumns(ctx context.Context, dataset string) ([]*enginepb.Column, error) {
	request := queryRequest{Query: "SELECT table_schema, table_name, column_name, data_type, ordinal_position, is_nullable FROM " +
		t.informationSchema("COLUMNS") + " WHERE is_hidden = 'NO'"}
	if dataset != "" {
		request.Query += " AND table_schema = @dataset"
		request.ParameterMode, request.QueryParameters = "NAMED", []stringParameter{namedString("dataset", dataset)}
	}
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

// readRoutines lists the location's routine names, or one dataset's, as (dataset, name) rows.
func (t *target) readRoutines(ctx context.Context, dataset string) ([][]*string, error) {
	request := queryRequest{Query: "SELECT routine_schema, routine_name FROM " + t.informationSchema("ROUTINES")}
	if dataset != "" {
		request.Query += " WHERE routine_schema = @dataset"
		request.ParameterMode, request.QueryParameters = "NAMED", []stringParameter{namedString("dataset", dataset)}
	}
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

func (t *target) Introspect(ctx context.Context) (*pb.CatalogRequest, error) {
	columns, err := t.readColumns(ctx, "")
	if err != nil {
		return nil, err
	}
	rows, err := t.readRoutines(ctx, "")
	if err != nil {
		return nil, err
	}
	var routines []*enginepb.SchemaFunctions
	index := map[string]*enginepb.SchemaFunctions{}
	for _, row := range rows {
		schema := index[*row[0]]
		if schema == nil {
			schema = &enginepb.SchemaFunctions{Schema: *row[0]}
			index[*row[0]] = schema
			routines = append(routines, schema)
		}
		schema.Names = append(schema.Names, bigquerySession.FunctionName(*row[1]).String())
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
	columns, err := t.readColumns(ctx, schema)
	if err != nil {
		return nil, fmt.Errorf("introspecting dataset %q: %w", schema, err)
	}
	rows, err := t.readRoutines(ctx, schema)
	if err != nil {
		return nil, fmt.Errorf("introspecting dataset %q routines: %w", schema, err)
	}
	routines := make([]string, 0, len(rows))
	for _, row := range rows {
		routines = append(routines, bigquerySession.FunctionName(*row[1]).String())
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
