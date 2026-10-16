package athena

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsa "github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/athena/types"
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// catalogIdentity is the catalog name the control plane and analyzer key on; Athena folds catalog names.
func (t *target) catalogIdentity() string { return strings.ToLower(t.config.catalog) }

// skippedSampleSize bounds the relation names one skip log lists; a catalog can hold hundreds of views.
const skippedSampleSize = 10

type skippedRelation struct{ schema, table, kind string }

// Introspect scans the configured catalog's Glue metadata, leaving out relations that are not tables.
func (t *target) Introspect(ctx context.Context) (*pb.CatalogRequest, error) {
	group, err := t.api.GetWorkGroup(ctx, &awsa.GetWorkGroupInput{WorkGroup: aws.String(t.config.workgroup)})
	if err != nil {
		return nil, err
	}
	version := ""
	if group.WorkGroup != nil && group.WorkGroup.Configuration != nil && group.WorkGroup.Configuration.EngineVersion != nil {
		version = aws.ToString(group.WorkGroup.Configuration.EngineVersion.EffectiveEngineVersion)
	}
	databases, err := t.databases(ctx, t.config.catalog)
	if err != nil {
		return nil, err
	}
	columns := []*enginepb.Column{}
	var skipped []skippedRelation
	for _, database := range databases {
		fragment, unproved, err := t.readColumns(ctx, t.config.catalog, database)
		if err != nil {
			return nil, err
		}
		columns = append(columns, fragment...)
		skipped = append(skipped, unproved...)
	}
	logSkippedRelations(slog.Default(), slog.LevelWarn, skipped)
	return &pb.CatalogRequest{
		CurrentCatalog: t.catalogIdentity(), DefaultSchemas: []string{t.config.database},
		Catalog:       &enginepb.CatalogSnapshot{Columns: columns, UnprovedRelations: unprovedRelations(t.catalogIdentity(), skipped)},
		EngineVersion: version,
	}, nil
}

// readColumns lists the columns of one database's tables and the relations it left out.
func (t *target) readColumns(ctx context.Context, catalog, database string) ([]*enginepb.Column, []skippedRelation, error) {
	if catalog == "" || database == "" {
		return nil, nil, errors.New("athena: namespace is incomplete")
	}
	pages := awsa.NewListTableMetadataPaginator(t.api, &awsa.ListTableMetadataInput{
		CatalogName: aws.String(catalog), DatabaseName: aws.String(database), WorkGroup: aws.String(t.config.workgroup),
	})
	var columns []*enginepb.Column
	var skipped []skippedRelation
	seen := make(map[string]bool)
	tokens := make(map[string]bool)
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, nil, err
		}
		if err := checkMetadataToken(page.NextToken, tokens); err != nil {
			return nil, nil, err
		}
		for _, table := range page.TableMetadataList {
			name := aws.ToString(table.Name)
			if name == "" || seen[name] {
				return nil, nil, errors.New("athena: missing or duplicate table metadata")
			}
			seen[name] = true
			if kind := aws.ToString(table.TableType); kind != "EXTERNAL_TABLE" && kind != "MANAGED_TABLE" {
				skipped = append(skipped, skippedRelation{schema: database, table: name, kind: kind})
				continue
			}
			tableColumns, err := metadataColumns(table)
			if err != nil {
				return nil, nil, err
			}
			for i, column := range tableColumns {
				columns = append(columns, &enginepb.Column{
					Catalog: strings.ToLower(catalog), Schema: database, Table: name,
					Column: aws.ToString(column.Name), DataType: aws.ToString(column.Type), Ordinal: int32(i + 1), Nullable: true,
				})
			}
		}
	}
	return columns, skipped, nil
}

func logSkippedRelations(logger *slog.Logger, level slog.Level, skipped []skippedRelation) {
	if len(skipped) == 0 {
		return
	}
	types := make(map[string]int)
	sample := make([]string, 0, min(len(skipped), skippedSampleSize))
	for _, relation := range skipped {
		kind := relation.kind
		if kind == "" {
			kind = "(none)"
		}
		types[kind]++
		if len(sample) < skippedSampleSize {
			sample = append(sample, relation.schema+"."+relation.table)
		}
	}
	logger.Log(context.Background(), level, "athena: catalog skipped relations that are not tables; statements naming them are denied",
		"count", len(skipped), "types", types, "sample", sample)
}

func unprovedRelations(catalog string, skipped []skippedRelation) []*enginepb.ObjectRef {
	relations := make([]*enginepb.ObjectRef, 0, len(skipped))
	for _, relation := range skipped {
		relations = append(relations, &enginepb.ObjectRef{Catalog: catalog, Schema: relation.schema, Table: relation.table})
	}
	return relations
}

func unprovedTables(skipped []skippedRelation) []string {
	tables := make([]string, 0, len(skipped))
	for _, relation := range skipped {
		tables = append(tables, relation.table)
	}
	return tables
}

func metadataColumns(table types.TableMetadata) ([]types.Column, error) {
	columns := append(append([]types.Column(nil), table.Columns...), table.PartitionKeys...)
	seen := make(map[string]bool, len(columns))
	for _, column := range columns {
		name := aws.ToString(column.Name)
		if name == "" || aws.ToString(column.Type) == "" || seen[name] {
			return nil, fmt.Errorf("athena: missing or duplicate column metadata for table %q", aws.ToString(table.Name))
		}
		seen[name] = true
	}
	return columns, nil
}

func (t *target) ReadTableDetail(ctx context.Context, table *enginepb.ObjectRef) (*spi.TableDetail, error) {
	if table == nil || table.Table == "" || table.Schema == "" {
		return nil, errors.New("athena: table selector is incomplete")
	}
	catalog := table.Catalog
	if catalog == "" || strings.EqualFold(catalog, t.config.catalog) {
		catalog = t.config.catalog
	}
	response, err := t.api.GetTableMetadata(ctx, &awsa.GetTableMetadataInput{
		CatalogName: aws.String(catalog), DatabaseName: aws.String(table.Schema), TableName: aws.String(table.Table), WorkGroup: aws.String(t.config.workgroup),
	})
	if err != nil {
		return nil, err
	}
	if response.TableMetadata == nil || aws.ToString(response.TableMetadata.Name) != table.Table {
		return nil, errors.New("athena: table metadata does not match requested table")
	}
	columns, err := metadataColumns(*response.TableMetadata)
	if err != nil {
		return nil, err
	}
	detail := &spi.TableDetail{
		Catalog: strings.ToLower(catalog), Schema: table.Schema, Table: table.Table,
		Columns: []spi.TableDetailColumn{}, Indexes: []spi.TableIndex{}, ForeignKeys: []spi.TableRelation{}, ReferencedBy: []spi.TableRelation{},
		Metadata: spi.TableMetadata{Engine: "athena"},
	}
	if comment, ok := response.TableMetadata.Parameters["comment"]; ok {
		detail.Metadata.Comment = &comment
	}
	for i, column := range columns {
		detail.Columns = append(detail.Columns, spi.TableDetailColumn{
			Name: aws.ToString(column.Name), DataType: aws.ToString(column.Type), Ordinal: i + 1, Nullable: true, Comment: column.Comment,
		})
	}
	return detail, nil
}
