package athena

import (
	"context"
	"errors"
	"fmt"
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

func (t *target) ReadCatalog(ctx context.Context) (*pb.CatalogRequest, error) {
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
	for _, database := range databases {
		fragment, err := t.readColumns(ctx, t.config.catalog, database)
		if err != nil {
			return nil, err
		}
		columns = append(columns, fragment...)
	}
	return &pb.CatalogRequest{
		CurrentCatalog: aws.String(t.catalogIdentity()), DefaultSchemas: []string{t.config.database},
		Catalog: &enginepb.CatalogSnapshot{Columns: columns}, EngineVersion: version,
	}, nil
}

func (t *target) readColumns(ctx context.Context, catalog, database string) ([]*enginepb.Column, error) {
	if catalog == "" || database == "" {
		return nil, errors.New("athena: namespace is incomplete")
	}
	pages := awsa.NewListTableMetadataPaginator(t.api, &awsa.ListTableMetadataInput{
		CatalogName: aws.String(catalog), DatabaseName: aws.String(database), WorkGroup: aws.String(t.config.workgroup),
	})
	var columns []*enginepb.Column
	seen := make(map[string]bool)
	tokens := make(map[string]bool)
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if err := checkMetadataToken(page.NextToken, tokens); err != nil {
			return nil, err
		}
		for _, table := range page.TableMetadataList {
			name := aws.ToString(table.Name)
			if name == "" || seen[name] {
				return nil, errors.New("athena: missing or duplicate table metadata")
			}
			seen[name] = true
			if kind := aws.ToString(table.TableType); kind != "EXTERNAL_TABLE" && kind != "MANAGED_TABLE" {
				return nil, fmt.Errorf("athena: catalog cannot represent unproved relation %q of type %q", name, kind)
			}
			tableColumns, err := metadataColumns(table)
			if err != nil {
				return nil, err
			}
			for i, column := range tableColumns {
				columns = append(columns, &enginepb.Column{
					Catalog: strings.ToLower(catalog), Schema: database, Table: name,
					Column: aws.ToString(column.Name), DataType: aws.ToString(column.Type), Ordinal: int32(i + 1), Nullable: true,
				})
			}
		}
	}
	return columns, nil
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

func (t *target) ReadTableDetail(ctx context.Context, table *enginepb.TableRef) (*spi.TableDetail, error) {
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
		Catalog: aws.String(strings.ToLower(catalog)), Schema: table.Schema, Table: table.Table,
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
