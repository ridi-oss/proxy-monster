package athena

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsa "github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/athena/types"
	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// introspected is one Athena API row as the analyzer keys it.
func introspected(catalog, database, table, column string) engines.ColumnName {
	return engines.Athena.IntrospectedColumns(engines.CaseMode{}, []*enginepb.Column{{Catalog: catalog, Schema: database, Table: table, Column: column}})[0]
}

func canonicalSchema(database string) string {
	return engines.Athena.IntrospectedSchema(engines.CaseMode{}, &enginepb.Column{Schema: database}).String()
}

// catalogIdentity is the catalog name the control plane and analyzer key on.
func (t *target) catalogIdentity() string {
	return engines.Athena.CatalogName(t.config.catalog).String()
}

// databaseIdentity is the configured database as the control plane and analyzer key on it.
func (t *target) databaseIdentity() string { return canonicalSchema(t.config.database) }

// ReadCatalog scans every database of the configured catalog through Glue table metadata. A relation the
// catalog cannot prove (a view, an unknown table type) fails the scan rather than being flattened or dropped.
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
	for _, database := range databases {
		fragment, err := t.readColumns(ctx, t.config.catalog, database)
		if err != nil {
			return nil, err
		}
		columns = append(columns, fragment...)
	}
	return &pb.CatalogRequest{
		CurrentCatalog: t.catalogIdentity(), DefaultSchemas: []string{t.databaseIdentity()},
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
			name := introspected("", "", aws.ToString(table.Name), "").Table()
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
				n := introspected(catalog, database, aws.ToString(table.Name), aws.ToString(column.Name))
				columns = append(columns, &enginepb.Column{
					Catalog: n.Catalog().String(), Schema: n.Schema().String(), Table: n.Table(),
					Column: n.Column(), DataType: aws.ToString(column.Type), Ordinal: int32(i + 1), Nullable: true,
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
		name := introspected("", "", "", aws.ToString(column.Name)).Column()
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
	if catalog == "" || catalog == t.catalogIdentity() {
		catalog = t.config.catalog
	}
	response, err := t.api.GetTableMetadata(ctx, &awsa.GetTableMetadataInput{
		CatalogName: aws.String(catalog), DatabaseName: aws.String(table.Schema), TableName: aws.String(table.Table), WorkGroup: aws.String(t.config.workgroup),
	})
	if err != nil {
		return nil, err
	}
	if response.TableMetadata == nil || introspected("", "", aws.ToString(response.TableMetadata.Name), "").Table() != table.Table {
		return nil, errors.New("athena: table metadata does not match requested table")
	}
	columns, err := metadataColumns(*response.TableMetadata)
	if err != nil {
		return nil, err
	}
	detail := &spi.TableDetail{
		Catalog: engines.Athena.CatalogName(catalog).String(), Schema: canonicalSchema(table.Schema), Table: table.Table,
		Columns: []spi.TableDetailColumn{}, Indexes: []spi.TableIndex{}, ForeignKeys: []spi.TableRelation{}, ReferencedBy: []spi.TableRelation{},
		Metadata: spi.TableMetadata{Engine: "athena"},
	}
	if comment, ok := response.TableMetadata.Parameters["comment"]; ok {
		detail.Metadata.Comment = &comment
	}
	for i, column := range columns {
		detail.Columns = append(detail.Columns, spi.TableDetailColumn{
			Name: introspected("", "", "", aws.ToString(column.Name)).Column(), DataType: aws.ToString(column.Type), Ordinal: i + 1, Nullable: true, Comment: column.Comment,
		})
	}
	return detail, nil
}
