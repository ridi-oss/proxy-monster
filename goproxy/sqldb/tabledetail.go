package sqldb

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const DetailQueryTimeout = 30 * time.Second

type DetailIndexes struct {
	Indexes        []spi.TableIndex
	IndexedColumns map[string]struct{}
}

// canonicalDetailNames rewrites the detail's names to canonical spelling: MySQL reports `Email`, the catalog keys `email`.
func canonicalDetailNames(folder *engines.Session, detail *spi.TableDetail) {
	var refs []*pb.Column
	add := func(schema, table string, columns ...*string) {
		for _, c := range columns {
			refs = append(refs, &pb.Column{Schema: schema, Table: table, Column: *c})
		}
	}
	for i := range detail.Columns {
		add(detail.Schema, detail.Table, &detail.Columns[i].Name)
	}
	for i := range detail.Indexes {
		for j := range detail.Indexes[i].Columns {
			add(detail.Schema, detail.Table, &detail.Indexes[i].Columns[j].Name)
		}
	}
	relations := [][]spi.TableRelation{detail.ForeignKeys, detail.ReferencedBy}
	for _, list := range relations {
		for _, r := range list {
			var relation string
			add(r.SourceSchema, r.SourceTable, &relation)
			add(r.TargetSchema, r.TargetTable, &relation)
			for j := range r.SourceColumns {
				add(r.SourceSchema, r.SourceTable, &r.SourceColumns[j])
			}
			for j := range r.TargetColumns {
				add(r.TargetSchema, r.TargetTable, &r.TargetColumns[j])
			}
		}
	}
	folded := folder.CanonicalColumns(refs)
	next := 0
	take := func() *pb.Column { next++; return folded[next-1] }
	for i := range detail.Columns {
		detail.Columns[i].Name = take().GetColumn()
	}
	for i := range detail.Indexes {
		for j := range detail.Indexes[i].Columns {
			detail.Indexes[i].Columns[j].Name = take().GetColumn()
		}
	}
	for _, list := range relations {
		for i := range list {
			r := &list[i]
			source, target := take(), take()
			r.SourceSchema, r.SourceTable = source.GetSchema(), source.GetTable()
			r.TargetSchema, r.TargetTable = target.GetSchema(), target.GetTable()
			for j := range r.SourceColumns {
				r.SourceColumns[j] = take().GetColumn()
			}
			for j := range r.TargetColumns {
				r.TargetColumns[j] = take().GetColumn()
			}
		}
	}
}

func tableDetailTableExists(conn *sql.Conn, folder *engines.Session, schema, table string) (bool, error) {
	query := fmt.Sprintf(
		"SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema = %s AND table_name = %s",
		folder.Engine().Placeholder(1), folder.Engine().Placeholder(2),
	)
	found := false
	err := DetailQuery(conn, query, []any{schema, table}, func(rows *sql.Rows) error {
		for rows.Next() {
			var rowSchema, rowTable string
			if err := rows.Scan(&rowSchema, &rowTable); err != nil {
				return err
			}
			canonical := folder.CanonicalColumns([]*pb.Column{{Schema: rowSchema, Table: rowTable}})[0]
			if canonical.GetSchema() == schema && canonical.GetTable() == table {
				found = true
			}
		}
		return nil
	})
	return found, err
}

type IndexAccumulator struct {
	Name     string
	Columns  []spi.TableIndexColumn
	Unique   bool
	TypeName string
}

type RelationIdentity struct {
	Name         string
	SourceSchema string
	SourceTable  string
	TargetSchema string
	TargetTable  string
}

type RelationAccumulator struct {
	Identity      RelationIdentity
	SourceColumns []string
	TargetColumns []string
	OnUpdate      *string
	OnDelete      *string
}

func DetailQuery(conn *sql.Conn, query string, args []any, consume func(*sql.Rows) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), DetailQueryTimeout)
	defer cancel()
	statement, err := conn.PrepareContext(ctx, query)
	if err != nil {
		return err
	}
	defer statement.Close()
	rows, err := statement.QueryContext(ctx, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	if err := consume(rows); err != nil {
		return err
	}
	return rows.Err()
}

func StringPtr(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	result := value.String
	return &result
}

func Int64Ptr(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	result := value.Int64
	return &result
}

func IntPtr(value sql.NullInt64) *int {
	if !value.Valid {
		return nil
	}
	result := int(value.Int64)
	return &result
}

func EqualStringPtr(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func Relation(relation *RelationAccumulator) spi.TableRelation {
	return spi.TableRelation{
		Name:          relation.Identity.Name,
		SourceSchema:  relation.Identity.SourceSchema,
		SourceTable:   relation.Identity.SourceTable,
		SourceColumns: relation.SourceColumns,
		TargetSchema:  relation.Identity.TargetSchema,
		TargetTable:   relation.Identity.TargetTable,
		TargetColumns: relation.TargetColumns,
		OnUpdate:      relation.OnUpdate,
		OnDelete:      relation.OnDelete,
	}
}
