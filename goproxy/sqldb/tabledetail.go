package sqldb

import (
	"context"
	"database/sql"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const DetailQueryTimeout = 30 * time.Second

type DetailIndexes struct {
	Indexes        []spi.TableIndex
	IndexedColumns map[string]struct{}
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
