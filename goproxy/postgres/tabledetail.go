package postgres

import (
	"database/sql"
	"fmt"
	"sort"

	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"
)

func readPostgresTableDetail(conn *sql.Conn, schema, table string) (*spi.TableDetail, error) {
	indexes, err := readPostgresIndexes(conn, schema, table)
	if err != nil {
		return nil, err
	}
	columns, err := readPostgresColumns(conn, schema, table, indexes.IndexedColumns)
	if err != nil {
		return nil, err
	}
	foreignKeys, err := readPostgresRelations(conn, schema, table, false)
	if err != nil {
		return nil, err
	}
	referencedBy, err := readPostgresRelations(conn, schema, table, true)
	if err != nil {
		return nil, err
	}
	metadata, err := readPostgresMetadata(conn, schema, table)
	if err != nil {
		return nil, err
	}
	return &spi.TableDetail{
		Schema:       schema,
		Table:        table,
		Columns:      columns,
		Indexes:      indexes.Indexes,
		ForeignKeys:  foreignKeys,
		ReferencedBy: referencedBy,
		Metadata:     metadata,
	}, nil
}

func readPostgresColumns(conn *sql.Conn, schema, table string, indexedColumns map[string]struct{}) ([]spi.TableDetailColumn, error) {
	const query = `SELECT cols.column_name, cols.data_type, cols.ordinal_position, cols.is_nullable,
                  cols.column_default, cols.character_maximum_length, cols.numeric_precision,
                  cols.numeric_scale, cols.character_set_name, cols.collation_name,
                  description.description AS column_comment,
                  (cols.is_identity = 'YES' OR cols.column_default LIKE 'nextval(%') AS auto_increment
           FROM information_schema.columns cols
           JOIN pg_namespace namespace ON namespace.nspname = cols.table_schema
           JOIN pg_class table_class
             ON table_class.relnamespace = namespace.oid AND table_class.relname = cols.table_name
           JOIN pg_attribute attribute
             ON attribute.attrelid = table_class.oid AND attribute.attname = cols.column_name
            AND attribute.attnum > 0 AND NOT attribute.attisdropped
           LEFT JOIN pg_description description
             ON description.objoid = table_class.oid AND description.objsubid = attribute.attnum
           WHERE cols.table_schema = $1 AND cols.table_name = $2
           ORDER BY cols.ordinal_position`
	columns := make([]spi.TableDetailColumn, 0)
	err := sqldb.DetailQuery(conn, query, []any{schema, table}, func(rows *sql.Rows) error {
		for rows.Next() {
			var name, dataType, nullable string
			var ordinal int
			var defaultValue, charset, collation, comment sql.NullString
			var characterMaximumLength, numericPrecision, numericScale sql.NullInt64
			var autoIncrement sql.NullBool
			if err := rows.Scan(
				&name,
				&dataType,
				&ordinal,
				&nullable,
				&defaultValue,
				&characterMaximumLength,
				&numericPrecision,
				&numericScale,
				&charset,
				&collation,
				&comment,
				&autoIncrement,
			); err != nil {
				return err
			}
			_, partOfIndex := indexedColumns[name]
			columns = append(columns, spi.TableDetailColumn{
				Name:                   name,
				DataType:               dataType,
				Ordinal:                ordinal,
				Nullable:               nullable == "YES",
				DefaultValue:           sqldb.StringPtr(defaultValue),
				CharacterMaximumLength: sqldb.Int64Ptr(characterMaximumLength),
				NumericPrecision:       sqldb.IntPtr(numericPrecision),
				NumericScale:           sqldb.IntPtr(numericScale),
				PartOfIndex:            partOfIndex,
				AutoIncrement:          autoIncrement.Valid && autoIncrement.Bool,
				Comment:                sqldb.StringPtr(comment),
				Charset:                sqldb.StringPtr(charset),
				Collation:              sqldb.StringPtr(collation),
				Classification:         nil,
			})
		}
		return nil
	})
	return columns, err
}

func readPostgresIndexes(conn *sql.Conn, schema, table string) (sqldb.DetailIndexes, error) {
	const indexedColumnsQuery = `SELECT DISTINCT attribute.attname AS column_name
               FROM pg_namespace namespace
               JOIN pg_class table_class ON table_class.relnamespace = namespace.oid
               JOIN pg_index index_info ON index_info.indrelid = table_class.oid
               CROSS JOIN LATERAL generate_series(0, index_info.indnatts - 1) AS ordinal(key_offset)
               JOIN pg_attribute attribute
                 ON attribute.attrelid = table_class.oid
                AND attribute.attnum = index_info.indkey[ordinal.key_offset]
               WHERE namespace.nspname = $1 AND table_class.relname = $2
               ORDER BY attribute.attname`
	indexedColumns := make(map[string]struct{})
	if err := sqldb.DetailQuery(conn, indexedColumnsQuery, []any{schema, table}, func(rows *sql.Rows) error {
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				return err
			}
			indexedColumns[name] = struct{}{}
		}
		return nil
	}); err != nil {
		return sqldb.DetailIndexes{}, err
	}

	const indexesQuery = `SELECT index_class.relname AS index_name, index_info.indisunique,
                      access_method.amname AS index_type, ordinal.key_offset + 1 AS position,
                      pg_get_indexdef(index_info.indexrelid, ordinal.key_offset + 1, true) AS column_name,
                      CASE WHEN access_method.amname = 'btree'
                           THEN CASE WHEN (index_info.indoption[ordinal.key_offset]::integer & 1) = 1
                                     THEN 'DESC' ELSE 'ASC' END
                           ELSE NULL END AS direction
               FROM pg_namespace namespace
               JOIN pg_class table_class ON table_class.relnamespace = namespace.oid
               JOIN pg_index index_info ON index_info.indrelid = table_class.oid
               JOIN pg_class index_class ON index_class.oid = index_info.indexrelid
               JOIN pg_am access_method ON access_method.oid = index_class.relam
               CROSS JOIN LATERAL generate_series(0, index_info.indnkeyatts - 1) AS ordinal(key_offset)
               WHERE namespace.nspname = $1 AND table_class.relname = $2
               ORDER BY index_class.relname, ordinal.key_offset`
	grouped := make(map[string]*sqldb.IndexAccumulator)
	order := make([]string, 0)
	if err := sqldb.DetailQuery(conn, indexesQuery, []any{schema, table}, func(rows *sql.Rows) error {
		for rows.Next() {
			var name, typeName, columnName string
			var unique bool
			var position int
			var direction sql.NullString
			if err := rows.Scan(&name, &unique, &typeName, &position, &columnName, &direction); err != nil {
				return err
			}
			accumulator := grouped[name]
			if accumulator == nil {
				accumulator = &sqldb.IndexAccumulator{
					Name:     name,
					Columns:  make([]spi.TableIndexColumn, 0),
					Unique:   unique,
					TypeName: typeName,
				}
				grouped[name] = accumulator
				order = append(order, name)
			}
			if accumulator.Unique != unique || accumulator.TypeName != typeName {
				return fmt.Errorf("inconsistent index metadata for %s", name)
			}
			accumulator.Columns = append(accumulator.Columns, spi.TableIndexColumn{
				Name:      columnName,
				Position:  position,
				Direction: sqldb.StringPtr(direction),
			})
		}
		return nil
	}); err != nil {
		return sqldb.DetailIndexes{}, err
	}

	indexes := make([]spi.TableIndex, 0, len(order))
	for _, name := range order {
		accumulator := grouped[name]
		sort.SliceStable(accumulator.Columns, func(i, j int) bool {
			return accumulator.Columns[i].Position < accumulator.Columns[j].Position
		})
		indexes = append(indexes, spi.TableIndex{
			Name:    accumulator.Name,
			Columns: accumulator.Columns,
			Unique:  accumulator.Unique,
			Type:    accumulator.TypeName,
		})
	}
	return sqldb.DetailIndexes{Indexes: indexes, IndexedColumns: indexedColumns}, nil
}

func readPostgresRelations(conn *sql.Conn, schema, table string, incoming bool) ([]spi.TableRelation, error) {
	directionPredicate := "source_namespace.nspname = $1 AND source_table.relname = $2"
	if incoming {
		directionPredicate = "target_namespace.nspname = $1 AND target_table.relname = $2"
	}
	query := `SELECT constraint_info.oid AS constraint_oid, constraint_info.conname AS constraint_name,
                      source_namespace.nspname AS source_schema, source_table.relname AS source_table,
                      source_attribute.attname AS source_column,
                      target_namespace.nspname AS target_schema, target_table.relname AS target_table,
                      target_attribute.attname AS target_column,
                      constraint_info.confupdtype::text AS update_action,
                      constraint_info.confdeltype::text AS delete_action,
                      source_key.position
               FROM pg_constraint constraint_info
               JOIN pg_class source_table ON source_table.oid = constraint_info.conrelid
               JOIN pg_namespace source_namespace ON source_namespace.oid = source_table.relnamespace
               JOIN pg_class target_table ON target_table.oid = constraint_info.confrelid
               JOIN pg_namespace target_namespace ON target_namespace.oid = target_table.relnamespace
               CROSS JOIN LATERAL unnest(constraint_info.conkey)
                   WITH ORDINALITY AS source_key(attnum, position)
               JOIN LATERAL unnest(constraint_info.confkey)
                   WITH ORDINALITY AS target_key(attnum, position)
                 ON target_key.position = source_key.position
               JOIN pg_attribute source_attribute
                 ON source_attribute.attrelid = source_table.oid
                AND source_attribute.attnum = source_key.attnum
               JOIN pg_attribute target_attribute
                 ON target_attribute.attrelid = target_table.oid
                AND target_attribute.attnum = target_key.attnum
               WHERE constraint_info.contype = 'f' AND ` + directionPredicate + `
               ORDER BY constraint_info.oid, source_key.position`

	grouped := make(map[int64]*sqldb.RelationAccumulator)
	order := make([]int64, 0)
	err := sqldb.DetailQuery(conn, query, []any{schema, table}, func(rows *sql.Rows) error {
		for rows.Next() {
			var oid int64
			var identity sqldb.RelationIdentity
			var sourceColumn, targetColumn string
			var updateAction, deleteAction sql.NullString
			var position int
			if err := rows.Scan(
				&oid,
				&identity.Name,
				&identity.SourceSchema,
				&identity.SourceTable,
				&sourceColumn,
				&identity.TargetSchema,
				&identity.TargetTable,
				&targetColumn,
				&updateAction,
				&deleteAction,
				&position,
			); err != nil {
				return err
			}
			onUpdate, err := postgresReferentialAction(sqldb.StringPtr(updateAction))
			if err != nil {
				return err
			}
			onDelete, err := postgresReferentialAction(sqldb.StringPtr(deleteAction))
			if err != nil {
				return err
			}
			relation := grouped[oid]
			if relation == nil {
				relation = &sqldb.RelationAccumulator{
					Identity:      identity,
					SourceColumns: make([]string, 0),
					TargetColumns: make([]string, 0),
					OnUpdate:      onUpdate,
					OnDelete:      onDelete,
				}
				grouped[oid] = relation
				order = append(order, oid)
			}
			if relation.Identity != identity || !sqldb.EqualStringPtr(relation.OnUpdate, onUpdate) || !sqldb.EqualStringPtr(relation.OnDelete, onDelete) {
				return fmt.Errorf("inconsistent foreign-key metadata for %s", identity.Name)
			}
			relation.SourceColumns = append(relation.SourceColumns, sourceColumn)
			relation.TargetColumns = append(relation.TargetColumns, targetColumn)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	relations := make([]spi.TableRelation, 0, len(order))
	for _, oid := range order {
		relations = append(relations, sqldb.Relation(grouped[oid]))
	}
	return relations, nil
}

func readPostgresMetadata(conn *sql.Conn, schema, table string) (spi.TableMetadata, error) {
	const query = `SELECT CASE WHEN table_class.reltuples < 0 THEN NULL
                           ELSE table_class.reltuples::bigint END AS estimated_rows,
                      pg_total_relation_size(table_class.oid) AS on_disk_bytes,
                      obj_description(table_class.oid, 'pg_class') AS table_comment
               FROM pg_namespace namespace
               JOIN pg_class table_class ON table_class.relnamespace = namespace.oid
               WHERE namespace.nspname = $1 AND table_class.relname = $2`
	var metadata *spi.TableMetadata
	err := sqldb.DetailQuery(conn, query, []any{schema, table}, func(rows *sql.Rows) error {
		if !rows.Next() {
			return fmt.Errorf("validated table disappeared while reading table metadata")
		}
		var estimatedRows, onDiskBytes sql.NullInt64
		var comment sql.NullString
		if err := rows.Scan(&estimatedRows, &onDiskBytes, &comment); err != nil {
			return err
		}
		metadata = &spi.TableMetadata{
			Engine:        "PostgreSQL",
			EstimatedRows: sqldb.Int64Ptr(estimatedRows),
			RowFormat:     nil,
			OnDiskBytes:   sqldb.Int64Ptr(onDiskBytes),
			Collation:     nil,
			Comment:       sqldb.StringPtr(comment),
		}
		return nil
	})
	if err != nil {
		return spi.TableMetadata{}, err
	}
	if metadata == nil {
		return spi.TableMetadata{}, fmt.Errorf("validated table disappeared while reading table metadata")
	}
	return *metadata, nil
}

func postgresReferentialAction(value *string) (*string, error) {
	if value == nil {
		return nil, nil
	}
	var action string
	switch *value {
	case "a":
		action = "NO ACTION"
	case "r":
		action = "RESTRICT"
	case "c":
		action = "CASCADE"
	case "n":
		action = "SET NULL"
	case "d":
		action = "SET DEFAULT"
	default:
		return nil, fmt.Errorf("unknown PostgreSQL referential action: %s", *value)
	}
	return &action, nil
}

// ReadTableDetail reads one PostgreSQL table's detail.
func ReadTableDetail(conn *sql.Conn, schema, table string) (*spi.TableDetail, error) {
	return readPostgresTableDetail(conn, schema, table)
}
