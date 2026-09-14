package dialects

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const tableDetailQueryTimeout = 30 * time.Second

type tableDetailIndexes struct {
	indexes        []spi.TableIndex
	indexedColumns map[string]struct{}
}

func tableDetailTableExists(ctx context.Context, conn *sql.Conn, dialect engine.Dialect, schema, table string) (bool, error) {
	query := fmt.Sprintf(
		"SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema = %s AND table_name = %s",
		dialect.Placeholder(1), dialect.Placeholder(2),
	)
	found := false
	err := tableDetailQuery(ctx, conn, query, []any{schema, table}, func(rows *sql.Rows) error {
		for rows.Next() {
			var rowSchema, rowTable string
			if err := rows.Scan(&rowSchema, &rowTable); err != nil {
				return err
			}
			if rowSchema == schema && rowTable == table {
				found = true
			}
		}
		return nil
	})
	return found, err
}

func readMySQLTableDetail(ctx context.Context, conn *sql.Conn, schema, table string) (*spi.TableDetail, error) {
	indexes, err := readMySQLIndexes(ctx, conn, schema, table)
	if err != nil {
		return nil, err
	}
	columns, err := readMySQLColumns(ctx, conn, schema, table, indexes.indexedColumns)
	if err != nil {
		return nil, err
	}
	foreignKeys, err := readMySQLRelations(ctx, conn, schema, table, false)
	if err != nil {
		return nil, err
	}
	referencedBy, err := readMySQLRelations(ctx, conn, schema, table, true)
	if err != nil {
		return nil, err
	}
	metadata, err := readMySQLMetadata(ctx, conn, schema, table)
	if err != nil {
		return nil, err
	}
	return &spi.TableDetail{
		Schema:       schema,
		Table:        table,
		Columns:      columns,
		Indexes:      indexes.indexes,
		ForeignKeys:  foreignKeys,
		ReferencedBy: referencedBy,
		Metadata:     metadata,
	}, nil
}

func readMySQLColumns(ctx context.Context, conn *sql.Conn, schema, table string, indexedColumns map[string]struct{}) ([]spi.TableDetailColumn, error) {
	const query = `SELECT column_name, data_type, ordinal_position, is_nullable, column_default,
                  character_maximum_length, numeric_precision, numeric_scale, extra, column_comment,
                  character_set_name, collation_name
           FROM information_schema.columns
           WHERE table_schema = ? AND table_name = ?
           ORDER BY ordinal_position`
	columns := make([]spi.TableDetailColumn, 0)
	err := tableDetailQuery(ctx, conn, query, []any{schema, table}, func(rows *sql.Rows) error {
		for rows.Next() {
			var name, dataType, nullable string
			var ordinal int
			var defaultValue, extra, comment, charset, collation sql.NullString
			var characterMaximumLength, numericPrecision, numericScale sql.NullInt64
			if err := rows.Scan(
				&name,
				&dataType,
				&ordinal,
				&nullable,
				&defaultValue,
				&characterMaximumLength,
				&numericPrecision,
				&numericScale,
				&extra,
				&comment,
				&charset,
				&collation,
			); err != nil {
				return err
			}
			_, partOfIndex := indexedColumns[name]
			columns = append(columns, spi.TableDetailColumn{
				Name:                   name,
				DataType:               dataType,
				Ordinal:                ordinal,
				Nullable:               nullable == "YES",
				DefaultValue:           tableDetailStringPtr(defaultValue),
				CharacterMaximumLength: tableDetailInt64Ptr(characterMaximumLength),
				NumericPrecision:       tableDetailIntPtr(numericPrecision),
				NumericScale:           tableDetailIntPtr(numericScale),
				PartOfIndex:            partOfIndex,
				AutoIncrement:          extra.Valid && strings.Contains(strings.ToLower(extra.String), "auto_increment"),
				Comment:                tableDetailStringPtr(comment),
				Charset:                tableDetailStringPtr(charset),
				Collation:              tableDetailStringPtr(collation),
				Classification:         nil,
			})
		}
		return nil
	})
	return columns, err
}

type tableDetailIndexAccumulator struct {
	name     string
	columns  []spi.TableIndexColumn
	unique   bool
	typeName string
}

func readMySQLIndexes(ctx context.Context, conn *sql.Conn, schema, table string) (tableDetailIndexes, error) {
	indexedColumns := make(map[string]struct{})
	const indexedColumnsQuery = `SELECT column_name, seq_in_index
               FROM information_schema.statistics
               WHERE table_schema = ? AND table_name = ?
               ORDER BY index_name, seq_in_index`
	if err := tableDetailQuery(ctx, conn, indexedColumnsQuery, []any{schema, table}, func(rows *sql.Rows) error {
		for rows.Next() {
			var columnName sql.NullString
			var sequence int
			if err := rows.Scan(&columnName, &sequence); err != nil {
				return err
			}
			if columnName.Valid {
				indexedColumns[columnName.String] = struct{}{}
			}
		}
		return nil
	}); err != nil {
		return tableDetailIndexes{}, err
	}

	query := "SHOW INDEX FROM " + mysqlIdentifier(table) + " FROM " + mysqlIdentifier(schema)
	grouped := make(map[string]*tableDetailIndexAccumulator)
	order := make([]string, 0)
	if err := tableDetailQueryMaps(ctx, conn, query, nil, func(row map[string]*string) error {
		name, ok := tableDetailMapString(row, "key_name")
		if !ok {
			return fmt.Errorf("index has no name metadata")
		}
		nonUnique, err := tableDetailMapInt64(row, "non_unique")
		if err != nil {
			return err
		}
		typeName, ok := tableDetailMapString(row, "index_type")
		if !ok {
			return fmt.Errorf("index %s has no type metadata", name)
		}
		position, err := tableDetailMapInt64(row, "seq_in_index")
		if err != nil {
			return err
		}
		unique := nonUnique == 0
		accumulator := grouped[name]
		if accumulator == nil {
			accumulator = &tableDetailIndexAccumulator{
				name:     name,
				columns:  make([]spi.TableIndexColumn, 0),
				unique:   unique,
				typeName: typeName,
			}
			grouped[name] = accumulator
			order = append(order, name)
		}
		if accumulator.unique != unique || accumulator.typeName != typeName {
			return fmt.Errorf("inconsistent index metadata for %s", name)
		}
		columnName, ok := tableDetailMapString(row, "column_name")
		if !ok {
			columnName, ok = tableDetailMapString(row, "expression")
		}
		if !ok {
			return fmt.Errorf("index %s has no column or expression metadata", name)
		}
		accumulator.columns = append(accumulator.columns, spi.TableIndexColumn{
			Name:      columnName,
			Position:  int(position),
			Direction: mysqlIndexDirection(tableDetailMapStringPtr(row, "collation")),
		})
		return nil
	}); err != nil {
		return tableDetailIndexes{}, err
	}

	indexes := make([]spi.TableIndex, 0, len(order))
	for _, name := range order {
		accumulator := grouped[name]
		sort.SliceStable(accumulator.columns, func(i, j int) bool {
			return accumulator.columns[i].Position < accumulator.columns[j].Position
		})
		indexes = append(indexes, spi.TableIndex{
			Name:    accumulator.name,
			Columns: accumulator.columns,
			Unique:  accumulator.unique,
			Type:    accumulator.typeName,
		})
	}
	return tableDetailIndexes{indexes: indexes, indexedColumns: indexedColumns}, nil
}

type tableDetailRelationIdentity struct {
	name         string
	sourceSchema string
	sourceTable  string
	targetSchema string
	targetTable  string
}

type tableDetailRelationAccumulator struct {
	identity      tableDetailRelationIdentity
	sourceColumns []string
	targetColumns []string
	onUpdate      *string
	onDelete      *string
}

func readMySQLRelations(ctx context.Context, conn *sql.Conn, schema, table string, incoming bool) ([]spi.TableRelation, error) {
	directionPredicate := "kcu.table_schema = ? AND kcu.table_name = ? AND kcu.referenced_table_schema = ?"
	if incoming {
		directionPredicate = "kcu.referenced_table_schema = ? AND kcu.referenced_table_name = ? AND kcu.table_schema = ?"
	}
	query := `SELECT kcu.constraint_name, kcu.table_schema AS source_schema,
                      kcu.table_name AS source_table, kcu.column_name AS source_column,
                      kcu.referenced_table_schema AS target_schema,
                      kcu.referenced_table_name AS target_table,
                      kcu.referenced_column_name AS target_column,
                      rc.update_rule, rc.delete_rule, kcu.ordinal_position
               FROM information_schema.key_column_usage kcu
               JOIN information_schema.referential_constraints rc
                 ON rc.constraint_schema = kcu.constraint_schema
                AND rc.constraint_name = kcu.constraint_name
                AND rc.table_name = kcu.table_name
               WHERE kcu.referenced_table_name IS NOT NULL AND ` + directionPredicate + `
               ORDER BY kcu.constraint_schema, kcu.table_name, kcu.constraint_name, kcu.ordinal_position`

	grouped := make(map[tableDetailRelationIdentity]*tableDetailRelationAccumulator)
	order := make([]tableDetailRelationIdentity, 0)
	err := tableDetailQuery(ctx, conn, query, []any{schema, table, schema}, func(rows *sql.Rows) error {
		for rows.Next() {
			var identity tableDetailRelationIdentity
			var sourceColumn, targetColumn string
			var onUpdate, onDelete sql.NullString
			var ordinal int
			if err := rows.Scan(
				&identity.name,
				&identity.sourceSchema,
				&identity.sourceTable,
				&sourceColumn,
				&identity.targetSchema,
				&identity.targetTable,
				&targetColumn,
				&onUpdate,
				&onDelete,
				&ordinal,
			); err != nil {
				return err
			}
			updatePtr := tableDetailStringPtr(onUpdate)
			deletePtr := tableDetailStringPtr(onDelete)
			relation := grouped[identity]
			if relation == nil {
				relation = &tableDetailRelationAccumulator{
					identity:      identity,
					sourceColumns: make([]string, 0),
					targetColumns: make([]string, 0),
					onUpdate:      updatePtr,
					onDelete:      deletePtr,
				}
				grouped[identity] = relation
				order = append(order, identity)
			}
			if !tableDetailEqualStringPtr(relation.onUpdate, updatePtr) || !tableDetailEqualStringPtr(relation.onDelete, deletePtr) {
				return fmt.Errorf("inconsistent foreign-key metadata for %s", identity.name)
			}
			relation.sourceColumns = append(relation.sourceColumns, sourceColumn)
			relation.targetColumns = append(relation.targetColumns, targetColumn)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return tableDetailRelations(grouped, order), nil
}

func readMySQLMetadata(ctx context.Context, conn *sql.Conn, schema, table string) (spi.TableMetadata, error) {
	query := "SHOW TABLE STATUS FROM " + mysqlIdentifier(schema) + " WHERE Name = ?"
	var metadata *spi.TableMetadata
	err := tableDetailQueryMaps(ctx, conn, query, []any{table}, func(row map[string]*string) error {
		name, ok := tableDetailMapString(row, "name")
		if !ok || name != table {
			return nil
		}
		dataLength, err := tableDetailMapOptionalInt64(row, "data_length")
		if err != nil {
			return err
		}
		indexLength, err := tableDetailMapOptionalInt64(row, "index_length")
		if err != nil {
			return err
		}
		var onDiskBytes *int64
		if dataLength != nil || indexLength != nil {
			var data, index int64
			if dataLength != nil {
				data = *dataLength
			}
			if indexLength != nil {
				index = *indexLength
			}
			if (index > 0 && data > math.MaxInt64-index) || (index < 0 && data < math.MinInt64-index) {
				return fmt.Errorf("table size overflow")
			}
			total := data + index
			onDiskBytes = &total
		}
		engineName, ok := tableDetailMapString(row, "engine")
		if !ok {
			engineName = "MySQL"
		}
		estimatedRows, err := tableDetailMapOptionalInt64(row, "rows")
		if err != nil {
			return err
		}
		metadata = &spi.TableMetadata{
			Engine:        engineName,
			EstimatedRows: estimatedRows,
			RowFormat:     tableDetailMapStringPtr(row, "row_format"),
			OnDiskBytes:   onDiskBytes,
			Collation:     tableDetailMapStringPtr(row, "collation"),
			Comment:       tableDetailMapStringPtr(row, "comment"),
		}
		return nil
	})
	if err != nil {
		return spi.TableMetadata{}, err
	}
	if metadata == nil {
		return spi.TableMetadata{}, fmt.Errorf("validated table disappeared while reading table status")
	}
	return *metadata, nil
}

func readPostgresTableDetail(ctx context.Context, conn *sql.Conn, schema, table string) (*spi.TableDetail, error) {
	indexes, err := readPostgresIndexes(ctx, conn, schema, table)
	if err != nil {
		return nil, err
	}
	columns, err := readPostgresColumns(ctx, conn, schema, table, indexes.indexedColumns)
	if err != nil {
		return nil, err
	}
	foreignKeys, err := readPostgresRelations(ctx, conn, schema, table, false)
	if err != nil {
		return nil, err
	}
	referencedBy, err := readPostgresRelations(ctx, conn, schema, table, true)
	if err != nil {
		return nil, err
	}
	metadata, err := readPostgresMetadata(ctx, conn, schema, table)
	if err != nil {
		return nil, err
	}
	return &spi.TableDetail{
		Schema:       schema,
		Table:        table,
		Columns:      columns,
		Indexes:      indexes.indexes,
		ForeignKeys:  foreignKeys,
		ReferencedBy: referencedBy,
		Metadata:     metadata,
	}, nil
}

func readPostgresColumns(ctx context.Context, conn *sql.Conn, schema, table string, indexedColumns map[string]struct{}) ([]spi.TableDetailColumn, error) {
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
	err := tableDetailQuery(ctx, conn, query, []any{schema, table}, func(rows *sql.Rows) error {
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
				DefaultValue:           tableDetailStringPtr(defaultValue),
				CharacterMaximumLength: tableDetailInt64Ptr(characterMaximumLength),
				NumericPrecision:       tableDetailIntPtr(numericPrecision),
				NumericScale:           tableDetailIntPtr(numericScale),
				PartOfIndex:            partOfIndex,
				AutoIncrement:          autoIncrement.Valid && autoIncrement.Bool,
				Comment:                tableDetailStringPtr(comment),
				Charset:                tableDetailStringPtr(charset),
				Collation:              tableDetailStringPtr(collation),
				Classification:         nil,
			})
		}
		return nil
	})
	return columns, err
}

func readPostgresIndexes(ctx context.Context, conn *sql.Conn, schema, table string) (tableDetailIndexes, error) {
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
	if err := tableDetailQuery(ctx, conn, indexedColumnsQuery, []any{schema, table}, func(rows *sql.Rows) error {
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				return err
			}
			indexedColumns[name] = struct{}{}
		}
		return nil
	}); err != nil {
		return tableDetailIndexes{}, err
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
	grouped := make(map[string]*tableDetailIndexAccumulator)
	order := make([]string, 0)
	if err := tableDetailQuery(ctx, conn, indexesQuery, []any{schema, table}, func(rows *sql.Rows) error {
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
				accumulator = &tableDetailIndexAccumulator{
					name:     name,
					columns:  make([]spi.TableIndexColumn, 0),
					unique:   unique,
					typeName: typeName,
				}
				grouped[name] = accumulator
				order = append(order, name)
			}
			if accumulator.unique != unique || accumulator.typeName != typeName {
				return fmt.Errorf("inconsistent index metadata for %s", name)
			}
			accumulator.columns = append(accumulator.columns, spi.TableIndexColumn{
				Name:      columnName,
				Position:  position,
				Direction: tableDetailStringPtr(direction),
			})
		}
		return nil
	}); err != nil {
		return tableDetailIndexes{}, err
	}

	indexes := make([]spi.TableIndex, 0, len(order))
	for _, name := range order {
		accumulator := grouped[name]
		sort.SliceStable(accumulator.columns, func(i, j int) bool {
			return accumulator.columns[i].Position < accumulator.columns[j].Position
		})
		indexes = append(indexes, spi.TableIndex{
			Name:    accumulator.name,
			Columns: accumulator.columns,
			Unique:  accumulator.unique,
			Type:    accumulator.typeName,
		})
	}
	return tableDetailIndexes{indexes: indexes, indexedColumns: indexedColumns}, nil
}

func readPostgresRelations(ctx context.Context, conn *sql.Conn, schema, table string, incoming bool) ([]spi.TableRelation, error) {
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

	grouped := make(map[int64]*tableDetailRelationAccumulator)
	order := make([]int64, 0)
	err := tableDetailQuery(ctx, conn, query, []any{schema, table}, func(rows *sql.Rows) error {
		for rows.Next() {
			var oid int64
			var identity tableDetailRelationIdentity
			var sourceColumn, targetColumn string
			var updateAction, deleteAction sql.NullString
			var position int
			if err := rows.Scan(
				&oid,
				&identity.name,
				&identity.sourceSchema,
				&identity.sourceTable,
				&sourceColumn,
				&identity.targetSchema,
				&identity.targetTable,
				&targetColumn,
				&updateAction,
				&deleteAction,
				&position,
			); err != nil {
				return err
			}
			onUpdate, err := postgresReferentialAction(tableDetailStringPtr(updateAction))
			if err != nil {
				return err
			}
			onDelete, err := postgresReferentialAction(tableDetailStringPtr(deleteAction))
			if err != nil {
				return err
			}
			relation := grouped[oid]
			if relation == nil {
				relation = &tableDetailRelationAccumulator{
					identity:      identity,
					sourceColumns: make([]string, 0),
					targetColumns: make([]string, 0),
					onUpdate:      onUpdate,
					onDelete:      onDelete,
				}
				grouped[oid] = relation
				order = append(order, oid)
			}
			if relation.identity != identity || !tableDetailEqualStringPtr(relation.onUpdate, onUpdate) || !tableDetailEqualStringPtr(relation.onDelete, onDelete) {
				return fmt.Errorf("inconsistent foreign-key metadata for %s", identity.name)
			}
			relation.sourceColumns = append(relation.sourceColumns, sourceColumn)
			relation.targetColumns = append(relation.targetColumns, targetColumn)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	relations := make([]spi.TableRelation, 0, len(order))
	for _, oid := range order {
		relations = append(relations, tableDetailRelation(grouped[oid]))
	}
	return relations, nil
}

func readPostgresMetadata(ctx context.Context, conn *sql.Conn, schema, table string) (spi.TableMetadata, error) {
	const query = `SELECT CASE WHEN table_class.reltuples < 0 THEN NULL
                           ELSE table_class.reltuples::bigint END AS estimated_rows,
                      pg_total_relation_size(table_class.oid) AS on_disk_bytes,
                      obj_description(table_class.oid, 'pg_class') AS table_comment
               FROM pg_namespace namespace
               JOIN pg_class table_class ON table_class.relnamespace = namespace.oid
               WHERE namespace.nspname = $1 AND table_class.relname = $2`
	var metadata *spi.TableMetadata
	err := tableDetailQuery(ctx, conn, query, []any{schema, table}, func(rows *sql.Rows) error {
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
			EstimatedRows: tableDetailInt64Ptr(estimatedRows),
			RowFormat:     nil,
			OnDiskBytes:   tableDetailInt64Ptr(onDiskBytes),
			Collation:     nil,
			Comment:       tableDetailStringPtr(comment),
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

func tableDetailQuery(ctx context.Context, conn *sql.Conn, query string, args []any, consume func(*sql.Rows) error) error {
	ctx, cancel := context.WithTimeout(ctx, tableDetailQueryTimeout)
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

func tableDetailQueryMaps(ctx context.Context, conn *sql.Conn, query string, args []any, consume func(map[string]*string) error) error {
	return tableDetailQuery(ctx, conn, query, args, func(rows *sql.Rows) error {
		columns, err := rows.Columns()
		if err != nil {
			return err
		}
		for rows.Next() {
			values := make([]sql.RawBytes, len(columns))
			destinations := make([]any, len(columns))
			for i := range values {
				destinations[i] = &values[i]
			}
			if err := rows.Scan(destinations...); err != nil {
				return err
			}
			row := make(map[string]*string, len(columns))
			for i, column := range columns {
				if values[i] == nil {
					row[strings.ToLower(column)] = nil
					continue
				}
				value := string(values[i])
				row[strings.ToLower(column)] = &value
			}
			if err := consume(row); err != nil {
				return err
			}
		}
		return nil
	})
}

func tableDetailStringPtr(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	result := value.String
	return &result
}

func tableDetailInt64Ptr(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	result := value.Int64
	return &result
}

func tableDetailIntPtr(value sql.NullInt64) *int {
	if !value.Valid {
		return nil
	}
	result := int(value.Int64)
	return &result
}

func tableDetailMapString(row map[string]*string, key string) (string, bool) {
	value, ok := row[strings.ToLower(key)]
	if !ok || value == nil {
		return "", false
	}
	return *value, true
}

func tableDetailMapStringPtr(row map[string]*string, key string) *string {
	value, ok := tableDetailMapString(row, key)
	if !ok {
		return nil
	}
	return &value
}

func tableDetailMapInt64(row map[string]*string, key string) (int64, error) {
	value, ok := tableDetailMapString(row, key)
	if !ok {
		return 0, fmt.Errorf("missing %s metadata", key)
	}
	result, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s metadata %q: %w", key, value, err)
	}
	return result, nil
}

func tableDetailMapOptionalInt64(row map[string]*string, key string) (*int64, error) {
	value, ok := tableDetailMapString(row, key)
	if !ok {
		return nil, nil
	}
	result, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid %s metadata %q: %w", key, value, err)
	}
	return &result, nil
}

func tableDetailEqualStringPtr(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func mysqlIdentifier(value string) string {
	return "`" + strings.ReplaceAll(value, "`", "``") + "`"
}

func mysqlIndexDirection(value *string) *string {
	if value == nil {
		return nil
	}
	var direction string
	switch *value {
	case "A":
		direction = "ASC"
	case "D":
		direction = "DESC"
	default:
		return nil
	}
	return &direction
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

func tableDetailRelations(grouped map[tableDetailRelationIdentity]*tableDetailRelationAccumulator, order []tableDetailRelationIdentity) []spi.TableRelation {
	relations := make([]spi.TableRelation, 0, len(order))
	for _, identity := range order {
		relations = append(relations, tableDetailRelation(grouped[identity]))
	}
	return relations
}

func tableDetailRelation(relation *tableDetailRelationAccumulator) spi.TableRelation {
	return spi.TableRelation{
		Name:          relation.identity.name,
		SourceSchema:  relation.identity.sourceSchema,
		SourceTable:   relation.identity.sourceTable,
		SourceColumns: relation.sourceColumns,
		TargetSchema:  relation.identity.targetSchema,
		TargetTable:   relation.identity.targetTable,
		TargetColumns: relation.targetColumns,
		OnUpdate:      relation.onUpdate,
		OnDelete:      relation.onDelete,
	}
}
