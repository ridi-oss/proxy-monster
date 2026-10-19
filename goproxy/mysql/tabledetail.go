package mysql

import (
	"database/sql"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"
)

func readMySQLTableDetail(conn *sql.Conn, schema, table string) (*spi.TableDetail, error) {
	indexes, err := readMySQLIndexes(conn, schema, table)
	if err != nil {
		return nil, err
	}
	columns, err := readMySQLColumns(conn, schema, table, indexes.IndexedColumns)
	if err != nil {
		return nil, err
	}
	foreignKeys, err := readMySQLRelations(conn, schema, table, false)
	if err != nil {
		return nil, err
	}
	referencedBy, err := readMySQLRelations(conn, schema, table, true)
	if err != nil {
		return nil, err
	}
	metadata, err := readMySQLMetadata(conn, schema, table)
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

func readMySQLColumns(conn *sql.Conn, schema, table string, indexedColumns map[string]struct{}) ([]spi.TableDetailColumn, error) {
	const query = `SELECT column_name, data_type, ordinal_position, is_nullable, column_default,
                  character_maximum_length, numeric_precision, numeric_scale, extra, column_comment,
                  character_set_name, collation_name
           FROM information_schema.columns
           WHERE table_schema = ? AND table_name = ?
           ORDER BY ordinal_position`
	columns := make([]spi.TableDetailColumn, 0)
	err := sqldb.DetailQuery(conn, query, []any{schema, table}, func(rows *sql.Rows) error {
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
				DefaultValue:           sqldb.StringPtr(defaultValue),
				CharacterMaximumLength: sqldb.Int64Ptr(characterMaximumLength),
				NumericPrecision:       sqldb.IntPtr(numericPrecision),
				NumericScale:           sqldb.IntPtr(numericScale),
				PartOfIndex:            partOfIndex,
				AutoIncrement:          extra.Valid && strings.Contains(strings.ToLower(extra.String), "auto_increment"),
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

func readMySQLIndexes(conn *sql.Conn, schema, table string) (sqldb.DetailIndexes, error) {
	indexedColumns := make(map[string]struct{})
	const indexedColumnsQuery = `SELECT column_name, seq_in_index
               FROM information_schema.statistics
               WHERE table_schema = ? AND table_name = ?
               ORDER BY index_name, seq_in_index`
	if err := sqldb.DetailQuery(conn, indexedColumnsQuery, []any{schema, table}, func(rows *sql.Rows) error {
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
		return sqldb.DetailIndexes{}, err
	}

	query := "SHOW INDEX FROM " + mysqlIdentifier(table) + " FROM " + mysqlIdentifier(schema)
	grouped := make(map[string]*sqldb.IndexAccumulator)
	order := make([]string, 0)
	if err := tableDetailQueryMaps(conn, query, nil, func(row map[string]*string) error {
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
		columnName, ok := tableDetailMapString(row, "column_name")
		if !ok {
			columnName, ok = tableDetailMapString(row, "expression")
		}
		if !ok {
			return fmt.Errorf("index %s has no column or expression metadata", name)
		}
		accumulator.Columns = append(accumulator.Columns, spi.TableIndexColumn{
			Name:      columnName,
			Position:  int(position),
			Direction: mysqlIndexDirection(tableDetailMapStringPtr(row, "collation")),
		})
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

func readMySQLRelations(conn *sql.Conn, schema, table string, incoming bool) ([]spi.TableRelation, error) {
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

	grouped := make(map[sqldb.RelationIdentity]*sqldb.RelationAccumulator)
	order := make([]sqldb.RelationIdentity, 0)
	err := sqldb.DetailQuery(conn, query, []any{schema, table, schema}, func(rows *sql.Rows) error {
		for rows.Next() {
			var identity sqldb.RelationIdentity
			var sourceColumn, targetColumn string
			var onUpdate, onDelete sql.NullString
			var ordinal int
			if err := rows.Scan(
				&identity.Name,
				&identity.SourceSchema,
				&identity.SourceTable,
				&sourceColumn,
				&identity.TargetSchema,
				&identity.TargetTable,
				&targetColumn,
				&onUpdate,
				&onDelete,
				&ordinal,
			); err != nil {
				return err
			}
			updatePtr := sqldb.StringPtr(onUpdate)
			deletePtr := sqldb.StringPtr(onDelete)
			relation := grouped[identity]
			if relation == nil {
				relation = &sqldb.RelationAccumulator{
					Identity:      identity,
					SourceColumns: make([]string, 0),
					TargetColumns: make([]string, 0),
					OnUpdate:      updatePtr,
					OnDelete:      deletePtr,
				}
				grouped[identity] = relation
				order = append(order, identity)
			}
			if !sqldb.EqualStringPtr(relation.OnUpdate, updatePtr) || !sqldb.EqualStringPtr(relation.OnDelete, deletePtr) {
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
	return tableDetailRelations(grouped, order), nil
}

func readMySQLMetadata(conn *sql.Conn, schema, table string) (spi.TableMetadata, error) {
	query := "SHOW TABLE STATUS FROM " + mysqlIdentifier(schema) + " WHERE Name = ?"
	var metadata *spi.TableMetadata
	err := tableDetailQueryMaps(conn, query, []any{table}, func(row map[string]*string) error {
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

func tableDetailQueryMaps(conn *sql.Conn, query string, args []any, consume func(map[string]*string) error) error {
	return sqldb.DetailQuery(conn, query, args, func(rows *sql.Rows) error {
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

func tableDetailRelations(grouped map[sqldb.RelationIdentity]*sqldb.RelationAccumulator, order []sqldb.RelationIdentity) []spi.TableRelation {
	relations := make([]spi.TableRelation, 0, len(order))
	for _, identity := range order {
		relations = append(relations, sqldb.Relation(grouped[identity]))
	}
	return relations
}

// ReadTableDetail reads one MySQL table's detail.
func ReadTableDetail(conn *sql.Conn, schema, table string) (*spi.TableDetail, error) {
	return readMySQLTableDetail(conn, schema, table)
}
