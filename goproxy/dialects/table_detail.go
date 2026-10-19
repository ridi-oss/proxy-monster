package dialects

import (
	"database/sql"
	"fmt"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"
)

func tableDetailTableExists(conn *sql.Conn, e *engines.Engine, schema, table string) (bool, error) {
	query := fmt.Sprintf(
		"SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema = %s AND table_name = %s",
		e.Placeholder(1), e.Placeholder(2),
	)
	found := false
	err := sqldb.DetailQuery(conn, query, []any{schema, table}, func(rows *sql.Rows) error {
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
