package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	// The named import both registers the "mysql" driver and gives mysqldriver.Config for DSN-free construction.
	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"
)

// OpenPool opens a database/sql handle to a MySQL target (5s connect / 30s socket).
func OpenPool(config spi.TargetConfig) (*sql.DB, error) {
	cfg := mysqldriver.NewConfig()
	cfg.User = config.User
	cfg.Passwd = config.Password
	cfg.Net = "tcp"
	cfg.Addr = fmt.Sprintf("%s:%d", config.Host, config.Port)
	cfg.DBName = config.Db
	cfg.Timeout = sqldb.ConnectTimeout
	cfg.ReadTimeout = sqldb.QueryTimeout
	cfg.WriteTimeout = sqldb.QueryTimeout
	// go-sql-driver handles caching_sha2_password public-key retrieval natively; no
	// allowPublicKeyRetrieval equivalent is needed. zeroDateTimeBehavior/connectionTimeZone are moot
	// since every read here is a string or int (no parseTime).
	cfg.TLSConfig = "false"
	if config.TLS != nil {
		cfg.TLS = config.TLS.Clone()
	}
	// Hand the *Config straight to a connector rather than FormatDSN()->sql.Open(): FormatDSN does not
	// escape the username, so a service account like "svc:reader" would round-trip back through the DSN
	// grammar as user "svc" / password "reader:<pw>" and fail auth on every catalog refresh. The
	// connector path keeps credentials as structured fields, never serialized through DSN syntax.
	connector, err := mysqldriver.NewConnector(cfg)
	if err != nil {
		return nil, fmt.Errorf("introspect: building mysql connector: %w", err)
	}
	return sql.OpenDB(connector), nil
}

// ProbeNamespace reads the current database, checks it is the bound one, and reports lower_case_table_names.
func ProbeNamespace(ctx context.Context, conn *sql.Conn, targetDb string, session *engines.Session) (*pb.CatalogRequest, error) {
	ctx, cancel := context.WithTimeout(ctx, sqldb.QueryTimeout)
	defer cancel()

	row := conn.QueryRowContext(ctx, "SELECT DATABASE(), DATABASE() = ?", targetDb)
	var currentDb sql.NullString
	var matches sql.NullBool
	if err := row.Scan(&currentDb, &matches); err != nil {
		return nil, fmt.Errorf("introspect: MySQL namespace probe: %w", err)
	}
	if !currentDb.Valid {
		return nil, errors.New("introspect: MySQL connection has no current database")
	}
	if !matches.Valid || !matches.Bool {
		return nil, fmt.Errorf("introspect: MySQL current database %q does not match bound database %q", currentDb.String, targetDb)
	}
	return &pb.CatalogRequest{DefaultSchemas: []string{currentDb.String}, MysqlLowerCaseTableNames: session.TargetSettings().MysqlLowerCaseTableNames, CurrentCatalog: engines.MySQL.CatalogName("").String()}, nil
}
