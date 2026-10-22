// Package sqldb is what MySQL and PostgreSQL share through database/sql: introspection, refetch, table detail, pools.
package sqldb

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const tableDetailConnectTimeout = 5 * time.Second

// OpenPool opens a target's metadata pool and the endpoint it advertises to clients.
func OpenPool(open func(spi.TargetConfig) (*sql.DB, error), config spi.TargetConfig) (pool *sql.DB, info *pb.ConnectionInfo, err error) {
	pool, err = open(config)
	if err != nil {
		return nil, nil, err
	}
	// Metadata reads must observe the defaults a new target session would inherit.
	pool.SetMaxIdleConns(0)
	advertise, _ := os.LookupEnv("PM_ADVERTISE_ADDR")
	return pool, &pb.ConnectionInfo{Endpoint: strings.TrimSpace(advertise)}, nil
}

// ReadTableDetail reads one table's detail, names in canonical spelling, on its own pooled connection.
func ReadTableDetail(ctx context.Context, pool *sql.DB, queries Queries, catalogOf func(context.Context, *sql.Conn) (string, error),
	read func(*sql.Conn, string, string) (*spi.TableDetail, error), table *enginepb.ObjectRef) (*spi.TableDetail, error) {
	if table == nil || table.Schema == "" || table.Table == "" {
		return nil, fmt.Errorf("table selector is incomplete")
	}
	connectCtx, cancel := context.WithTimeout(ctx, tableDetailConnectTimeout+DetailQueryTimeout)
	defer cancel()
	conn, err := pool.Conn(connectCtx)
	if err != nil {
		return nil, fmt.Errorf("connecting to target: %w", err)
	}
	defer conn.Close()
	catalog, err := catalogOf(ctx, conn)
	if err != nil {
		return nil, err
	}
	if table.Catalog != catalog {
		return nil, fmt.Errorf("table catalog %q does not match target catalog %q", table.Catalog, catalog)
	}
	session, err := NewConnSession(ctx, conn, queries)
	if err != nil {
		return nil, err
	}
	schema := table.Schema
	exists, err := tableDetailTableExists(conn, session, schema, table.Table)
	if err != nil || !exists {
		return nil, err
	}
	detail, err := read(conn, schema, table.Table)
	if detail != nil {
		detail.Catalog = catalog
		for i := range detail.ForeignKeys {
			detail.ForeignKeys[i].SourceCatalog, detail.ForeignKeys[i].TargetCatalog = catalog, catalog
		}
		for i := range detail.ReferencedBy {
			detail.ReferencedBy[i].SourceCatalog, detail.ReferencedBy[i].TargetCatalog = catalog, catalog
		}
	}
	return detail, err
}
