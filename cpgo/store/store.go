// Package store opens the control-plane Postgres store from the same PM_DB_* settings the Kotlin
// control plane reads.
package store

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DSN turns the JDBC URL the Kotlin side takes (jdbc:postgresql://host:port/db?params) into a pgx DSN.
func DSN(jdbcURL, user, password string) (string, error) {
	raw, ok := strings.CutPrefix(jdbcURL, "jdbc:")
	if !ok || !strings.HasPrefix(raw, "postgresql://") {
		return "", fmt.Errorf("store: PM_DB_URL must start with jdbc:postgresql://, got %q", jdbcURL)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("store: parsing PM_DB_URL: %w", err)
	}
	u.User = url.UserPassword(user, password)
	return u.String(), nil
}

// Open connects a pool to the control-plane store.
func Open(ctx context.Context, jdbcURL, user, password string) (*pgxpool.Pool, error) {
	dsn, err := DSN(jdbcURL, user, password)
	if err != nil {
		return nil, err
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	cfg.MaxConns = 10
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: %w", err)
	}
	return pool, nil
}
