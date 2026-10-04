package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxPoolSize reproduces Db.kt's HikariConfig.maximumPoolSize = 10 (01-bootstrap.md §2). The cap is
// carried across verbatim: it is the control plane's whole share of the Postgres connection budget,
// and auditmon plus the UI read the same store.
const MaxPoolSize = 10

// PoolName reproduces Db.kt's HikariConfig.poolName = "pm-control-plane".
//
// It is deliberately NOT wired to the connection's application_name. HikariCP's poolName names the
// pool's JMX bean and its housekeeping thread — it is never sent to Postgres, so it does not appear
// in pg_stat_activity. Setting application_name here would be a new observable behaviour rather than
// a port of an existing one. The constant exists so log lines can carry the same label the Kotlin
// used.
const PoolName = "pm-control-plane"

// Config is the narrow slice of the process configuration Db needs. It is NOT internal/config's
// Config: this package owns the database handle and nothing else, and depending on the whole env
// contract would make every store test carry the eleven validation rules with it.
//
// TODO(A1): App wiring builds this from internal/config.Config's dbUrl/dbUser/dbPassword fields
// (01-bootstrap.md §1). That adapter belongs in the composition root, not here.
type Config struct {
	// DBURL is PM_DB_URL, a JDBC URL. See TranslateJDBCURL.
	DBURL string
	// DBUser is PM_DB_USER.
	DBUser string
	// DBPassword is PM_DB_PASSWORD.
	DBPassword string
}

// Db is the control-plane Postgres store: a pooled connection with Flyway migrations applied at
// startup. It is the Go equivalent of Db.kt (48 LOC); Pool is the analogue of its `dataSource`
// field, and every other area's store takes a handle from it rather than opening its own.
//
// Area doc: 01-bootstrap.md §2.
type Db struct {
	// Pool is the shared pgxpool. *pgxpool.Pool satisfies both Beginner and Queryer, so a store
	// method can take either the pool (autocommit, one statement) or a pgx.Tx from InTx.
	Pool *pgxpool.Pool
}

// Compile-time proof that the pool satisfies the two narrow handles every other area's store will
// take. If this ever stops holding, the stores break, not just this package.
var (
	_ Beginner = (*pgxpool.Pool)(nil)
	_ Queryer  = (*pgxpool.Pool)(nil)
	_ Queryer  = (pgx.Tx)(nil)
)

// New builds the pool. It is the Go equivalent of `Db(config)`.
//
// Behaviour reproduced from Db.kt:
//
//  1. jdbcUrl / username / password come from config; the driver is hardcoded to PostgreSQL (here,
//     by using pgx at all — there is no store-engine setting to reproduce, see docs/migrations.md).
//  2. maximumPoolSize = 10.
//  3. Construction is EAGER. `HikariDataSource(HikariConfig)` runs checkFailFast() in its
//     constructor, so an unreachable database fails `Db(config)` rather than the first query. The
//     Ping below reproduces that: pgxpool.NewWithConfig is lazy on its own and would defer the
//     failure into migrate(). Both orderings abort the process, but the boot log differs, and A1's
//     boot sequence (Config → banner → Db → migrate) is contractual.
//
// The connect deadline comes from ctx. HikariCP's own connectionTimeout (30s by default) has no
// direct analogue and is not reproduced — the caller owns the deadline.
func New(ctx context.Context, cfg Config) (*Db, error) {
	dsn, err := TranslateJDBCURL(cfg.DBURL)
	if err != nil {
		return nil, err
	}
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse PM_DB_URL: %w", err)
	}

	// HikariCP hands username/password to the driver as properties, which take precedence over any
	// user=/password= in the URL. Assigning after ParseConfig reproduces that precedence exactly.
	poolCfg.ConnConfig.User = cfg.DBUser
	poolCfg.ConnConfig.Password = cfg.DBPassword
	poolCfg.MaxConns = MaxPoolSize

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("%s: open pool: %w", PoolName, err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("%s: %w", PoolName, err)
	}
	return &Db{Pool: pool}, nil
}

// Close releases the pool. Kotlin leaks the HikariDataSource for the process lifetime (Db has no
// close and Main.kt never disposes it), so this exists for tests and for a graceful shutdown that
// A1's Main does not currently perform.
func (d *Db) Close() { d.Pool.Close() }

// Beginner starts a transaction. It is the narrow half of javax.sql.DataSource that InTx needs.
type Beginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Queryer is the read/write surface shared by *pgxpool.Pool, *pgxpool.Conn, *pgx.Conn and pgx.Tx —
// the Go analogue of java.sql.Connection as the stores use it.
//
// Every store method that must be composable into a caller's transaction takes a Queryer, mirroring
// the Kotlin's `(…, c: Connection)` overloads. Passing the pool instead runs the statement on its own
// implicit transaction, exactly as passing a pooled autoCommit Connection does in the Kotlin.
type Queryer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// DB is a handle that can both start transactions and run statements. The migration runner needs
// both; *pgxpool.Pool satisfies it.
type DB interface {
	Beginner
	Queryer
}
