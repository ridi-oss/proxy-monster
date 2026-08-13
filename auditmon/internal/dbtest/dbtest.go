// Package dbtest provides the ONE shared PostgreSQL backend that every DB-backed test in the auditmon
// module uses. The container is started once and REUSED for the whole suite (testcontainers Reuse by a
// fixed Name). DB-backed tests are MANDATORY: if no Docker provider is available these helpers FAIL the
// test (t.Fatal), they never skip.
//
// Each OpenPostgres call carves out a fresh, uniquely-named database inside the shared container so the
// fixed-name audit tables never collide across the store/verify/monitor packages, which the test runner
// builds and runs in parallel.
package dbtest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/moby/moby/api/types/network"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver for wait.ForSQL
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Backend is the connection info for the shared test container.
type Backend struct {
	Host     string
	Port     int
	User     string
	Password string
	DB       string
}

// PostgresDSN is a pgx DSN for this backend and the given database (blank = the default database).
func (b Backend) PostgresDSN(db string) string {
	if db == "" {
		db = b.DB
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", b.User, b.Password, b.Host, b.Port, db)
}

var (
	pgOnce sync.Once
	pgB    Backend
	pgErr  error

	dbCounter atomic.Int64
)

// Postgres returns the shared PostgreSQL 16 backend, starting it once and reusing it across the whole
// suite. It fails the test if no Docker provider is available.
func Postgres(t testing.TB) Backend {
	t.Helper()
	pgOnce.Do(func() { pgB, pgErr = startPostgres() })
	if pgErr != nil {
		t.Fatalf("shared Postgres test container unavailable (Docker is required for DB-backed tests): %v", pgErr)
	}
	return pgB
}

// OpenPostgres creates a fresh, uniquely-named database in the shared container, opens a pgxpool against
// it, and returns the pool plus its DSN (so a caller can also open a read-only store.Reader on the same
// database). The database is dropped on test cleanup.
func OpenPostgres(t testing.TB) (*pgxpool.Pool, string) {
	t.Helper()
	be := Postgres(t)
	ctx := context.Background()

	name := fmt.Sprintf("auditmon_%d_%d", os.Getpid(), dbCounter.Add(1))
	admin, err := pgx.Connect(ctx, be.PostgresDSN(be.DB))
	if err != nil {
		t.Fatalf("connect admin db: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close(ctx)
		t.Fatalf("create database %s: %v", name, err)
	}
	admin.Close(ctx)

	dsn := be.PostgresDSN(name)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open pool for %s: %v", name, err)
	}
	t.Cleanup(func() {
		pool.Close()
		drop, err := pgx.Connect(context.Background(), be.PostgresDSN(be.DB))
		if err != nil {
			return
		}
		defer drop.Close(context.Background())
		_, _ = drop.Exec(context.Background(), "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	})
	return pool, dsn
}

const startupTimeout = 180 * time.Second

// postgresImage is the container image the shared backend runs. Newest supported series by default so a
// plain `go test ./...` covers what most installs run; PM_TEST_POSTGRES_IMAGE pins one version for a CI
// matrix leg. The supported set is declared in db-support.json at the repo root.
func postgresImage() string {
	if v := os.Getenv("PM_TEST_POSTGRES_IMAGE"); v != "" {
		return v
	}
	return "postgres:17"
}

// containerName derives the shared container's name from its image. testcontainers Reuse keys on the
// name, so the image has to be part of it: one name across two images would attach to a container built
// from the other version and run the tests against it while reporting the version that was asked for.
func containerName(img string) string {
	name := "pm-auditmon-it-pg-" + strings.NewReplacer(":", "-", "/", "-", ".", "-").Replace(img)
	// PM_TEST_CONTAINER_SUFFIX partitions the name further, so two suites that could run concurrently
	// against the SAME image get their own server instead of sharing one and colliding on fixtures.
	if s := os.Getenv("PM_TEST_CONTAINER_SUFFIX"); s != "" {
		name += "-" + strings.NewReplacer(":", "-", "/", "-", ".", "-").Replace(s)
	}
	return name
}

func startPostgres() (Backend, error) {
	const user, pass, db = "postgres", "pgpw", "app"
	img := postgresImage()
	name := containerName(img)

	// go test runs each package's tests in a separate process, so the sync.Once above only serializes
	// creation within one binary. testcontainers' Reuse is not atomic across processes, so a cold start
	// where several package binaries create the same-named container at once can race (one sees a
	// half-started or being-reaped container). A cross-process file lock lets exactly one binary win the
	// create; the rest attach to the ready container. The lock is per container name so that two
	// different-version runs serialize independently rather than blocking each other.
	unlock, err := lockShared(name)
	if err != nil {
		return Backend{}, err
	}
	defer unlock()

	req := testcontainers.ContainerRequest{
		Image:        img,
		Name:         name,
		ExposedPorts: []string{"5432/tcp"},
		Env:          map[string]string{"POSTGRES_PASSWORD": pass, "POSTGRES_DB": db},
		WaitingFor: wait.ForSQL("5432/tcp", "pgx", func(host string, port network.Port) string {
			return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", user, pass, host, port.Port(), db)
		}).WithStartupTimeout(startupTimeout),
	}
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Reuse:            true,
	})
	if err != nil {
		return Backend{}, err
	}
	host, err := c.Host(ctx)
	if err != nil {
		return Backend{}, err
	}
	mapped, err := c.MappedPort(ctx, "5432/tcp")
	if err != nil {
		return Backend{}, err
	}
	return Backend{Host: host, Port: int(mapped.Num()), User: user, Password: pass, DB: db}, nil
}

// lockShared takes an exclusive cross-process advisory lock on a temp file, serializing the shared-container
// create/reuse across the parallel per-package test binaries. It returns an unlock func.
func lockShared(name string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(os.TempDir(), name+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open container lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock container: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
