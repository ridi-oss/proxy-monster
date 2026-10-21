// Package dbtest gives tests a fresh control-plane store: a shared Postgres container, one database per
// test, with the Kotlin control plane's Flyway migrations applied.
package dbtest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // the "pgx" database/sql driver wait.ForSQL uses
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Store is one migrated test database.
type Store struct {
	Pool *pgxpool.Pool
	// JDBCURL, User and Password are the PM_DB_* values that reach it.
	JDBCURL, User, Password string
}

const user, password, adminDB = "postgres", "pgpw", "app"

var (
	once     sync.Once
	host     string
	port     int
	startErr error
	counter  atomic.Int64
)

// Open creates and migrates a database for t, dropped when t ends.
func Open(t testing.TB) Store {
	t.Helper()
	once.Do(func() { host, port, startErr = start() })
	if startErr != nil {
		t.Fatalf("Postgres test container unavailable (Docker is required): %v", startErr)
	}
	ctx := context.Background()
	name := fmt.Sprintf("cpgo_%d_%d", os.Getpid(), counter.Add(1))
	admin, err := pgx.Connect(ctx, dsn(adminDB))
	if err != nil {
		t.Fatal(err)
	}
	_, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
	_ = admin.Close(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn(name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if c, err := pgx.Connect(context.Background(), dsn(adminDB)); err == nil {
			_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
			_ = c.Close(context.Background())
		}
	})
	migrate(t, pool)
	return Store{
		Pool:     pool,
		JDBCURL:  fmt.Sprintf("jdbc:postgresql://%s:%d/%s?sslmode=disable", host, port, name),
		User:     user,
		Password: password,
	}
}

func dsn(db string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", user, password, host, port, db)
}

var versioned = regexp.MustCompile(`^V(\d+)__.*\.sql$`)

// migrate applies control-plane/src/main/resources/db/migration in version order, as Flyway does.
func migrate(t testing.TB, pool *pgxpool.Pool) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(file), "../../../control-plane/src/main/resources/db/migration")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	type migration struct {
		version int
		path    string
	}
	var ms []migration
	for _, e := range entries {
		if m := versioned.FindStringSubmatch(e.Name()); m != nil {
			v, _ := strconv.Atoi(m[1])
			ms = append(ms, migration{v, filepath.Join(dir, e.Name())})
		}
	}
	slices.SortFunc(ms, func(a, b migration) int { return a.version - b.version })
	for _, m := range ms {
		sql, err := os.ReadFile(m.path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(context.Background(), string(sql)); err != nil {
			t.Fatalf("migration %s: %v", filepath.Base(m.path), err)
		}
	}
}

func image() string {
	if v := os.Getenv("PM_TEST_POSTGRES_IMAGE"); v != "" {
		return v
	}
	return "postgres:16"
}

func start() (string, int, error) {
	img := image()
	name := "pm-cpgo-it-pg-" + strings.NewReplacer(":", "-", "/", "-", ".", "-").Replace(img)
	if s := os.Getenv("PM_TEST_CONTAINER_SUFFIX"); s != "" {
		name += "-" + strings.NewReplacer(":", "-", "/", "-", ".", "-").Replace(s)
	}
	// go test runs each package in its own process; the lock lets exactly one create the shared container.
	unlock, err := lock(name)
	if err != nil {
		return "", 0, err
	}
	defer unlock()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        img,
			Name:         name,
			ExposedPorts: []string{"5432/tcp"},
			Env:          map[string]string{"POSTGRES_PASSWORD": password, "POSTGRES_DB": adminDB},
			WaitingFor: wait.ForSQL("5432/tcp", "pgx", func(host string, port network.Port) string {
				return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", user, password, host, port.Port(), adminDB)
			}).WithStartupTimeout(180 * time.Second),
		},
		Started: true,
		Reuse:   true,
	})
	if err != nil {
		return "", 0, err
	}
	h, err := c.Host(ctx)
	if err != nil {
		return "", 0, err
	}
	p, err := c.MappedPort(ctx, "5432/tcp")
	if err != nil {
		return "", 0, err
	}
	return h, int(p.Num()), nil
}

func lock(name string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(os.TempDir(), name+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
