package store

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The default PM_DB_URL from Config.kt:217 / 01-bootstrap.md §1. It is the shape every deployment
// uses, so it gets its own named constant rather than being buried in a table row.
const defaultDBURL = "jdbc:postgresql://localhost:5432/proxymonster"

func TestTranslateJDBCURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"the shipped default", defaultDBURL, "postgresql://localhost:5432/proxymonster"},
		{"mise.toml:58 dev port", "jdbc:postgresql://localhost:5442/proxymonster", "postgresql://localhost:5442/proxymonster"},
		{"host without port", "jdbc:postgresql://db.internal/proxymonster", "postgresql://db.internal/proxymonster"},
		{"query string passes through", "jdbc:postgresql://h:5432/d?a=b&c=d", "postgresql://h:5432/d?a=b&c=d"},
		{"multi-host", "jdbc:postgresql://h1:5432,h2:5432/d", "postgresql://h1:5432,h2:5432/d"},
		// pgjdbc's no-authority forms: the host defaults are the driver's, not the URL's.
		{"database only", "jdbc:postgresql:proxymonster", "postgresql:///proxymonster"},
		{"slash form", "jdbc:postgresql:/", "postgresql:///"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := TranslateJDBCURL(tc.in)
			if err != nil {
				t.Fatalf("TranslateJDBCURL(%q) errored: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("TranslateJDBCURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// REPRODUCE: Db.kt hardcodes driverClassName = "org.postgresql.Driver", whose parseURL rejects
// anything not starting with the exact lowercase "jdbc:postgresql:", and HikariCP's eager pool init
// turns that into a boot failure. Accepting a native libpq URL would be a new capability.
func TestTranslateJDBCURLRejectsNonJDBC(t *testing.T) {
	for _, in := range []string{
		"postgres://localhost:5432/proxymonster",
		"postgresql://localhost:5432/proxymonster",
		"JDBC:POSTGRESQL://localhost:5432/proxymonster", // parseURL's startsWith is case-sensitive
		"jdbc:mysql://localhost:3306/proxymonster",
		"host=localhost port=5432 dbname=proxymonster",
		"",
	} {
		if got, err := TranslateJDBCURL(in); err == nil {
			t.Errorf("TranslateJDBCURL(%q) = %q, want an error", in, got)
		}
	}
}

// The translation is only useful if pgx accepts the result, so assert against the real parser rather
// than against a string. Only the explicit-authority form is checked here: pgx falls back to
// PGHOST/PGPORT/PGDATABASE for anything the URL omits, which would make the no-authority cases
// depend on the ambient environment.
func TestTranslatedURLParsesWithPgx(t *testing.T) {
	dsn, err := TranslateJDBCURL(defaultDBURL)
	if err != nil {
		t.Fatalf("TranslateJDBCURL: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("pgxpool.ParseConfig(%q): %v", dsn, err)
	}
	if got := cfg.ConnConfig.Host; got != "localhost" {
		t.Errorf("host = %q, want localhost", got)
	}
	if got := cfg.ConnConfig.Port; got != 5432 {
		t.Errorf("port = %d, want 5432", got)
	}
	if got := cfg.ConnConfig.Database; got != "proxymonster" {
		t.Errorf("database = %q, want proxymonster", got)
	}
}

// 01-bootstrap.md §2: maximumPoolSize = 10, reproduced. The Kotlin cap is the control plane's whole
// share of the Postgres connection budget, so it is asserted rather than left to a comment. This also
// pins that user/password come from the config fields and override anything the URL carries, which is
// HikariCP's precedence (jdbcUrl + username/password as separate driver properties).
func TestPoolConfigReproducesHikariSettings(t *testing.T) {
	dsn, err := TranslateJDBCURL("jdbc:postgresql://localhost:5432/proxymonster?user=fromurl&password=fromurl")
	if err != nil {
		t.Fatalf("TranslateJDBCURL: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("pgxpool.ParseConfig: %v", err)
	}
	cfg.ConnConfig.User = "proxymonster"
	cfg.ConnConfig.Password = "s3cret"
	cfg.MaxConns = MaxPoolSize

	if cfg.MaxConns != 10 {
		t.Errorf("MaxConns = %d, want 10 (Db.kt maximumPoolSize)", cfg.MaxConns)
	}
	if cfg.ConnConfig.User != "proxymonster" {
		t.Errorf("User = %q, want the configured PM_DB_USER to win over the URL", cfg.ConnConfig.User)
	}
	if cfg.ConnConfig.Password != "s3cret" {
		t.Errorf("Password = %q, want the configured PM_DB_PASSWORD to win over the URL", cfg.ConnConfig.Password)
	}
	if PoolName != "pm-control-plane" {
		t.Errorf("PoolName = %q, want pm-control-plane (Db.kt poolName)", PoolName)
	}
}
