// Package conn renders a brokered datasource's LOCAL connection string in the formats a client expects. The
// host is always loopback and the credentials are the authenticated principal plus the sticky local password:
// cosmetic to the broker (it injects the wire token upstream), but they make a copy-paste connection a real
// client accepts, and the password never rotates.
package conn

import (
	"fmt"
	"net/url"
	"strings"
)

// Format is a connection-string flavor.
type Format string

const (
	// URL is a driver URI, the default.
	URL Format = "url"
	// JDBC is a JDBC URL.
	JDBC Format = "jdbc"
	// GoDSN is a Go driver DSN: go-sql-driver/mysql for MySQL, lib/pq keyword form for Postgres.
	GoDSN Format = "go-dsn"
	// CLI is a mysql/psql command line.
	CLI Format = "cli"
)

// Host is the loopback address every broker listens on.
const Host = "127.0.0.1"

// Target is what a connection string is rendered for.
type Target struct {
	Engine   string // "mysql" | "postgres"
	DbName   string
	Port     int
	User     string
	Password string
}

// String renders t in the requested format, defaulting to [URL] for an empty or unknown one.
func String(format Format, t Target) string {
	return StringWithOptions(format, t, Options{})
}

// Options adjusts connection-string rendering for clients with non-default requirements.
type Options struct {
	// JDBCTruncationDiagnostics leaves MySQL JDBC driver options unspecified. The default false adds pmon's
	// compatibility setting that prevents Connector/J from automatically issuing SHOW WARNINGS.
	JDBCTruncationDiagnostics bool
}

// StringWithOptions renders t in the requested format using opts.
func StringWithOptions(format Format, t Target, opts Options) string {
	if t.Engine == "postgres" {
		return postgres(format, t)
	}
	return mysql(format, t, opts)
}

func mysql(format Format, t Target, opts Options) string {
	switch format {
	case JDBC:
		jdbc := fmt.Sprintf("jdbc:mysql://%s:%d/%s?user=%s&password=%s",
			Host, t.Port, t.DbName, url.QueryEscape(t.User), url.QueryEscape(t.Password))
		if opts.JDBCTruncationDiagnostics {
			return jdbc
		}
		return jdbc + "&jdbcCompliantTruncation=false"
	case GoDSN:
		// go-sql-driver/mysql: user:pass@tcp(host:port)/db?params. parseTime + utf8mb4 are the conventional
		// defaults; TLS is deliberately absent — the loopback hop to the broker is plaintext by design (the
		// broker owns the TLS-and-pinning hop to the proxy).
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&charset=utf8mb4",
			t.User, t.Password, Host, t.Port, t.DbName)
	case CLI:
		// Shell-quote each field: Go's %q is NOT shell-safe (it would leave $()/backticks live), and a
		// datasource/db/principal name can legally contain spaces or shell metacharacters.
		return fmt.Sprintf("mysql -h %s -P %d -u %s -p%s %s",
			Host, t.Port, shellQuote(t.User), shellQuote(t.Password), shellQuote(t.DbName))
	default:
		return fmt.Sprintf("mysql://%s:%s@%s:%d/%s",
			url.QueryEscape(t.User), url.QueryEscape(t.Password), Host, t.Port, t.DbName)
	}
}

func postgres(format Format, t Target) string {
	dbPath := url.PathEscape(t.DbName)
	keywordUser := postgresKeywordValue(t.User)
	keywordPassword := postgresKeywordValue(t.Password)
	keywordDB := postgresKeywordValue(t.DbName)
	switch format {
	case JDBC:
		return fmt.Sprintf("jdbc:postgresql://%s:%d/%s?user=%s&password=%s&sslmode=disable",
			Host, t.Port, dbPath, url.QueryEscape(t.User), url.QueryEscape(t.Password))
	case GoDSN:
		// lib/pq keyword form. sslmode=disable for the same reason MySQL's DSN carries no TLS: the loopback
		// hop is plaintext by design.
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
			Host, t.Port, keywordUser, keywordPassword, keywordDB)
	case CLI:
		return fmt.Sprintf("psql %s", shellQuote(fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=disable",
			Host, t.Port, keywordDB, keywordUser, keywordPassword)))
	default:
		return fmt.Sprintf("postgresql://%s@%s:%d/%s?sslmode=disable",
			url.UserPassword(t.User, t.Password), Host, t.Port, dbPath)
	}
}

func postgresKeywordValue(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\r\n'\\") {
		return s
	}
	escaped := strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s)
	return "'" + escaped + "'"
}

// shellQuote wraps s in single quotes for safe copy-paste into a POSIX shell, escaping any embedded single
// quote as the standard '\” sequence. Unlike Go's %q, this neutralizes $(), backticks, and spaces.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
