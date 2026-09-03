package store

import (
	"fmt"
	"strings"
)

// jdbcPostgresPrefix is the prefix org.postgresql.Driver.parseURL accepts. The check there is
// case-SENSITIVE (`url.startsWith("jdbc:postgresql:")`), so this one is too: a PM_DB_URL of
// "JDBC:POSTGRESQL://…" fails to boot the Kotlin and must fail to boot the port.
const jdbcPostgresPrefix = "jdbc:postgresql:"

// TranslateJDBCURL converts a PostgreSQL JDBC URL into the libpq/pgx connection URL that carries the
// same host, port, database and query string.
//
// 01-bootstrap.md §1 pins PM_DB_URL to the JDBC form
// (default "jdbc:postgresql://localhost:5432/proxymonster") and §5 Q1 records that changing the
// contract would touch deploy/, docker-compose.yml, mise.toml:58 and every deployed environment. So
// the port translates rather than redefines, and — REPRODUCE — it rejects anything that is not a
// JDBC URL: Db.kt hardcodes driverClassName = "org.postgresql.Driver", and HikariCP's eager pool
// initialisation throws "Driver claims to not accept jdbcUrl" for any other shape. Accepting a bare
// "postgres://…" here would be a new capability, not a port.
//
// The three JDBC forms org.postgresql.Driver accepts map as follows:
//
//	jdbc:postgresql://host:port/db?a=b  ->  postgresql://host:port/db?a=b
//	jdbc:postgresql://host/db           ->  postgresql://host/db
//	jdbc:postgresql:db                  ->  postgresql:///db          (host defaults)
//
// User and password are NOT taken from the URL here. HikariCP passes them as separate driver
// properties (jdbcUrl + username + password), where they override any user=/password= carried in the
// URL; New reproduces that precedence by assigning ConnConfig.User/Password after parsing.
//
// ⚠️ Unverified: JDBC connection properties and libpq parameters are different vocabularies —
// pgjdbc's `ssl`, `currentSchema`, `socketTimeout`, `ApplicationName` have no libpq spelling, and
// pgx forwards an unrecognised query parameter to the server as a startup RuntimeParam, which the
// server rejects. No shipped configuration carries any query parameter (grepped: INSTALL.md,
// mise.toml:58, control-plane/Dockerfile and Config.kt:217 all use the bare host/port/db form), so
// the query string is passed through untouched and per-parameter translation is left as a TODO.
//
// TODO(A1): translate the pgjdbc property names above if a deployment ever sets one.
func TranslateJDBCURL(jdbcURL string) (string, error) {
	rest, ok := strings.CutPrefix(jdbcURL, jdbcPostgresPrefix)
	if !ok {
		return "", fmt.Errorf("PM_DB_URL must be a PostgreSQL JDBC URL (%q…): %q", jdbcPostgresPrefix, jdbcURL)
	}
	if strings.HasPrefix(rest, "//") {
		// Authority form. "postgresql:" is a scheme libpq and pgx both accept, so the remainder needs
		// no rewriting at all — including the multi-host "host1:5432,host2:5432" form both support.
		return "postgresql:" + rest, nil
	}
	// Database-only form: jdbc:postgresql:mydb, and the degenerate jdbc:postgresql:/ . An empty
	// authority makes pgx fall back to its own host defaults, which is what pgjdbc does here too.
	return "postgresql:///" + strings.TrimPrefix(rest, "/"), nil
}
