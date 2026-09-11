package conn

import (
	"strings"
	"testing"
)

func TestMySQLFormats(t *testing.T) {
	target := Target{Engine: "mysql", DbName: "app", Port: 6100, User: "you@example.com", Password: "pw"}
	cases := map[Format]string{
		URL:   "mysql://you%40example.com:pw@127.0.0.1:6100/app",
		JDBC:  "jdbc:mysql://127.0.0.1:6100/app?user=you%40example.com&password=pw&jdbcCompliantTruncation=false",
		GoDSN: "you@example.com:pw@tcp(127.0.0.1:6100)/app?parseTime=true&charset=utf8mb4",
		CLI:   `mysql -h 127.0.0.1 -P 6100 -u 'you@example.com' -p'pw' 'app'`,
	}
	for format, want := range cases {
		if got := String(format, target); got != want {
			t.Errorf("String(%s) = %q, want %q", format, got, want)
		}
	}
}

func TestMySQLJDBCTruncationDiagnostics(t *testing.T) {
	target := Target{Engine: "mysql", DbName: "app", Port: 6100, User: "you@example.com", Password: "pw"}
	if got, want := StringWithOptions(JDBC, target, Options{JDBCTruncationDiagnostics: true}),
		"jdbc:mysql://127.0.0.1:6100/app?user=you%40example.com&password=pw"; got != want {
		t.Errorf("StringWithOptions(JDBC, truncation diagnostics) = %q, want %q", got, want)
	}
}

func TestPostgresFormats(t *testing.T) {
	target := Target{Engine: "postgres", DbName: "app", Port: 6101, User: "you@example.com", Password: "pw"}
	cases := map[Format]string{
		URL:   "postgresql://you%40example.com:pw@127.0.0.1:6101/app?sslmode=disable",
		JDBC:  "jdbc:postgresql://127.0.0.1:6101/app?user=you%40example.com&password=pw&sslmode=disable",
		GoDSN: "host=127.0.0.1 port=6101 user=you@example.com password=pw dbname=app sslmode=disable",
		CLI:   `psql 'host=127.0.0.1 port=6101 dbname=app user=you@example.com password=pw sslmode=disable'`,
	}
	for format, want := range cases {
		if got := String(format, target); got != want {
			t.Errorf("String(%s) = %q, want %q", format, got, want)
		}
	}
}

func TestPostgresEscapesURLPathAndUserInfo(t *testing.T) {
	target := Target{
		Engine: "postgres", DbName: "team / reports", Port: 6101,
		User: "user name", Password: "pw/secret",
	}
	cases := map[Format]string{
		URL:  "postgresql://user%20name:pw%2Fsecret@127.0.0.1:6101/team%20%2F%20reports?sslmode=disable",
		JDBC: "jdbc:postgresql://127.0.0.1:6101/team%20%2F%20reports?user=user+name&password=pw%2Fsecret&sslmode=disable",
	}
	for format, want := range cases {
		if got := String(format, target); got != want {
			t.Errorf("String(%s) = %q, want %q", format, got, want)
		}
	}
}

func TestPostgresEscapesKeywordValues(t *testing.T) {
	target := Target{
		Engine: "postgres", DbName: "team / reports", Port: 6101,
		User: "user name", Password: `pw'\secret`,
	}
	wantDSN := `host=127.0.0.1 port=6101 user='user name' password='pw\'\\secret' dbname='team / reports' sslmode=disable`
	if got := String(GoDSN, target); got != wantDSN {
		t.Errorf("String(%s) = %q, want %q", GoDSN, got, wantDSN)
	}
	wantCLIFields := `host=127.0.0.1 port=6101 dbname='team / reports' user='user name' password='pw\'\\secret' sslmode=disable`
	if got, want := String(CLI, target), "psql "+shellQuote(wantCLIFields); got != want {
		t.Errorf("String(%s) = %q, want %q", CLI, got, want)
	}
}

// TestUnknownFormatFallsBackToURL locks the documented default, so a caller that forgets to map a flag gets a
// usable URI rather than an empty string.
func TestUnknownFormatFallsBackToURL(t *testing.T) {
	target := Target{Engine: "mysql", DbName: "app", Port: 6100, User: "u", Password: "p"}
	if got, want := String("", target), String(URL, target); got != want {
		t.Errorf("empty format = %q, want the URL form %q", got, want)
	}
	if got, want := String("nonsense", target), String(URL, target); got != want {
		t.Errorf("unknown format = %q, want the URL form %q", got, want)
	}
}

// TestUnknownEngineRendersAsMySQL: MySQL is the brokered engine, so an unrecognized engine string must still
// produce something usable rather than an empty line.
func TestUnknownEngineRendersAsMySQL(t *testing.T) {
	got := String(URL, Target{Engine: "mariadb", DbName: "app", Port: 6100, User: "u", Password: "p"})
	if !strings.HasPrefix(got, "mysql://") {
		t.Errorf("unknown engine rendered %q, want the mysql:// form", got)
	}
}

// TestCLIQuotingNeutralizesShellMetacharacters guards the copy-paste path: a password or db name can contain
// quotes, spaces, $(), or backticks, and the CLI form is pasted straight into a shell. Go's %q would leave
// command substitution live.
func TestCLIQuotingNeutralizesShellMetacharacters(t *testing.T) {
	got := String(CLI, Target{
		Engine: "mysql", DbName: "my db", Port: 6100,
		User: "you@example.com", Password: "pw'$(id)`whoami`",
	})
	// The single quote is closed and re-opened via the '\'' idiom, so nothing inside reaches the shell live.
	if !strings.Contains(got, `-p'pw'\''$(id)`+"`whoami`'") {
		t.Errorf("password not shell-quoted safely: %s", got)
	}
	if !strings.Contains(got, `'my db'`) {
		t.Errorf("db name with a space not quoted: %s", got)
	}
}

// TestURLFormsPercentEncodeCredentials: a principal is an email (with @) and a password is random base64url,
// so both must be escaped or the URI parses wrong.
func TestURLFormsPercentEncodeCredentials(t *testing.T) {
	target := Target{Engine: "mysql", DbName: "app", Port: 6100, User: "you@example.com", Password: "a/b+c=d"}
	for _, format := range []Format{URL, JDBC} {
		got := String(format, target)
		if strings.Contains(got, "you@example.com") {
			t.Errorf("String(%s) = %q leaves the raw @ in the user", format, got)
		}
		if strings.Contains(got, "a/b+c=d") {
			t.Errorf("String(%s) = %q leaves the raw password unescaped", format, got)
		}
	}
}
