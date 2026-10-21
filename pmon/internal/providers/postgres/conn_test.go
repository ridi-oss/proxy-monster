package postgres

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

func TestFormatsCarrySSLModeDisable(t *testing.T) {
	target := driver.Target{Engine: "postgres", DbName: "app", Port: 6101, User: "you@example.com", Password: "pw"}
	cases := map[driver.Format]string{
		driver.URL:   "postgresql://you%40example.com:pw@127.0.0.1:6101/app?sslmode=disable",
		driver.JDBC:  "jdbc:postgresql://127.0.0.1:6101/app?user=you%40example.com&password=pw&sslmode=disable",
		driver.GoDSN: "host=127.0.0.1 port=6101 user=you@example.com password=pw dbname=app sslmode=disable",
		driver.CLI:   `psql 'host=127.0.0.1 port=6101 dbname=app user=you@example.com password=pw sslmode=disable'`,
	}
	for format, want := range cases {
		if got := (Provider{}).FormatConnectionString(format, target, driver.Options{}); got != want {
			t.Errorf("FormatConnectionString(%s) = %q, want %q", format, got, want)
		}
	}
}

func TestEscapesURLPathAndUserInfo(t *testing.T) {
	target := driver.Target{Engine: "postgres", DbName: "team / reports", Port: 6101, User: "user name", Password: "pw/secret"}
	cases := map[driver.Format]string{
		driver.URL:  "postgresql://user%20name:pw%2Fsecret@127.0.0.1:6101/team%20%2F%20reports?sslmode=disable",
		driver.JDBC: "jdbc:postgresql://127.0.0.1:6101/team%20%2F%20reports?user=user+name&password=pw%2Fsecret&sslmode=disable",
	}
	for format, want := range cases {
		if got := (Provider{}).FormatConnectionString(format, target, driver.Options{}); got != want {
			t.Errorf("FormatConnectionString(%s) = %q, want %q", format, got, want)
		}
	}
}

func TestEscapesKeywordValues(t *testing.T) {
	target := driver.Target{Engine: "postgres", DbName: "team / reports", Port: 6101, User: "user name", Password: `pw'\secret`}
	wantDSN := `host=127.0.0.1 port=6101 user='user name' password='pw\'\\secret' dbname='team / reports' sslmode=disable`
	if got := (Provider{}).FormatConnectionString(driver.GoDSN, target, driver.Options{}); got != wantDSN {
		t.Errorf("GoDSN = %q, want %q", got, wantDSN)
	}
	wantCLI := "psql " + driver.ShellQuote(`host=127.0.0.1 port=6101 dbname='team / reports' user='user name' password='pw\'\\secret' sslmode=disable`)
	if got := (Provider{}).FormatConnectionString(driver.CLI, target, driver.Options{}); got != wantCLI {
		t.Errorf("CLI = %q, want %q", got, wantCLI)
	}
}
