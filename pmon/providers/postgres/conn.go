package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

// Provider is the PostgreSQL engine. It formats connection strings; brokering is not implemented yet, so
// every endpoint reports unavailable and Serve is never reached.
type Provider struct{}

func (Provider) Engine() string { return "postgres" }

func (Provider) UnavailableReason(driver.Endpoint) string {
	return "postgres brokering not yet supported"
}

func (Provider) RouteKey(driver.Endpoint) string { return "" }

func (Provider) Serve(context.Context, net.Listener, driver.ResolveSession) error {
	return errors.New("postgres brokering not yet supported")
}

func (Provider) FormatConnectionString(format driver.Format, t driver.Target, _ driver.Options) string {
	dbPath := url.PathEscape(t.DbName)
	keywordUser := keywordValue(t.User)
	keywordPassword := keywordValue(t.Password)
	keywordDB := keywordValue(t.DbName)
	switch format {
	case driver.JDBC:
		return fmt.Sprintf("jdbc:postgresql://%s:%d/%s?user=%s&password=%s&sslmode=disable",
			driver.Host, t.Port, dbPath, url.QueryEscape(t.User), url.QueryEscape(t.Password))
	case driver.GoDSN:
		// lib/pq keyword form. sslmode=disable: the loopback hop is plaintext by design.
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
			driver.Host, t.Port, keywordUser, keywordPassword, keywordDB)
	case driver.CLI:
		return fmt.Sprintf("psql %s", driver.ShellQuote(fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=disable",
			driver.Host, t.Port, keywordDB, keywordUser, keywordPassword)))
	default:
		return fmt.Sprintf("postgresql://%s@%s:%d/%s?sslmode=disable",
			url.UserPassword(t.User, t.Password), driver.Host, t.Port, dbPath)
	}
}

// libpq keyword form: p@ss 'word -> 'p@ss \'word'.
func keywordValue(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\r\n'\\") {
		return s
	}
	escaped := strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s)
	return "'" + escaped + "'"
}
