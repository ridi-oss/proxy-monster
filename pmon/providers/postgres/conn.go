package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"

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
	switch format {
	case driver.JDBC:
		return fmt.Sprintf("jdbc:postgresql://%s:%d/%s?user=%s&password=%s",
			driver.Host, t.Port, t.DbName, url.QueryEscape(t.User), url.QueryEscape(t.Password))
	case driver.GoDSN:
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
			driver.Host, t.Port, t.User, t.Password, t.DbName)
	case driver.CLI:
		return fmt.Sprintf("psql %s", driver.ShellQuote(fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s",
			driver.Host, t.Port, t.DbName, t.User, t.Password)))
	default:
		return fmt.Sprintf("postgresql://%s:%s@%s:%d/%s",
			url.QueryEscape(t.User), url.QueryEscape(t.Password), driver.Host, t.Port, t.DbName)
	}
}
