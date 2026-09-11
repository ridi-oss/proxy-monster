package postgres

import (
	"fmt"
	"net/url"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

type Renderer struct{}

func (Renderer) Render(format driver.Format, t driver.Target, _ driver.Options) string {
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
