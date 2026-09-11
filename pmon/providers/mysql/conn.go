package mysql

import (
	"fmt"
	"net/url"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

func (Provider) Render(format driver.Format, t driver.Target, opts driver.Options) string {
	switch format {
	case driver.JDBC:
		jdbc := fmt.Sprintf("jdbc:mysql://%s:%d/%s?user=%s&password=%s",
			driver.Host, t.Port, t.DbName, url.QueryEscape(t.User), url.QueryEscape(t.Password))
		if opts.JDBCTruncationDiagnostics {
			return jdbc
		}
		return jdbc + "&jdbcCompliantTruncation=false"
	case driver.GoDSN:
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&charset=utf8mb4",
			t.User, t.Password, driver.Host, t.Port, t.DbName)
	case driver.CLI:
		return fmt.Sprintf("mysql -h %s -P %d -u %s -p%s %s",
			driver.Host, t.Port, driver.ShellQuote(t.User), driver.ShellQuote(t.Password), driver.ShellQuote(t.DbName))
	default:
		return fmt.Sprintf("mysql://%s:%s@%s:%d/%s",
			url.QueryEscape(t.User), url.QueryEscape(t.Password), driver.Host, t.Port, t.DbName)
	}
}
