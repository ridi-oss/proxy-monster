package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ridi-oss/proxy-monster/pmon/conn"
	"github.com/ridi-oss/proxy-monster/pmon/control"
)

// showCmd prints ONE datasource's local connection string, in the flavor the target client wants:
//
//	pmon show acme-mysql            postgres://…  |  mysql://…      (--url, the default)
//	pmon show acme-mysql --jdbc     jdbc:mysql://127.0.0.1:6100/app?user=…&password=…
//	pmon show acme-mysql --jdbc --jdbc-with-truncation-diagnostics
//	pmon show acme-mysql --go-dsn   user:pass@tcp(127.0.0.1:6100)/app?parseTime=true&charset=utf8mb4
//	pmon show acme-mysql --cli      mysql -h 127.0.0.1 -P 6100 -u … -p… app
//
// Output is the bare string, so it pipes straight into a client or an env var.
type showCmd struct {
	Datasource                string `arg:"" help:"Datasource name (as shown by 'pmon status')."`
	URL                       bool   `xor:"format" help:"Print a driver URI (default)."`
	JDBC                      bool   `xor:"format" help:"Print a JDBC URL."`
	JDBCTruncationDiagnostics bool   `name:"jdbc-with-truncation-diagnostics" help:"With --jdbc, omit the compatibility parameter so Connector/J can fetch truncation diagnostics (may issue SHOW WARNINGS)."`
	GoDSN                     bool   `name:"go-dsn" xor:"format" help:"Print a Go driver DSN."`
	CLI                       bool   `xor:"format" help:"Print the mysql/psql command line."`
}

func (c *showCmd) Run() error {
	if c.JDBCTruncationDiagnostics && !c.JDBC {
		return fmt.Errorf("--jdbc-with-truncation-diagnostics requires --jdbc")
	}

	ctx := context.Background()
	client, err := control.Connect(ctx)
	if err != nil {
		return fmt.Errorf("the daemon is not running — run `pmon login` (or `pmon start` if you are already logged in)")
	}
	s, err := client.Status(ctx)
	if err != nil {
		return err
	}
	warnVersionSkew(s)
	// A second daemon makes the port this prints ambiguous.
	warnOtherDaemons()
	if !s.LoggedIn {
		return fmt.Errorf("not logged in — run `pmon login`")
	}

	var found *control.Datasource
	for i := range s.Datasources {
		if s.Datasources[i].Name == c.Datasource {
			found = &s.Datasources[i]
			break
		}
	}
	if found == nil {
		return fmt.Errorf("unknown datasource %q — known: %s", c.Datasource, strings.Join(names(s), ", "))
	}
	if !found.Brokered {
		return fmt.Errorf("datasource %q is not brokered locally: %s", found.Name, found.Reason)
	}

	fmt.Println(conn.StringWithOptions(c.format(), conn.Target{
		Engine:   found.Engine,
		DbName:   found.DbName,
		Port:     found.LocalPort,
		User:     s.Principal,
		Password: s.LocalPassword,
	}, conn.Options{JDBCTruncationDiagnostics: c.JDBCTruncationDiagnostics}))
	return nil
}

// format maps the mutually-exclusive flags onto a [conn.Format], defaulting to a driver URI.
func (c *showCmd) format() conn.Format {
	switch {
	case c.JDBC:
		return conn.JDBC
	case c.GoDSN:
		return conn.GoDSN
	case c.CLI:
		return conn.CLI
	default:
		return conn.URL
	}
}

func names(s *control.Status) []string {
	out := make([]string, 0, len(s.Datasources))
	for _, ds := range s.Datasources {
		out = append(out, ds.Name)
	}
	sort.Strings(out)
	return out
}
