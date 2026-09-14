package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ridi-oss/proxy-monster/pmon/conn"
	"github.com/ridi-oss/proxy-monster/pmon/control"
)

type showCmd struct {
	Datasource                string `arg:"" help:"Datasource name (as shown by 'pmon status')."`
	Format                    string `xor:"format" help:"Print a provider-supported format (for example url, jdbc, cli, python, node, aws-config); defaults to the provider's preferred format."`
	URL                       bool   `xor:"format" help:"Print a connection URL."`
	JDBC                      bool   `xor:"format" help:"Print a JDBC URL."`
	JDBCTruncationDiagnostics bool   `name:"jdbc-with-truncation-diagnostics" help:"With --jdbc, omit the compatibility parameter so Connector/J can fetch truncation diagnostics (may issue SHOW WARNINGS)."`
	GoDSN                     bool   `name:"go-dsn" xor:"format" help:"Print a Go driver DSN."`
	CLI                       bool   `xor:"format" help:"Print the native client command line."`
}

func (c *showCmd) Run() error {
	if c.JDBCTruncationDiagnostics && c.format() != conn.JDBC {
		return fmt.Errorf("--jdbc-with-truncation-diagnostics requires --jdbc or --format jdbc")
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

	format := c.format()
	if format == "" {
		format = conn.DefaultFormat(found.Engine)
	}
	if !conn.SupportsFormat(found.Engine, format) {
		var supported []string
		for _, value := range conn.SupportedFormats(found.Engine) {
			supported = append(supported, string(value))
		}
		return fmt.Errorf("format %q is not supported by %q; supported formats: %s", format, found.Engine, strings.Join(supported, ", "))
	}
	output := conn.StringWithOptions(format, conn.Target{
		Name:           found.Name,
		ConnectionInfo: found.ConnectionInfo.Clone(),
		Engine:         found.Engine,
		DbName:         found.DbName,
		Port:           found.LocalPort,
		User:           s.Principal,
		Password:       s.LocalPassword,
	}, conn.Options{JDBCTruncationDiagnostics: c.JDBCTruncationDiagnostics})
	if output == "" {
		return fmt.Errorf("cannot render format %q for %q: connection metadata is incomplete or invalid", format, found.Name)
	}
	fmt.Println(output)
	return nil
}

func (c *showCmd) format() conn.Format {
	switch {
	case c.URL:
		return conn.URL
	case c.JDBC:
		return conn.JDBC
	case c.GoDSN:
		return conn.GoDSN
	case c.CLI:
		return conn.CLI
	default:
		return conn.Format(c.Format)
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
