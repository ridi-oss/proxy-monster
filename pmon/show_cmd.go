package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ridi-oss/proxy-monster/pmon/conn"
	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/driver"
	"github.com/ridi-oss/proxy-monster/pmon/state"
)

type showCmd struct {
	Args                      []string `arg:"" name:"[server] datasource" help:"Datasource name, optionally after a server name (default: \"default\")."`
	Format                    string   `xor:"format" help:"Print a provider-supported format (for example url, jdbc, cli, python, node, aws-config); defaults to the provider's preferred format."`
	URL                       bool     `xor:"format" help:"Print a connection URL."`
	JDBC                      bool     `xor:"format" help:"Print a JDBC URL."`
	JDBCTruncationDiagnostics bool     `name:"jdbc-with-truncation-diagnostics" help:"With --jdbc, omit the compatibility parameter so Connector/J can fetch truncation diagnostics (may issue SHOW WARNINGS)."`
	GoDSN                     bool     `name:"go-dsn" xor:"format" help:"Print a Go driver DSN."`
	CLI                       bool     `xor:"format" help:"Print the native client command line."`
}

func (c *showCmd) Run() error {
	if c.JDBCTruncationDiagnostics && c.format() != driver.JDBC {
		return fmt.Errorf("--jdbc-with-truncation-diagnostics requires --jdbc or --format jdbc")
	}

	server, name := state.DefaultServer, ""
	switch len(c.Args) {
	case 1:
		name = c.Args[0]
	case 2:
		server, name = c.Args[0], c.Args[1]
	default:
		return fmt.Errorf("expected [server] <datasource>")
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
	srv := s.Server(server)
	if srv == nil {
		return fmt.Errorf("unknown server %q — known: %s", server, strings.Join(serverNames(s), ", "))
	}
	if !srv.LoggedIn {
		return fmt.Errorf("not logged in to %q — run `%s`", server, loginHint(server))
	}

	var found *control.Datasource
	for i := range s.Datasources {
		if s.Datasources[i].Server == server && s.Datasources[i].Name == name {
			found = &s.Datasources[i]
			break
		}
	}
	if found == nil {
		return fmt.Errorf("unknown datasource %q on %q — known: %s", name, server, strings.Join(names(s, server), ", "))
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
	output := conn.StringWithOptions(format, driver.Target{
		Name:           found.Name,
		ConnectionInfo: found.ConnectionInfo.Clone(),
		Engine:         found.Engine,
		DbName:         found.DbName,
		Port:           found.LocalPort,
		User:           srv.Principal,
		Password:       s.LocalPassword,
	}, driver.Options{JDBCTruncationDiagnostics: c.JDBCTruncationDiagnostics})
	if output == "" {
		return fmt.Errorf("cannot format %q for %q: connection metadata is incomplete or invalid", format, found.Name)
	}
	fmt.Println(output)
	return nil
}

func (c *showCmd) format() driver.Format {
	switch {
	case c.URL:
		return driver.URL
	case c.JDBC:
		return driver.JDBC
	case c.GoDSN:
		return driver.GoDSN
	case c.CLI:
		return driver.CLI
	default:
		return driver.Format(c.Format)
	}
}

func names(s *control.Status, server string) []string {
	var out []string
	for _, ds := range s.Datasources {
		if ds.Server == server {
			out = append(out, ds.Name)
		}
	}
	sort.Strings(out)
	return out
}

func serverNames(s *control.Status) []string {
	out := make([]string, 0, len(s.Servers))
	for _, srv := range s.Servers {
		out = append(out, srv.Name)
	}
	return out
}

// showHint is the command that prints a connection string for a datasource on server.
func showHint(server string) string {
	if server == state.DefaultServer {
		return "pmon show <datasource>"
	}
	return "pmon show " + server + " <datasource>"
}
