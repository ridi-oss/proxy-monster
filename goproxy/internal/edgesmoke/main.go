package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/go-sql-driver/mysql"
)

func main() {
	addr := flag.String("addr", "", "the edge's host:port")
	serverName := flag.String("sni", "", "TLS server name the edge routes on")
	ca := flag.String("ca", "", "PEM bundle to trust")
	user := flag.String("user", "", "MySQL user; the password is MYSQL_PWD")
	database := flag.String("db", "", "database to connect to")
	query := flag.String("e", "", "statement to run")
	flag.Parse()
	if err := run(*addr, *serverName, *ca, *user, *database, *query); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(addr, serverName, ca, user, database, query string) error {
	pem, err := os.ReadFile(ca)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return errors.New("no certificate in " + ca)
	}
	cfg := mysql.NewConfig()
	cfg.Net, cfg.Addr, cfg.User, cfg.Passwd, cfg.DBName = "tcp", addr, user, os.Getenv("MYSQL_PWD"), database
	cfg.AllowCleartextPasswords = true
	cfg.TLS = &tls.Config{ServerName: serverName, RootCAs: pool, MinVersion: tls.VersionTLS12}
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return err
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	rows, err := db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return err
	}
	values := make([]sql.NullString, len(columns))
	targets := make([]any, len(columns))
	for i := range values {
		targets[i] = &values[i]
	}
	for rows.Next() {
		if err := rows.Scan(targets...); err != nil {
			return err
		}
		cells := make([]string, len(values))
		for i, v := range values {
			cells[i] = v.String
		}
		fmt.Println(strings.Join(cells, "\t"))
	}
	return rows.Err()
}
