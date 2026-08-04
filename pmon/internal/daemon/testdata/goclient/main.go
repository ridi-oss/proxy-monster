// Command goclient is the Go-driver client for the client-interop e2e suite: it connects with the
// go-sql-driver DSN `pmon show --go-dsn` prints (passed via PM_DSN), selects its database, and reads the
// seed row. It lives under testdata so it is never part of a normal build; the e2e test cross-compiles it
// for the container and runs it. Success is the three markers the suite asserts on.
package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	db, err := sql.Open("mysql", os.Getenv("PM_DSN"))
	if err != nil {
		fmt.Println("ERR open:", err)
		os.Exit(1)
	}
	defer db.Close()

	var dbName, name string
	if err := db.QueryRow("SELECT DATABASE()").Scan(&dbName); err != nil {
		fmt.Println("ERR db:", err)
		os.Exit(1)
	}
	fmt.Println("DB=" + dbName)
	if err := db.QueryRow("SELECT name FROM members WHERE id=1").Scan(&name); err != nil {
		fmt.Println("ERR row:", err)
		os.Exit(1)
	}
	fmt.Println("ROW=" + name)
	fmt.Println("GO_OK")
}
