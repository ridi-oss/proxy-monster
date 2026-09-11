package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func main() {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("PM_DSN"))
	if err != nil {
		fmt.Println("ERR connect:", err)
		os.Exit(1)
	}
	defer conn.Close(ctx)

	var dbName, name string
	if err := conn.QueryRow(ctx, "SELECT current_database()").Scan(&dbName); err != nil {
		fmt.Println("ERR db:", err)
		os.Exit(1)
	}
	fmt.Println("DB=" + dbName)
	if err := conn.QueryRow(ctx, "SELECT name FROM members WHERE id=1").Scan(&name); err != nil {
		fmt.Println("ERR row:", err)
		os.Exit(1)
	}
	fmt.Println("ROW=" + name)

	result := conn.PgConn().Exec(ctx, "SELECT pg_sleep(30)")
	cancelDone := make(chan error, 1)
	go func() {
		time.Sleep(time.Second)
		cancelCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cancelDone <- conn.PgConn().CancelRequest(cancelCtx)
	}()
	for result.NextResult() {
	}
	var pgErr *pgconn.PgError
	if err := result.Close(); !errors.As(err, &pgErr) || pgErr.Code != "57014" {
		fmt.Println("ERR cancel result:", err)
		os.Exit(1)
	}
	if err := <-cancelDone; err != nil {
		fmt.Println("ERR cancel request:", err)
		os.Exit(1)
	}
	fmt.Println("CANCEL_OK")
	fmt.Println("GO_OK")
}
