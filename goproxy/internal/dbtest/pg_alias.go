package dbtest

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// PostgresAlias rewrites only the startup database; authentication and query traffic reach the real server unchanged.
func PostgresAlias(t testing.TB, target TargetDb, alias string) (TargetDb, *atomic.Uint64) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	var mu sync.Mutex
	connections := make(map[net.Conn]struct{})
	track := func(conn net.Conn) bool {
		mu.Lock()
		defer mu.Unlock()
		if ctx.Err() != nil {
			_ = conn.Close()
			return false
		}
		connections[conn] = struct{}{}
		return true
	}
	untrack := func(conn net.Conn) {
		_ = conn.Close()
		mu.Lock()
		delete(connections, conn)
		mu.Unlock()
	}
	rewritten := new(atomic.Uint64)
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			if !track(client) {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer untrack(client)
				startup, err := aliasStartup(client, alias, target.DB)
				if err != nil {
					if ctx.Err() == nil && !errors.Is(err, io.EOF) {
						t.Errorf("alias startup: %v", err)
					}
					return
				}
				dialer := net.Dialer{Timeout: 5 * time.Second}
				upstream, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
				if err != nil {
					if ctx.Err() == nil {
						t.Errorf("alias target dial: %v", err)
					}
					return
				}
				if !track(upstream) {
					return
				}
				defer untrack(upstream)
				if _, err := upstream.Write(startup); err != nil {
					return
				}
				rewritten.Add(1)
				copyDone := make(chan struct{})
				go func() {
					_, _ = io.Copy(upstream, client)
					_ = upstream.Close()
					close(copyDone)
				}()
				_, _ = io.Copy(client, upstream)
				_ = client.Close()
				<-copyDone
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		<-acceptDone
		mu.Lock()
		for conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	address := listener.Addr().(*net.TCPAddr)
	return TargetDb{Host: address.IP.String(), Port: address.Port, DB: alias, User: target.User, Password: target.Password}, rewritten
}

func aliasStartup(client net.Conn, alias, database string) ([]byte, error) {
	for {
		var header [4]byte
		if _, err := io.ReadFull(client, header[:]); err != nil {
			return nil, err
		}
		length := binary.BigEndian.Uint32(header[:])
		if length < 8 || length > 1<<20 {
			return nil, fmt.Errorf("invalid startup length %d", length)
		}
		body := make([]byte, length-4)
		if _, err := io.ReadFull(client, body); err != nil {
			return nil, err
		}
		code := binary.BigEndian.Uint32(body[:4])
		if code == 80877103 || code == 80877104 {
			if _, err := client.Write([]byte{'N'}); err != nil {
				return nil, err
			}
			continue
		}
		var startup pgproto3.StartupMessage
		if err := startup.Decode(body); err != nil {
			return nil, err
		}
		if got := startup.Parameters["database"]; got != alias {
			return nil, fmt.Errorf("startup database %q, want alias %q", got, alias)
		}
		startup.Parameters["database"] = database
		return startup.Encode(nil)
	}
}
