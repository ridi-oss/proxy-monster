package mysql

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/mysqlwire"
	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

func TestUnavailableSessionUsesMySQLRejection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- (Provider{}).Serve(context.Background(), listener, func() (driver.Endpoint, driver.Credentials, bool) {
			return driver.Endpoint{}, driver.Credentials{}, false
		})
	}()
	t.Cleanup(func() {
		listener.Close()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	local, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	if err := local.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	sequence, packet, err := mysqlwire.ReadPacket(local)
	if err != nil {
		t.Fatal(err)
	}
	if sequence != 2 || len(packet) == 0 || packet[0] != 0xff || mysqlwire.ErrString(packet) != "proxy-monster: datasource no longer available" {
		t.Fatalf("unavailable reply: sequence %d, packet %x", sequence, packet)
	}
}
