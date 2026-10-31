package edge

import (
	"fmt"
	"net"

	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

const (
	mysqlServerVersion      = "8.0.40-proxy-monster"
	maxMySQLHandshakePacket = 64 << 10
	mysqlSSLRequestSeq      = 1
	mysqlErrPacketHeader    = 0xff
)

func openMySQL(client net.Conn, connID uint32) (opening, error) {
	scramble, err := mysqlwire.Scramble()
	if err != nil {
		return opening{}, err
	}
	greeting := mysqlwire.ServerGreetingSSL(connID, scramble, mysqlServerVersion, true)
	if err := mysqlwire.WritePacket(client, 0, greeting); err != nil {
		return opening{}, err
	}
	seq, sslRequest, err := mysqlwire.ReadPacketLimited(client, maxMySQLHandshakePacket)
	if err != nil {
		return opening{}, err
	}
	if !mysqlwire.LooksLikeSSLRequest(sslRequest) {
		_ = mysqlwire.WritePacket(client, seq+1, mysqlwire.ErrPacketState(
			1045,
			"28000",
			"proxy-monster: TLS required; reconnect with ssl-mode=VERIFY_IDENTITY",
		))
		return opening{}, errPlaintext
	}
	if seq != mysqlSSLRequestSeq {
		return opening{}, fmt.Errorf("mysql SSLRequest has sequence id %d, want %d", seq, mysqlSSLRequestSeq)
	}
	serverName, hello, err := peekClientHello(client)
	if err != nil {
		return opening{}, err
	}
	prepare := func(backend net.Conn) error {
		greetingSeq, backendGreeting, err := mysqlwire.ReadPacketLimited(backend, maxMySQLHandshakePacket)
		if err != nil {
			return fmt.Errorf("reading the backend greeting: %w", err)
		}
		if len(backendGreeting) > 0 && backendGreeting[0] == mysqlErrPacketHeader {
			return fmt.Errorf("backend refused the connection: %s", mysqlwire.ErrString(backendGreeting))
		}
		if greetingSeq != 0 || !mysqlwire.GreetingOffersSSL(backendGreeting) {
			return errBackendNoTLS
		}
		return mysqlwire.WritePacket(backend, seq, sslRequest)
	}
	return opening{serverName: serverName, hello: hello, prepare: prepare}, nil
}
