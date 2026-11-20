package edge

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

const (
	maxMySQLHandshakePacket = 64 << 10
	mysqlSSLRequestSeq      = 1
	mysqlErrPacketHeader    = 0xff
	mysqlServerVersion      = "8.0.40-proxy-monster"
	mysqlConnectWithDB      = true
)

func mysqlGreeting(connID uint32, scramble []byte) []byte {
	return mysqlwire.ServerGreetingSSL(connID, scramble, mysqlServerVersion, mysqlConnectWithDB)
}

func openMySQL(client net.Conn, connID uint32) (opening, error) {
	scramble, err := mysqlwire.Scramble()
	if err != nil {
		return opening{}, err
	}
	greeting := mysqlGreeting(connID, scramble)
	_, offered, ok := parseMySQLGreeting(greeting)
	if !ok {
		return opening{}, fmt.Errorf("edge built an unparsable MySQL greeting")
	}
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
		_, backendCaps, ok := parseMySQLGreeting(backendGreeting)
		if !ok {
			return fmt.Errorf("backend greeting is not a HandshakeV10 packet")
		}
		if missing := offered &^ backendCaps; missing != 0 {
			return fmt.Errorf("backend greeting lacks capabilities 0x%08x that the edge offered", missing)
		}
		return mysqlwire.WritePacket(backend, seq, sslRequest)
	}
	return opening{serverName: serverName, hello: hello, prepare: prepare}, nil
}

func parseMySQLGreeting(payload []byte) (version string, capabilities uint32, ok bool) {
	const protocolV10 = 10
	if len(payload) < 1 || payload[0] != protocolV10 {
		return "", 0, false
	}
	i := 1
	for i < len(payload) && payload[i] != 0 {
		i++
	}
	if i >= len(payload) {
		return "", 0, false
	}
	version = string(payload[1:i])
	i += 1 + 4 + 8 + 1
	if i+2 > len(payload) {
		return "", 0, false
	}
	capabilities = uint32(binary.LittleEndian.Uint16(payload[i : i+2]))
	if i+7 <= len(payload) {
		capabilities |= uint32(binary.LittleEndian.Uint16(payload[i+5:i+7])) << 16
	}
	return version, capabilities, true
}
