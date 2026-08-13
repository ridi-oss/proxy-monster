package pgproxy

import "net"

// switchConn lets a pgproto3 codec retain its buffered reader while the underlying socket changes. During
// frontend startup, strictReads prevents pgproto3's chunk reader from swallowing a pipelined TLS ClientHello;
// during target-DB startup, it prevents reads beyond ReadyForQuery before dialTargetDbAuth returns the connection.
type switchConn struct {
	net.Conn
	strictReads bool
}

func (c *switchConn) Read(payload []byte) (int, error) {
	if c.strictReads && len(payload) > 1 {
		payload = payload[:1]
	}
	return c.Conn.Read(payload)
}
