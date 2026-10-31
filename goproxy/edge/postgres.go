package edge

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/jackc/pgx/v5/pgproto3"
)

const (
	postgresCancelRequestCode      = 80877102
	postgresSSLRequestCode         = 80877103
	postgresGSSEncRequestCode      = 80877104
	postgresProtocolMajor3         = 3
	minPostgresStartupPacket       = 8
	maxPostgresStartupPacket       = 10000
	postgresTLSAccepted       byte = 'S'
	postgresTLSRefused        byte = 'N'
)

var errCancelRequest = errors.New("postgres CancelRequest is not routed")

func openPostgres(client net.Conn) (opening, error) {
	gssRefused := false
	for {
		code, err := readPostgresStartup(client)
		if err != nil {
			return opening{}, err
		}
		switch {
		case code == postgresSSLRequestCode:
			if _, err := client.Write([]byte{postgresTLSAccepted}); err != nil {
				return opening{}, err
			}
			serverName, hello, err := peekClientHello(client)
			if err != nil {
				return opening{}, err
			}
			return opening{serverName: serverName, hello: hello, prepare: requestPostgresTLS}, nil
		case code == postgresGSSEncRequestCode && !gssRefused:
			gssRefused = true
			if _, err := client.Write([]byte{postgresTLSRefused}); err != nil {
				return opening{}, err
			}
		case code == postgresCancelRequestCode:
			return opening{}, errCancelRequest
		case code>>16 == postgresProtocolMajor3:
			_ = writePostgresFatal(client, "28000", "proxy-monster: TLS required; reconnect with sslmode=verify-full")
			return opening{}, errPlaintext
		default:
			return opening{}, fmt.Errorf("postgres startup packet has unexpected code %d", code)
		}
	}
}

func readPostgresStartup(r io.Reader) (uint32, error) {
	var header [8]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, err
	}
	length := binary.BigEndian.Uint32(header[:4])
	if length < minPostgresStartupPacket || length > maxPostgresStartupPacket {
		return 0, fmt.Errorf("postgres startup packet length %d is out of range", length)
	}
	if _, err := io.CopyN(io.Discard, r, int64(length-minPostgresStartupPacket)); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(header[4:]), nil
}

func writePostgresFatal(w io.Writer, code, message string) error {
	packet, err := (&pgproto3.ErrorResponse{
		Severity:            "FATAL",
		SeverityUnlocalized: "FATAL",
		Code:                code,
		Message:             message,
	}).Encode(nil)
	if err != nil {
		return err
	}
	_, err = w.Write(packet)
	return err
}

func requestPostgresTLS(backend net.Conn) error {
	request, err := (&pgproto3.SSLRequest{}).Encode(nil)
	if err != nil {
		return err
	}
	if _, err := backend.Write(request); err != nil {
		return err
	}
	var answer [1]byte
	if _, err := io.ReadFull(backend, answer[:]); err != nil {
		return fmt.Errorf("reading the backend SSLRequest answer: %w", err)
	}
	if answer[0] != postgresTLSAccepted {
		return errBackendNoTLS
	}
	return nil
}
