package daemon

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	pgProtocolVersion30      = 196608
	pgProtocolVersion32      = 196610
	pgCancelRequest          = 80877102
	pgSSLRequest             = 80877103
	pgGSSENCRequest          = 80877104
	maxPGStartupPacket       = 4 + 10_000
	minPGCancelPacket        = 16
	maxPGCancelPacket        = 268
	maxPGAuthBody            = 8192
	maxPGStartupResponseBody = 1 << 20
)

var errPostgresLocalAuth = errors.New("access denied")

func brokerPostgres(local net.Conn, proxyAddr, certChainPEM string, wireTLS bool, token, localPassword string) error {
	startup, cancel, err := localPostgresHandshake(local, localPassword)
	if err != nil {
		if errors.Is(err, errPostgresLocalAuth) {
			_ = writePostgresError(local, "28P01", "proxy-monster: access denied")
		}
		return err
	}
	if cancel != nil {
		return forwardPostgresCancel(proxyAddr, certChainPEM, wireTLS, cancel)
	}
	if err := local.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return err
	}

	raw, err := net.DialTimeout("tcp", proxyAddr, dialTimeout)
	if err != nil {
		_ = writePostgresError(local, "08001", "proxy-monster: cannot reach proxy")
		return err
	}
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return err
	}

	up, responded, err := postgresProxyConnect(raw, hostOf(proxyAddr), certChainPEM, wireTLS, startup, token, local)
	if err != nil {
		if !responded {
			_ = writePostgresError(local, "08001", "proxy-monster: "+err.Error())
		}
		return err
	}
	if err := up.SetDeadline(time.Time{}); err != nil {
		return err
	}
	if err := local.SetDeadline(time.Time{}); err != nil {
		return err
	}
	pipe(up, local)
	return nil
}

func postgresProtocolNegotiationBody(unrecognized []string) []byte {
	body := binary.BigEndian.AppendUint32(nil, 0)
	body = binary.BigEndian.AppendUint32(body, uint32(len(unrecognized)))
	for _, name := range unrecognized {
		body = append(body, name...)
		body = append(body, 0)
	}
	return body
}

func normalizePostgresStartup(packet []byte) ([]byte, []string, error) {
	if len(packet) < 9 {
		return nil, nil, errors.New("invalid postgres startup parameters")
	}
	code := binary.BigEndian.Uint32(packet[4:8])
	body := packet[8:]
	params := make([]byte, 0, len(body))
	unrecognized := []string{}
	for len(body) > 1 {
		nameEnd := bytes.IndexByte(body, 0)
		if nameEnd <= 0 {
			return nil, nil, errors.New("invalid postgres startup parameter name")
		}
		name := string(body[:nameEnd])
		body = body[nameEnd+1:]
		valueEnd := bytes.IndexByte(body, 0)
		if valueEnd < 0 {
			return nil, nil, errors.New("invalid postgres startup parameter value")
		}
		value := body[:valueEnd]
		body = body[valueEnd+1:]
		if strings.HasPrefix(name, "_pq_.") {
			unrecognized = append(unrecognized, name)
			continue
		}
		params = append(params, name...)
		params = append(params, 0)
		params = append(params, value...)
		params = append(params, 0)
	}
	if len(body) != 1 || body[0] != 0 {
		return nil, nil, errors.New("invalid postgres startup terminator")
	}
	if code == pgProtocolVersion30 && len(unrecognized) == 0 {
		return packet, nil, nil
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(4+4+len(params)+1))
	out = binary.BigEndian.AppendUint32(out, pgProtocolVersion30)
	out = append(out, params...)
	out = append(out, 0)
	return out, unrecognized, nil
}

func localPostgresHandshake(local net.Conn, localPassword string) (startup, cancel []byte, err error) {
	for {
		packet, code, err := readPostgresStartup(local)
		if err != nil {
			return nil, nil, err
		}
		switch code {
		case pgSSLRequest, pgGSSENCRequest:
			if _, err := local.Write([]byte{'N'}); err != nil {
				return nil, nil, err
			}
		case pgCancelRequest:
			if len(packet) < minPGCancelPacket || len(packet) > maxPGCancelPacket {
				return nil, nil, fmt.Errorf("invalid postgres cancel request length %d", len(packet))
			}
			return nil, packet, nil
		case pgProtocolVersion30, pgProtocolVersion32:
			startup, unrecognized, err := normalizePostgresStartup(packet)
			if err != nil {
				return nil, nil, err
			}
			if code == pgProtocolVersion32 || len(unrecognized) > 0 {
				if err := writePostgresFrame(local, 'v', postgresProtocolNegotiationBody(unrecognized)); err != nil {
					return nil, nil, err
				}
			}
			if err := writePostgresFrame(local, 'R', uint32Bytes(3)); err != nil {
				return nil, nil, err
			}
			typ, body, _, err := readPostgresFrame(local, maxPGAuthBody)
			if err != nil {
				return nil, nil, err
			}
			if typ != 'p' || len(body) == 0 || body[len(body)-1] != 0 || localPassword == "" {
				return nil, nil, errPostgresLocalAuth
			}
			password := body[:len(body)-1]
			if subtle.ConstantTimeCompare(password, []byte(localPassword)) != 1 {
				return nil, nil, errPostgresLocalAuth
			}
			return startup, nil, nil
		default:
			_ = writePostgresError(local, "08P01", "proxy-monster: unsupported startup packet")
			return nil, nil, fmt.Errorf("unsupported postgres startup code %d", code)
		}
	}
}

func postgresProxyConnect(
	raw net.Conn,
	serverName, certChainPEM string,
	wireTLS bool,
	startup []byte,
	token string,
	local io.Writer,
) (net.Conn, bool, error) {
	up, err := postgresUpgrade(raw, serverName, certChainPEM, wireTLS)
	if err != nil {
		return nil, false, err
	}
	if err := writePostgresBytes(up, startup); err != nil {
		return nil, false, err
	}
	var typ byte
	var body, rawFrame []byte
	for {
		typ, body, rawFrame, err = readPostgresFrame(up, maxPGStartupResponseBody)
		if err != nil {
			return nil, false, err
		}
		if typ != 'v' {
			break
		}
	}
	if typ == 'E' {
		return nil, true, forwardPostgresResponse(local, rawFrame, "proxy rejected postgres startup")
	}
	if typ != 'R' || len(body) != 4 || binary.BigEndian.Uint32(body) != 3 {
		return nil, false, fmt.Errorf("unexpected authentication request from proxy")
	}
	password := append([]byte(token), 0)
	if err := writePostgresFrame(up, 'p', password); err != nil {
		return nil, false, err
	}
	typ, body, rawFrame, err = readPostgresFrame(up, maxPGStartupResponseBody)
	if err != nil {
		return nil, false, err
	}
	if typ == 'E' {
		return nil, true, forwardPostgresResponse(local, rawFrame, "proxy rejected postgres authentication")
	}
	if typ != 'R' || len(body) != 4 || binary.BigEndian.Uint32(body) != 0 {
		return nil, false, fmt.Errorf("unexpected authentication result from proxy")
	}
	if err := writePostgresBytes(local, rawFrame); err != nil {
		return nil, true, err
	}

	for {
		typ, body, rawFrame, err = readPostgresFrame(up, maxPGStartupResponseBody)
		if err != nil {
			return nil, true, err
		}
		if err := writePostgresBytes(local, rawFrame); err != nil {
			return nil, true, err
		}
		if typ == 'E' {
			return nil, true, errors.New("proxy rejected postgres startup")
		}
		if typ == 'Z' {
			if len(body) != 1 {
				return nil, true, fmt.Errorf("invalid ReadyForQuery from proxy")
			}
			return up, true, nil
		}
	}
}

func forwardPostgresResponse(w io.Writer, frame []byte, message string) error {
	if err := writePostgresBytes(w, frame); err != nil {
		return err
	}
	return errors.New(message)
}

func writePostgresBytes(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func postgresUpgrade(raw net.Conn, serverName, certChainPEM string, wireTLS bool) (net.Conn, error) {
	if _, err := raw.Write(postgresStartupPacket(pgSSLRequest)); err != nil {
		return nil, err
	}
	var response [1]byte
	if _, err := io.ReadFull(raw, response[:]); err != nil {
		return nil, err
	}
	switch response[0] {
	case 'S':
		tlsCfg, err := upstreamTLSConfig(serverName, certChainPEM)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(raw, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			return nil, fmt.Errorf("TLS handshake with proxy failed: %w", err)
		}
		return tlsConn, nil
	case 'N':
		if wireTLS {
			return nil, fmt.Errorf("the control plane says this datasource's proxy serves TLS but it refused the SSL request — refusing to send credentials in plaintext")
		}
		return raw, nil
	default:
		return nil, fmt.Errorf("unexpected SSL response from proxy: %q", response[0])
	}
}

func forwardPostgresCancel(proxyAddr, certChainPEM string, wireTLS bool, packet []byte) error {
	raw, err := net.DialTimeout("tcp", proxyAddr, dialTimeout)
	if err != nil {
		return err
	}
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return err
	}
	up, err := postgresUpgrade(raw, hostOf(proxyAddr), certChainPEM, wireTLS)
	if err != nil {
		return err
	}
	_, err = up.Write(packet)
	return err
}

func rejectPostgresUnavailable(local net.Conn) error {
	for {
		_, code, err := readPostgresStartup(local)
		if err != nil {
			return err
		}
		switch code {
		case pgSSLRequest, pgGSSENCRequest:
			if _, err := local.Write([]byte{'N'}); err != nil {
				return err
			}
		case pgCancelRequest:
			return nil
		default:
			return writePostgresError(local, "08004", "proxy-monster: datasource no longer available")
		}
	}
}

func readPostgresStartup(r io.Reader) ([]byte, uint32, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, 0, err
	}
	length := int(binary.BigEndian.Uint32(header[:]))
	if length < 8 || length > maxPGStartupPacket {
		return nil, 0, fmt.Errorf("invalid postgres startup packet length %d", length)
	}
	packet := make([]byte, length)
	copy(packet, header[:])
	if _, err := io.ReadFull(r, packet[4:]); err != nil {
		return nil, 0, err
	}
	return packet, binary.BigEndian.Uint32(packet[4:8]), nil
}

func readPostgresFrame(r io.Reader, maxBody int) (byte, []byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, nil, err
	}
	length := int(binary.BigEndian.Uint32(header[1:]))
	if length < 4 || length-4 > maxBody {
		return 0, nil, nil, fmt.Errorf("invalid postgres frame length %d", length)
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, nil, err
	}
	raw := make([]byte, 0, len(header)+len(body))
	raw = append(raw, header[:]...)
	raw = append(raw, body...)
	return header[0], body, raw, nil
}

func writePostgresFrame(w io.Writer, typ byte, body []byte) error {
	frame := make([]byte, 0, 5+len(body))
	frame = append(frame, typ)
	frame = binary.BigEndian.AppendUint32(frame, uint32(4+len(body)))
	frame = append(frame, body...)
	_, err := w.Write(frame)
	return err
}

func writePostgresError(w io.Writer, code, message string) error {
	body := make([]byte, 0, len(code)+len(message)+32)
	for _, field := range []struct {
		typ   byte
		value string
	}{{'S', "FATAL"}, {'V', "FATAL"}, {'C', code}, {'M', message}} {
		body = append(body, field.typ)
		body = append(body, field.value...)
		body = append(body, 0)
	}
	body = append(body, 0)
	return writePostgresFrame(w, 'E', body)
}

func postgresStartupPacket(code uint32) []byte {
	packet := make([]byte, 0, 8)
	packet = binary.BigEndian.AppendUint32(packet, 8)
	packet = binary.BigEndian.AppendUint32(packet, code)
	return packet
}

func uint32Bytes(v uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, v)
}
