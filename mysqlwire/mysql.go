// Package mysqlwire holds the low-level MySQL wire-protocol framing and message primitives
// shared between pmon (the local broker/CLI) and the data-plane proxy. It is deliberately
// dependency-free: packet framing, capability flags, and the handful of handshake/OK/ERR
// message builders + parsers. Higher-level flows — who authenticates how, what gets relayed,
// enforcement — live in each importer, not here.
package mysqlwire

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

// MySQL capability flags (the subset the handshake needs).
const (
	CapLongPassword     = 0x00000001
	CapConnectWithDB    = 0x00000008
	CapProtocol41       = 0x00000200
	CapSSL              = 0x00000800
	CapTransactions     = 0x00002000
	CapSecureConn       = 0x00008000
	CapPluginAuth       = 0x00080000
	CapPluginAuthLenenc = 0x00200000
	CapSessionTrack     = 0x00800000
	CapDeprecateEOF     = 0x01000000
)

// MySQL command bytes.
const (
	ComQuit             = 0x01
	ComInitDB           = 0x02
	ComQuery            = 0x03
	ComFieldList        = 0x04
	ComPing             = 0x0e
	ComStmtPrepare      = 0x16
	ComStmtExecute      = 0x17
	ComStmtSendLongData = 0x18
	ComStmtClose        = 0x19
	ComStmtReset        = 0x1a
)

// caching_sha2_password protocol markers. After the client sends its initial caching_sha2 response the
// server replies with an AuthMoreData packet whose first byte is AuthMoreData and whose second byte is
// the fast-auth outcome: CachingSHA2FastAuthSuccess means the credential was already cached (the OK
// packet follows immediately), CachingSHA2FullAuth means the client must run the full exchange. Over a
// non-TLS link the client requests the server's RSA public key by sending a one-byte packet carrying
// CachingSHA2RequestPublicKey. Mirrors the go-sql-driver/mysql const.go markers.
const (
	AuthMoreData                = 0x01
	CachingSHA2RequestPublicKey = 0x02
	CachingSHA2FastAuthSuccess  = 0x03
	CachingSHA2FullAuth         = 0x04
)

// MaxPacketPayload is the largest payload one physical MySQL packet can carry. A payload of exactly
// this size requires a continuation packet, which higher-level callers must handle explicitly.
const MaxPacketPayload = 0xFFFFFF

// ErrPacketTooLarge reports a packet header or outbound payload that exceeds its permitted size.
var ErrPacketTooLarge = errors.New("mysqlwire: packet payload exceeds limit")

// ReadPacket reads one MySQL packet: [len:3 LE][seq:1][payload].
func ReadPacket(r io.Reader) (seq byte, payload []byte, err error) {
	return ReadPacketLimited(r, MaxPacketPayload)
}

// ReadPacketLimited reads one physical packet but rejects its declared payload length before allocating
// when it exceeds maxPayload. Callers use a small limit during unauthenticated handshake phases.
func ReadPacketLimited(r io.Reader, maxPayload int) (seq byte, payload []byte, err error) {
	var hdr [4]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	seq = hdr[3]
	if maxPayload < 0 || n > maxPayload {
		return seq, nil, fmt.Errorf("%w: %d > %d", ErrPacketTooLarge, n, maxPayload)
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return seq, nil, err
	}
	return seq, payload, nil
}

// WritePacket frames and writes one physical MySQL packet.
func WritePacket(w io.Writer, seq byte, payload []byte) error {
	if len(payload) > MaxPacketPayload {
		return fmt.Errorf("%w: %d > %d", ErrPacketTooLarge, len(payload), MaxPacketPayload)
	}
	hdr := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), seq}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ComQueryPayload builds a COM_QUERY command payload.
func ComQueryPayload(sql string) []byte {
	payload := make([]byte, 1, 1+len(sql))
	payload[0] = ComQuery
	return append(payload, sql...)
}

// ComStmtPreparePayload builds a COM_STMT_PREPARE command payload.
func ComStmtPreparePayload(sql string) []byte {
	payload := make([]byte, 1, 1+len(sql))
	payload[0] = ComStmtPrepare
	return append(payload, sql...)
}

// AppendLenenc appends a MySQL length-encoded integer.
func AppendLenenc(dst []byte, v uint64) []byte {
	switch {
	case v < 251:
		return append(dst, byte(v))
	case v < 65536:
		dst = append(dst, 0xfc)
		return binary.LittleEndian.AppendUint16(dst, uint16(v))
	case v < 16777216:
		return append(dst, 0xfd, byte(v), byte(v>>8), byte(v>>16))
	default:
		dst = append(dst, 0xfe)
		return binary.LittleEndian.AppendUint64(dst, v)
	}
}

// AppendLenencStr appends a UTF-8 string prefixed by its byte length.
func AppendLenencStr(dst []byte, s string) []byte {
	dst = AppendLenenc(dst, uint64(len(s)))
	return append(dst, s...)
}

const serverGreetingCapabilities = uint32(CapLongPassword | CapProtocol41 | CapSecureConn | CapPluginAuth | CapTransactions | CapDeprecateEOF)

// ServerGreeting builds an Initial Handshake (v10) advertising mysql_native_password without SSL.
// ServerGreetingSSL builds the same greeting with CLIENT_SSL advertised. serverVersion is the
// NUL-terminated version string the greeting reports to the client.
//
// connectWithDB advertises CapConnectWithDB. An importer passes true only if it FORWARDS the
// handshake-supplied database (parsing it via ParseHandshakeResponse's connectWithDBSupported and
// issuing a COM_INIT_DB); otherwise the client's selected database is silently dropped. Both importers
// forward it — goproxy/mysqlproxy relays it to the backend, and pmon's local broker replays it upstream
// as COM_INIT_DB — so both pass true. Advertising it is also what keeps a JDBC driver parseable: such a
// driver writes the database field whether or not the capability was offered, so a greeting that
// withholds it leaves that field unclaimed and the auth-plugin name that follows is misread as the
// database.
func ServerGreeting(connID uint32, scramble []byte, serverVersion string, connectWithDB bool) []byte {
	return serverGreeting(connID, scramble, serverVersion, greetingCapabilities(connectWithDB))
}

// ServerGreetingSSL builds the TLS-capable Initial Handshake variant.
func ServerGreetingSSL(connID uint32, scramble []byte, serverVersion string, connectWithDB bool) []byte {
	return serverGreeting(connID, scramble, serverVersion, greetingCapabilities(connectWithDB)|CapSSL)
}

func greetingCapabilities(connectWithDB bool) uint32 {
	caps := serverGreetingCapabilities
	if connectWithDB {
		caps |= CapConnectWithDB
	}
	return caps
}

func serverGreeting(connID uint32, scramble []byte, serverVersion string, caps uint32) []byte {
	var b []byte
	b = append(b, 10) // protocol version
	b = append(b, []byte(serverVersion)...)
	b = append(b, 0)
	b = binary.LittleEndian.AppendUint32(b, connID)
	b = append(b, scramble[:8]...)
	b = append(b, 0) // filler
	// DEPRECATE_EOF is advertised so a modern client opts into it; callers mirror the client's EOF
	// choice upstream so framing matches.
	b = append(b, byte(caps), byte(caps>>8))
	b = append(b, 45)         // charset utf8mb4
	b = append(b, 0x02, 0x00) // status: autocommit
	b = append(b, byte(caps>>16), byte(caps>>24))
	b = append(b, 21)                  // auth-plugin-data length
	b = append(b, make([]byte, 10)...) // reserved
	b = append(b, scramble[8:20]...)
	b = append(b, 0)
	b = append(b, []byte("mysql_native_password")...)
	b = append(b, 0)
	return b
}

// OKPacket is a minimal PROTOCOL_41 OK.
func OKPacket() []byte {
	return []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
}

// ErrPacket builds a PROTOCOL_41 ERR packet with the general HY000 SQL state.
func ErrPacket(code int, msg string) []byte {
	return ErrPacketState(code, "HY000", msg)
}

// ErrPacketState builds a PROTOCOL_41 ERR packet.
func ErrPacketState(code int, sqlState, msg string) []byte {
	for len(sqlState) < 5 {
		sqlState += "0"
	}
	if len(sqlState) > 5 {
		sqlState = sqlState[:5]
	}
	b := []byte{0xff, byte(code), byte(code >> 8), '#'}
	b = append(b, sqlState...)
	return append(b, msg...)
}

// AuthSwitchClearPassword builds an AuthSwitchRequest for mysql_clear_password.
func AuthSwitchClearPassword() []byte {
	return []byte("\xfemysql_clear_password\x00")
}

// Scramble returns a fresh 20-byte auth scramble drawn from printable ASCII (0x21..0x7e), the exact
// range a real MySQL server uses.
//
// The scramble must be printable, not merely NUL-free. It travels NUL-terminated, so a NUL truncates
// the salt for a client that reads it as a C string; but beyond that, some clients (notably MySQL
// Connector/J, and so DBeaver) read the auth-plugin-data through a text decoder and mangle any byte
// >= 0x80 before hashing it — the digest then disagrees with the server's and every such connection is
// denied. A uniformly random 20 bytes hits one of those ~55% of the time, so the failure looks constant
// rather than intermittent. Matching the server's own 94-character range sidesteps both hazards; the
// salt's job is freshness, not a uniform distribution.
func Scramble() ([]byte, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	for i := range b {
		b[i] = 0x21 + b[i]%94
	}
	return b, nil
}

// AuthSwitchCachingSHA2 builds an AuthSwitchRequest for caching_sha2_password carrying scramble. The
// scramble is sent NUL-terminated, as a server does, because the client reads it as a C string and
// would otherwise fold the terminator into the salt it hashes.
func AuthSwitchCachingSHA2(scramble []byte) []byte {
	b := []byte("\xfecaching_sha2_password\x00")
	b = append(b, scramble...)
	return append(b, 0)
}

// AuthMoreDataPacket builds an AuthMoreData packet carrying one status marker — the fast-auth
// outcome a caching_sha2_password server reports after seeing the client's digest.
func AuthMoreDataPacket(marker byte) []byte {
	return []byte{AuthMoreData, marker}
}

// ParseClearPassword returns the clear-password response, stripping one trailing NUL.
func ParseClearPassword(payload []byte) string {
	if len(payload) > 0 && payload[len(payload)-1] == 0 {
		payload = payload[:len(payload)-1]
	}
	return string(payload)
}

// ClientHandshakeResponse builds a HandshakeResponse41 for connecting to a server. The auth
// response is passed through verbatim (callers that rely on an auth-switch send it empty here).
func ClientHandshakeResponse(caps uint32, user string, authResp []byte) []byte {
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, caps)
	b = binary.LittleEndian.AppendUint32(b, 0x01000000) // max packet size (16M)
	b = append(b, 45)                                   // charset
	b = append(b, make([]byte, 23)...)                  // reserved
	b = append(b, []byte(user)...)
	b = append(b, 0)
	b = append(b, byte(len(authResp))) // CLIENT_SECURE_CONNECTION: 1-byte length
	b = append(b, authResp...)
	if caps&CapPluginAuth != 0 {
		b = append(b, []byte("mysql_native_password")...)
		b = append(b, 0)
	}
	return b
}

// SSLRequest builds the short (32-byte) Protocol 41 SSLRequest: caps + max packet + charset +
// 23 reserved, and NOTHING else — the server upgrades to TLS before the real handshake response.
func SSLRequest(caps uint32) []byte {
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, caps)
	b = binary.LittleEndian.AppendUint32(b, 0x01000000) // max packet size (16M)
	b = append(b, 45)                                   // charset (utf8mb4)
	b = append(b, make([]byte, 23)...)                  // reserved
	return b
}

// ClientCapabilities parses the first four little-endian bytes of a handshake response or SSLRequest.
func ClientCapabilities(payload []byte) uint32 {
	if len(payload) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(payload[:4])
}

// LooksLikeSSLRequest reports whether payload is the short Protocol 41 SSLRequest form.
func LooksLikeSSLRequest(payload []byte) bool {
	return len(payload) >= 4 && len(payload) <= 32 && ClientCapabilities(payload)&CapSSL != 0
}

// GreetingOffersSSL parses a HandshakeV10 payload and reports whether the server advertised
// CLIENT_SSL. Layout: proto(1) version(cstr) connid(4) scramble1(8) filler(1) caplow(2)
// charset(1) status(2) caphigh(2) ...
func GreetingOffersSSL(payload []byte) bool {
	i := 1 // protocol version
	for i < len(payload) && payload[i] != 0 {
		i++ // server version cstr
	}
	i++                     // NUL
	i += 4 + 8 + 1          // connid + scramble1 + filler
	if i+4 > len(payload) { // need caplow(2) [+ charset(1) status(2)] caphigh(2)
		return false
	}
	capLow := uint32(binary.LittleEndian.Uint16(payload[i : i+2]))
	if i+5+2 > len(payload) {
		return capLow&CapSSL != 0
	}
	capHigh := uint32(binary.LittleEndian.Uint16(payload[i+5 : i+7]))
	return (capLow|(capHigh<<16))&CapSSL != 0
}

// ErrString extracts the human-readable message from an ERR packet payload.
func ErrString(payload []byte) string {
	i := 3 // 0xff + 2-byte code
	if len(payload) > 3 && payload[3] == '#' {
		i += 6 // '#' + 5-char sqlstate
	}
	if i > len(payload) {
		return "error"
	}
	return string(payload[i:])
}

// Reader is a fail-closed sequential reader over one decoded packet payload.
type Reader struct {
	b []byte
	i int
}

// NewReader returns a Reader positioned at the start of payload.
func NewReader(payload []byte) *Reader { return &Reader{b: payload} }

// U8 reads one unsigned byte.
func (r *Reader) U8() (byte, error) {
	if r.i >= len(r.b) {
		return 0, io.ErrUnexpectedEOF
	}
	v := r.b[r.i]
	r.i++
	return v, nil
}

// U16 reads a little-endian unsigned 16-bit integer.
func (r *Reader) U16() (uint16, error) {
	b, err := r.Bytes(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

// U32 reads a little-endian unsigned 32-bit integer.
func (r *Reader) U32() (uint32, error) {
	b, err := r.Bytes(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

// Skip advances n bytes.
func (r *Reader) Skip(n int) error {
	if n < 0 || n > len(r.b)-r.i {
		return io.ErrUnexpectedEOF
	}
	r.i += n
	return nil
}

// Bytes reads exactly n bytes.
func (r *Reader) Bytes(n int) ([]byte, error) {
	if n < 0 || n > len(r.b)-r.i {
		return nil, io.ErrUnexpectedEOF
	}
	b := r.b[r.i : r.i+n]
	r.i += n
	return b, nil
}

// Cstr reads a NUL-terminated string.
func (r *Reader) Cstr() (string, error) {
	start := r.i
	for r.i < len(r.b) && r.b[r.i] != 0 {
		r.i++
	}
	if r.i == len(r.b) {
		return "", io.ErrUnexpectedEOF
	}
	s := string(r.b[start:r.i])
	r.i++
	return s, nil
}

// Lenenc reads a MySQL length-encoded integer.
func (r *Reader) Lenenc() (uint64, error) {
	first, err := r.U8()
	if err != nil {
		return 0, err
	}
	switch first {
	case 0xfc:
		b, err := r.Bytes(2)
		if err != nil {
			return 0, err
		}
		return uint64(binary.LittleEndian.Uint16(b)), nil
	case 0xfd:
		b, err := r.Bytes(3)
		if err != nil {
			return 0, err
		}
		return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16, nil
	case 0xfe:
		b, err := r.Bytes(8)
		if err != nil {
			return 0, err
		}
		return binary.LittleEndian.Uint64(b), nil
	case 0xfb, 0xff:
		return 0, fmt.Errorf("mysqlwire: invalid length-encoded integer prefix 0x%02x", first)
	default:
		return uint64(first), nil
	}
}

// LenencStr reads a length-encoded string.
func (r *Reader) LenencStr() (string, error) {
	n, err := r.Lenenc()
	if err != nil {
		return "", err
	}
	if n > uint64(len(r.b)-r.i) {
		return "", io.ErrUnexpectedEOF
	}
	b, err := r.Bytes(int(n))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// RowValue reads a text-protocol value, preserving NULL as nil.
func (r *Reader) RowValue() (*string, error) {
	if !r.HasRemaining() {
		return nil, io.ErrUnexpectedEOF
	}
	if r.b[r.i] == 0xfb {
		r.i++
		return nil, nil
	}
	v, err := r.LenencStr()
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// HasRemaining reports whether unread bytes remain.
func (r *Reader) HasRemaining() bool { return r.i < len(r.b) }

// HandshakeResponse is the client handshake data needed by the server role.
type HandshakeResponse struct {
	Capabilities uint32
	Username     string
	Database     string
	// AuthResponse is the client's answer to the greeting's scramble, in whichever encoding its
	// capabilities selected. Empty when the client sent no password at all, which is not the same as
	// a wrong one: a server that treats the two alike accepts every unauthenticated connection.
	AuthResponse []byte
	// AuthPlugin is the plugin the client used to compute AuthResponse, which need not be the one the
	// greeting asked for. Empty when the client negotiated no CapPluginAuth.
	AuthPlugin string
}

// ParseHandshakeResponse parses a Protocol 41 HandshakeResponse. connectWithDBSupported must be the
// SERVER's own CapConnectWithDB support (serverGreetingCapabilities here), not derived from the
// client's reported caps: a real client (e.g. the mysql CLI) still sets its OWN CapConnectWithDB bit
// when given a database, but gates actually WRITING the database field on the server having
// advertised that capability, not on its own request. Trusting the client's bit alone would make
// r.HasRemaining() true (the plugin-name field is still unread) and misread the plugin name as the
// database, relaying it verbatim as a bogus COM_INIT_DB.
func ParseHandshakeResponse(payload []byte, connectWithDBSupported bool) (HandshakeResponse, error) {
	r := NewReader(payload)
	caps, err := r.U32()
	if err != nil {
		return HandshakeResponse{}, err
	}
	if err := r.Skip(4 + 1 + 23); err != nil {
		return HandshakeResponse{}, err
	}
	username, err := r.Cstr()
	if err != nil {
		return HandshakeResponse{}, err
	}
	var authResponse []byte
	switch {
	case caps&CapPluginAuthLenenc != 0:
		n, err := r.Lenenc()
		if err != nil {
			return HandshakeResponse{}, err
		}
		if n > uint64(len(payload)) {
			return HandshakeResponse{}, io.ErrUnexpectedEOF
		}
		if authResponse, err = r.Bytes(int(n)); err != nil {
			return HandshakeResponse{}, io.ErrUnexpectedEOF
		}
	case caps&CapSecureConn != 0:
		n, err := r.U8()
		if err != nil {
			return HandshakeResponse{}, err
		}
		if authResponse, err = r.Bytes(int(n)); err != nil {
			return HandshakeResponse{}, err
		}
	default:
		s, err := r.Cstr()
		if err != nil {
			return HandshakeResponse{}, err
		}
		authResponse = []byte(s)
	}

	database := ""
	if connectWithDBSupported && caps&CapConnectWithDB != 0 && r.HasRemaining() {
		database, err = r.Cstr()
		if err != nil {
			return HandshakeResponse{}, err
		}
	}
	// The plugin the client actually used to compute AuthResponse. A client may answer with a plugin
	// other than the one the greeting named, so a server that verifies the response has to know which
	// digest it is looking at rather than assume its own advertisement was honored. Absent when the
	// client negotiated no CapPluginAuth, which leaves the greeting's plugin as the only claim.
	authPlugin := ""
	if caps&CapPluginAuth != 0 && r.HasRemaining() {
		authPlugin, _ = r.Cstr()
	}
	return HandshakeResponse{
		Capabilities: caps,
		Username:     username,
		Database:     database,
		AuthResponse: authResponse,
		AuthPlugin:   authPlugin,
	}, nil
}

// Greeting is the backend server data needed by the client role.
type Greeting struct {
	ConnectionID uint32
	Scramble     []byte
	AuthPlugin   string
	Capabilities uint32
}

// ParseHandshakeV10 parses a backend Initial Handshake.
func ParseHandshakeV10(payload []byte) (Greeting, error) {
	r := NewReader(payload)
	protocol, err := r.U8()
	if err != nil {
		return Greeting{}, err
	}
	if protocol != 10 {
		return Greeting{}, fmt.Errorf("mysqlwire: unsupported handshake protocol %d", protocol)
	}
	if _, err := r.Cstr(); err != nil {
		return Greeting{}, err
	}
	connectionID, err := r.U32()
	if err != nil {
		return Greeting{}, err
	}
	part1, err := r.Bytes(8)
	if err != nil {
		return Greeting{}, err
	}
	if err := r.Skip(1); err != nil {
		return Greeting{}, err
	}
	capLowerBytes, err := r.Bytes(2)
	if err != nil {
		return Greeting{}, err
	}
	capLower := uint32(binary.LittleEndian.Uint16(capLowerBytes))
	if !r.HasRemaining() {
		return Greeting{ConnectionID: connectionID, Scramble: append([]byte(nil), part1...), AuthPlugin: "mysql_native_password", Capabilities: capLower}, nil
	}
	if err := r.Skip(1 + 2); err != nil {
		return Greeting{}, err
	}
	capUpperBytes, err := r.Bytes(2)
	if err != nil {
		return Greeting{}, err
	}
	caps := capLower | uint32(binary.LittleEndian.Uint16(capUpperBytes))<<16
	authDataLen, err := r.U8()
	if err != nil {
		return Greeting{}, err
	}
	if err := r.Skip(10); err != nil {
		return Greeting{}, err
	}
	part2Len := 13
	if n := int(authDataLen) - 8; n > part2Len {
		part2Len = n
	}
	part2, err := r.Bytes(part2Len)
	if err != nil {
		return Greeting{}, err
	}
	if len(part2) < 12 {
		return Greeting{}, errors.New("mysqlwire: backend greeting scramble is truncated")
	}
	scramble := append(append(make([]byte, 0, 20), part1...), part2[:12]...)
	authPlugin := "mysql_native_password"
	if caps&CapPluginAuth != 0 && r.HasRemaining() {
		authPlugin, err = r.Cstr()
		if err != nil {
			return Greeting{}, err
		}
	}
	return Greeting{ConnectionID: connectionID, Scramble: scramble, AuthPlugin: authPlugin, Capabilities: caps}, nil
}

// NativePassword computes mysql_native_password authentication bytes.
func NativePassword(password string, scramble []byte) []byte {
	if password == "" {
		return []byte{}
	}
	stage1 := sha1.Sum([]byte(password))
	stage2 := sha1.Sum(stage1[:])
	h := sha1.New()
	_, _ = h.Write(scramble)
	_, _ = h.Write(stage2[:])
	seed := h.Sum(nil)
	out := make([]byte, len(stage1))
	for i := range out {
		out[i] = stage1[i] ^ seed[i]
	}
	return out
}

// CachingSHA2Password computes the caching_sha2_password fast-auth response:
// XOR(SHA256(password), SHA256(SHA256(SHA256(password)) ++ scramble)). An empty password yields an
// empty response (the server accepts it directly). This is the response sent in the initial
// HandshakeResponse and in an auth-switch to caching_sha2_password; the server answers with an
// AuthMoreData packet indicating fast-auth success or a demand for full authentication. Mirrors
// go-sql-driver/mysql's scrambleSHA256Password.
func CachingSHA2Password(password string, scramble []byte) []byte {
	if password == "" {
		return []byte{}
	}
	message1 := sha256.Sum256([]byte(password))
	message1Hash := sha256.Sum256(message1[:])
	h := sha256.New()
	_, _ = h.Write(message1Hash[:])
	_, _ = h.Write(scramble)
	message2 := h.Sum(nil)
	out := make([]byte, len(message1))
	for i := range out {
		out[i] = message1[i] ^ message2[i]
	}
	return out
}

// EncryptCachingSHA2Password produces the full-auth response for caching_sha2_password over a NON-TLS
// link: the cleartext password (NUL-terminated) is XOR-obfuscated with the connection scramble (cycled
// to cover the password length), then RSA-OAEP(SHA-1) encrypted with the server's public key. The key
// is the PEM the server sends in its AuthMoreData reply to the public-key request. Over a TLS link the
// caller sends the cleartext password + NUL instead (no encryption). Mirrors go-sql-driver/mysql's
// encryptPassword.
func EncryptCachingSHA2Password(password string, scramble []byte, pubKeyPEM []byte) ([]byte, error) {
	if len(scramble) == 0 {
		return nil, errors.New("mysqlwire: empty scramble for caching_sha2_password full auth")
	}
	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		return nil, errors.New("mysqlwire: server public key is not valid PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mysqlwire: parse server public key: %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("mysqlwire: server public key is %T, want RSA", parsed)
	}
	plain := make([]byte, len(password)+1)
	copy(plain, password)
	for i := range plain {
		plain[i] ^= scramble[i%len(scramble)]
	}
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, plain, nil)
}

// BackendHandshakeResponse builds the service-account HandshakeResponse41. authPlugin names the client
// authentication plugin advertised when CapPluginAuth is set — it MUST match the plugin whose response
// bytes are in authResp (e.g. "mysql_native_password" or "caching_sha2_password"); an empty authPlugin
// defaults to mysql_native_password.
func BackendHandshakeResponse(caps uint32, user string, authResp []byte, database, authPlugin string) []byte {
	if authPlugin == "" {
		authPlugin = "mysql_native_password"
	}
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, caps)
	b = binary.LittleEndian.AppendUint32(b, 0x01000000)
	b = append(b, 45)
	b = append(b, make([]byte, 23)...)
	b = append(b, user...)
	b = append(b, 0)
	b = append(b, byte(len(authResp)))
	b = append(b, authResp...)
	if caps&CapConnectWithDB != 0 && database != "" {
		b = append(b, database...)
		b = append(b, 0)
	}
	if caps&CapPluginAuth != 0 {
		b = append(b, authPlugin...)
		b = append(b, 0)
	}
	return b
}

// StmtPrepareOK holds the statement metadata from a COM_STMT_PREPARE_OK response.
type StmtPrepareOK struct {
	StmtID     uint32
	NumColumns int
	NumParams  int
}

// ParseStmtPrepareOK parses a COM_STMT_PREPARE_OK response.
func ParseStmtPrepareOK(payload []byte) (StmtPrepareOK, error) {
	if len(payload) < 12 {
		return StmtPrepareOK{}, io.ErrUnexpectedEOF
	}
	r := NewReader(payload)
	status, err := r.U8()
	if err != nil {
		return StmtPrepareOK{}, err
	}
	if status != 0x00 {
		return StmtPrepareOK{}, fmt.Errorf("mysqlwire: invalid COM_STMT_PREPARE_OK header 0x%02x", status)
	}
	stmtID, err := r.U32()
	if err != nil {
		return StmtPrepareOK{}, err
	}
	numColumns, err := r.U16()
	if err != nil {
		return StmtPrepareOK{}, err
	}
	numParams, err := r.U16()
	if err != nil {
		return StmtPrepareOK{}, err
	}
	return StmtPrepareOK{StmtID: stmtID, NumColumns: int(numColumns), NumParams: int(numParams)}, nil
}

// StmtID returns the statement ID from a COM_STMT command payload.
func StmtID(payload []byte) (uint32, error) {
	if len(payload) < 5 {
		return 0, io.ErrUnexpectedEOF
	}
	return binary.LittleEndian.Uint32(payload[1:5]), nil
}

// ParseColumnName returns the fifth length-encoded string in a ColumnDefinition41 packet.
func ParseColumnName(payload []byte) (string, error) {
	r := NewReader(payload)
	for range 4 {
		if _, err := r.LenencStr(); err != nil {
			return "", err
		}
	}
	return r.LenencStr()
}

// ParseTextRow decodes one text-protocol result row, preserving NULL.
func ParseTextRow(payload []byte, columnCount int) ([]*string, error) {
	if columnCount < 0 {
		return nil, errors.New("mysqlwire: negative column count")
	}
	r := NewReader(payload)
	values := make([]*string, columnCount)
	for i := range values {
		v, err := r.RowValue()
		if err != nil {
			return nil, err
		}
		values[i] = v
	}
	if r.HasRemaining() {
		return nil, errors.New("mysqlwire: trailing bytes after text row")
	}
	return values, nil
}

// TextRowPayload encodes one text-protocol result row.
func TextRowPayload(values []*string) []byte {
	var b []byte
	for _, v := range values {
		if v == nil {
			b = append(b, 0xfb)
		} else {
			b = AppendLenencStr(b, *v)
		}
	}
	return b
}

// IsResultTerminator reports whether payload is the short EOF/OK result terminator.
func IsResultTerminator(payload []byte) bool {
	return len(payload) > 0 && payload[0] == 0xfe && len(payload) < 9
}
