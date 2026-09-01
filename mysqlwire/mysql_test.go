package mysqlwire

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strconv"
	"testing"
)

func ptr(s string) *string { return &s }

func TestLenencRoundTripBoundaries(t *testing.T) {
	for _, value := range []uint64{0, 250, 251, 65535, 65536, 16777215, 16777216, math.MaxUint64} {
		t.Run(strconv.FormatUint(value, 10), func(t *testing.T) {
			payload := AppendLenenc(nil, value)
			got, err := NewReader(payload).Lenenc()
			if err != nil {
				t.Fatalf("Lenenc(%x): %v", payload, err)
			}
			if got != value {
				t.Fatalf("Lenenc(AppendLenenc(%d)) = %d", value, got)
			}
		})
	}
}

func TestPacketSizeLimitsRejectBeforeBodyAllocation(t *testing.T) {
	var oversized bytes.Buffer
	over := 4097
	overHeader := []byte{byte(over), byte(over >> 8), byte(over >> 16), 7}
	overHeader = append(overHeader, make([]byte, over)...)
	oversized.Write(overHeader)
	seq, payload, err := ReadPacketLimited(&oversized, 4096)
	if !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("ReadPacketLimited error = %v, want ErrPacketTooLarge", err)
	}
	if seq != 7 || payload != nil {
		t.Fatalf("ReadPacketLimited = seq %d payload %v, want seq 7 nil", seq, payload)
	}
	if got := oversized.Len(); got != over {
		t.Fatalf("oversized body bytes consumed = %d, want 0", over-got)
	}

	var framed bytes.Buffer
	if err := WritePacket(&framed, 0, make([]byte, MaxPacketPayload+1)); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("WritePacket oversized error = %v, want ErrPacketTooLarge", err)
	}
	if framed.Len() != 0 {
		t.Fatalf("WritePacket wrote %d bytes before rejecting oversized payload", framed.Len())
	}
}

func TestServerGreetingTLSCapabilities(t *testing.T) {
	scramble := bytes.Repeat([]byte{0x42}, 20)
	plaintext := ServerGreeting(7, scramble, "8.0.40-test", false)
	if GreetingOffersSSL(plaintext) {
		t.Fatal("ServerGreeting advertised CLIENT_SSL")
	}

	ssl := ServerGreetingSSL(7, scramble, "8.0.40-test", false)
	if !GreetingOffersSSL(ssl) {
		t.Fatal("ServerGreetingSSL did not advertise CLIENT_SSL")
	}
	greeting, err := ParseHandshakeV10(ssl)
	if err != nil {
		t.Fatalf("ParseHandshakeV10: %v", err)
	}
	// connectWithDB=false must not advertise CONNECT_WITH_DB: an importer that does not forward a
	// handshake-supplied database upstream passes false, and advertising it would let a client's
	// selected database be silently dropped.
	if greeting.Capabilities&CapConnectWithDB != 0 {
		t.Fatalf("server capabilities = %#x, want CONNECT_WITH_DB not advertised", greeting.Capabilities)
	}
}

func TestServerGreetingConnectWithDBOptIn(t *testing.T) {
	scramble := bytes.Repeat([]byte{0x42}, 20)
	// connectWithDB=true (e.g. goproxy/mysqlproxy, which relays a handshake-supplied database to the
	// target DB as COM_INIT_DB) must advertise CONNECT_WITH_DB, or a real client that gates writing the
	// database field on server-advertised support (unlike go-sql-driver/mysql, which writes it
	// unconditionally) will set its own CapConnectWithDB bit without ever including the field.
	greeting, err := ParseHandshakeV10(ServerGreetingSSL(7, scramble, "8.0.40-test", true))
	if err != nil {
		t.Fatalf("ParseHandshakeV10: %v", err)
	}
	if greeting.Capabilities&CapConnectWithDB == 0 {
		t.Fatalf("server capabilities = %#x, want CONNECT_WITH_DB advertised", greeting.Capabilities)
	}
}

func TestLooksLikeSSLRequestDiscriminatesShortRequest(t *testing.T) {
	caps := uint32(CapProtocol41 | CapSSL)
	shortHandshake := ClientHandshakeResponse(caps, "", nil)
	largeHandshake := ClientHandshakeResponse(caps, string(bytes.Repeat([]byte{'x'}, 166)), nil)
	if len(shortHandshake) != 34 || len(largeHandshake) != 200 {
		t.Fatalf("handshake fixture lengths = %d, %d; want 34, 200", len(shortHandshake), len(largeHandshake))
	}
	tests := []struct {
		name    string
		payload []byte
		want    bool
	}{
		{name: "32-byte SSLRequest", payload: SSLRequest(caps), want: true},
		{name: "34-byte handshake response", payload: shortHandshake, want: false},
		{name: "large handshake response", payload: largeHandshake, want: false},
		{name: "short packet without CLIENT_SSL", payload: SSLRequest(caps &^ CapSSL), want: false},
		{name: "runt packet", payload: []byte{1, 2, 3}, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := LooksLikeSSLRequest(test.payload); got != test.want {
				t.Fatalf("LooksLikeSSLRequest(%d bytes) = %v, want %v", len(test.payload), got, test.want)
			}
		})
	}
}

func TestReaderTruncatedInputFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		read func() error
	}{
		{"u8", func() error { _, err := NewReader(nil).U8(); return err }},
		{"u32", func() error { _, err := NewReader([]byte{1, 2, 3}).U32(); return err }},
		{"skip", func() error { return NewReader([]byte{1}).Skip(2) }},
		{"bytes", func() error { _, err := NewReader([]byte{1}).Bytes(2); return err }},
		{"cstr without nul", func() error { _, err := NewReader([]byte("abc")).Cstr(); return err }},
		{"lenenc u16", func() error { _, err := NewReader([]byte{0xfc, 1}).Lenenc(); return err }},
		{"lenenc u24", func() error { _, err := NewReader([]byte{0xfd, 1, 2}).Lenenc(); return err }},
		{"lenenc u64", func() error { _, err := NewReader([]byte{0xfe, 1, 2, 3}).Lenenc(); return err }},
		{"lenenc string", func() error { _, err := NewReader([]byte{3, 'a'}).LenencStr(); return err }},
		{"row value", func() error { _, err := NewReader(nil).RowValue(); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.read(); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("error = %v, want io.ErrUnexpectedEOF", err)
			}
		})
	}
}

func TestTextRowRoundTrip(t *testing.T) {
	values := []*string{ptr("plain"), nil, ptr(""), ptr("안녕하세요😀")}
	payload := TextRowPayload(values)
	if payload[len(AppendLenencStr(nil, "plain"))] != 0xfb {
		t.Fatalf("NULL marker missing from %x", payload)
	}
	got, err := ParseTextRow(payload, len(values))
	if err != nil {
		t.Fatalf("ParseTextRow: %v", err)
	}
	if !reflect.DeepEqual(got, values) {
		t.Fatalf("round trip = %#v, want %#v", got, values)
	}
}

func TestIsResultTerminator(t *testing.T) {
	tests := []struct {
		payload []byte
		want    bool
	}{
		{[]byte{0xfe}, true},
		{make([]byte, 8), true},
		{append([]byte{0xfe}, make([]byte, 8)...), false},
		{[]byte{0x00}, false},
	}
	tests[1].payload[0] = 0xfe
	for _, test := range tests {
		if got := IsResultTerminator(test.payload); got != test.want {
			t.Errorf("IsResultTerminator(%x) = %v, want %v", test.payload, got, test.want)
		}
	}
}

func TestParseHandshakeV10MySQL8Greeting(t *testing.T) {
	// Captured-shape MySQL 8 HandshakeV10: protocol/version/id, 8+13 auth data bytes, then plugin.
	payload, err := hex.DecodeString(
		"0a38302e302e333600" +
			"d2040000" +
			"6162636465666768" + "00" +
			"ffff" + "2d" + "0200" + "ffdf" + "15" +
			"00000000000000000000" +
			"696a6b6c6d6e6f707172737400" +
			"6d7973716c5f6e61746976655f70617373776f726400",
	)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseHandshakeV10(payload)
	if err != nil {
		t.Fatalf("ParseHandshakeV10: %v", err)
	}
	if got.ConnectionID != 1234 {
		t.Errorf("ConnectionID = %d, want 1234", got.ConnectionID)
	}
	if string(got.Scramble) != "abcdefghijklmnopqrst" {
		t.Errorf("Scramble = %q", got.Scramble)
	}
	if got.AuthPlugin != "mysql_native_password" {
		t.Errorf("AuthPlugin = %q", got.AuthPlugin)
	}
	if got.Capabilities&CapPluginAuth == 0 {
		t.Errorf("Capabilities = %#x, want CapPluginAuth", got.Capabilities)
	}
}

func handshakeResponsePayload(caps uint32, authMode string) []byte {
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, caps)
	b = binary.LittleEndian.AppendUint32(b, 16<<20)
	b = append(b, 45)
	b = append(b, make([]byte, 23)...)
	b = append(b, "alice"...)
	b = append(b, 0)
	switch authMode {
	case "lenenc":
		b = AppendLenenc(b, 3)
		b = append(b, 1, 2, 3)
	case "secure":
		b = append(b, 3, 1, 2, 3)
	case "cstr":
		b = append(b, "auth"...)
		b = append(b, 0)
	}
	if caps&CapConnectWithDB != 0 {
		b = append(b, "app"...)
		b = append(b, 0)
	}
	return b
}

func TestParseHandshakeResponseAuthModes(t *testing.T) {
	tests := []struct {
		name string
		caps uint32
		mode string
		auth []byte
	}{
		{"lenenc auth", CapProtocol41 | CapPluginAuthLenenc | CapConnectWithDB, "lenenc", []byte{1, 2, 3}},
		{"secure auth", CapProtocol41 | CapSecureConn | CapConnectWithDB, "secure", []byte{1, 2, 3}},
		{"cstr auth", CapProtocol41 | CapConnectWithDB, "cstr", []byte("auth")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseHandshakeResponse(handshakeResponsePayload(test.caps, test.mode), true)
			if err != nil {
				t.Fatalf("ParseHandshakeResponse: %v", err)
			}
			if got.Capabilities != test.caps || got.Username != "alice" || got.Database != "app" {
				t.Fatalf("got %+v, want caps=%d user=alice db=app", got, test.caps)
			}
			// The auth response is what a password check compares; every encoding must surface it.
			if !bytes.Equal(got.AuthResponse, test.auth) {
				t.Fatalf("auth response: got %v, want %v", got.AuthResponse, test.auth)
			}
		})
	}
}

// TestParseHandshakeResponseIgnoresUnsupportedConnectWithDB reproduces a real mysql CLI against this
// proxy: it sets its own CapConnectWithDB bit whenever a database was given on the command line, but
// only WRITES the database field when the SERVER'S greeting advertised that capability. Since
// serverGreetingCapabilities never advertises CapConnectWithDB, a real client still reports the bit
// but sends nothing for it — auth-response is directly followed by its plugin name, no database field
// at all. connectWithDBSupported=false (what this proxy passes) must not misread that plugin name as
// the database.
func TestParseHandshakeResponseIgnoresUnsupportedConnectWithDB(t *testing.T) {
	caps := uint32(CapProtocol41 | CapSecureConn | CapPluginAuth | CapConnectWithDB)
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, caps)
	b = binary.LittleEndian.AppendUint32(b, 16<<20)
	b = append(b, 45)
	b = append(b, make([]byte, 23)...)
	b = append(b, "alice"...)
	b = append(b, 0)
	b = append(b, 3, 1, 2, 3) // 3-byte auth-response, CapSecureConn encoding
	b = append(b, "mysql_native_password"...)
	b = append(b, 0)

	got, err := ParseHandshakeResponse(b, false)
	if err != nil {
		t.Fatalf("ParseHandshakeResponse: %v", err)
	}
	if got.Database != "" {
		t.Fatalf("Database = %q, want empty (misread the plugin name as the database)", got.Database)
	}
	if got.Username != "alice" {
		t.Fatalf("Username = %q, want alice", got.Username)
	}
}

func TestNativePasswordKnownVector(t *testing.T) {
	got := hex.EncodeToString(NativePassword("password", []byte("12345678901234567890")))
	const want = "1957dce2724282e018f40d905824cb6361f88d41"
	if got != want {
		t.Fatalf("NativePassword = %s, want %s", got, want)
	}
	if got := NativePassword("", []byte("12345678901234567890")); len(got) != 0 {
		t.Fatalf("empty password response = %x, want empty", got)
	}
}

func TestTargetDbHandshakeResponseDatabase(t *testing.T) {
	auth := []byte{1, 2, 3}
	for _, test := range []struct {
		name       string
		caps       uint32
		database   string
		authPlugin string
		wantDB     string
		wantPlugin string
	}{
		{"with database", CapProtocol41 | CapSecureConn | CapPluginAuth | CapConnectWithDB, "app", "mysql_native_password", "app", "mysql_native_password"},
		{"empty database omitted", CapProtocol41 | CapSecureConn | CapPluginAuth | CapConnectWithDB, "", "mysql_native_password", "", "mysql_native_password"},
		{"capability absent", CapProtocol41 | CapSecureConn | CapPluginAuth, "app", "mysql_native_password", "", "mysql_native_password"},
		{"caching_sha2 plugin", CapProtocol41 | CapSecureConn | CapPluginAuth | CapConnectWithDB, "app", "caching_sha2_password", "app", "caching_sha2_password"},
		{"empty plugin defaults to native", CapProtocol41 | CapSecureConn | CapPluginAuth | CapConnectWithDB, "app", "", "app", "mysql_native_password"},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := TargetDbHandshakeResponse(test.caps, "svc", auth, test.database, test.authPlugin)
			r := NewReader(payload)
			caps, err := r.U32()
			if err != nil || caps != test.caps {
				t.Fatalf("caps = %#x, err %v", caps, err)
			}
			if err := r.Skip(4 + 1 + 23); err != nil {
				t.Fatal(err)
			}
			user, err := r.Cstr()
			if err != nil || user != "svc" {
				t.Fatalf("user = %q, err %v", user, err)
			}
			n, err := r.U8()
			if err != nil || n != byte(len(auth)) {
				t.Fatalf("auth length = %d, err %v", n, err)
			}
			if got, err := r.Bytes(int(n)); err != nil || !reflect.DeepEqual(got, auth) {
				t.Fatalf("auth = %x, err %v", got, err)
			}
			if test.wantDB != "" {
				database, err := r.Cstr()
				if err != nil || database != test.wantDB {
					t.Fatalf("database = %q, err %v", database, err)
				}
			}
			plugin, err := r.Cstr()
			if err != nil || plugin != test.wantPlugin {
				t.Fatalf("plugin = %q, err %v", plugin, err)
			}
		})
	}
}

func TestCachingSHA2PasswordKnownVectors(t *testing.T) {
	seq20 := []byte("12345678901234567890")
	seq1to20 := make([]byte, 20)
	for i := range seq1to20 {
		seq1to20[i] = byte(i + 1)
	}
	tests := []struct {
		name     string
		password string
		scramble []byte
		want     string
	}{
		{"password", "password", seq20, "718d80fb92b693f7ee1fcad95bfe7a2be1f332ac2c3ec6cdc85893b65b240650"},
		{"s3cr3t", "s3cr3t", seq1to20, "eaaa1f23aa3a7aa171e525c43fe5fe33338896b259c9cd4c8827d484a76382fc"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := hex.EncodeToString(CachingSHA2Password(test.password, test.scramble))
			if got != test.want {
				t.Fatalf("CachingSHA2Password = %s, want %s", got, test.want)
			}
		})
	}
	if got := CachingSHA2Password("", seq20); len(got) != 0 {
		t.Fatalf("empty password response = %x, want empty", got)
	}
}

func TestEncryptCachingSHA2PasswordRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pkix, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix})

	for _, password := range []string{"", "svc-secret", "unicode✓и"} {
		scramble := []byte("abcdefghijklmnopqrst") // 20-byte handshake scramble
		enc, err := EncryptCachingSHA2Password(password, scramble, pubPEM)
		if err != nil {
			t.Fatalf("EncryptCachingSHA2Password(%q): %v", password, err)
		}
		decrypted, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, key, enc, nil)
		if err != nil {
			t.Fatalf("DecryptOAEP(%q): %v", password, err)
		}
		want := make([]byte, len(password)+1)
		copy(want, password)
		for i := range want {
			want[i] ^= scramble[i%len(scramble)]
		}
		if !bytes.Equal(decrypted, want) {
			t.Fatalf("decrypted plaintext = %x, want %x", decrypted, want)
		}
	}

	if _, err := EncryptCachingSHA2Password("pw", []byte("scramble"), []byte("not pem")); err == nil {
		t.Fatal("EncryptCachingSHA2Password accepted invalid PEM")
	}
	if _, err := EncryptCachingSHA2Password("pw", nil, pubPEM); err == nil {
		t.Fatal("EncryptCachingSHA2Password accepted empty scramble")
	}
}

func TestComQueryPayload(t *testing.T) {
	if got, want := ComQueryPayload("SELECT 1"), append([]byte{ComQuery}, "SELECT 1"...); !reflect.DeepEqual(got, want) {
		t.Fatalf("ComQueryPayload = %x, want %x", got, want)
	}
}

func TestComStmtPreparePayload(t *testing.T) {
	if got, want := ComStmtPreparePayload("SELECT ?"), append([]byte{ComStmtPrepare}, "SELECT ?"...); !reflect.DeepEqual(got, want) {
		t.Fatalf("ComStmtPreparePayload = %x, want %x", got, want)
	}
}

func TestReaderU16(t *testing.T) {
	got, err := NewReader([]byte{0x34, 0x12}).U16()
	if err != nil {
		t.Fatalf("U16: %v", err)
	}
	if got != 0x1234 {
		t.Fatalf("U16 = %#x, want 0x1234", got)
	}
	if _, err := NewReader([]byte{0x34}).U16(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated U16 error = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestParseStmtPrepareOK(t *testing.T) {
	tests := []struct {
		name string
		id   uint32
	}{
		{"zero statement ID", 0},
		{"sample statement ID", 0x01020304},
		{"maximum statement ID", math.MaxUint32},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := []byte{0x00}
			payload = binary.LittleEndian.AppendUint32(payload, test.id)
			payload = binary.LittleEndian.AppendUint16(payload, 2)
			payload = binary.LittleEndian.AppendUint16(payload, 1)
			payload = append(payload, 0x00, 0x00, 0x00, 0xaa)
			got, err := ParseStmtPrepareOK(payload)
			if err != nil {
				t.Fatalf("ParseStmtPrepareOK: %v", err)
			}
			want := StmtPrepareOK{StmtID: test.id, NumColumns: 2, NumParams: 1}
			if got != want {
				t.Fatalf("ParseStmtPrepareOK = %+v, want %+v", got, want)
			}
		})
	}

	errPayload := make([]byte, 12)
	errPayload[0] = 0xff
	if _, err := ParseStmtPrepareOK(errPayload); err == nil {
		t.Fatal("ParseStmtPrepareOK accepted ERR packet header")
	}

	header := []byte{0x00, 0x04, 0x03, 0x02, 0x01, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	for n := range len(header) {
		t.Run(fmt.Sprintf("truncated at %d", n), func(t *testing.T) {
			if _, err := ParseStmtPrepareOK(header[:n]); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("ParseStmtPrepareOK(%x) error = %v, want io.ErrUnexpectedEOF", header[:n], err)
			}
		})
	}
}

func TestStmtID(t *testing.T) {
	for _, command := range []byte{ComStmtExecute, ComStmtClose, ComStmtReset, ComStmtSendLongData} {
		payload := []byte{command, 0x04, 0x03, 0x02, 0x01, 0xaa}
		got, err := StmtID(payload)
		if err != nil {
			t.Fatalf("StmtID(command %#x): %v", command, err)
		}
		if got != 0x01020304 {
			t.Fatalf("StmtID(command %#x) = %#x, want 0x01020304", command, got)
		}
	}
	for n := 0; n < 5; n++ {
		if _, err := StmtID(make([]byte, n)); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("StmtID(length %d) error = %v, want io.ErrUnexpectedEOF", n, err)
		}
	}
}

func TestParseColumnName(t *testing.T) {
	var payload []byte
	for _, value := range []string{"def", "app", "people", "people", "display_name", "name"} {
		payload = AppendLenencStr(payload, value)
	}
	payload = AppendLenenc(payload, 0x0c)
	payload = append(payload, make([]byte, 12)...)
	got, err := ParseColumnName(payload)
	if err != nil {
		t.Fatalf("ParseColumnName: %v", err)
	}
	if got != "display_name" {
		t.Fatalf("name = %q, want display_name", got)
	}
}

func TestParseColumnDefinition(t *testing.T) {
	var payload []byte
	for _, value := range []string{"def", "app", "people", "people", "uuid", "uuid"} {
		payload = AppendLenencStr(payload, value)
	}
	payload = AppendLenenc(payload, 0x0c)
	payload = binary.LittleEndian.AppendUint16(payload, CharsetBinary)
	payload = binary.LittleEndian.AppendUint32(payload, 16)
	payload = append(payload, ColumnTypeString)
	payload = binary.LittleEndian.AppendUint16(payload, 0x80)
	payload = append(payload, 0, 0, 0)

	got, err := ParseColumnDefinition(payload)
	if err != nil {
		t.Fatalf("ParseColumnDefinition: %v", err)
	}
	if got.Name != "uuid" || got.Charset != CharsetBinary || got.ColumnLength != 16 || got.Type != ColumnTypeString || got.Flags != 0x80 {
		t.Fatalf("definition = %+v, want uuid binary string metadata", got)
	}
}

func TestErrPacketRetainsExistingBytes(t *testing.T) {
	want := append([]byte{0xff, 0x15, 0x04, '#'}, "HY000boom"...)
	if got := ErrPacket(1045, "boom"); !reflect.DeepEqual(got, want) {
		t.Fatalf("ErrPacket = %x, want %x", got, want)
	}
}

// TestScrambleIsPrintableASCII: the scramble must stay inside MySQL's own printable range
// (0x21..0x7e). A NUL truncates the salt for a client that reads it as a C string; a byte >= 0x80 is
// mangled by a client that decodes the auth-plugin-data as text (MySQL Connector/J, and so DBeaver),
// which breaks its password digest. A uniformly random 20 bytes leaves the range ~55% of the time, so
// the failure looks constant rather than intermittent — hence the whole range is asserted, not just NUL.
func TestScrambleIsPrintableASCII(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		s, err := Scramble()
		if err != nil {
			t.Fatalf("Scramble: %v", err)
		}
		if len(s) != 20 {
			t.Fatalf("len = %d, want 20", len(s))
		}
		for _, c := range s {
			if c < 0x21 || c > 0x7e {
				t.Fatalf("scramble byte %#x outside printable ASCII 0x21..0x7e: % x", c, s)
			}
		}
		seen[string(s)] = true
	}
	// Freshness matters as much as the shape: a constant scramble would let a captured digest replay.
	if len(seen) < 1900 {
		t.Fatalf("only %d distinct scrambles in 2000 draws", len(seen))
	}
}
