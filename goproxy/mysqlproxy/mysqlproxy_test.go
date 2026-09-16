package mysqlproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

func TestNormalizeTargetDbOKExtractsSchemaAndStripsTracking(t *testing.T) {
	block := mysqlwire.AppendLenencStr(nil, "other_db")
	state := []byte{sessionTrackSchema}
	state = mysqlwire.AppendLenenc(state, uint64(len(block)))
	state = append(state, block...)

	payload := trackedOKPacket(0x00, serverStatusSessionStateChanged|0x0002, "rows matched", state)
	clean, _, schema, _, err := normalizeTargetDbOK(payload)
	if err != nil {
		t.Fatalf("normalizeTargetDbOK: %v", err)
	}
	if schema == nil || *schema != "other_db" {
		t.Fatalf("schema = %v, want other_db", schema)
	}
	want := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
	want = append(want, "rows matched"...)
	if !bytes.Equal(clean, want) {
		t.Fatalf("clean OK = %x, want %x", clean, want)
	}
}

func TestMaskedRowExpansionAtPacketBoundaryFailsClosed(t *testing.T) {
	// The input is below one physical packet, but replacing the final empty value with "####" makes the
	// re-encoded row exactly MaxPacketPayload. That still requires a continuation packet and must be refused.
	largeLen := maxPacketPayload - 9
	payload := mysqlwire.AppendLenenc(nil, uint64(largeLen))
	payload = append(payload, make([]byte, largeLen)...)
	payload = append(payload, 0x00)
	if len(payload) >= maxPacketPayload {
		t.Fatalf("test input length = %d, want below max", len(payload))
	}
	masker := engine.NewRowMasker([]*pb.ColumnMask{{Column: "masked", Kind: "FIXED", Ordinal: proto.Int32(1)}}, 2)
	if masker == nil {
		t.Fatal("test mask did not bind")
	}
	if _, err := rewriteMaskedTextRow(payload, 2, masker); !errors.Is(err, errRowTooLong) {
		t.Fatalf("rewriteMaskedTextRow error = %v, want errRowTooLong", err)
	}
}

func TestUnmaskedRowContinuationCannotMasqueradeAsTerminator(t *testing.T) {
	var targetDb bytes.Buffer
	writeTestPacket(t, &targetDb, 1, []byte{0x01})
	writeTestPacket(t, &targetDb, 2, []byte{0x03, 'd', 'e', 'f'})
	firstFragment := make([]byte, maxPacketPayload)
	firstFragment[0] = 0xfe
	binary.LittleEndian.PutUint64(firstFragment[1:9], uint64(maxPacketPayload+3))
	writeTestPacket(t, &targetDb, 3, firstFragment)
	writeTestPacket(t, &targetDb, 4, []byte{0xfe, 0x01, 0x02})
	writeTestPacket(t, &targetDb, 5, trackedOKPacket(0xfe, 0x0002, "", nil))

	var got [][]byte
	ok, err := relayResultSet(&targetDb, true, resultHooks{Sink: func(_ byte, payload []byte) error {
		got = append(got, append([]byte(nil), payload...))
		return nil
	}})
	if err != nil {
		t.Fatalf("relayResultSet: %v", err)
	}
	if !ok {
		t.Fatal("relayResultSet reported target-DB failure for a fragmented successful result")
	}
	if len(got) != 5 {
		t.Fatalf("relayed packets = %d, want 5", len(got))
	}
	if !reflect.DeepEqual(got[3], []byte{0xfe, 0x01, 0x02}) {
		t.Fatalf("continuation = %x, want opaque 0xfe data", got[3])
	}
}

func TestRelayResultSetReportsTargetDbError(t *testing.T) {
	var targetDb bytes.Buffer
	writeTestPacket(t, &targetDb, 1, mysqlwire.ErrPacketState(1146, "42S02", "missing table"))

	ok, err := relayResultSet(&targetDb, true, resultHooks{})
	if err != nil {
		t.Fatalf("relayResultSet: %v", err)
	}
	if ok {
		t.Fatal("relayResultSet reported success for a target-DB ERR packet")
	}
}

func TestRelayResultSetReportsAffectedRowsFromFirstOK(t *testing.T) {
	payload := mysqlwire.OKPacket()
	payload[1] = 7
	var targetDb bytes.Buffer
	writeTestPacket(t, &targetDb, 1, payload)

	var affected uint64
	ok, err := relayResultSet(&targetDb, true, resultHooks{OnOK: func(n uint64) { affected = n }})
	if err != nil || !ok || affected != 7 {
		t.Fatalf("ok=%v affected=%d err=%v, want true, 7, nil", ok, affected, err)
	}
}

func TestRelayResultSetRejectsFragmentedColumnDefinitionForCollector(t *testing.T) {
	var targetDb bytes.Buffer
	writeTestPacket(t, &targetDb, 1, []byte{0x01})
	writeTestPacket(t, &targetDb, 2, make([]byte, maxPacketPayload))

	_, err := relayResultSet(&targetDb, true, resultHooks{OnColumnDef: func([]byte) error { return nil }})
	if err == nil || !strings.Contains(err.Error(), "fragmented MySQL column definitions") {
		t.Fatalf("err=%v, want fragmented column-definition rejection", err)
	}
}

// TestDialTargetDbCachingSHA2FullAuth proves the service-account dial completes the caching_sha2_password
// full-auth exchange over the plaintext link. The user is created fresh (unique name), so the server's
// fast-auth cache has never seen it and MUST demand full authentication — a successful dial therefore
// necessarily ran the RSA public-key path, which the test hook confirms directly.
func TestDialTargetDbCachingSHA2FullAuth(t *testing.T) {
	targetDb := dbtest.MySQL(t)
	seed := dbtest.OpenMySQL(t, "")

	user := fmt.Sprintf("it_csha2_%d", time.Now().UnixNano())
	const password = "csha2-full-auth-pw"
	if _, err := seed.Exec("CREATE USER '" + user + "'@'%' IDENTIFIED WITH caching_sha2_password BY '" + password + "'"); err != nil {
		t.Fatalf("create caching_sha2 user: %v", err)
	}
	if _, err := seed.Exec("GRANT SELECT ON " + targetDb.DB + ".* TO '" + user + "'@'%'"); err != nil {
		t.Fatalf("grant caching_sha2 user: %v", err)
	}
	t.Cleanup(func() { _, _ = seed.Exec("DROP USER IF EXISTS '" + user + "'@'%'") })

	var fullAuthViaPublicKey int
	testHookCachingSHA2FullAuth = func(viaPublicKey bool) {
		if viaPublicKey {
			fullAuthViaPublicKey++
		}
	}
	t.Cleanup(func() { testHookCachingSHA2FullAuth = nil })

	target := spi.TargetDb{
		Host:     targetDb.Host,
		Port:     targetDb.Port,
		Db:       targetDb.DB,
		User:     user,
		Password: password,
	}
	conn, connID, err := dialTargetDbAuthID(context.Background(), target, true)
	if err != nil {
		t.Fatalf("dialTargetDbAuthID against caching_sha2 target DB: %v", err)
	}
	defer conn.Close()
	if connID == 0 {
		t.Fatal("target-DB connection id = 0, want the server-assigned id")
	}
	if fullAuthViaPublicKey != 1 {
		t.Fatalf("caching_sha2 full-auth public-key path ran %d times, want exactly 1", fullAuthViaPublicKey)
	}
}

func trackedOKPacket(header byte, status uint16, info string, state []byte) []byte {
	payload := []byte{header, 0x00, 0x00}
	payload = binary.LittleEndian.AppendUint16(payload, status)
	payload = binary.LittleEndian.AppendUint16(payload, 0)
	payload = mysqlwire.AppendLenencStr(payload, info)
	if status&serverStatusSessionStateChanged != 0 {
		payload = mysqlwire.AppendLenenc(payload, uint64(len(state)))
		payload = append(payload, state...)
	}
	return payload
}

func writeTestPacket(t *testing.T, dst *bytes.Buffer, seq byte, payload []byte) {
	t.Helper()
	if err := mysqlwire.WritePacket(dst, seq, payload); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
}
