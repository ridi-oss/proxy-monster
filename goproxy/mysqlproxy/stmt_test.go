package mysqlproxy

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

func TestRelayStmtPrepareResponseRelaysMetadata(t *testing.T) {
	for _, deprecateEOF := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy_eof", true: "deprecate_eof"}[deprecateEOF], func(t *testing.T) {
			packets := []stmtTestPacket{
				{seq: 1, payload: stmtPrepareOKPayload(42, 2, 1)},
				{seq: 2, payload: []byte("param-definition")},
			}
			if !deprecateEOF {
				packets = append(packets, stmtTestPacket{seq: 3, payload: stmtTestEOFPacket()})
			}
			packets = append(packets,
				stmtTestPacket{seq: byte(len(packets) + 1), payload: []byte("column-definition-1")},
				stmtTestPacket{seq: byte(len(packets) + 2), payload: []byte("column-definition-2")},
			)
			if !deprecateEOF {
				packets = append(packets, stmtTestPacket{seq: byte(len(packets) + 1), payload: stmtTestEOFPacket()})
			}

			targetDb := stmtTestPacketBuffer(t, packets)
			var client bytes.Buffer
			stmtID, prepared, err := relayStmtPrepareResponse(&client, targetDb, deprecateEOF, nil)
			if err != nil {
				t.Fatalf("relayStmtPrepareResponse: %v", err)
			}
			if stmtID != 42 || !prepared {
				t.Fatalf("result = (%d, %v), want (42, true)", stmtID, prepared)
			}
			if targetDb.Len() != 0 {
				t.Fatalf("target DB has %d unread bytes", targetDb.Len())
			}
			if got := readStmtTestPackets(t, &client); !reflect.DeepEqual(got, packets) {
				t.Fatalf("relayed packets = %#v, want %#v", got, packets)
			}
		})
	}
}

func TestRelayStmtPrepareResponseMetadataShapes(t *testing.T) {
	tests := []struct {
		name        string
		columns     uint16
		params      uint16
		deprecate   bool
		definitions []stmtTestPacket
	}{
		{
			name:   "params_only_legacy",
			params: 2,
			definitions: []stmtTestPacket{
				{seq: 2, payload: []byte("p1")},
				{seq: 3, payload: []byte("p2")},
				{seq: 4, payload: stmtTestEOFPacket()},
			},
		},
		{
			name:      "params_only_deprecate_eof",
			params:    1,
			deprecate: true,
			definitions: []stmtTestPacket{
				{seq: 2, payload: []byte("p1")},
			},
		},
		{
			name:    "columns_only_legacy",
			columns: 2,
			definitions: []stmtTestPacket{
				{seq: 2, payload: []byte("c1")},
				{seq: 3, payload: []byte("c2")},
				{seq: 4, payload: stmtTestEOFPacket()},
			},
		},
		{
			name:      "columns_only_deprecate_eof",
			columns:   1,
			deprecate: true,
			definitions: []stmtTestPacket{
				{seq: 2, payload: []byte("c1")},
			},
		},
		{name: "no_metadata_legacy"},
		{name: "no_metadata_deprecate_eof", deprecate: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packets := append(
				[]stmtTestPacket{{seq: 1, payload: stmtPrepareOKPayload(99, test.columns, test.params)}},
				test.definitions...,
			)
			targetDb := stmtTestPacketBuffer(t, packets)
			var client bytes.Buffer
			stmtID, prepared, err := relayStmtPrepareResponse(&client, targetDb, test.deprecate, nil)
			if err != nil {
				t.Fatalf("relayStmtPrepareResponse: %v", err)
			}
			if stmtID != 99 || !prepared {
				t.Fatalf("result = (%d, %v), want (99, true)", stmtID, prepared)
			}
			if targetDb.Len() != 0 {
				t.Fatalf("target DB has %d unread bytes", targetDb.Len())
			}
			if got := readStmtTestPackets(t, &client); !reflect.DeepEqual(got, packets) {
				t.Fatalf("relayed packets = %#v, want %#v", got, packets)
			}
		})
	}
}

func TestRelayStmtPrepareResponseCountsLogicalDefinitions(t *testing.T) {
	firstFragment := make([]byte, maxPacketPayload)
	firstFragment[0] = 0x03
	packets := []stmtTestPacket{
		{seq: 1, payload: stmtPrepareOKPayload(77, 0, 1)},
		{seq: 2, payload: firstFragment},
		{seq: 3, payload: []byte("definition-continuation")},
	}
	targetDb := stmtTestPacketBuffer(t, packets)
	var client bytes.Buffer

	stmtID, prepared, err := relayStmtPrepareResponse(&client, targetDb, true, nil)
	if err != nil {
		t.Fatalf("relayStmtPrepareResponse: %v", err)
	}
	if stmtID != 77 || !prepared {
		t.Fatalf("result = (%d, %v), want (77, true)", stmtID, prepared)
	}
	if targetDb.Len() != 0 {
		t.Fatalf("target DB has %d unread bytes", targetDb.Len())
	}
	if got := readStmtTestPackets(t, &client); !reflect.DeepEqual(got, packets) {
		t.Fatalf("relayed packets = %#v, want %#v", got, packets)
	}
}

func TestRelayStmtPrepareResponseRelaysTargetDbError(t *testing.T) {
	targetDbErr := mysqlwire.ErrPacketState(1064, "42000", "target DB rejected prepare")
	packets := []stmtTestPacket{{seq: 1, payload: targetDbErr}}
	targetDb := stmtTestPacketBuffer(t, packets)
	var client bytes.Buffer

	stmtID, prepared, err := relayStmtPrepareResponse(&client, targetDb, true, nil)
	if err != nil {
		t.Fatalf("relayStmtPrepareResponse: %v", err)
	}
	if stmtID != 0 || prepared {
		t.Fatalf("result = (%d, %v), want (0, false)", stmtID, prepared)
	}
	if got := readStmtTestPackets(t, &client); !reflect.DeepEqual(got, packets) {
		t.Fatalf("relayed packets = %#v, want %#v", got, packets)
	}
}

func TestRelayStmtPrepareResponseRejectsMalformedHeader(t *testing.T) {
	malformed := stmtPrepareOKPayload(42, 0, 0)
	malformed[0] = 0x01
	targetDb := stmtTestPacketBuffer(t, []stmtTestPacket{{seq: 7, payload: malformed}})
	var client bytes.Buffer

	if _, prepared, err := relayStmtPrepareResponse(&client, targetDb, true, nil); err == nil || prepared {
		t.Fatalf("result = (prepared %v, error %v), want false and error", prepared, err)
	}
	packets := readStmtTestPackets(t, &client)
	want := []stmtTestPacket{{
		seq:     7,
		payload: mysqlwire.ErrPacketState(1105, "HY000", malformedStmtPrepareMessage),
	}}
	if !reflect.DeepEqual(packets, want) {
		t.Fatalf("client packets = %#v, want %#v", packets, want)
	}
}

func TestRelayStmtPrepareResponseRequiresLegacyEOF(t *testing.T) {
	packets := []stmtTestPacket{
		{seq: 1, payload: stmtPrepareOKPayload(42, 0, 1)},
		{seq: 2, payload: []byte("param-definition")},
		{seq: 3, payload: []byte("not-an-eof")},
	}
	targetDb := stmtTestPacketBuffer(t, packets)
	var client bytes.Buffer

	if _, prepared, err := relayStmtPrepareResponse(&client, targetDb, false, nil); err == nil || prepared {
		t.Fatalf("result = (prepared %v, error %v), want false and error", prepared, err)
	}
	got := readStmtTestPackets(t, &client)
	want := []stmtTestPacket{
		packets[0],
		packets[1],
		{seq: 3, payload: mysqlwire.ErrPacketState(1105, "HY000", malformedStmtPrepareMessage)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("client packets = %#v, want %#v", got, want)
	}
}

type stmtTestPacket struct {
	seq     byte
	payload []byte
}

func stmtPrepareOKPayload(stmtID uint32, columns, params uint16) []byte {
	payload := []byte{0x00}
	payload = binary.LittleEndian.AppendUint32(payload, stmtID)
	payload = binary.LittleEndian.AppendUint16(payload, columns)
	payload = binary.LittleEndian.AppendUint16(payload, params)
	payload = append(payload, 0x00)
	return binary.LittleEndian.AppendUint16(payload, 0)
}

func stmtTestEOFPacket() []byte { return []byte{0xfe, 0x00, 0x00, 0x02, 0x00} }

func stmtTestPacketBuffer(t *testing.T, packets []stmtTestPacket) *bytes.Buffer {
	t.Helper()
	var buffer bytes.Buffer
	for _, packet := range packets {
		writeTestPacket(t, &buffer, packet.seq, packet.payload)
	}
	return &buffer
}

func readStmtTestPackets(t *testing.T, buffer *bytes.Buffer) []stmtTestPacket {
	t.Helper()
	var packets []stmtTestPacket
	for buffer.Len() > 0 {
		seq, payload, err := mysqlwire.ReadPacket(buffer)
		if err != nil {
			t.Fatalf("ReadPacket: %v", err)
		}
		packets = append(packets, stmtTestPacket{seq: seq, payload: payload})
	}
	return packets
}
