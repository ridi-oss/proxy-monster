package mysqlproxy

import (
	"bytes"
	"testing"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

func TestByteCapRejectsWholeFragmentedRow(t *testing.T) {
	for _, limit := range []int64{10, maxPacketPayload + 1, maxPacketPayload + 3} {
		var target bytes.Buffer
		writeTestPacket(t, &target, 1, []byte{1})
		writeTestPacket(t, &target, 2, []byte{3, 'd', 'e', 'f'})
		writeTestPacket(t, &target, 3, make([]byte, maxPacketPayload))
		writeTestPacket(t, &target, 4, []byte{0xff, 1, 2})
		writeTestPacket(t, &target, 5, trackedOKPacket(0xfe, 2, "", nil))
		var stats engine.RelayStats
		cancels, packets := 0, 0
		_, capped, err := relayResultSet(&target, true, resultHooks{
			MaxBytes: limit, Stats: &stats,
			OnCapExceeded: func() { cancels++ },
			Sink:          func(_ byte, _ []byte) error { packets++; return nil },
		})
		if err != nil || target.Len() != 0 {
			t.Fatalf("drain = %v, remaining %d", err, target.Len())
		}
		if limit < maxPacketPayload+3 {
			if capped == nil || cancels != 1 || packets != 2 || stats.Rows != 0 || stats.Bytes != 0 {
				t.Fatalf("limit %d: cap=%v cancels=%d packets=%d stats=%+v", limit, capped, cancels, packets, stats)
			}
		} else if capped != nil || cancels != 0 || packets != 5 || stats.Rows != 1 || stats.Bytes != limit {
			t.Fatalf("limit %d: cap=%v cancels=%d packets=%d stats=%+v", limit, capped, cancels, packets, stats)
		}
	}
}

func TestRowCapSwallowsCancellationError(t *testing.T) {
	var target bytes.Buffer
	for i, payload := range [][]byte{{1}, {3, 'd', 'e', 'f'}, {1, 'a'}, {1, 'b'}, mysqlwire.ErrPacketState(1317, "70100", "interrupted")} {
		writeTestPacket(t, &target, byte(i+1), payload)
	}
	var stats engine.RelayStats
	cancels, rows, packets := 0, 0, 0
	ok, capped, err := relayResultSet(&target, true, resultHooks{
		MaxRows: 1, Stats: &stats,
		OnCapExceeded: func() { cancels++ },
		OnRow:         func(payload []byte) ([]byte, error) { rows++; return payload, nil },
		Sink:          func(_ byte, _ []byte) error { packets++; return nil },
	})
	if err != nil || ok || capped == nil || cancels != 1 || rows != 1 || packets != 3 || stats.Rows != 1 || stats.Bytes != 2 || target.Len() != 0 {
		t.Fatalf("ok=%v cap=%v err=%v cancels=%d rows=%d packets=%d stats=%+v remaining=%d", ok, capped, err, cancels, rows, packets, stats, target.Len())
	}
}
