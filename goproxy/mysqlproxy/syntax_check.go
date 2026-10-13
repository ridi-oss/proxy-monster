package mysqlproxy

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

const erParseError = 1064

func targetSyntaxError(targetDb io.ReadWriter, deprecateEOF bool, sql string) ([]byte, error) {
	preparePayload := mysqlwire.ComStmtPreparePayload(sql)
	if len(preparePayload) >= maxPacketPayload {
		return nil, nil
	}
	if err := mysqlwire.WritePacket(targetDb, 0, preparePayload); err != nil {
		return nil, err
	}
	var response bytes.Buffer
	stmtID, prepared, err := relayStmtPrepareResponse(&response, targetDb, deprecateEOF, nil)
	if err != nil {
		return nil, err
	}
	if prepared {
		closePayload := binary.LittleEndian.AppendUint32([]byte{mysqlwire.ComStmtClose}, stmtID)
		return nil, mysqlwire.WritePacket(targetDb, 0, closePayload)
	}
	_, errPayload, err := mysqlwire.ReadPacket(&response)
	if err != nil {
		return nil, err
	}
	if len(errPayload) < 3 || errPayload[0] != 0xff || binary.LittleEndian.Uint16(errPayload[1:3]) != erParseError {
		return nil, nil
	}
	return errPayload, nil
}

func writeDeny(client io.Writer, targetDb io.ReadWriter, deprecateEOF bool, seq byte, sql string, dec *engine.Decision) (rejected bool, err error) {
	if dec != nil && dec.CheckTargetSyntax {
		errPayload, err := targetSyntaxError(targetDb, deprecateEOF, sql)
		if err != nil {
			return false, err
		}
		if errPayload != nil {
			return true, mysqlwire.WritePacket(client, seq+1, errPayload)
		}
	}
	reason := "policy"
	if dec != nil && dec.DenyReason != "" {
		reason = dec.DenyReason
	}
	return false, mysqlwire.WritePacket(client, seq+1, mysqlwire.ErrPacketState(1142, "42000", "proxy-monster denied: "+reason))
}
