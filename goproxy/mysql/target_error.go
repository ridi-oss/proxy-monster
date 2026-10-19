package mysql

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strconv"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

const (
	erParseError = 1064
	// ER_UNSUPPORTED_PS: the statement can run but cannot be prepared, so the check learns nothing.
	erUnsupportedPS = 1295
)

// checkTargetError prepares sql on the target without executing it and returns the target's ERR packet.
func checkTargetError(targetDb io.ReadWriter, deprecateEOF bool, sql string) (*engine.TargetError, error) {
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
	if len(errPayload) < 3 || errPayload[0] != 0xff {
		return nil, errors.New("mysqlproxy: target prepare returned neither OK nor ERR")
	}
	essno := binary.LittleEndian.Uint16(errPayload[1:3])
	if essno == erUnsupportedPS {
		return nil, nil
	}
	return &engine.TargetError{Code: strconv.Itoa(int(essno)), Message: errPayload}, nil
}

// writeDeny answers a denied statement: the target's error when the decision forwards one, else the
// proxy's deny. forwarded reports the former, which completes as a target error.
func writeDeny(client io.Writer, seq byte, dec *engine.Decision, redact func([]byte) []byte) (forwarded bool, err error) {
	if dec != nil && dec.TargetError != nil {
		if payload, ok := dec.TargetError.Message.([]byte); ok {
			// A prepare runs nothing, so its syntax error holds client text, fixed text, or object names.
			if redact != nil && dec.TargetError.Code != strconv.Itoa(erParseError) {
				payload = redact(payload)
			}
			return true, mysqlwire.WritePacket(client, seq+1, payload)
		}
	}
	reason := "policy"
	if dec != nil && dec.DenyReason != "" {
		reason = dec.DenyReason
	}
	return false, mysqlwire.WritePacket(client, seq+1, mysqlwire.ErrPacketState(1142, "42000", "proxy-monster denied: "+reason))
}
