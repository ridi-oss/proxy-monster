package postgres

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// checkTargetError prepares sql on the target without executing it and returns the target's ErrorResponse.
// It ends with Flush, so in extended mode the client's own Sync clears a failed Parse.
func (s *Server) checkTargetError(wireState *clientWireState, sql string, parameterOIDs []uint32) (*spi.TargetError, error) {
	statementName := fmt.Sprintf("__pm_syntax_check_%d__", extendedProbeSequence.Add(1))
	wireState.targetDb.Send(&pgproto3.Parse{Name: statementName, Query: sql, ParameterOIDs: parameterOIDs})
	wireState.targetDb.Send(&pgproto3.Close{ObjectType: 'S', Name: statementName})
	wireState.targetDb.Send(&pgproto3.Flush{})
	if err := wireState.targetDb.Flush(); err != nil {
		return nil, err
	}
	for {
		message, err := wireState.targetDb.Receive()
		if err != nil {
			return nil, err
		}
		switch message := message.(type) {
		case *pgproto3.ParameterStatus:
			if err := s.guardParameterStatus(wireState, message); err != nil {
				return nil, err
			}
		case *pgproto3.NoticeResponse:
			forwardNotice(wireState, message)
		case *pgproto3.ParseComplete:
		case *pgproto3.CloseComplete:
			return nil, nil
		case *pgproto3.ErrorResponse:
			copied := *message
			return &spi.TargetError{Code: message.Code, Message: &copied}, nil
		default:
			return nil, failClosedRelay(wireState, "58000", "proxy-monster: malformed target-DB response", fmt.Errorf("unexpected target DB prepare response %T", message))
		}
	}
}

const sqlStateSyntaxError = "42601"

// forwardTargetError sends the check's error. Parse runs nothing, so a syntax error holds client text,
// fixed text, or object names (which redaction keeps anyway) and skips redaction.
func forwardTargetError(wireState *clientWireState, msg *pgproto3.ErrorResponse) {
	if msg.Code == sqlStateSyntaxError {
		wireState.client.Send(msg)
		return
	}
	forwardError(wireState, msg)
}

// checkTargetErrorAndSync is checkTargetError for a simple query, which has no client Sync to follow.
func (s *Server) checkTargetErrorAndSync(wireState *clientWireState, sql string) (*spi.TargetError, error) {
	targetErr, err := s.checkTargetError(wireState, sql, nil)
	if err != nil {
		return nil, err
	}
	return targetErr, syncTarget(wireState)
}

func syncTarget(wireState *clientWireState) error {
	wireState.targetDb.Send(&pgproto3.Sync{})
	if err := wireState.targetDb.Flush(); err != nil {
		return err
	}
	_, err := wireState.streamResult(nil, streamOpts{extended: true}, nil)
	return err
}
