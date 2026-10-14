package pgproxy

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
)

// checkTargetError prepares sql on the target without executing it and returns the target's ErrorResponse.
// It ends with Flush, so in extended mode the client's own Sync clears a failed Parse.
func (s *Server) checkTargetError(sess *session, sql string, parameterOIDs []uint32) (*engine.TargetError, error) {
	statementName := fmt.Sprintf("__pm_syntax_check_%d__", extendedProbeSequence.Add(1))
	sess.targetDb.Send(&pgproto3.Parse{Name: statementName, Query: sql, ParameterOIDs: parameterOIDs})
	sess.targetDb.Send(&pgproto3.Close{ObjectType: 'S', Name: statementName})
	sess.targetDb.Send(&pgproto3.Flush{})
	if err := sess.targetDb.Flush(); err != nil {
		return nil, err
	}
	for {
		message, err := sess.targetDb.Receive()
		if err != nil {
			return nil, err
		}
		switch message := message.(type) {
		case *pgproto3.ParameterStatus:
			if err := s.guardParameterStatus(sess, message); err != nil {
				return nil, err
			}
		case *pgproto3.NoticeResponse:
			forwardNotice(sess, message)
		case *pgproto3.ParseComplete:
		case *pgproto3.CloseComplete:
			return nil, nil
		case *pgproto3.ErrorResponse:
			copied := *message
			return &engine.TargetError{Code: message.Code, Message: &copied}, nil
		default:
			return nil, failClosedRelay(sess, "58000", "proxy-monster: malformed target-DB response", fmt.Errorf("unexpected target DB prepare response %T", message))
		}
	}
}

const sqlStateSyntaxError = "42601"

// forwardTargetError sends the check's error. Parse runs nothing, so a syntax error holds client text,
// fixed text, or object names (which redaction keeps anyway) and skips redaction.
func forwardTargetError(sess *session, msg *pgproto3.ErrorResponse) {
	if msg.Code == sqlStateSyntaxError {
		sess.client.Send(msg)
		return
	}
	forwardError(sess, msg)
}

// checkTargetErrorAndSync is checkTargetError for a simple query, which has no client Sync to follow.
func (s *Server) checkTargetErrorAndSync(sess *session, sql string) (*engine.TargetError, error) {
	targetErr, err := s.checkTargetError(sess, sql, nil)
	if err != nil {
		return nil, err
	}
	return targetErr, syncTarget(sess)
}

func syncTarget(sess *session) error {
	sess.targetDb.Send(&pgproto3.Sync{})
	if err := sess.targetDb.Flush(); err != nil {
		return err
	}
	_, err := sess.streamResult(nil, streamOpts{extended: true}, nil)
	return err
}
