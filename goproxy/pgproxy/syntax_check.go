package pgproxy

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgproto3"
)

const sqlStateSyntaxError = "42601"

func (s *Server) targetPrepareError(sess *session, sql string) (*pgproto3.ErrorResponse, error) {
	statementName := fmt.Sprintf("__pm_syntax_check_%d__", extendedProbeSequence.Add(1))
	sess.targetDb.Send(&pgproto3.Parse{Name: statementName, Query: sql})
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
			return &copied, nil
		default:
			return nil, failClosedRelay(sess, "58000", "proxy-monster: malformed target-DB response", fmt.Errorf("unexpected target DB prepare response %T", message))
		}
	}
}

func syncTarget(sess *session) error {
	sess.targetDb.Send(&pgproto3.Sync{})
	if err := sess.targetDb.Flush(); err != nil {
		return err
	}
	_, err := sess.streamResult(nil, streamOpts{extended: true}, nil)
	return err
}
