package mysqlproxy

import (
	"errors"
	"math"
	"net"
	"strconv"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

type RunSession struct {
	conn         net.Conn
	connID       uint32
	target       spi.BackendTarget
	token        string
	connectionID []byte
	qe           *engine.QueryEngine
	ref          *engine.Refetcher
	guard        engine.ExecGuard
}

func NewRunSession(target spi.BackendTarget, db engine.Db, client spi.SessionClient, token string, connectionID []byte, guard engine.ExecGuard, readTimeout time.Duration) (*RunSession, error) {
	conn, connID, err := dialBackendAuthID(target, true)
	if err != nil {
		return nil, err
	}
	conn = withIODeadlines(conn, readTimeout, socketWriteTimeout)
	generation := backendGeneration.Add(1)
	if generation == 0 || generation > maxBackendGeneration {
		_ = conn.Close()
		return nil, errors.New("run backend generation out of range")
	}
	s := &RunSession{
		conn:         conn,
		connID:       connID,
		target:       target,
		token:        token,
		connectionID: append([]byte(nil), connectionID...),
		qe:           engine.NewQueryEngine(db, client),
		guard:        guard,
	}
	s.ref = engine.NewRefetcher(db, s.connectionID, generation, func(sql string, expectedColumns int) ([][]*string, error) {
		return runInternalQuery(s.conn, true, sql, expectedColumns)
	}, client.PushSchemaFragment, nil)
	return s, nil
}

func (s *RunSession) OnOpen(cmds []*pb.Refetch) error { return s.ref.RunAllSettled(cmds) }

func (s *RunSession) ServeStatement(sql string, maxRows int) (result engine.StatementResult, err error) {
	result.Decision, result.Denied, err = engine.ServeStatement(s.qe, engine.AuthzInput{
		SQL:            sql,
		Token:          s.token,
		ConnectionID:   s.connectionID,
		ProbeNamespace: func() (engine.NamespaceProbe, error) { return probeNamespaceObservation(s.conn, true) },
		RunCommands:    s.ref.RunAll,
	}, s.ref, s.guard, func(toSend string, masks []*pb.ColumnMask) (clean bool, runErr error) {
		payload := mysqlwire.ComQueryPayload(toSend)
		if len(payload) >= mysqlwire.MaxPacketPayload {
			return false, errors.New("query exceeds the maximum MySQL packet payload")
		}
		capped := maxRows > 0
		if capped {
			if maxRows == math.MaxInt {
				return false, errors.New("max rows exceeds MySQL SQL_SELECT_LIMIT range")
			}
			if err := execBackendSet(s.conn, "SET SQL_SELECT_LIMIT = "+strconv.Itoa(maxRows+1)); err != nil {
				return false, err
			}
		}
		reset := func() error {
			if !capped {
				return nil
			}
			return execBackendSet(s.conn, "SET SQL_SELECT_LIMIT = DEFAULT")
		}

		if err := mysqlwire.WritePacket(s.conn, 0, payload); err != nil {
			_ = reset()
			return false, err
		}
		collect := textResultCollector{maxRows: maxRows, masks: masks, result: &result}
		h := collect.hooks()
		h.OnSysVars = checkSysVarInvariants
		h.RedactErr = errRedactor(s.qe)
		clean, relayErr := relayResultSet(s.conn, true, h)
		s.qe.MarkNamespaceDirty()
		resetErr := reset()
		if relayErr != nil {
			return false, relayErr
		}
		if collect.backendErr != nil {
			return false, collect.backendErr
		}
		if resetErr != nil {
			return false, resetErr
		}
		return clean, nil
	})
	return result, err
}

func (s *RunSession) Cancel() error {
	conn, _, err := dialBackendAuthID(s.target, true)
	if err != nil {
		_ = s.conn.Close()
		return err
	}
	conn = withIODeadlines(conn, 5*time.Second, 5*time.Second)
	defer conn.Close()
	if err := execBackendSet(conn, "KILL QUERY "+strconv.FormatUint(uint64(s.connID), 10)); err != nil {
		_ = s.conn.Close()
		return err
	}
	return nil
}

func (s *RunSession) Close() error { return s.conn.Close() }
