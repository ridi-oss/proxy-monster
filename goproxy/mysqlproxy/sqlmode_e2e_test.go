package mysqlproxy_test

import (
	"strings"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

// allowAllDecide is the fake-CP verdict for these sql_mode wire tests. The analyzer is not in the loop here,
// so every statement is ALLOWed and each assertion rides on the proxy's OWN sql_mode observation/forwarding
// (the masked-read proof against a real ANSI_QUOTES target DB + the live analyzer is a control-plane / pm-demo
// check, not a wire-layer one).
func allowAllDecide(*pb.DecisionRequest) (*pb.WireDecision, error) {
	return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
}

// TestAnsiQuotesObservedAndForwarded is the ANSI_QUOTES wire flip against a real MySQL target DB: a session
// that enters ANSI_QUOTES is NO LONGER failed closed. The SET succeeds and every subsequent statement's
// DecisionRequest carries MysqlAnsiQuotes=true, so the control plane can mask a `"`-quoted column instead of
// the proxy killing the session. Because the proxy re-probes sql_mode before every statement, the flip is
// observed even when the SESSION_TRACK tracker is defeated — closing the mid-session race airtight.
func TestAnsiQuotesObservedAndForwarded(t *testing.T) {
	const readSQL = "SELECT id FROM people ORDER BY id"

	t.Run("direct SET is allowed and forwarded", func(t *testing.T) {
		h := startBroker(t)
		h.fake.decideFn = allowAllDecide
		client := openRawClient(t, h.addr, validToken)
		// The SET itself now succeeds (OK, not fail-closed ERR): ANSI_QUOTES is observable, not unsafe.
		response := client.firstQueryPacket(t, "SET sql_mode = 'STRICT_TRANS_TABLES,ANSI_QUOTES'")
		if len(response) == 0 || response[0] != 0x00 {
			t.Fatalf("SET ANSI_QUOTES response = %x, want OK (ANSI_QUOTES is now observed, not failed)", response)
		}
		// The next statement is decided with MysqlAnsiQuotes=true (read by the pre-statement probe).
		client.query(t, readSQL)
		assertLastDecideAnsiQuotes(t, h, readSQL, true)
	})

	t.Run("observed past a defeated tracker", func(t *testing.T) {
		h := startBroker(t)
		h.fake.decideFn = allowAllDecide
		client := openRawClient(t, h.addr, validToken)
		// Clear the tracker so the sql_mode change is NOT reported in its OK, flip it (accepted silently),
		// then a bare read whose pre-statement re-probe observes ANSI_QUOTES and forwards it anyway.
		client.query(t, "SET session_track_system_variables=''")
		client.query(t, "SET sql_mode = 'ANSI_QUOTES'")
		client.query(t, readSQL)
		assertLastDecideAnsiQuotes(t, h, readSQL, true)
	})

	t.Run("default mode forwards false", func(t *testing.T) {
		h := startBroker(t)
		h.fake.decideFn = allowAllDecide
		client := openRawClient(t, h.addr, validToken)
		client.query(t, readSQL)
		assertLastDecideAnsiQuotes(t, h, readSQL, false)
	})
}

// TestUnmodeledSqlModeStillFailsClosed proves the other half of the split: a lexer-changing flag the analyzer
// cannot model still fails the session closed — both when the change is reported directly (its SESSION_TRACK
// OK) and when it is chained past a defeated tracker (the pre-statement re-probe). ANSI is included because
// MySQL stores it EXPANDED (…,PIPES_AS_CONCAT,ANSI_QUOTES,IGNORE_SPACE,…): the guard must fail closed on its
// component flags, never treat an ANSI session as plain ANSI_QUOTES and let its `||` / function-name grammar
// slip past the analyzer.
func TestUnmodeledSqlModeStillFailsClosed(t *testing.T) {
	for _, mode := range []string{"NO_BACKSLASH_ESCAPES", "PIPES_AS_CONCAT", "ANSI"} {
		t.Run("direct "+mode, func(t *testing.T) {
			h := startBroker(t)
			h.fake.decideFn = allowAllDecide
			client := openRawClient(t, h.addr, validToken)
			response := client.firstQueryPacket(t, "SET sql_mode = '"+mode+"'")
			if len(response) == 0 || response[0] != 0xff {
				t.Fatalf("SET sql_mode=%s response = %x, want fail-closed ERR", mode, response)
			}
			if got := mysqlwire.ErrString(response); !strings.Contains(strings.ToLower(got), "sql_mode") {
				t.Fatalf("SET sql_mode=%s error = %q, want a sql_mode fail-closed", mode, got)
			}
		})
	}

	t.Run("chained past a defeated tracker", func(t *testing.T) {
		h := startBroker(t)
		h.fake.decideFn = allowAllDecide
		client := openRawClient(t, h.addr, validToken)
		// Clear the tracker so the sql_mode change is not reported in its OK, flip it (accepted silently),
		// then a bare read whose pre-statement re-probe observes the unsafe sql_mode.
		client.query(t, "SET session_track_system_variables=''")
		client.query(t, "SET sql_mode = 'NO_BACKSLASH_ESCAPES'")
		response := client.firstQueryPacket(t, "SELECT id FROM people ORDER BY id")
		if len(response) == 0 || response[0] != 0xff {
			t.Fatalf("post-bypass SELECT response = %x, want fail-closed ERR", response)
		}
		if got := mysqlwire.ErrString(response); !strings.Contains(got, "namespace probe failed") || !strings.Contains(strings.ToLower(got), "sql_mode") {
			t.Fatalf("post-bypass sql_mode error = %q, want probe-time sql_mode fail-closed", got)
		}
	})
}

// assertLastDecideAnsiQuotes fails unless the most recent Decide request for sql carried the wanted
// MysqlAnsiQuotes value.
func assertLastDecideAnsiQuotes(t *testing.T, h *brokerHarness, sql string, want bool) {
	t.Helper()
	reqs := h.fake.requests()
	for i := len(reqs) - 1; i >= 0; i-- {
		if reqs[i].GetSql() == sql {
			if reqs[i].GetMysqlAnsiQuotes() != want {
				t.Fatalf("DecisionRequest(%q).MysqlAnsiQuotes = %v, want %v", sql, reqs[i].GetMysqlAnsiQuotes(), want)
			}
			return
		}
	}
	t.Fatalf("no Decide request found for %q", sql)
}
