package probe

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// TestGucAliasPrivilegeSetIsSystemCritical locks the privilege-escalation floor for EVERY spelling of
// SET ROLE / SET SESSION AUTHORIZATION — keyword and GUC-alias (`SET role = x`, which parses as a
// structured Set, not the SET-keyword Command form, so keying on the SetItem kind alone misses it). Each
// resolves carrying the system-classified Utility grant for its identity change; the control-plane's
// shipped system:critical floor forbids it (forbid-wins over any grant, preset-relaxable), so a plain
// policy/read grant still cannot escalate the session.
func TestGucAliasPrivilegeSetIsSystemCritical(t *testing.T) {
	byCommand := map[string]string{
		"SET session_authorization = 'attacker'":       "SET_SESSION_AUTHORIZATION",
		"SET SESSION role = 'attacker'":                "SET_ROLE",
		"SET role = 'attacker'":                        "SET_ROLE",
		"SET LOCAL session_authorization = 'attacker'": "SET_SESSION_AUTHORIZATION",
		"SET ROLE = 'attacker'":                        "SET_ROLE",
		`SET "role" = 'attacker'`:                      "SET_ROLE",
		"SET ROLE attacker":                            "SET_ROLE",                  // keyword form (Command)
		"SET SESSION AUTHORIZATION attacker":           "SET_SESSION_AUTHORIZATION", // keyword form (Command)
	}
	for sql, command := range byCommand {
		parityUtility(t, sql, "postgres", command)
	}

	// Benign session SETs must still relay as a SESSION passthrough with no grants.
	allowed := []string{
		"SET search_path = public",
		"SET TIME ZONE 'UTC'",
		"SET statement_timeout = 1000",
	}
	for _, sql := range allowed {
		facts := postgresFacts(t, sql)
		if !facts.GetResolved() || factsKind(facts) != pb.StatementKind_STATEMENT_KIND_SET_SESSION_VAR || len(nonExecuteGrants(facts)) != 0 {
			t.Errorf("%q: expected a benign session-var passthrough with no grants beyond execute, got resolved=%v kind=%v grants=%d",
				sql, facts.GetResolved(), factsKind(facts), len(nonExecuteGrants(facts)))
		}
	}
}
