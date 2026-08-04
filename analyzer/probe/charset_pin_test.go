package probe

import "testing"

// TestResultsCharsetPinFacts is the analyzer half of the #81 fix: the MySQL SET that Connector/J (and so
// DBeaver) sends at session init is recognized on the parsed AST and emitted as a rewrite pinning the
// results charset to utf8mb4, so the wire masker keeps decoding UTF-8. It stays a SESSION passthrough (no
// grants); only the executed SQL changes. Because recognition is on the AST, every spelling MySQL accepts
// collapses to the same pin, and anything that is not a single session-scoped `character_set_results = NULL`
// is left untouched for the wire session invariant to fail closed.
func TestResultsCharsetPinFacts(t *testing.T) {
	const want = "SET character_set_results = utf8mb4"

	pinned := []string{
		"SET character_set_results = NULL",
		"set character_set_results=null",
		"SET character_set_results = NULL;",
		"SET SESSION character_set_results = NULL",
		"SET LOCAL character_set_results = NULL",
		"SET @@character_set_results = NULL",
		"SET @@session.character_set_results = NULL",
		"SET @@local.character_set_results = null",
	}
	for _, sql := range pinned {
		t.Run("pin/"+sql, func(t *testing.T) {
			f := mysqlFacts(t, sql)
			if got := resolve(t, sql); got != "session" {
				t.Fatalf("classification = %q, want session", got)
			}
			if f.RewrittenSql == nil || f.GetRewrittenSql() != want {
				t.Fatalf("rewrittenSql = (%q, has=%v), want %q", f.GetRewrittenSql(), f.RewrittenSql != nil, want)
			}
		})
	}

	untouched := []string{
		"SET character_set_results = utf8mb4",              // already safe
		"SET character_set_results = latin1",               // explicit non-utf8
		"SET GLOBAL character_set_results = NULL",          // different variable (future-connection default)
		"SET @@global.character_set_results = NULL",        // ditto, sigil form
		"SET PERSIST character_set_results = NULL",         // persisted
		"SET character_set_client = NULL",                  // different variable
		"SET character_set_results = 'NULL'",               // string literal, not the NULL keyword
		"SET NAMES latin1",                                 // not an assignment to character_set_results
		"SET autocommit = 1, character_set_results = NULL", // compound
		"SET character_set_results = NULL, autocommit = 1", // compound
		"SET @character_set_results = NULL",                // a same-named USER variable, not the system one
		"SET foo.character_set_results = NULL",             // qualified target, not the bare system variable
		"SET @@bogus.character_set_results = NULL",         // an invalid @@ scope MySQL would reject
	}
	for _, sql := range untouched {
		t.Run("untouched/"+sql, func(t *testing.T) {
			if f := mysqlFacts(t, sql); f.RewrittenSql != nil {
				t.Fatalf("rewrittenSql = %q, want none (must fail closed at the wire invariant, not be pinned)", f.GetRewrittenSql())
			}
		})
	}
}
