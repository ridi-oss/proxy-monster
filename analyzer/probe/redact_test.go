package probe

import (
	"strings"
	"testing"
)

func TestRedactLiteralsReplacesEveryLiteralAndKeepsTheLimit(t *testing.T) {
	for _, tc := range []struct{ engine, sql, want string }{
		{"mysql", "SELECT * FROM users WHERE email = 'a@b.c' AND age > 30", "SELECT * FROM users WHERE email = ? AND age > ?"},
		{"mysql", "SELECT id FROM users ORDER BY id LIMIT 1000 OFFSET 5000", "SELECT id FROM users ORDER BY id LIMIT 1000 OFFSET ?"},
		{"mysql", "SELECT id FROM users ORDER BY id LIMIT 5000, 1000", "SELECT id FROM users ORDER BY id LIMIT ?, 1000"},
		{"mysql", "SELECT phone FROM users WHERE phone IN ('010-1234-5678', '010-9999-0000') AND active = TRUE", "SELECT phone FROM users WHERE phone IN (?, ?) AND active = TRUE"},
		{"mysql", `SELECT name FROM users WHERE email = "a@b.c"`, "SELECT name FROM users WHERE email = ?"},
		{"mysql", "SELECT name FROM users WHERE email = N'a@b.c'", "SELECT name FROM users WHERE email = ?"},
		{"mysql", "SELECT 0x736563726574, X'7365', b'101'", "SELECT ?, ?, ?"},
		{"mysql", "SELECT id FROM users /* lookup for a@b.c */ WHERE id = 7 -- ssn 900101", "SELECT id FROM users WHERE id = ?"},
		{"mysql", "CREATE USER 'bob'@'%' IDENTIFIED BY 'hunter2'", "CREATE USER ?@? IDENTIFIED BY ?"},
		{"mysql", "SELEC broken 'secret-value'", "SELEC broken ?"},
		{"postgres", "SELECT name FROM customers WHERE ssn = '900101-1234567'", "SELECT name FROM customers WHERE ssn = ?"},
		{"postgres", "SELECT $$secret@example.com$$, E'secret', U&'d\\0061t\\+000061'", "SELECT ?, ?, ?"},
		{"postgres", "SELECT id FROM users ORDER BY id OFFSET 5000 LIMIT 1000", "SELECT id FROM users ORDER BY id OFFSET ? LIMIT 1000"},
		{"postgres", "UPDATE t SET a = 'secret' WHERE id = 7", "UPDATE t SET a = ? WHERE id = ?"},
		{"athena", "SELECT * FROM logs WHERE ip = '10.0.0.1' LIMIT 10", "SELECT * FROM logs WHERE ip = ? LIMIT 10"},
		{"athena", "CREATE EXTERNAL TABLE t (a string) LOCATION 's3://secret-bucket/x'", "CREATE EXTERNAL TABLE t (a string) LOCATION ?"},
	} {
		got, ok := RedactLiterals(tc.sql, tc.engine)
		if !ok || got != tc.want {
			t.Errorf("RedactLiterals(%q, %s) = %q, %v; want %q", tc.sql, tc.engine, got, ok, tc.want)
		}
		for _, secret := range []string{"a@b.c", "hunter2", "secret", "900101", "736563726574", "010-"} {
			if strings.Contains(got, secret) {
				t.Errorf("RedactLiterals(%q) leaks %q: %q", tc.sql, secret, got)
			}
		}
	}
}

func TestRedactLiteralsWithholdsWhatItCannotShowWhole(t *testing.T) {
	for _, tc := range []struct{ engine, sql string }{
		{"no-such-engine", "SELECT 1"},
		{"mysql", "SELECT 1 /*! , password FROM mysql.user */"},
		{"mysql", "SELECT /*+ MAX_EXECUTION_TIME(1) */ 1"},
	} {
		if got, ok := RedactLiterals(tc.sql, tc.engine); ok {
			t.Errorf("RedactLiterals(%q, %s) = %q; want it withheld", tc.sql, tc.engine, got)
		}
	}
}
