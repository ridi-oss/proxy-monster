package engine

import "testing"

// ParseDialect is the one gate raw engine strings pass through on the proxy; it is fail-closed and
// case-sensitive (callers feed the already-lowercased canonical wire string), and rejects the
// "postgresql" alias. Pin those edges.
func TestParseDialect(t *testing.T) {
	ok := []struct {
		in   string
		want Dialect
	}{
		{"mysql", MySQL},
		{"postgres", Postgres},
		{"athena", Athena},
	}
	for _, c := range ok {
		got, err := ParseDialect(c.in)
		if err != nil {
			t.Errorf("ParseDialect(%q) unexpected error: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("ParseDialect(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	for _, bad := range []string{"MySQL", "Postgres", "Athena", "postgresql", "oracle", ""} {
		if _, err := ParseDialect(bad); err == nil {
			t.Errorf("ParseDialect(%q) = nil error, want fail-closed rejection", bad)
		}
	}
}

func TestDialectWireNameAndPredicates(t *testing.T) {
	if MySQL.WireName() != "mysql" {
		t.Errorf("MySQL.WireName() = %q, want mysql", MySQL.WireName())
	}
	if Postgres.WireName() != "postgres" {
		t.Errorf("Postgres.WireName() = %q, want postgres", Postgres.WireName())
	}
	if !MySQL.IsMySQL() || MySQL.IsPostgres() {
		t.Errorf("MySQL predicates: IsMySQL=%v IsPostgres=%v", MySQL.IsMySQL(), MySQL.IsPostgres())
	}
	if !Postgres.IsPostgres() || Postgres.IsMySQL() {
		t.Errorf("Postgres predicates: IsPostgres=%v IsMySQL=%v", Postgres.IsPostgres(), Postgres.IsMySQL())
	}
	// WireName → ParseDialect round-trips.
	for _, d := range []Dialect{MySQL, Postgres, Athena} {
		got, err := ParseDialect(d.WireName())
		if err != nil || got != d {
			t.Errorf("round-trip ParseDialect(%q) = %v, %v; want %v", d.WireName(), got, err, d)
		}
	}
}
