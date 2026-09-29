package probe

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

func TestSourcelessSelectRelaysAnUnresolvableName(t *testing.T) {
	cases := []struct {
		dialect string
		sql     string
		outputs []string
	}{
		{"mysql", "select $$", []string{"$$"}},
		{"mysql", "select foo", []string{"foo"}},
		{"mysql", "select $$, 1 as one", []string{"$$", "one"}},
		{"mysql", "select (select $$)", nil},
		{"mysql", "select current_role", []string{"current_role"}},
		{"postgres", "select foo", []string{"foo"}},
		{"postgres", "select foo, 1 as one", []string{"foo", "one"}},
		{"postgres", "select (select foo)", nil},
		{"postgres", "select current_role", []string{"current_role"}},
	}
	for _, c := range cases {
		f := factsFor(t, c.sql, c.dialect)
		if !f.Resolved || factsKind(f) != pb.StatementKind_STATEMENT_KIND_SELECT {
			t.Errorf("[%s] %q: want resolved SELECT, got resolved=%v kind=%s detail=%q", c.dialect, c.sql, f.Resolved, factsKind(f), f.Detail)
			continue
		}
		for _, g := range f.GetResultReads() {
			if g.GetColumn() != nil || g.GetTable() != nil {
				t.Errorf("[%s] %q: a sourceless statement emitted a column/table read: %v", c.dialect, c.sql, g)
			}
		}
		want := len(c.outputs)
		if c.outputs == nil {
			want = 1
		}
		got := f.GetOutputColumns()
		if len(got) != want {
			t.Errorf("[%s] %q: want %d output columns, got %v", c.dialect, c.sql, want, got)
			continue
		}
		for i, name := range c.outputs {
			if got[i] != name {
				t.Errorf("[%s] %q: output %d: want %q, got %q", c.dialect, c.sql, i, name, got[i])
			}
		}
	}
}

func TestSourcelessSelectKeepsTheFunctionGate(t *testing.T) {
	cases := []struct {
		dialect string
		sql     string
		name    string
	}{
		{"mysql", "select foo, load_file('/etc/passwd')", "load_file"},
		{"postgres", "select foo, pg_read_file('/etc/passwd')", "pg_read_file"},
	}
	for _, c := range cases {
		f := factsFor(t, c.sql, c.dialect)
		if !f.Resolved {
			t.Errorf("[%s] %q: want resolved, got stage=%q detail=%q", c.dialect, c.sql, f.GetFailedStage(), f.Detail)
			continue
		}
		if got := len(f.GetOutputColumns()); got != 2 {
			t.Errorf("[%s] %q: want 2 output columns, got %v", c.dialect, c.sql, f.GetOutputColumns())
		}
		for _, g := range f.GetResultReads() {
			if g.GetColumn() != nil || g.GetTable() != nil {
				t.Errorf("[%s] %q: a sourceless statement emitted a column/table read: %v", c.dialect, c.sql, g)
			}
		}
		parityFunctionGated(t, c.sql, c.dialect, c.name)
	}
	bothDialects(func(d string) { parityFunctionGrant(t, "select foo, leak_ssn()", d) })
}

func TestUnresolvableNameWithASourceStaysFailClosed(t *testing.T) {
	cases := []struct {
		dialect string
		sql     string
		stage   string
	}{
		{"mysql", "select $$ from users", "VALIDATE"},
		{"mysql", "select ssn from users where id = $$", "VALIDATE"},
		{"mysql", "select $$ from (select 1) t", "VALIDATE"},
		{"mysql", "with c as (select 1) select $$", "VALIDATE"},
		{"mysql", "select $$ into outfile '/tmp/x'", "VALIDATE"},
		{"mysql", "select * from users where ssn = (select $$)", "VALIDATE"},
		{"mysql", "select (table users)", "VALIDATE"},
		{"mysql", "select session_user", "VALIDATE"},
		{"mysql", "select users.$$", "VALIDATE"},
		{"postgres", "select (table users)", "VALIDATE"},
		{"postgres", "select foo from users", "VALIDATE"},
		{"postgres", "select $$", "PARSE"},
	}
	for _, c := range cases {
		f := factsFor(t, c.sql, c.dialect)
		if f.Resolved || f.GetFailedStage() != c.stage {
			t.Errorf("[%s] %q: want fail-closed at %s, got resolved=%v stage=%q detail=%q", c.dialect, c.sql, c.stage, f.Resolved, f.GetFailedStage(), f.Detail)
		}
	}
}
