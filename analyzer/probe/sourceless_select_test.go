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

func TestSourcelessSelectKeepsTheFunctionGrant(t *testing.T) {
	parityFunctionGrant(t, "select foo, load_file('/etc/passwd')", "mysql")
	parityFunctionGrant(t, "select foo, pg_read_file('/etc/passwd')", "postgres")
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
