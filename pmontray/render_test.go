package main

import (
	"strings"
	"sync"
	"testing"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

// The menu-item plumbing is macOS-only, so these tests exercise the row-assignment model directly: what a row
// DISPLAYS and what it COPIES must always describe the same datasource. That pairing is the security-relevant
// part — a mismatch hands a user another datasource's credentials.

// newTestApp builds an app with the row pool but no systray, so row bookkeeping can be tested off-screen.
func newTestApp(rows int) *app {
	a := &app{}
	for range rows {
		a.dsItems = append(a.dsItems, &dsItem{})
	}
	return a
}

func statusWith(names ...string) *control.Status {
	s := &control.Status{Principal: "you@example.com", LoggedIn: true, LocalPassword: "pw"}
	for i, n := range names {
		s.Datasources = append(s.Datasources, control.Datasource{
			Name: n, Engine: "mysql", DbName: n + "_db", LocalPort: 6100 + i, Brokered: true,
		})
	}
	return s
}

// TestConcurrentRendersNeverLeaveAMixedPool is the invariant serializing renders exists for. render is reachable
// from the event watcher AND from every action goroutine, and it walks the row pool writing the new set then
// clearing the tail. Unserialized, two renders interleave so one clears the tail before the other has written
// it — leaving a pool like [zulu yankee delta echo], a datasource list that never existed on any daemon. The
// user would then see, and be able to copy credentials for, a set that is not the real state.
func TestConcurrentRendersNeverLeaveAMixedPool(t *testing.T) {
	a := newTestApp(8)
	setA := statusWith("alpha", "bravo", "charlie", "delta", "echo")
	setB := statusWith("zulu", "yankee")

	for attempt := range 4000 {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); a.render(setA) }()
		go func() { defer wg.Done(); a.render(setB) }()
		wg.Wait()

		var names []string
		for _, row := range a.dsItems {
			row.mu.Lock()
			name, conn := row.name, row.connString
			row.mu.Unlock()
			if name == "" {
				continue
			}
			names = append(names, name)
			// Each row must also carry ITS OWN datasource's payload, never a neighbour's credentials.
			if conn != "" && !strings.Contains(conn, name+"_db") {
				t.Fatalf("row labeled %q carries a connection string for another datasource: %q", name, conn)
			}
		}
		// The settled pool must be exactly one of the two real sets.
		isA := len(names) == 5 && names[0] == "alpha"
		isB := len(names) == 2 && names[0] == "zulu"
		if !isA && !isB {
			t.Fatalf("attempt %d left a pool that never existed on any daemon: %v", attempt, names)
		}
	}
}

// TestUnbrokeredRowCarriesNoPayload: a row without an advertised address must be un-clickable rather than
// copying an empty or bogus string.
func TestUnbrokeredRowCarriesNoPayload(t *testing.T) {
	a := newTestApp(4)
	s := &control.Status{Principal: "you@example.com", LoggedIn: true, LocalPassword: "pw"}
	s.Datasources = []control.Datasource{
		{Name: "no-addr", Engine: "postgres", Brokered: false, Reason: "no advertised proxy address"},
	}
	a.applyRows(s)

	if a.dsItems[0].name != "no-addr" {
		t.Fatalf("row 0 = %q, want no-addr", a.dsItems[0].name)
	}
	if a.dsItems[0].connString != "" {
		t.Errorf("unbrokered row carries a payload %q; a click must copy nothing", a.dsItems[0].connString)
	}
}

// TestOverflowSpendsTheLastRowOnANotice: the pool is fixed, so a larger set must stop somewhere — with the last
// row spent saying how many are hidden, never silently truncated into a list that reads as complete. The count
// must add up: rows shown + "and N more" == the real total.
func TestOverflowSpendsTheLastRowOnANotice(t *testing.T) {
	a := newTestApp(4)
	a.applyRows(statusWith("a", "b", "c", "d", "e", "f"))

	// Rows 0..2 carry datasources; row 3 is the notice, with no payload so a click copies nothing.
	var named []string
	for i := range 3 {
		if n := a.dsItems[i].name; n != "" {
			named = append(named, n)
		}
	}
	if len(named) != 3 || named[0] != "a" || named[2] != "c" {
		t.Errorf("rows = %v, want the first three datasources", named)
	}
	notice := a.dsItems[3]
	if notice.name != "" || notice.connString != "" {
		t.Errorf("the overflow notice carries a payload (name=%q conn=%q); it must not be clickable",
			notice.name, notice.connString)
	}

	// Exactly as many datasources as rows: every one is shown, no row spent on a notice.
	b := newTestApp(4)
	b.applyRows(statusWith("a", "b", "c", "d"))
	for i, want := range []string{"a", "b", "c", "d"} {
		if got := b.dsItems[i].name; got != want {
			t.Errorf("row %d = %q, want %q (a set that fits must not lose a row to the notice)", i, got, want)
		}
	}
}
