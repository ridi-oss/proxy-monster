package worm

import (
	"strings"
	"testing"
)

type countingGetStore struct {
	ObjectStore
	gets   map[string]int
	hidden map[string]bool
}

func newCountingGetStore() *countingGetStore {
	return &countingGetStore{ObjectStore: NewMemory(), gets: map[string]int{}, hidden: map[string]bool{}}
}

func (s *countingGetStore) Get(key string) ([]byte, error) {
	s.gets[key]++
	return s.ObjectStore.Get(key)
}

func (s *countingGetStore) ListObjects(prefix string) ([]ObjectInfo, error) {
	all, err := s.ObjectStore.ListObjects(prefix)
	if err != nil {
		return nil, err
	}
	var out []ObjectInfo
	for _, o := range all {
		if !s.hidden[o.Key] {
			out = append(out, o)
		}
	}
	return out, nil
}

func (s *countingGetStore) totalGets() int {
	n := 0
	for _, c := range s.gets {
		n += c
	}
	return n
}

func writeTestAnchor(t *testing.T, os ObjectStore, id int64, head string) {
	t.Helper()
	if err := WriteAnchor(os, Anchor{UpToID: id, HeadHash: head, Signature: "c2ln", KeyID: "k1"}); err != nil {
		t.Fatalf("write anchor %d: %v", id, err)
	}
}

func TestReaderFetchesEachAnchorOnceAcrossReads(t *testing.T) {
	store := newCountingGetStore()
	for id := int64(1); id <= 3; id++ {
		writeTestAnchor(t, store, id, "aa")
	}
	r := NewReader(store)
	store.gets = map[string]int{}

	for range 3 {
		got, err := r.Anchors()
		if err != nil {
			t.Fatalf("read anchors: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("got %d anchors, want 3", len(got))
		}
	}
	if n := store.totalGets(); n != 3 {
		t.Fatalf("three reads of three unchanged anchors made %d GETs, want 3", n)
	}

	writeTestAnchor(t, store, 4, "bb")
	store.gets = map[string]int{}
	got, err := r.Anchors()
	if err != nil {
		t.Fatalf("read anchors: %v", err)
	}
	if len(got) != 4 || got[3].UpToID != 4 {
		t.Fatalf("anchors = %+v, want ids 1..4 ascending", got)
	}
	if n := store.totalGets(); n != 1 || store.gets[checkpointPrefix+"4.json"] != 1 {
		t.Fatalf("GETs after one new anchor = %v, want only the new key once", store.gets)
	}
}

func TestReaderRefetchesAnObjectReplacedAtTheSameKey(t *testing.T) {
	store := newCountingGetStore()
	writeTestAnchor(t, store, 7, "aa")
	r := NewReader(store)
	if _, err := r.Anchors(); err != nil {
		t.Fatalf("read anchors: %v", err)
	}

	if err := store.Put(checkpointPrefix+"7.json", []byte(`{"up_to_id":7,"head_hash":"ff","signature":"Zm9yZ2Vk","key_id":"k1"}`)); err != nil {
		t.Fatalf("replace anchor: %v", err)
	}
	got, err := r.Anchors()
	if err != nil {
		t.Fatalf("read anchors: %v", err)
	}
	if len(got) != 1 || got[0].HeadHash != "ff" || got[0].Signature != "Zm9yZ2Vk" {
		t.Fatalf("anchors = %+v, want the replacement object, not the cached original", got)
	}
}

func TestReaderRemembersJunkWithoutRefetching(t *testing.T) {
	store := newCountingGetStore()
	if err := store.Put(checkpointPrefix+"5.json", []byte("not json")); err != nil {
		t.Fatalf("put junk: %v", err)
	}
	r := NewReader(store)
	for range 3 {
		got, err := r.Anchors()
		if err != nil {
			t.Fatalf("read anchors: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("junk object parsed as %+v", got)
		}
	}
	if n := store.gets[checkpointPrefix+"5.json"]; n != 1 {
		t.Fatalf("junk object fetched %d times, want 1", n)
	}
}

func TestReaderDropsAKeyNoLongerListed(t *testing.T) {
	store := newCountingGetStore()
	writeTestAnchor(t, store, 1, "aa")
	writeTestAnchor(t, store, 2, "bb")
	r := NewReader(store)
	if _, err := r.Anchors(); err != nil {
		t.Fatalf("read anchors: %v", err)
	}

	store.hidden[checkpointPrefix+"2.json"] = true
	got, err := r.Anchors()
	if err != nil {
		t.Fatalf("read anchors: %v", err)
	}
	if len(got) != 1 || got[0].UpToID != 1 {
		t.Fatalf("anchors = %+v, want only id 1 once id 2 is no longer listed", got)
	}
}

func TestReaderLeavesItsCacheIntactWhenAGetFails(t *testing.T) {
	backing := NewMemory()
	writeTestAnchor(t, backing, 1, "aa")
	writeTestAnchor(t, backing, 2, "bb")
	blind := failingGetStore{ObjectStore: backing, failKey: checkpointPrefix + "2.json"}
	r := NewReader(blind)
	if _, err := r.Anchors(); err == nil || !strings.Contains(err.Error(), "connection reset") {
		t.Fatalf("read with a failing GET returned err=%v, want the GET error", err)
	}

	r.store = backing
	got, err := r.Anchors()
	if err != nil {
		t.Fatalf("read anchors: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("anchors = %+v, want both after the GET recovers", got)
	}
}

func TestReaderAcceptancesFetchesEachOnce(t *testing.T) {
	store := newCountingGetStore()
	acc := Acceptance{DivergentID: 3, Reason: "content_mismatch", Expected: "aa", Actual: "bb", ResumeHash: "bb", Signature: "c2ln", KeyID: "k1"}
	if err := WriteAcceptance(store, acc); err != nil {
		t.Fatalf("write acceptance: %v", err)
	}
	r := NewReader(store)
	for range 3 {
		got, err := r.Acceptances()
		if err != nil {
			t.Fatalf("read acceptances: %v", err)
		}
		if len(got) != 1 || got[0] != acc {
			t.Fatalf("acceptances = %+v, want [%+v]", got, acc)
		}
	}
	if n := store.totalGets(); n != 1 {
		t.Fatalf("three reads of one acceptance made %d GETs, want 1", n)
	}
}
