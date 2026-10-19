package athena

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func privateCachePath(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, "contexts.aof")
}

func testContext(t *testing.T, id string) *enginepb.AthenaCachedContext {
	t.Helper()
	instructions, err := proto.Marshal(&pb.Verdict{Decision: pb.EnfAction_MASK, DecisionId: 42, Masks: []*pb.ColumnMask{{Ordinal: proto.Int32(0), Kind: "FIXED"}}, SanitizeDiagnostics: true})
	if err != nil {
		t.Fatal(err)
	}
	return &enginepb.AthenaCachedContext{Version: 1, ContextId: "context-" + id, ResourceId: id, Owner: "alice", TargetBinding: bytes.Repeat([]byte{1}, 32), ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)), ExpectedWidth: proto.Uint32(2), EnforcementInstructions: instructions}
}

func TestContextAOFReopenOwnershipExpiryAndPermissions(t *testing.T) {
	path := privateCachePath(t)
	cache, err := OpenContextCache(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	record := testContext(t, "native-id")
	original := proto.Clone(record).(*enginepb.AthenaCachedContext)
	if err := cache.Associate("source", record); err != nil {
		t.Fatal(err)
	}
	record.Owner = "mutated"
	if other, err := OpenContextCache(path, 10); err == nil {
		_ = other.Close()
		t.Fatal("second owner opened AOF")
	}
	for _, file := range []string{path, path + ".lock"} {
		info, err := os.Stat(file)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("non-private file %s: %v", file, err)
		}
	}
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}
	cache, err = OpenContextCache(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	restored, err := cache.Lookup("source", "native-id", "alice", original.TargetBinding)
	if err != nil || !proto.Equal(original, restored) {
		t.Fatalf("original context changed on reopen: %v %v", restored, err)
	}
	if _, err := cache.Lookup("source", "native-id", "bob", original.TargetBinding); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("owner binding ignored")
	}
	if _, err := cache.Lookup("source", "native-id", "alice", bytes.Repeat([]byte{2}, 32)); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("target binding ignored")
	}
	if _, err := cache.Lookup("other-source", "native-id", "alice", original.TargetBinding); !errors.Is(err, ErrOriginalContextUnavailable) {
		t.Fatal("datasource binding ignored")
	}
	cache.now = func() time.Time { return original.ExpiresAt.AsTime().Add(time.Second) }
	if _, err := cache.Lookup("source", "native-id", "alice", original.TargetBinding); !errors.Is(err, ErrOriginalContextUnavailable) {
		t.Fatal("restart renewed absolute expiry")
	}
}

func TestContextAssociationIsImmutableAndBounded(t *testing.T) {
	cache, err := OpenContextCache(":memory:", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	first := testContext(t, "first")
	if err := cache.Associate("source", first); err != nil {
		t.Fatal(err)
	}
	if err := cache.Associate("source", proto.Clone(first).(*enginepb.AthenaCachedContext)); err != nil {
		t.Fatal(err)
	}
	changed := proto.Clone(first).(*enginepb.AthenaCachedContext)
	changed.Owner = "bob"
	if err := cache.Associate("source", changed); !errors.Is(err, ErrContextConflict) {
		t.Fatal("existing owner replaced")
	}
	second := testContext(t, "second")
	if err := cache.Associate("source", second); !errors.Is(err, ErrContextCapacity) {
		t.Fatal("capacity ignored")
	}
	cache.now = func() time.Time { return first.ExpiresAt.AsTime().Add(time.Second) }
	second.ExpiresAt = timestamppb.New(cache.now().Add(time.Hour))
	if err := cache.Associate("source", second); err != nil {
		t.Fatalf("expired capacity not reclaimed: %v", err)
	}
	if _, err := cache.Lookup("source", "first", "alice", first.TargetBinding); !errors.Is(err, ErrOriginalContextUnavailable) {
		t.Fatal("expired entry retained")
	}
}

func TestSyncFailurePoisonsCacheBeforeReadersObserveBinding(t *testing.T) {
	path := privateCachePath(t)
	cache, err := OpenContextCache(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	failure := errors.New("injected sync failure")
	cache.syncFile = func() error { close(entered); <-release; return failure }
	record := testContext(t, "native-id")
	associated := make(chan error, 1)
	go func() { associated <- cache.Associate("source", record) }()
	<-entered
	if cache.mu.TryLock() {
		cache.mu.Unlock()
		t.Fatal("binding exposed before checked sync")
	}
	read := make(chan error, 1)
	go func() { _, err := cache.Lookup("source", "native-id", "alice", record.TargetBinding); read <- err }()
	close(release)
	if err := <-associated; !errors.Is(err, failure) {
		t.Fatalf("association ignored sync failure: %v", err)
	}
	if err := <-read; !errors.Is(err, failure) {
		t.Fatalf("reader observed unsynced binding: %v", err)
	}
	cache.syncFile = cache.file.Sync
	if err := cache.Associate("source", testContext(t, "next")); !errors.Is(err, failure) {
		t.Fatal("cache resumed after failed sync")
	}
}

func TestContextAOFFailsClosedWithoutRepairingPartialRecords(t *testing.T) {
	path := privateCachePath(t)
	cache, err := OpenContextCache(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err = cache.Associate("source", testContext(t, "native-id")); err != nil {
		t.Fatal(err)
	}
	if err = cache.Close(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"*3\r\n$3\r\nset\r\n", "*3\r\n$999999999999\r\n", "*2\r\n$0\r\n\r\n$0\r\n\r\n"} {
		corrupt := append(bytes.Clone(original), []byte(suffix)...)
		if err := os.WriteFile(path, corrupt, 0600); err != nil {
			t.Fatal(err)
		}
		if opened, err := OpenContextCache(path, 10); err == nil {
			_ = opened.Close()
			t.Fatal("corrupt AOF opened")
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(after, corrupt) {
			t.Fatal("opening silently repaired corrupt AOF")
		}
	}
}

func TestContextRejectsHistoryAndIncompatibleInstructions(t *testing.T) {
	for _, mutate := range []func(*enginepb.AthenaCachedContext){
		func(record *enginepb.AthenaCachedContext) { record.Version = 2 },
		func(record *enginepb.AthenaCachedContext) { record.ExpiresAt = nil },
		func(record *enginepb.AthenaCachedContext) { record.TargetBinding = []byte("short") },
		func(record *enginepb.AthenaCachedContext) {
			record.EnforcementInstructions, _ = proto.Marshal(&pb.Verdict{Decision: pb.EnfAction_ALLOW, RewrittenSql: proto.String("SELECT secret")})
		},
		func(record *enginepb.AthenaCachedContext) {
			record.EnforcementInstructions, _ = proto.Marshal(&pb.Verdict{Decision: pb.EnfAction_ALLOW, EffectiveRoles: []string{"role"}})
		},
		func(record *enginepb.AthenaCachedContext) {
			record.EnforcementInstructions, _ = proto.Marshal(&pb.Verdict{Decision: pb.EnfAction_DENY})
		},
	} {
		cache, err := OpenContextCache(":memory:", 1)
		if err != nil {
			t.Fatal(err)
		}
		record := testContext(t, "native-id")
		mutate(record)
		if err := cache.Associate("source", record); !errors.Is(err, ErrContextCorrupt) {
			t.Fatalf("invalid context accepted: %v", err)
		}
		_ = cache.Close()
	}
}

func TestContextAOFRejectsPublicDirectoryAndFile(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if cache, err := OpenContextCache(filepath.Join(directory, "context.aof"), 10); err == nil {
		_ = cache.Close()
		t.Fatal("public directory accepted")
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "context.aof")
	if err := os.WriteFile(path, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if cache, err := OpenContextCache(path, 10); err == nil {
		_ = cache.Close()
		t.Fatal("public AOF accepted")
	}
}
