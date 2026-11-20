package monitor_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/auditmon/canon"
	"github.com/ridi-oss/proxy-monster/auditmon/config"
	"github.com/ridi-oss/proxy-monster/auditmon/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/auditmon/monitor"
	"github.com/ridi-oss/proxy-monster/auditmon/sign"
	"github.com/ridi-oss/proxy-monster/auditmon/store"
	"github.com/ridi-oss/proxy-monster/auditmon/verify"
	"github.com/ridi-oss/proxy-monster/auditmon/worm"
)

// errVerifySigner signs like a stub but always fails Verify with a fixed error, to drive the anchor
// verify-error path.
type errVerifySigner struct{ err error }

func (errVerifySigner) Sign([]byte) ([]byte, string, error) { return []byte("stub-sig"), "stub", nil }

func (s errVerifySigner) Verify([]byte, []byte, string) (bool, error) { return false, s.err }

// spyDetector records that Inspect ran and how many events it saw.
type spyDetector struct {
	called bool
	count  int
}

func (d *spyDetector) InspectCatchUp(events []store.StoredEvent) error { return d.Inspect(events) }

func (d *spyDetector) Inspect(events []store.StoredEvent) error {
	d.called = true
	d.count = len(events)
	return nil
}

// spyReporter records any findings raised.
type spyReporter struct {
	findings []verify.Finding
}

func (r *spyReporter) Report(f verify.Finding) { r.findings = append(r.findings, f) }

// readLastAnchor returns the highest-up_to_id anchor in the store (nil,false when none), for test assertions
// about what the monitor signed.
func readLastAnchor(t *testing.T, os worm.ObjectStore) (*worm.Anchor, bool, error) {
	t.Helper()
	anchors, err := worm.ReadAnchors(os)
	if err != nil || len(anchors) == 0 {
		return nil, false, err
	}
	return &anchors[len(anchors)-1], true, nil
}

const secretSQL = "SELECT ssn FROM users WHERE id = 42"

func decisionEvent(principal, statement string) canon.AuditEvent {
	return canon.AuditEvent{
		Kind:               "decision",
		TSMicros:           canon.EpochMicros(time.Now()),
		Principal:          principal,
		Roles:              []string{"analyst"},
		Datasource:         "warehouse",
		Statement:          statement,
		Decision:           "ALLOW",
		EffectiveNamespace: []string{"public"},
		PIITouched:         []string{"pii:ssn"},
	}
}

// exportedIDs reads every events/ NDJSON batch in the store and returns the event ids it carries, in the
// order encountered. Duplicates are preserved so a caller can assert exactly-once.
func exportedIDs(t *testing.T, os worm.ObjectStore) []int64 {
	t.Helper()
	keys, err := os.List("events/")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	var ids []int64
	for _, key := range keys {
		body, err := os.Get(key)
		if err != nil {
			t.Fatalf("get %s: %v", key, err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
			if line == "" {
				continue
			}
			var rec struct {
				ID int64 `json:"id"`
			}
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("decode export line %q: %v", line, err)
			}
			ids = append(ids, rec.ID)
		}
	}
	return ids
}

// assertExportedExactlyOnce asserts the exported batches carry precisely the given ids, each exactly once.
func assertExportedExactlyOnce(t *testing.T, os worm.ObjectStore, want ...int64) {
	t.Helper()
	got := exportedIDs(t, os)
	seen := make(map[int64]int, len(got))
	for _, id := range got {
		seen[id]++
	}
	for _, id := range want {
		if seen[id] != 1 {
			t.Fatalf("event %d exported %d times, want exactly once (all exported ids: %v)", id, seen[id], got)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("exported %d records %v, want exactly %v", len(got), got, want)
	}
}

func TestPollVerifiesExportsAndSigns(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	genesis := canon.GenesisHash()
	dbtest.SeedChain(t, ctx, pool, genesis, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", secretSQL),
	})

	reader, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer reader.Close()

	signer, err := sign.NewFileKey(filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("new file key: %v", err)
	}
	objStore := worm.NewMemory()
	detector := &spyDetector{}
	reporter := &spyReporter{}

	cfg := config.MonitorConfig{PollInterval: time.Second, SignInterval: time.Hour}
	m := monitor.New(reader, signer, objStore, genesis, cfg, detector, reporter)

	if err := m.Poll(ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if err := m.SignHead(ctx); err != nil {
		t.Fatalf("sign head: %v", err)
	}

	if len(reporter.findings) != 0 {
		t.Fatalf("expected no integrity findings, got %+v", reporter.findings)
	}
	if !detector.called {
		t.Fatal("detector hook did not run")
	}
	if detector.count != 2 {
		t.Fatalf("detector saw %d events, want 2", detector.count)
	}

	// The anchor exists and its signature verifies against the recorded head hash.
	anchor, ok, err := readLastAnchor(t, objStore)
	if err != nil {
		t.Fatalf("read last anchor: %v", err)
	}
	if !ok {
		t.Fatal("expected an anchor after Poll+SignHead")
	}
	if anchor.UpToID != 2 {
		t.Errorf("anchor up_to_id = %d, want 2", anchor.UpToID)
	}
	headHash, err := hex.DecodeString(anchor.HeadHash)
	if err != nil {
		t.Fatalf("decode head hash: %v", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(anchor.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	// The signature covers the digest binding up_to_id AND head hash, not the bare head hash.
	valid, err := signer.Verify(sign.AnchorDigest(anchor.UpToID, headHash), sigBytes, anchor.KeyID)
	if err != nil {
		t.Fatalf("verify anchor: %v", err)
	}
	if !valid {
		t.Fatal("anchor signature failed to verify")
	}

	// The exported batch carries the statement HASH and never the SQL text.
	keys, err := objStore.List("events/")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("event batches = %v, want exactly one", keys)
	}
	body, err := objStore.Get(keys[0])
	if err != nil {
		t.Fatalf("get batch: %v", err)
	}
	text := string(body)
	sum := sha256.Sum256([]byte(secretSQL))
	if !strings.Contains(text, hex.EncodeToString(sum[:])) {
		t.Errorf("exported batch missing statement hash")
	}
	if strings.Contains(text, secretSQL) || strings.Contains(text, "\"statement\"") {
		t.Fatalf("exported batch leaked SQL text:\n%s", text)
	}
}

func TestPollReportsTamperFinding(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	genesis := canon.GenesisHash()
	dbtest.SeedChain(t, ctx, pool, genesis, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
	})
	if _, err := pool.Exec(ctx, "UPDATE audit_event SET principal = 'mallory' WHERE id = 1"); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	reader, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer reader.Close()

	signer, err := sign.NewFileKey(filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("new file key: %v", err)
	}
	objStore := worm.NewMemory()
	reporter := &spyReporter{}
	cfg := config.MonitorConfig{PollInterval: time.Second, SignInterval: time.Hour}
	m := monitor.New(reader, signer, objStore, genesis, cfg, monitor.NoopDetector{}, reporter)

	if err := m.Poll(ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(reporter.findings) != 1 {
		t.Fatalf("expected exactly one finding, got %+v", reporter.findings)
	}
	if reporter.findings[0].DivergentID != 1 || reporter.findings[0].Reason != verify.ReasonRowHashMismatch {
		t.Fatalf("finding = %+v, want row_hash_mismatch at id 1", reporter.findings[0])
	}
	// A broken tail must not be exported.
	keys, err := objStore.List("events/")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected no export for a broken tail, got %v", keys)
	}
}

func TestPollReportsInvalidAnchorSignature(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	genesis := canon.GenesisHash()
	_, head := dbtest.SeedChain(t, ctx, pool, genesis, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
	})

	reader, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer reader.Close()

	signer, err := sign.NewFileKey(filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("new file key: %v", err)
	}

	// Plant an anchor over the real head but corrupt its signature, as a tampered/replaced off-box anchor
	// would look. The monitor must distrust it rather than build on top of it.
	sig, keyID, err := signer.Sign(sign.AnchorDigest(2, head))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig[0] ^= 0xff
	objStore := worm.NewMemory()
	if err := worm.WriteAnchor(objStore, worm.Anchor{
		UpToID:    2,
		HeadHash:  hex.EncodeToString(head),
		Signature: base64.StdEncoding.EncodeToString(sig),
		KeyID:     keyID,
	}); err != nil {
		t.Fatalf("write anchor: %v", err)
	}

	detector := &spyDetector{}
	reporter := &spyReporter{}
	cfg := config.MonitorConfig{PollInterval: time.Second, SignInterval: time.Hour}
	m := monitor.New(reader, signer, objStore, genesis, cfg, detector, reporter)

	if err := m.Poll(ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(reporter.findings) != 1 || reporter.findings[0].Reason != monitor.ReasonAnchorSignatureInvalid {
		t.Fatalf("findings = %+v, want one %s", reporter.findings, monitor.ReasonAnchorSignatureInvalid)
	}
	if reporter.findings[0].DivergentID != 2 {
		t.Errorf("finding id = %d, want 2", reporter.findings[0].DivergentID)
	}
	// A poll that distrusts its anchor must neither inspect, export, nor advance.
	if detector.called {
		t.Error("detector must not run when the anchor is untrusted")
	}
	if keys, err := objStore.List("events/"); err != nil || len(keys) != 0 {
		t.Fatalf("expected no export on a bad anchor, got keys=%v err=%v", keys, err)
	}
}

func TestPollReportsAnchorVerifyError(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	genesis := canon.GenesisHash()
	dbtest.SeedChain(t, ctx, pool, genesis, []canon.AuditEvent{decisionEvent("alice", "select 1")})

	reader, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer reader.Close()

	objStore := worm.NewMemory()
	if err := worm.WriteAnchor(objStore, worm.Anchor{
		UpToID:    1,
		HeadHash:  hex.EncodeToString(genesis),
		Signature: base64.StdEncoding.EncodeToString([]byte("stub-sig")),
		KeyID:     "stub",
	}); err != nil {
		t.Fatalf("write anchor: %v", err)
	}

	detector := &spyDetector{}
	reporter := &spyReporter{}
	signer := errVerifySigner{err: errors.New("kms unavailable")}
	cfg := config.MonitorConfig{PollInterval: time.Second, SignInterval: time.Hour}
	m := monitor.New(reader, signer, objStore, genesis, cfg, detector, reporter)

	// A verify ERROR is a finding, never a poll failure that would surface as a returned error.
	if err := m.Poll(ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(reporter.findings) != 1 || reporter.findings[0].Reason != monitor.ReasonAnchorVerifyError {
		t.Fatalf("findings = %+v, want one %s", reporter.findings, monitor.ReasonAnchorVerifyError)
	}
	if detector.called {
		t.Error("detector must not run when the anchor cannot be verified")
	}
	if keys, err := objStore.List("events/"); err != nil || len(keys) != 0 {
		t.Fatalf("expected no export on anchor verify error, got keys=%v err=%v", keys, err)
	}
}

// TestPollExportsEachEventOnce runs Poll twice across a growing tail and asserts every event is exported
// exactly once — the export watermark must ship only the rows past it, never re-ship the whole tail and
// never skip a row.
func TestPollExportsEachEventOnce(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	genesis := canon.GenesisHash()
	_, head := dbtest.SeedChain(t, ctx, pool, genesis, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
	})

	reader, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer reader.Close()

	signer, err := sign.NewFileKey(filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("new file key: %v", err)
	}
	objStore := worm.NewMemory()
	cfg := config.MonitorConfig{PollInterval: time.Second, SignInterval: time.Hour}
	m := monitor.New(reader, signer, objStore, genesis, cfg, monitor.NoopDetector{}, &spyReporter{})

	// First poll ships ids 1-2 and writes the initial anchor.
	if err := m.Poll(ctx); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	assertExportedExactlyOnce(t, objStore, 1, 2)

	// Two more rows land, and the second poll must ship only those.
	dbtest.AppendChain(t, ctx, pool, 3, head, []canon.AuditEvent{
		decisionEvent("carol", "select 3"),
		decisionEvent("dave", "select 4"),
	})
	if err := m.Poll(ctx); err != nil {
		t.Fatalf("second poll: %v", err)
	}
	assertExportedExactlyOnce(t, objStore, 1, 2, 3, 4)
}

// TestSignHeadExportsBeforeAdvancingAnchor guards SIEM/detection completeness across the sign cadence. The
// sign ticker is slower than the poll ticker and advances the off-box anchor; every future tail read is
// floored at that anchor. So rows that arrive between the last poll and a sign tick must be exported BEFORE
// the anchor moves past them, or they would fall out of every later tail and vanish from the export feed.
func TestSignHeadExportsBeforeAdvancingAnchor(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	genesis := canon.GenesisHash()
	_, head := dbtest.SeedChain(t, ctx, pool, genesis, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
	})

	reader, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer reader.Close()

	signer, err := sign.NewFileKey(filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("new file key: %v", err)
	}
	objStore := worm.NewMemory()
	detector := &spyDetector{}
	cfg := config.MonitorConfig{PollInterval: time.Second, SignInterval: time.Hour}
	m := monitor.New(reader, signer, objStore, genesis, cfg, detector, &spyReporter{})

	// First poll ships ids 1-2 and writes the initial anchor at id 2.
	if err := m.Poll(ctx); err != nil {
		t.Fatalf("first poll: %v", err)
	}

	// Two rows land in the window between the poll and the sign tick.
	dbtest.AppendChain(t, ctx, pool, 3, head, []canon.AuditEvent{
		decisionEvent("carol", "select 3"),
		decisionEvent("dave", "select 4"),
	})

	// The sign ticker fires before the next poll. It must flush 3-4 before advancing the anchor past them.
	if err := m.SignHead(ctx); err != nil {
		t.Fatalf("sign head: %v", err)
	}

	anchor, ok, err := readLastAnchor(t, objStore)
	if err != nil || !ok {
		t.Fatalf("read anchor: ok=%v err=%v", ok, err)
	}
	if anchor.UpToID != 4 {
		t.Fatalf("anchor up_to_id = %d, want 4", anchor.UpToID)
	}
	// The rows the anchor now covers must all be in the export feed, exactly once.
	assertExportedExactlyOnce(t, objStore, 1, 2, 3, 4)
	// Detection must have seen the rows the sign tick flushed, not just the ones the first poll shipped.
	if detector.count != 2 {
		t.Fatalf("detector saw %d events on the sign flush, want the 2 that landed after the poll", detector.count)
	}
}

// TestSignHeadDoesNotLaunderBrokenTail is the direct regression for the anti-laundering property: SignHead
// signs only the head its own verify walk proves, so it can never advance the anchor past a break and lend
// the monitor's signature to a forged tail.
func TestSignHeadDoesNotLaunderBrokenTail(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	genesis := canon.GenesisHash()
	_, head := dbtest.SeedChain(t, ctx, pool, genesis, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
	})

	reader, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer reader.Close()

	signer, err := sign.NewFileKey(filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("new file key: %v", err)
	}
	objStore := worm.NewMemory()
	reporter := &spyReporter{}
	cfg := config.MonitorConfig{PollInterval: time.Second, SignInterval: time.Hour}
	m := monitor.New(reader, signer, objStore, genesis, cfg, monitor.NoopDetector{}, reporter)

	// Establish a valid, signed anchor over the intact head at id 2.
	if err := m.Poll(ctx); err != nil {
		t.Fatalf("first poll: %v", err)
	}

	// A row is appended and then tampered so the committed tail past the anchor no longer verifies.
	dbtest.AppendChain(t, ctx, pool, 3, head, []canon.AuditEvent{decisionEvent("carol", "select 3")})
	if _, err := pool.Exec(ctx, "UPDATE audit_event SET principal = 'mallory' WHERE id = 3"); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	// SignHead must refuse to advance over the break — the anchor stays at the last intact head.
	if err := m.SignHead(ctx); err != nil {
		t.Fatalf("sign head: %v", err)
	}
	anchor, ok, err := readLastAnchor(t, objStore)
	if err != nil || !ok {
		t.Fatalf("read anchor: ok=%v err=%v", ok, err)
	}
	if anchor.UpToID != 2 {
		t.Fatalf("anchor advanced to %d over a broken tail; want it held at 2", anchor.UpToID)
	}
	if len(reporter.findings) != 1 || reporter.findings[0].DivergentID != 3 || reporter.findings[0].Reason != verify.ReasonRowHashMismatch {
		t.Fatalf("findings = %+v, want one row_hash_mismatch at id 3", reporter.findings)
	}
	// The forged row must never reach the export feed either.
	assertExportedExactlyOnce(t, objStore, 1, 2)
}

// fixture builds a reader + filekey signer + in-memory store + monitor over a freshly-seeded chain, the
// shared setup the full-verify regression tests need.
type fixture struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	genesis  []byte
	signer   sign.Signer
	objStore worm.ObjectStore
	reporter *spyReporter
	m        *monitor.Monitor
	// dsn + cfg let a test build a SECOND Monitor over the same database and object store — which is what a
	// separate operator process (the `auditmon accept-break` CLI) actually is next to a running daemon.
	dsn string
	cfg config.MonitorConfig
}

func newFixture(t *testing.T, events []canon.AuditEvent) fixture {
	t.Helper()
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	genesis := canon.GenesisHash()
	dbtest.SeedChain(t, ctx, pool, genesis, events)

	reader, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	t.Cleanup(reader.Close)
	signer, err := sign.NewFileKey(filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("new file key: %v", err)
	}
	objStore := worm.NewMemory()
	reporter := &spyReporter{}
	cfg := config.MonitorConfig{PollInterval: time.Second, SignInterval: time.Hour, FullVerifyInterval: time.Hour}
	m := monitor.New(reader, signer, objStore, genesis, cfg, monitor.NoopDetector{}, reporter)
	return fixture{ctx: ctx, pool: pool, genesis: genesis, signer: signer, objStore: objStore, reporter: reporter, m: m, dsn: dsn, cfg: cfg}
}

// TestFullVerifyDetectsBelowAnchorContentRewrite is the core regression for the critical gap: once an anchor
// exists at id N, the per-poll tail verify only re-walks rows past N, so a rewrite of a row BELOW the anchor
// is invisible to it. The scheduled full re-verification must catch it, and then halt so nothing new is
// signed or exported over a chain proven tampered.
func TestFullVerifyDetectsBelowAnchorContentRewrite(t *testing.T) {
	fx := newFixture(t, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
		decisionEvent("carol", "select 3"),
	})
	_, head3, err := chainHead(fx)
	if err != nil {
		t.Fatalf("read head: %v", err)
	}

	// Establish the anchor at id 3 over the intact chain.
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	assertExportedExactlyOnce(t, fx.objStore, 1, 2, 3)

	// Rewrite the CONTENT of a row below the anchor without recomputing its row_hash.
	if _, err := fx.pool.Exec(fx.ctx, "UPDATE audit_event SET principal = 'mallory' WHERE id = 2"); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	// A plain poll (tail after the anchor) does NOT see it — proving the gap the full pass closes.
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll after tamper: %v", err)
	}
	if len(fx.reporter.findings) != 0 {
		t.Fatalf("tail poll unexpectedly reported %+v; the below-anchor rewrite should be invisible to it", fx.reporter.findings)
	}

	// The full re-verification catches it.
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	if len(fx.reporter.findings) != 1 || fx.reporter.findings[0].DivergentID != 2 || fx.reporter.findings[0].Reason != verify.ReasonRowHashMismatch {
		t.Fatalf("findings = %+v, want one row_hash_mismatch at id 2", fx.reporter.findings)
	}

	// Halted: a newly appended, well-formed row must not be exported or anchored over the tampered chain.
	dbtest.AppendChain(t, fx.ctx, fx.pool, 4, head3, []canon.AuditEvent{decisionEvent("dave", "select 4")})
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll while halted: %v", err)
	}
	if err := fx.m.SignHead(fx.ctx); err != nil {
		t.Fatalf("sign while halted: %v", err)
	}
	assertExportedExactlyOnce(t, fx.objStore, 1, 2, 3)
	anchor, ok, err := readLastAnchor(t, fx.objStore)
	if err != nil || !ok {
		t.Fatalf("read anchor: ok=%v err=%v", ok, err)
	}
	if anchor.UpToID != 3 {
		t.Fatalf("anchor advanced to %d while halted; want it held at 3", anchor.UpToID)
	}
}

// TestFullVerifyDetectsBelowAnchorDeletion confirms deleting a row below an anchor breaks the linkage the
// full pass re-walks.
func TestFullVerifyDetectsBelowAnchorDeletion(t *testing.T) {
	fx := newFixture(t, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
		decisionEvent("carol", "select 3"),
	})
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if _, err := fx.pool.Exec(fx.ctx, "DELETE FROM audit_event WHERE id = 2"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	if len(fx.reporter.findings) != 1 || fx.reporter.findings[0].DivergentID != 3 || fx.reporter.findings[0].Reason != verify.ReasonPrevHashMismatch {
		t.Fatalf("findings = %+v, want one prev_hash_mismatch at id 3", fx.reporter.findings)
	}
}

// TestFullVerifyDetectsConsistentRewriteViaAnchorCrossCheck is the regression for the anchor cross-check: an
// attacker who recomputes EVERY row_hash from the public genesis produces a chain that is internally
// consistent (the row-walk passes), but the head recomputed at the anchored id no longer equals the head the
// off-box signed anchor witnessed.
func TestFullVerifyDetectsConsistentRewriteViaAnchorCrossCheck(t *testing.T) {
	fx := newFixture(t, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
		decisionEvent("carol", "select 3"),
	})
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}

	// Full internally-consistent rewrite: drop the trail and rebuild a fresh, correctly-linked chain from the
	// same genesis but with different content, so every row_hash recomputes and the new head differs.
	if _, err := fx.pool.Exec(fx.ctx, "DELETE FROM audit_event"); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	dbtest.SeedChain(t, fx.ctx, fx.pool, fx.genesis, []canon.AuditEvent{
		decisionEvent("alice", "hacked 1"),
		decisionEvent("bob", "hacked 2"),
		decisionEvent("carol", "hacked 3"),
	})

	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	if len(fx.reporter.findings) != 1 || fx.reporter.findings[0].DivergentID != 3 || fx.reporter.findings[0].Reason != verify.ReasonAnchorHeadMismatch {
		t.Fatalf("findings = %+v, want one anchor_head_mismatch at id 3", fx.reporter.findings)
	}
}

// TestFullVerifySkipsPreChainRows confirms a non-greenfield database — earlier rows predating the hash chain
// (chain_version NULL) — does not false-wedge the full pass: it starts the walk at the first chained row.
func TestFullVerifySkipsPreChainRows(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	genesis := canon.GenesisHash()

	// Pre-chain historical rows 1..3 (no chain columns), then chained rows 4..6 building on genesis.
	for id := int64(1); id <= 3; id++ {
		if _, err := pool.Exec(ctx, `
INSERT INTO audit_event (id, principal, datasource, statement, decision)
VALUES ($1, 'legacy', 'warehouse', 'q', 'ALLOW')`, id); err != nil {
			t.Fatalf("insert pre-chain row %d: %v", id, err)
		}
	}
	dbtest.AppendChain(t, ctx, pool, 4, genesis, []canon.AuditEvent{
		decisionEvent("a", "select 4"),
		decisionEvent("b", "select 5"),
		decisionEvent("c", "select 6"),
	})

	reader, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer reader.Close()
	signer, err := sign.NewFileKey(filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("new file key: %v", err)
	}
	reporter := &spyReporter{}
	cfg := config.MonitorConfig{PollInterval: time.Second, SignInterval: time.Hour, FullVerifyInterval: time.Hour}
	m := monitor.New(reader, signer, worm.NewMemory(), genesis, cfg, monitor.NoopDetector{}, reporter)

	if err := m.FullVerify(ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	if len(reporter.findings) != 0 {
		t.Fatalf("full verify wedged on pre-chain rows: %+v", reporter.findings)
	}
}

// TestSelectBaselineSkipsHighNumberedBadAnchor is the regression for the junk-anchor DoS: a high-numbered
// checkpoint object with a bad signature (undeletable under Object-Lock) must be skipped, and the monitor
// must proceed from the highest VALID anchor rather than wedge on the junk one.
func TestSelectBaselineSkipsHighNumberedBadAnchor(t *testing.T) {
	fx := newFixture(t, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
	})
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	assertExportedExactlyOnce(t, fx.objStore, 1, 2)

	// Plant a junk anchor at a very high up_to_id with a corrupted signature.
	junkHead := bytes.Repeat([]byte{0x99}, 32)
	sig, keyID, err := fx.signer.Sign(sign.AnchorDigest(99999999, junkHead))
	if err != nil {
		t.Fatalf("sign junk: %v", err)
	}
	sig[0] ^= 0xff
	if err := worm.WriteAnchor(fx.objStore, worm.Anchor{
		UpToID: 99999999, HeadHash: hex.EncodeToString(junkHead),
		Signature: base64.StdEncoding.EncodeToString(sig), KeyID: keyID,
	}); err != nil {
		t.Fatalf("write junk anchor: %v", err)
	}

	// A row lands. The monitor must verify the tail after the highest VALID anchor (id 2) and export it,
	// rather than trust the junk anchor at id 99999999 (which would floor the tail read and drop row 3) or
	// wedge on its bad signature.
	_, head2, err := chainHead(fx)
	if err != nil {
		t.Fatalf("read head: %v", err)
	}
	dbtest.AppendChain(t, fx.ctx, fx.pool, 3, head2, []canon.AuditEvent{decisionEvent("carol", "select 3")})

	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll with junk anchor present: %v", err)
	}
	if len(fx.reporter.findings) != 0 {
		t.Fatalf("junk anchor must be skipped, not reported/wedged: %+v", fx.reporter.findings)
	}
	assertExportedExactlyOnce(t, fx.objStore, 1, 2, 3)
}

// TestAnchorUpToIDIsAuthenticated is the regression for signing both fields: a legitimately-signed anchor
// re-labeled with a different up_to_id (head + signature unchanged) must fail verification, because the
// signature covers a digest binding the up_to_id too.
func TestAnchorUpToIDIsAuthenticated(t *testing.T) {
	fx := newFixture(t, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
	})
	_, head2, err := chainHead(fx)
	if err != nil {
		t.Fatalf("read head: %v", err)
	}

	// Sign a valid anchor for up_to_id 2, then re-label it as up_to_id 5 keeping the head and signature.
	sig, keyID, err := fx.signer.Sign(sign.AnchorDigest(2, head2))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := worm.WriteAnchor(fx.objStore, worm.Anchor{
		UpToID: 5, HeadHash: hex.EncodeToString(head2),
		Signature: base64.StdEncoding.EncodeToString(sig), KeyID: keyID,
	}); err != nil {
		t.Fatalf("write relabeled anchor: %v", err)
	}

	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(fx.reporter.findings) != 1 || fx.reporter.findings[0].Reason != monitor.ReasonAnchorSignatureInvalid || fx.reporter.findings[0].DivergentID != 5 {
		t.Fatalf("findings = %+v, want one %s at id 5 (relabeled up_to_id must break the signature)", fx.reporter.findings, monitor.ReasonAnchorSignatureInvalid)
	}
	if keys, err := fx.objStore.List("events/"); err != nil || len(keys) != 0 {
		t.Fatalf("a relabeled anchor must not be trusted; expected no export, got keys=%v err=%v", keys, err)
	}
}

// chainHead reads the singleton audit_chain_head via a throwaway reader, so a test can chain new rows onto
// the committed head.
func chainHead(fx fixture) (int64, []byte, error) {
	var lastID int64
	var head []byte
	err := fx.pool.QueryRow(fx.ctx, "SELECT last_id, head_hash FROM audit_chain_head WHERE id = 1").Scan(&lastID, &head)
	return lastID, head, err
}

// TestAcceptBreakResumesMonitoring is the operator recovery path: a chain break is permanent — nothing
// repairs the diverged rows — so the decision available to a human is to ACCEPT the break and get forward
// coverage back. Without it a halted monitor witnesses nothing, so an incident that starts with tampering is
// followed by an unmonitored window, which is strictly worse.
func TestAcceptBreakResumesMonitoring(t *testing.T) {
	fx := newFixture(t, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
	})

	// Anchor the intact chain, then rewrite a row BELOW that anchor — the shape only the full pass catches.
	if err := fx.m.SignHead(fx.ctx); err != nil {
		t.Fatalf("sign head: %v", err)
	}
	if _, err := fx.pool.Exec(fx.ctx, "UPDATE audit_event SET principal = 'mallory' WHERE id = 1"); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	if !fx.m.Halted() {
		t.Fatal("monitor did not halt on a chain break")
	}

	// Diagnose is read-only: it tells the operator WHAT diverged without emitting another critical alert or
	// changing state, because asking the question must not itself be an event.
	findingsBefore := len(fx.reporter.findings)
	d, err := fx.m.Diagnose(fx.ctx)
	if err != nil {
		t.Fatalf("diagnose: %v", err)
	}
	if d.Finding == nil || d.Finding.DivergentID != 1 || d.Finding.Reason != verify.ReasonRowHashMismatch {
		t.Fatalf("diagnose = %+v, want a row_hash_mismatch at id 1", d.Finding)
	}
	if len(fx.reporter.findings) != findingsBefore {
		t.Errorf("diagnose emitted %d extra alert(s); it must be read-only", len(fx.reporter.findings)-findingsBefore)
	}
	if !fx.m.Halted() {
		t.Error("diagnose cleared the halt; only an accepted break may do that")
	}

	// Accept the break, then bring coverage forward.
	if _, err := fx.m.AcceptBreak(fx.ctx, *d.Finding); err != nil {
		t.Fatalf("accept break: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify after accept: %v", err)
	}
	if fx.m.Halted() {
		t.Fatal("monitor still halted after an accepted break")
	}
	if err := fx.m.ResumeCoverage(fx.ctx); err != nil {
		t.Fatalf("resume coverage: %v", err)
	}

	// Forward coverage is genuinely back: a new row exports and the anchor advances over it.
	_, headHash, err := chainHead(fx)
	if err != nil {
		t.Fatalf("read head: %v", err)
	}
	dbtest.AppendChain(t, fx.ctx, fx.pool, 3, headHash, []canon.AuditEvent{decisionEvent("carol", "select 3")})
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll after recovery: %v", err)
	}
	if err := fx.m.SignHead(fx.ctx); err != nil {
		t.Fatalf("sign after recovery: %v", err)
	}
	anchor, ok, err := readLastAnchor(t, fx.objStore)
	if err != nil || !ok {
		t.Fatalf("read anchor: ok=%v err=%v", ok, err)
	}
	if anchor.UpToID != 3 {
		t.Errorf("anchor = %d after recovery, want 3 — the monitor is not witnessing new rows", anchor.UpToID)
	}
}

// TestAcceptBreakDoesNotEraseTheEvidence pins the property that makes accepting a break safe to offer at all:
// recovery restores forward coverage, it does not rewrite history. The tampered row stays tampered, the
// critical alert stays delivered, and verification keeps REPORTING the divergence forever.
func TestAcceptBreakDoesNotEraseTheEvidence(t *testing.T) {
	fx := newFixture(t, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
	})
	if err := fx.m.SignHead(fx.ctx); err != nil {
		t.Fatalf("sign head: %v", err)
	}
	if _, err := fx.pool.Exec(fx.ctx, "UPDATE audit_event SET statement = 'covered up' WHERE id = 1"); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	alertsAtBreak := len(fx.reporter.findings)
	if alertsAtBreak == 0 {
		t.Fatal("no integrity finding was reported for the break")
	}
	d, err := fx.m.Diagnose(fx.ctx)
	if err != nil || d.Finding == nil {
		t.Fatalf("diagnose: %+v err=%v", d.Finding, err)
	}
	if _, err := fx.m.AcceptBreak(fx.ctx, *d.Finding); err != nil {
		t.Fatalf("accept break: %v", err)
	}

	// The alert is not retracted…
	if len(fx.reporter.findings) < alertsAtBreak {
		t.Errorf("findings dropped from %d to %d; recovery must not retract the evidence",
			alertsAtBreak, len(fx.reporter.findings))
	}
	// …the row is still the tampered one: recovery accepts the break, it does not undo it…
	var stmt string
	if err := fx.pool.QueryRow(fx.ctx, "SELECT statement FROM audit_event WHERE id = 1").Scan(&stmt); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if stmt != "covered up" {
		t.Errorf("row 1 statement = %q; recovery must not alter the trail", stmt)
	}
	// …and the divergence is still REPORTED, as an accepted one. An operator who accepts a break must never be
	// able to make the history read clean afterwards.
	after, err := fx.m.Diagnose(fx.ctx)
	if err != nil {
		t.Fatalf("diagnose after accept: %v", err)
	}
	if after.Finding != nil {
		t.Errorf("an accepted break still reports as UNaccepted: %+v", after.Finding)
	}
	if len(after.Accepted) == 0 {
		t.Error("the accepted divergence vanished from the diagnosis; an accepted break must stay visible")
	}
}

// TestAcceptBreakNeverOverwritesTheWitnessingAnchor is the regression for the worst failure mode recovery can
// have: erasing the evidence that proved the break.
//
// An internally-consistent rewrite from genesis recomputes every row_hash, so the row-walk comes back clean
// and the ONLY thing that contradicts it is the off-box signed anchor. If accepting that break wrote a fresh
// anchor at the same head id, it would replace that single witness with a signature over the forged head, and
// verification would go green — laundering the rewrite under the monitor's own key. Acceptance is therefore a
// separate, uniquely-keyed record, and every prior anchor must survive it byte-for-byte.
func TestAcceptBreakNeverOverwritesTheWitnessingAnchor(t *testing.T) {
	fx := newFixture(t, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
	})
	if err := fx.m.SignHead(fx.ctx); err != nil {
		t.Fatalf("sign head: %v", err)
	}
	anchorsBefore, err := worm.ReadAnchors(fx.objStore)
	if err != nil || len(anchorsBefore) == 0 {
		t.Fatalf("read anchors: %v (n=%d)", err, len(anchorsBefore))
	}

	// Rewrite the whole chain from the public genesis: internally consistent, so only the anchor disagrees.
	if _, err := fx.pool.Exec(fx.ctx, "DELETE FROM audit_event"); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	dbtest.SeedChain(t, fx.ctx, fx.pool, fx.genesis, []canon.AuditEvent{
		decisionEvent("mallory", "hacked 1"),
		decisionEvent("mallory", "hacked 2"),
	})
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	if !fx.m.Halted() {
		t.Fatal("a consistent rewrite from genesis was not caught by the anchor cross-check")
	}
	d, err := fx.m.Diagnose(fx.ctx)
	if err != nil || d.Finding == nil {
		t.Fatalf("diagnose: %+v err=%v", d.Finding, err)
	}
	if d.Finding.Reason != verify.ReasonAnchorHeadMismatch {
		t.Fatalf("reason = %q, want anchor_head_mismatch (the anchor is the only witness)", d.Finding.Reason)
	}

	if _, err := fx.m.AcceptBreak(fx.ctx, *d.Finding); err != nil {
		t.Fatalf("accept break: %v", err)
	}

	// Every anchor that existed before the accept must still be present, unchanged.
	anchorsAfter, err := worm.ReadAnchors(fx.objStore)
	if err != nil {
		t.Fatalf("read anchors after accept: %v", err)
	}
	for _, before := range anchorsBefore {
		var found bool
		for _, after := range anchorsAfter {
			if after.UpToID == before.UpToID && after.HeadHash == before.HeadHash && after.Signature == before.Signature {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("the anchor at id %d that WITNESSED the break was overwritten by the accept; the only "+
				"evidence of a consistent rewrite is gone", before.UpToID)
		}
	}
}

// TestTamperAfterAnAcceptedBreakStillHalts is the regression for the subtler way recovery can blind the
// monitor: verification walks from genesis and stops at the FIRST divergence, so honoring an acceptance by
// merely skipping the halt would leave the walk stopping at the old break forever — and every later tamper
// above it would be unreachable, since the tail walk never looks below its anchor either. An accepted break
// must be stepped OVER, not treated as the end of the walk.
func TestTamperAfterAnAcceptedBreakStillHalts(t *testing.T) {
	fx := newFixture(t, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
		decisionEvent("carol", "select 3"),
	})
	if err := fx.m.SignHead(fx.ctx); err != nil {
		t.Fatalf("sign head: %v", err)
	}
	// First break, low in the chain, then accepted.
	if _, err := fx.pool.Exec(fx.ctx, "UPDATE audit_event SET principal = 'mallory' WHERE id = 1"); err != nil {
		t.Fatalf("tamper 1: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	d, err := fx.m.Diagnose(fx.ctx)
	if err != nil || d.Finding == nil {
		t.Fatalf("diagnose: %+v err=%v", d.Finding, err)
	}
	if _, err := fx.m.AcceptBreak(fx.ctx, *d.Finding); err != nil {
		t.Fatalf("accept break: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify after accept: %v", err)
	}
	if fx.m.Halted() {
		t.Fatal("monitor stayed halted after accepting the only break")
	}

	// SECOND, independent tamper — higher in the chain, above the accepted one.
	if _, err := fx.pool.Exec(fx.ctx, "UPDATE audit_event SET principal = 'mallory' WHERE id = 3"); err != nil {
		t.Fatalf("tamper 2: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify after second tamper: %v", err)
	}
	if !fx.m.Halted() {
		t.Fatal("a NEW tamper above an accepted break did not halt the monitor: accepting one break blinded " +
			"verification to everything after it")
	}
	after, err := fx.m.Diagnose(fx.ctx)
	if err != nil {
		t.Fatalf("diagnose: %v", err)
	}
	if after.Finding == nil || after.Finding.DivergentID != 3 {
		t.Fatalf("finding = %+v, want the new divergence at id 3", after.Finding)
	}
}

// TestAcceptanceDoesNotWaiveASecondTamperAtTheSameRow pins the scope of an acceptance: it waives the exact
// bytes an operator reviewed, not "any future divergence at this row id". Otherwise accepting one edit would
// leave that row permanently editable with no alert.
func TestAcceptanceDoesNotWaiveASecondTamperAtTheSameRow(t *testing.T) {
	fx := newFixture(t, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
	})
	if err := fx.m.SignHead(fx.ctx); err != nil {
		t.Fatalf("sign head: %v", err)
	}
	if _, err := fx.pool.Exec(fx.ctx, "UPDATE audit_event SET principal = 'mallory' WHERE id = 1"); err != nil {
		t.Fatalf("tamper 1: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	d, err := fx.m.Diagnose(fx.ctx)
	if err != nil || d.Finding == nil {
		t.Fatalf("diagnose: %+v err=%v", d.Finding, err)
	}
	if _, err := fx.m.AcceptBreak(fx.ctx, *d.Finding); err != nil {
		t.Fatalf("accept break: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify after accept: %v", err)
	}
	if fx.m.Halted() {
		t.Fatal("monitor stayed halted after accepting the break")
	}

	// A DIFFERENT edit to the SAME row: the accepted bytes no longer describe what is there.
	if _, err := fx.pool.Exec(fx.ctx, "UPDATE audit_event SET principal = 'eve' WHERE id = 1"); err != nil {
		t.Fatalf("tamper 2: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify after re-tamper: %v", err)
	}
	if !fx.m.Halted() {
		t.Fatal("a new edit to an already-accepted row did not halt: the acceptance is acting as blanket " +
			"permission for that row instead of for the divergence it covered")
	}
}

// TestAcceptedBreakSurvivesOnlyWithAValidSignature pins that acceptance is authority, not a flag: an
// acceptance object anyone could write would let whoever tampered with the trail also waive the finding. Only
// a signature under the monitor's own key counts.
func TestAcceptedBreakSurvivesOnlyWithAValidSignature(t *testing.T) {
	fx := newFixture(t, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
	})
	if err := fx.m.SignHead(fx.ctx); err != nil {
		t.Fatalf("sign head: %v", err)
	}
	if _, err := fx.pool.Exec(fx.ctx, "UPDATE audit_event SET principal = 'mallory' WHERE id = 1"); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	d, err := fx.m.Diagnose(fx.ctx)
	if err != nil || d.Finding == nil {
		t.Fatalf("diagnose: %+v err=%v", d.Finding, err)
	}

	// An attacker-authored acceptance: correct fields, garbage signature.
	forged := worm.Acceptance{
		DivergentID: d.Finding.DivergentID,
		Reason:      d.Finding.Reason,
		Expected:    hex.EncodeToString(d.Finding.Expected),
		Actual:      hex.EncodeToString(d.Finding.Actual),
		ResumeHash:  hex.EncodeToString(d.Finding.Actual),
		Signature:   base64.StdEncoding.EncodeToString([]byte("not a real signature")),
		KeyID:       "attacker",
	}
	if err := worm.WriteAcceptance(fx.objStore, forged); err != nil {
		t.Fatalf("write forged acceptance: %v", err)
	}

	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	if !fx.m.Halted() {
		t.Fatal("an UNSIGNED acceptance cleared the halt: anyone who can write the bucket could silence the " +
			"monitor after tampering with the trail")
	}
}

// TestAcceptBreakExportsTheHaltedWindow pins the invariant the monitor documents for itself: an anchor is
// never advanced past rows that have not been exported. A halt is exactly when a backlog builds up, so if
// recovery anchored straight over the current head, every row that arrived while halted would sit below the
// new anchor — and since each tail read starts after the anchor, they would never reach the SIEM or the
// anomaly rules at all. Silent loss of precisely the window an incident happened in.
func TestAcceptBreakExportsTheHaltedWindow(t *testing.T) {
	fx := newFixture(t, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
	})
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("initial poll: %v", err)
	}
	if _, err := fx.pool.Exec(fx.ctx, "UPDATE audit_event SET principal = 'mallory' WHERE id = 1"); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	if !fx.m.Halted() {
		t.Fatal("monitor did not halt")
	}

	// Rows keep arriving while the monitor is halted — it exports none of them.
	_, headHash, err := chainHead(fx)
	if err != nil {
		t.Fatalf("read head: %v", err)
	}
	dbtest.AppendChain(t, fx.ctx, fx.pool, 3, headHash, []canon.AuditEvent{
		decisionEvent("carol", "select 3"),
		decisionEvent("dave", "select 4"),
	})
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll while halted: %v", err)
	}

	d, err := fx.m.Diagnose(fx.ctx)
	if err != nil || d.Finding == nil {
		t.Fatalf("diagnose: %+v err=%v", d.Finding, err)
	}
	if _, err := fx.m.AcceptBreak(fx.ctx, *d.Finding); err != nil {
		t.Fatalf("accept break: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify after accept: %v", err)
	}
	if err := fx.m.ResumeCoverage(fx.ctx); err != nil {
		t.Fatalf("resume coverage: %v", err)
	}

	// The rows from the halted window must have been exported, not stranded under the new anchor.
	exported := make(map[int64]bool)
	for _, id := range exportedIDs(t, fx.objStore) {
		exported[id] = true
	}
	for _, id := range []int64{3, 4} {
		if !exported[id] {
			t.Errorf("row %d arrived while halted and was never exported: recovery anchored over it, so no "+
				"future tail read will ever reach it", id)
		}
	}
}

// TestHaltDoesNotClearOnIncompleteEvidence pins the direction a halt must fail in. Resuming happens when a
// full pass finds nothing unaccepted — but if a signer or object-store failure left an anchor unverifiable,
// that pass ran with fewer witnesses than exist, and the cross-check that would have caught a rewrite simply
// did not happen. Clearing the halt there would mean an OUTAGE ends a halt, handing an attacker a way to
// resume the monitor by breaking its access to its own evidence.
func TestHaltDoesNotClearOnIncompleteEvidence(t *testing.T) {
	fx := newFixture(t, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
	})
	// The signer this monitor uses can be switched to "unavailable" partway through, modelling a KMS or
	// network failure that starts mid-incident — the monitor keeps running, it just cannot check its anchors.
	flaky := &flakyVerifier{Signer: fx.signer}
	reader, err := store.Open(fx.ctx, fx.dsn)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer reader.Close()
	m := monitor.New(reader, flaky, fx.objStore, fx.genesis, fx.cfg, monitor.NoopDetector{}, &spyReporter{})

	// Two anchors, so blocking one still leaves a valid witness: the monitor is partially blind, not fully.
	if err := m.SignHead(fx.ctx); err != nil {
		t.Fatalf("sign head: %v", err)
	}
	_, headHash, err := chainHead(fx)
	if err != nil {
		t.Fatalf("read head: %v", err)
	}
	dbtest.AppendChain(t, fx.ctx, fx.pool, 3, headHash, []canon.AuditEvent{decisionEvent("carol", "select 3")})
	if err := m.SignHead(fx.ctx); err != nil {
		t.Fatalf("sign head 2: %v", err)
	}
	anchors, err := worm.ReadAnchors(fx.objStore)
	if err != nil || len(anchors) < 2 {
		t.Fatalf("want two anchors, got %d (err=%v)", len(anchors), err)
	}

	if _, err := fx.pool.Exec(fx.ctx, "UPDATE audit_event SET principal = 'mallory' WHERE id = 1"); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if err := m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	if !m.Halted() {
		t.Fatal("monitor did not halt on the break")
	}

	// The trail is repaired to its original bytes, so a row-walk alone now comes back clean…
	if _, err := fx.pool.Exec(fx.ctx, "UPDATE audit_event SET principal = 'alice' WHERE id = 1"); err != nil {
		t.Fatalf("restore: %v", err)
	}
	// …but ONE anchor becomes unverifiable, so the cross-check at that anchored head never runs. The other
	// anchor still verifies, so this is a partially-blind pass, not a blind one.
	flaky.block(anchors[len(anchors)-1].Signature)
	if err := m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify while partially blind: %v", err)
	}
	if !m.Halted() {
		t.Fatal("the halt CLEARED while one anchor could not be verified: a clean walk over INCOMPLETE " +
			"evidence is not proof the trail is whole, so an attacker could resume the monitor by breaking " +
			"its access to a witness")
	}
}

// flakyVerifier signs normally but can be switched to failing verification for anchors at or above a chosen
// id, modelling a signer/KMS outage that leaves SOME evidence checkable and some not. Partial is the case that
// matters: with no anchor verifiable at all the monitor already halts on anchor_signature_invalid, so the
// interesting question is whether a clean walk over PARTIAL evidence is allowed to clear a halt.
type flakyVerifier struct {
	sign.Signer
	mu      sync.Mutex
	blocked map[string]bool // base64 signature -> unverifiable
}

func (f *flakyVerifier) Verify(digest, sig []byte, keyID string) (bool, error) {
	f.mu.Lock()
	down := f.blocked[base64.StdEncoding.EncodeToString(sig)]
	f.mu.Unlock()
	if down {
		return false, errors.New("signer unavailable")
	}
	return f.Signer.Verify(digest, sig, keyID)
}

// block marks one specific anchor's signature as unverifiable from now on.
func (f *flakyVerifier) block(sig string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.blocked == nil {
		f.blocked = map[string]bool{}
	}
	f.blocked[sig] = true
}

// TestDiagnoseRefusesToCallATrailIntactWithNoValidWitness pins that `auditmon verify` cannot print an
// all-clear when every off-box anchor is unusable. A rewritten-from-genesis chain verifies clean on its own —
// the anchor is the only thing that contradicts it — so with no valid anchor there is nothing left to catch
// it, and reporting "intact" would be a false negative at exactly the moment it matters most.
func TestDiagnoseRefusesToCallATrailIntactWithNoValidWitness(t *testing.T) {
	fx := newFixture(t, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
	})
	if err := fx.m.SignHead(fx.ctx); err != nil {
		t.Fatalf("sign head: %v", err)
	}
	// Replace every anchor's signature with garbage: the objects exist, none validates.
	anchors, err := worm.ReadAnchors(fx.objStore)
	if err != nil || len(anchors) == 0 {
		t.Fatalf("read anchors: %v (n=%d)", err, len(anchors))
	}
	for _, a := range anchors {
		a.Signature = base64.StdEncoding.EncodeToString([]byte("forged"))
		if err := worm.WriteAnchor(fx.objStore, a); err != nil {
			t.Fatalf("overwrite anchor: %v", err)
		}
	}

	d, err := fx.m.Diagnose(fx.ctx)
	if err != nil {
		t.Fatalf("diagnose: %v", err)
	}
	if d.Finding == nil {
		t.Fatal("diagnose reported the trail intact while NO anchor validates: an internally-consistent " +
			"rewrite would pass the row-walk with nothing left to contradict it")
	}
	if d.Finding.Reason != monitor.ReasonAnchorSignatureInvalid {
		t.Errorf("reason = %q, want anchor_signature_invalid", d.Finding.Reason)
	}
}

// TestAcceptedBreakResumesTheRunningMonitor pins the property that makes the operator recovery path actually
// work: the daemon that HALTED must resume, not merely the process that ran the accept.
//
// `auditmon accept-break` is a separate short-lived process next to a long-running daemon, which is exactly
// what the two Monitor values below model over one shared database and object store. It also re-runs the
// daemon's FullVerify afterwards, because that is what the daemon does on its own interval and on boot — a
// recovery that survives only until the next full pass is not a recovery.
func TestAcceptedBreakResumesTheRunningMonitor(t *testing.T) {
	fx := newFixture(t, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
	})
	if err := fx.m.SignHead(fx.ctx); err != nil {
		t.Fatalf("sign head: %v", err)
	}
	if _, err := fx.pool.Exec(fx.ctx, "UPDATE audit_event SET principal = 'mallory' WHERE id = 1"); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	// fx.m is the DAEMON: it verifies, finds the break, and halts.
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("daemon full verify: %v", err)
	}
	if !fx.m.Halted() {
		t.Fatal("daemon did not halt on a chain break")
	}

	// A SECOND monitor over the same DB + store is the operator's `accept-break` process.
	operatorReader, err := store.Open(fx.ctx, fx.dsn)
	if err != nil {
		t.Fatalf("operator reader: %v", err)
	}
	defer operatorReader.Close()
	operator := monitor.New(operatorReader, fx.signer, fx.objStore, fx.genesis, fx.cfg,
		monitor.NoopDetector{}, &spyReporter{})
	od, err := operator.Diagnose(fx.ctx)
	if err != nil || od.Finding == nil {
		t.Fatalf("operator diagnose: %+v err=%v", od.Finding, err)
	}
	if _, err := operator.AcceptBreak(fx.ctx, *od.Finding); err != nil {
		t.Fatalf("operator accept-break: %v", err)
	}
	if err := operator.ResumeCoverage(fx.ctx); err != nil {
		t.Fatalf("operator resume coverage: %v", err)
	}

	// The daemon must now resume on its own next pass — no restart — and STAY resumed across the full
	// verification it runs on its own interval.
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("daemon full verify after accept: %v", err)
	}
	if fx.m.Halted() {
		t.Fatal("the DAEMON is still halted after an operator accept-break: recovery only cleared the " +
			"operator's own process, so the running monitor stays blind until it is restarted")
	}

	// And it is genuinely witnessing again: a new row exports and the anchor advances over it.
	_, headHash, err := chainHead(fx)
	if err != nil {
		t.Fatalf("read head: %v", err)
	}
	dbtest.AppendChain(t, fx.ctx, fx.pool, 3, headHash, []canon.AuditEvent{decisionEvent("carol", "select 3")})
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("daemon poll after accept: %v", err)
	}
	if err := fx.m.SignHead(fx.ctx); err != nil {
		t.Fatalf("daemon sign after accept: %v", err)
	}
	anchor, ok, err := readLastAnchor(t, fx.objStore)
	if err != nil || !ok {
		t.Fatalf("read anchor: ok=%v err=%v", ok, err)
	}
	if anchor.UpToID < 3 {
		t.Errorf("anchor = %d after recovery, want >= 3: the daemon is not witnessing new rows", anchor.UpToID)
	}
}

// TestResumeCoverageAfterAcceptingAConsistentRewrite pins the behavior when the accepted break is a full
// rewrite from genesis, which is the case where the signed anchor is the ONLY evidence.
//
// The anchor keeps flooring the tail read at the head it witnessed, and the rewritten chain does not link to
// that head — so the tail cannot be verified and coverage does not advance. That is the correct, conservative
// outcome: the alternative is trusting a chain the monitor has proven diverges from its own witness. What must
// hold no matter what is that the witnessing anchor is never replaced, so the evidence outlives the decision
// to move on.
func TestResumeCoverageAfterAcceptingAConsistentRewrite(t *testing.T) {
	fx := newFixture(t, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
	})
	if err := fx.m.SignHead(fx.ctx); err != nil {
		t.Fatalf("sign head: %v", err)
	}
	witnesses, err := worm.ReadAnchors(fx.objStore)
	if err != nil || len(witnesses) == 0 {
		t.Fatalf("read anchors: %v (n=%d)", err, len(witnesses))
	}

	if _, err := fx.pool.Exec(fx.ctx, "DELETE FROM audit_event"); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	dbtest.SeedChain(t, fx.ctx, fx.pool, fx.genesis, []canon.AuditEvent{
		decisionEvent("mallory", "hacked 1"),
		decisionEvent("mallory", "hacked 2"),
	})
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	d, err := fx.m.Diagnose(fx.ctx)
	if err != nil || d.Finding == nil {
		t.Fatalf("diagnose: %+v err=%v", d.Finding, err)
	}
	if d.Finding.Reason != verify.ReasonAnchorHeadMismatch {
		t.Fatalf("reason = %q, want anchor_head_mismatch", d.Finding.Reason)
	}
	if _, err := fx.m.AcceptBreak(fx.ctx, *d.Finding); err != nil {
		t.Fatalf("accept break: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify after accept: %v", err)
	}
	if fx.m.Halted() {
		t.Fatal("still halted after accepting the rewrite; the acceptance covers this divergence")
	}

	// ResumeCoverage does not attempt a differing-head write here: the anchor floors the tail at the head it
	// witnessed, so with an empty tail it re-signs that same head. Assert what it actually does, then exercise
	// the guard DIRECTLY — otherwise this test would pass with the guard deleted, which is exactly the kind of
	// decoration that let the overwrite ship in the first place.
	if err := fx.m.ResumeCoverage(fx.ctx); err != nil {
		t.Logf("ResumeCoverage after a rewrite: %v (coverage does not advance; the witness is what matters)", err)
	}
	// The laundering write the guard exists to stop: the forged head at the witnessed id.
	forgedHead, err := hex.DecodeString(witnesses[0].HeadHash)
	if err != nil {
		t.Fatalf("decode witness head: %v", err)
	}
	forgedHead[0] ^= 0xff
	if err := worm.WriteAnchor(fx.objStore, worm.Anchor{
		UpToID:    witnesses[0].UpToID,
		HeadHash:  hex.EncodeToString(forgedHead),
		Signature: witnesses[0].Signature,
		KeyID:     witnesses[0].KeyID,
	}); err == nil {
		t.Error("a differing head was written over the anchor that witnessed the rewrite; the store must refuse it")
	}
	after, err := worm.ReadAnchors(fx.objStore)
	if err != nil {
		t.Fatalf("read anchors after resume: %v", err)
	}
	for _, w := range witnesses {
		var found bool
		for _, a := range after {
			if a.UpToID == w.UpToID && a.HeadHash == w.HeadHash && a.Signature == w.Signature {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("the anchor at id %d that WITNESSED the rewrite was replaced; the only evidence that the "+
				"trail was rewritten is gone", w.UpToID)
		}
	}
}

// TestAcceptanceWithASwappedResumeHashIsNotHonored pins that the resume head is authenticated, not merely
// carried alongside a signature. ResumeHash decides where verification CONTINUES after stepping over a waived
// divergence, so it is as security-relevant as the divergence itself. If it were outside the signed digest,
// anyone able to write the bucket could copy a genuine acceptance, change only that field, and store it under
// a fresh content-addressed key with a signature that still validates — steering the walk onto a chain no
// operator ever accepted.
func TestAcceptanceWithASwappedResumeHashIsNotHonored(t *testing.T) {
	fx := newFixture(t, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
	})
	if err := fx.m.SignHead(fx.ctx); err != nil {
		t.Fatalf("sign head: %v", err)
	}
	if _, err := fx.pool.Exec(fx.ctx, "UPDATE audit_event SET principal = 'mallory' WHERE id = 1"); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	d, err := fx.m.Diagnose(fx.ctx)
	if err != nil || d.Finding == nil {
		t.Fatalf("diagnose: %+v err=%v", d.Finding, err)
	}
	genuine, err := fx.m.AcceptBreak(fx.ctx, *d.Finding)
	if err != nil {
		t.Fatalf("accept break: %v", err)
	}

	// Copy the genuine acceptance, keep its signature, change ONLY the resume head.
	forged := genuine
	forged.ResumeHash = hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	if worm.AcceptanceKey(forged) == worm.AcceptanceKey(genuine) {
		t.Fatal("the variant collided with the genuine acceptance's key; it must land on its own object")
	}
	if err := worm.WriteAcceptance(fx.objStore, forged); err != nil {
		t.Fatalf("write the variant: %v", err)
	}

	// The variant must not be honored. Its signature does not cover the swapped resume head, so verification
	// must ignore it — and the genuine acceptance still stands, so the monitor stays resumed rather than
	// halting on its own valid waiver.
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify with the variant present: %v", err)
	}
	after, err := fx.m.Diagnose(fx.ctx)
	if err != nil {
		t.Fatalf("diagnose: %v", err)
	}
	if after.Finding != nil {
		t.Errorf("the genuine acceptance stopped covering its divergence once a variant was planted: %+v",
			after.Finding)
	}
	if len(after.Accepted) != 1 {
		t.Errorf("honored %d acceptances, want exactly 1 — the unsigned-resume variant must be ignored",
			len(after.Accepted))
	}
}

// TestAcceptingALinkMismatchDoesNotExemptTheRowsContent pins the scope of a prev_hash acceptance: it waives
// the LINK, never the row's contents.
//
// The row-walk checks prev_hash before recomputing row_hash, so a link mismatch is reported first. If stepping
// over that accepted finding skipped the whole row, the row's content hash would never be checked again — and
// an attacker could then edit that row's contents freely, forever, behind a waiver the operator granted for a
// deletion. An acceptance must cover exactly the divergence it names.
func TestAcceptingALinkMismatchDoesNotExemptTheRowsContent(t *testing.T) {
	fx := newFixture(t, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
		decisionEvent("carol", "select 3"),
	})
	if err := fx.m.SignHead(fx.ctx); err != nil {
		t.Fatalf("sign head: %v", err)
	}
	// Delete row 1: row 2's prev_hash now points at a row that is gone -> prev_hash_mismatch at 2.
	if _, err := fx.pool.Exec(fx.ctx, "DELETE FROM audit_event WHERE id = 1"); err != nil {
		t.Fatalf("delete row 1: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	d, err := fx.m.Diagnose(fx.ctx)
	if err != nil || d.Finding == nil {
		t.Fatalf("diagnose: %+v err=%v", d.Finding, err)
	}
	if d.Finding.Reason != verify.ReasonPrevHashMismatch || d.Finding.DivergentID != 2 {
		t.Fatalf("finding = %+v, want prev_hash_mismatch at id 2", d.Finding)
	}
	if _, err := fx.m.AcceptBreak(fx.ctx, *d.Finding); err != nil {
		t.Fatalf("accept break: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify after accept: %v", err)
	}
	if fx.m.Halted() {
		t.Fatal("still halted after accepting the only divergence")
	}

	// Now edit the CONTENT of the very row whose link was waived, leaving prev_hash and row_hash untouched.
	// The waiver was for a broken link, not a licence to rewrite this row.
	if _, err := fx.pool.Exec(fx.ctx, "UPDATE audit_event SET principal = 'mallory' WHERE id = 2"); err != nil {
		t.Fatalf("tamper row 2 content: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify after content tamper: %v", err)
	}
	if !fx.m.Halted() {
		t.Fatal("editing the CONTENT of a row whose LINK mismatch was accepted did not halt the monitor: the " +
			"acceptance is exempting that row's contents from verification permanently")
	}
}

// TestAcceptingATruncationDoesNotWaiveADeeperOne pins that accepting "rows below anchor N are gone" is not a
// standing waiver for losing MORE rows. An anchor_row_missing finding names the anchor and the head it
// witnessed — both fixed for that anchor — so a later, deeper truncation would reproduce a byte-identical
// finding and ride the earlier acceptance unless the finding also binds how far the trail actually reaches.
func TestAcceptingATruncationDoesNotWaiveADeeperOne(t *testing.T) {
	fx := newFixture(t, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
		decisionEvent("carol", "select 3"),
		decisionEvent("dave", "select 4"),
	})
	if err := fx.m.SignHead(fx.ctx); err != nil {
		t.Fatalf("sign head: %v", err)
	}
	// Truncate the top of the trail so the anchor witnesses rows the chain no longer reaches.
	if _, err := fx.pool.Exec(fx.ctx, "DELETE FROM audit_event WHERE id >= 4"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	d, err := fx.m.Diagnose(fx.ctx)
	if err != nil || d.Finding == nil {
		t.Fatalf("diagnose: %+v err=%v", d.Finding, err)
	}
	if d.Finding.Reason != verify.ReasonAnchorRowMissing {
		t.Fatalf("reason = %q, want anchor_row_missing", d.Finding.Reason)
	}
	if _, err := fx.m.AcceptBreak(fx.ctx, *d.Finding); err != nil {
		t.Fatalf("accept break: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify after accept: %v", err)
	}
	if fx.m.Halted() {
		t.Fatal("still halted after accepting the truncation")
	}

	// Delete MORE. This is a new act of destruction, not the one that was accepted.
	if _, err := fx.pool.Exec(fx.ctx, "DELETE FROM audit_event WHERE id >= 2"); err != nil {
		t.Fatalf("deeper truncate: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify after the deeper truncation: %v", err)
	}
	if !fx.m.Halted() {
		t.Fatal("a DEEPER truncation did not halt the monitor: accepting one truncation acts as a standing " +
			"waiver for destroying more of the trail")
	}
}

// TestAnInvalidAnchorMakesEvidenceIncomplete pins that a checkpoint whose signature does not validate cannot
// be quietly ignored while OLDER anchors carry the pass.
//
// A forged or corrupted anchor occupies the key where a real witness belongs, so the witness it should have
// provided is absent from this pass. If verification simply skipped it and cross-checked against the anchors
// below, a tail rewritten above those older anchors would verify clean — and a halted monitor could clear its
// halt on evidence that was never complete.
func TestAnInvalidAnchorMakesEvidenceIncomplete(t *testing.T) {
	fx := newFixture(t, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
	})
	// Two anchors, so invalidating the newer one still leaves an older valid witness behind.
	if err := fx.m.SignHead(fx.ctx); err != nil {
		t.Fatalf("sign head: %v", err)
	}
	_, headHash, err := chainHead(fx)
	if err != nil {
		t.Fatalf("read head: %v", err)
	}
	dbtest.AppendChain(t, fx.ctx, fx.pool, 3, headHash, []canon.AuditEvent{decisionEvent("carol", "select 3")})
	if err := fx.m.SignHead(fx.ctx); err != nil {
		t.Fatalf("sign head 2: %v", err)
	}

	// Halt on a real break first, so there is something that must NOT clear.
	if _, err := fx.pool.Exec(fx.ctx, "UPDATE audit_event SET principal = 'mallory' WHERE id = 1"); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	if !fx.m.Halted() {
		t.Fatal("monitor did not halt on the break")
	}

	// Restore the row so the walk itself is clean again, then forge the NEWEST anchor's signature.
	if _, err := fx.pool.Exec(fx.ctx, "UPDATE audit_event SET principal = 'alice' WHERE id = 1"); err != nil {
		t.Fatalf("restore: %v", err)
	}
	anchors, err := worm.ReadAnchors(fx.objStore)
	if err != nil || len(anchors) < 2 {
		t.Fatalf("want two anchors, got %d (err=%v)", len(anchors), err)
	}
	newest := anchors[len(anchors)-1]
	newest.Signature = base64.StdEncoding.EncodeToString([]byte("forged"))
	if err := worm.WriteAnchor(fx.objStore, newest); err != nil {
		t.Fatalf("plant the forged anchor: %v", err)
	}

	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify with a forged anchor present: %v", err)
	}
	if !fx.m.Halted() {
		t.Fatal("the halt cleared while a checkpoint's signature did not validate: an unusable witness was " +
			"skipped instead of counting as missing evidence, so a rewrite above the older anchors would pass")
	}
}

// TestPollCatchesUpLongBacklogInBatches proves the tail walk is bounded AND checkpointed: starting from a
// prior signed anchor at id 2 with a 7-row backlog behind it and tail_batch=2, one Poll verifies, exports,
// and re-anchors batch by batch — checkpoint anchors land at every full-batch boundary, every row reaches
// the store exactly once, and a fresh Monitor (a simulated crash) resumes from the last checkpoint rather
// than re-walking the backlog (issue #240's OOM crash loop).
func TestPollCatchesUpLongBacklogInBatches(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	genesis := canon.GenesisHash()

	reader, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer reader.Close()
	signer, err := sign.NewFileKey(filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("new file key: %v", err)
	}
	objStore := worm.NewMemory()
	reporter := &spyReporter{}
	cfg := config.MonitorConfig{PollInterval: time.Second, SignInterval: time.Hour, TailBatch: 2}

	// A steady-state monitor anchors at id 2, then goes down while 7 more rows land.
	baseID, baseHead := dbtest.SeedChain(t, ctx, pool, genesis, []canon.AuditEvent{
		decisionEvent("alice", "select 0"), decisionEvent("alice", "select 00"),
	})
	m0 := monitor.New(reader, signer, objStore, genesis, cfg, monitor.NoopDetector{}, reporter)
	if err := m0.Poll(ctx); err != nil {
		t.Fatalf("baseline poll: %v", err)
	}
	backlog := make([]canon.AuditEvent, 7)
	for i := range backlog {
		backlog[i] = decisionEvent("alice", fmt.Sprintf("select %d", i+1))
	}
	lastID, head := dbtest.AppendChain(t, ctx, pool, baseID+1, baseHead, backlog)

	// A fresh Monitor (the restart after the outage) catches up in one Poll.
	m := monitor.New(reader, signer, objStore, genesis, cfg, monitor.NoopDetector{}, reporter)
	if err := m.Poll(ctx); err != nil {
		t.Fatalf("catch-up poll: %v", err)
	}
	if len(reporter.findings) != 0 {
		t.Fatalf("expected no findings, got %+v", reporter.findings)
	}
	ids := exportedIDs(t, objStore)
	if len(ids) != 2+len(backlog) {
		t.Fatalf("exported %d events, want %d: %v", len(ids), 2+len(backlog), ids)
	}
	seen := map[int64]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("event %d exported more than once: %v", id, ids)
		}
		seen[id] = true
	}
	// Checkpoint anchors exist at every full-batch boundary of the catch-up (4, 6, 8), plus the baseline 2.
	anchors, err := worm.ReadAnchors(objStore)
	if err != nil {
		t.Fatalf("read anchors: %v", err)
	}
	got := map[int64]bool{}
	for _, a := range anchors {
		got[a.UpToID] = true
	}
	for _, want := range []int64{2, 4, 6, 8} {
		if !got[want] {
			t.Fatalf("missing checkpoint anchor at %d; anchors=%v", want, got)
		}
	}
	if got[lastID] {
		t.Fatalf("the short final batch must not checkpoint; anchors=%v", got)
	}

	// A crash after the walk resumes from the LAST checkpoint: a fresh Monitor's first tail read starts
	// after id 8, so only the final short batch is re-shipped — to its existing object key (idempotent) —
	// and nothing below the checkpoint is re-read or re-exported.
	spy := &spyDetector{}
	m2 := monitor.New(reader, signer, objStore, genesis, cfg, spy, reporter)
	if err := m2.Poll(ctx); err != nil {
		t.Fatalf("resume poll: %v", err)
	}
	if spy.count != 1 {
		t.Fatalf("resume inspected %d rows, want only the post-checkpoint row", spy.count)
	}
	after := exportedIDs(t, objStore)
	if len(after) != 2+len(backlog) {
		t.Fatalf("resume changed the exported set: %v", after)
	}
	if err := m2.SignHead(ctx); err != nil {
		t.Fatalf("sign head: %v", err)
	}
	anchor, ok, err := readLastAnchor(t, objStore)
	if err != nil || !ok {
		t.Fatalf("read last anchor: ok=%v err=%v", ok, err)
	}
	if anchor.UpToID != lastID || anchor.HeadHash != hex.EncodeToString(head) {
		t.Fatalf("final anchor = %+v, want head %d", anchor, lastID)
	}
}

// TestPollBreakInLaterBatchStopsThere pins the batched walk's break semantics: a chain break in a LATER
// batch leaves the earlier verified batches exported (and checkpointed), refuses everything from the broken
// batch on, and reports the finding.
func TestPollBreakInLaterBatchStopsThere(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	genesis := canon.GenesisHash()

	events := make([]canon.AuditEvent, 6)
	for i := range events {
		events[i] = decisionEvent("alice", fmt.Sprintf("select %d", i))
	}
	dbtest.SeedChain(t, ctx, pool, genesis, events)
	// Tamper row 5 (third batch of two) so batches 1-2 verify and the third breaks.
	if _, err := pool.Exec(ctx, "UPDATE audit_event SET principal = 'mallory' WHERE id = 5"); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	reader, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer reader.Close()
	signer, err := sign.NewFileKey(filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("new file key: %v", err)
	}
	objStore := worm.NewMemory()
	reporter := &spyReporter{}
	cfg := config.MonitorConfig{PollInterval: time.Second, SignInterval: time.Hour, TailBatch: 2}
	m := monitor.New(reader, signer, objStore, genesis, cfg, monitor.NoopDetector{}, reporter)

	if err := m.Poll(ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(reporter.findings) != 1 || reporter.findings[0].DivergentID != 5 ||
		reporter.findings[0].Reason != verify.ReasonRowHashMismatch {
		t.Fatalf("findings = %+v, want row_hash_mismatch at 5", reporter.findings)
	}
	ids := exportedIDs(t, objStore)
	if len(ids) != 4 || ids[len(ids)-1] != 4 {
		t.Fatalf("exported %v, want exactly the verified prefix 1-4", ids)
	}
	anchor, ok, err := readLastAnchor(t, objStore)
	if err != nil {
		t.Fatalf("read last anchor: %v", err)
	}
	if ok && anchor.UpToID > 4 {
		t.Fatalf("anchor advanced past the break: %+v", anchor)
	}
}

// TestPollReportsMidWalkTruncation pins the pinned-target rule: rows deleted between page reads (each page
// is its own snapshot) surface as a tail_truncated finding, never as a short clean walk.
func TestPollReportsMidWalkTruncation(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	genesis := canon.GenesisHash()

	events := make([]canon.AuditEvent, 5)
	for i := range events {
		events[i] = decisionEvent("alice", fmt.Sprintf("select %d", i))
	}
	dbtest.SeedChain(t, ctx, pool, genesis, events)

	reader, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer reader.Close()
	signer, err := sign.NewFileKey(filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("new file key: %v", err)
	}
	objStore := worm.NewMemory()
	reporter := &spyReporter{}
	cfg := config.MonitorConfig{PollInterval: time.Second, SignInterval: time.Hour, TailBatch: 2}

	// deleteTailDetector simulates the race: after the first batch is inspected, rows 4-5 vanish.
	deleted := false
	det := detectFunc(func([]store.StoredEvent) error {
		if !deleted {
			deleted = true
			if _, err := pool.Exec(ctx, "DELETE FROM audit_event WHERE id >= 4"); err != nil {
				t.Errorf("delete tail: %v", err)
			}
		}
		return nil
	})
	m := monitor.New(reader, signer, objStore, genesis, cfg, det, reporter)

	if err := m.Poll(ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(reporter.findings) != 1 || reporter.findings[0].Reason != monitor.ReasonTailTruncated {
		t.Fatalf("findings = %+v, want one tail_truncated", reporter.findings)
	}
}

// detectFunc adapts a func to the Detector interface (both hooks call it).
type detectFunc func([]store.StoredEvent) error

func (f detectFunc) Inspect(events []store.StoredEvent) error        { return f(events) }
func (f detectFunc) InspectCatchUp(events []store.StoredEvent) error { return f(events) }
