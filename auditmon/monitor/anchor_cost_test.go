package monitor_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
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

type countingSigner struct {
	sign.Signer
	verifies int
	failWith error
}

func (s *countingSigner) Verify(digest, sig []byte, keyID string) (bool, error) {
	s.verifies++
	if s.failWith != nil {
		return false, s.failWith
	}
	return s.Signer.Verify(digest, sig, keyID)
}

type checkpointGetCounter struct {
	worm.ObjectStore
	gets       int
	limitLists bool
	listBudget int
}

func (s *checkpointGetCounter) ListObjects(prefix string) ([]worm.ObjectInfo, error) {
	if s.limitLists && strings.HasPrefix(prefix, "checkpoints/") {
		if s.listBudget == 0 {
			return nil, errors.New("s3: list timed out")
		}
		s.listBudget--
	}
	return s.ObjectStore.ListObjects(prefix)
}

func (s *checkpointGetCounter) Get(key string) ([]byte, error) {
	if strings.HasPrefix(key, "checkpoints/") {
		s.gets++
	}
	return s.ObjectStore.Get(key)
}

type costFixture struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	lastID   int64
	head     []byte
	signer   *countingSigner
	store    *checkpointGetCounter
	reporter *spyReporter
	m        *monitor.Monitor
}

func newCostFixture(t *testing.T) *costFixture {
	t.Helper()
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	genesis := canon.GenesisHash()
	lastID, head := dbtest.SeedChain(t, ctx, pool, genesis, []canon.AuditEvent{
		decisionEvent("alice", "select 1"),
		decisionEvent("bob", "select 2"),
	})
	reader, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	t.Cleanup(reader.Close)
	fileKey, err := sign.NewFileKey(filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("new file key: %v", err)
	}
	fx := &costFixture{
		ctx: ctx, pool: pool, lastID: lastID, head: head,
		signer:   &countingSigner{Signer: fileKey},
		store:    &checkpointGetCounter{ObjectStore: worm.NewMemory()},
		reporter: &spyReporter{},
	}
	cfg := config.MonitorConfig{PollInterval: time.Second, SignInterval: time.Hour, FullVerifyInterval: time.Hour}
	fx.m = monitor.New(reader, fx.signer, fx.store, genesis, cfg, monitor.NoopDetector{}, fx.reporter)
	return fx
}

func (fx *costFixture) appendAndSign(t *testing.T, sqls ...string) {
	t.Helper()
	events := make([]canon.AuditEvent, 0, len(sqls))
	for _, sql := range sqls {
		events = append(events, decisionEvent("carol", sql))
	}
	fx.lastID, fx.head = dbtest.AppendChain(t, fx.ctx, fx.pool, fx.lastID+1, fx.head, events)
	if err := fx.m.SignHead(fx.ctx); err != nil {
		t.Fatalf("sign head: %v", err)
	}
}

func (fx *costFixture) resetCounts() {
	fx.signer.verifies = 0
	fx.store.gets = 0
}

func TestPollsNeverRecheckAnUnchangedAnchor(t *testing.T) {
	fx := newCostFixture(t)
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	fx.appendAndSign(t, "select 3")
	fx.appendAndSign(t, "select 4")
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}

	fx.resetCounts()
	for range 3 {
		if err := fx.m.Poll(fx.ctx); err != nil {
			t.Fatalf("poll: %v", err)
		}
	}
	if fx.signer.verifies != 0 || fx.store.gets != 0 {
		t.Fatalf("idle polls made %d Verify calls and %d anchor GETs, want 0 and 0",
			fx.signer.verifies, fx.store.gets)
	}
	if len(fx.reporter.findings) != 0 {
		t.Fatalf("unexpected findings: %+v", fx.reporter.findings)
	}
}

func (fx *costFixture) signedAnchors(t *testing.T) []worm.Anchor {
	t.Helper()
	anchors, err := worm.ReadAnchors(fx.store.ObjectStore)
	if err != nil {
		t.Fatalf("read anchors: %v", err)
	}
	var signed []worm.Anchor
	for _, a := range anchors {
		if a.UpToID > 0 {
			signed = append(signed, a)
		}
	}
	return signed
}

func (fx *costFixture) withThreeAnchors(t *testing.T) []worm.Anchor {
	t.Helper()
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	fx.appendAndSign(t, "select 3")
	fx.appendAndSign(t, "select 4")
	fx.appendAndSign(t, "select 5")
	anchors := fx.signedAnchors(t)
	if len(anchors) < 3 {
		t.Fatalf("anchors = %+v, want at least three past genesis", anchors)
	}
	return anchors
}

func (fx *costFixture) rewriteFromGenesis(t *testing.T) {
	t.Helper()
	if _, err := fx.pool.Exec(fx.ctx, "DELETE FROM audit_event"); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	events := make([]canon.AuditEvent, fx.lastID)
	for i := range events {
		events[i] = decisionEvent("mallory", "hacked "+strconv.Itoa(i+1))
	}
	dbtest.SeedChain(t, fx.ctx, fx.pool, canon.GenesisHash(), events)
}

func TestFullVerifyAsksTheSignerAboutTheNewestAnchorOnly(t *testing.T) {
	fx := newCostFixture(t)
	fx.withThreeAnchors(t)
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}

	fx.resetCounts()
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	if fx.signer.verifies != 1 || fx.store.gets != 0 {
		t.Fatalf("a clean full verify made %d Verify calls and %d anchor GETs, want 1 and 0",
			fx.signer.verifies, fx.store.gets)
	}
	fx.resetCounts()
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if fx.signer.verifies != 0 {
		t.Fatalf("a poll after a full verify made %d Verify calls, want 0", fx.signer.verifies)
	}
	if len(fx.reporter.findings) != 0 {
		t.Fatalf("unexpected findings: %+v", fx.reporter.findings)
	}
}

func TestARewriteIsReportedAtTheLowestAnchorItReaches(t *testing.T) {
	fx := newCostFixture(t)
	anchors := fx.withThreeAnchors(t)
	fx.rewriteFromGenesis(t)

	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	f := fx.reporter.findings
	if len(f) != 1 || f[0].Reason != verify.ReasonAnchorHeadMismatch || f[0].DivergentID != anchors[0].UpToID {
		t.Fatalf("findings = %+v, want one %s at id %d, the lowest anchor the rewrite reaches",
			f, verify.ReasonAnchorHeadMismatch, anchors[0].UpToID)
	}
}

func TestAFindingSurvivesAFailedRecheckOfEveryAnchor(t *testing.T) {
	fx := newCostFixture(t)
	anchors := fx.withThreeAnchors(t)
	fx.rewriteFromGenesis(t)

	fx.store.limitLists, fx.store.listBudget = true, 1
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	newest := anchors[len(anchors)-1].UpToID
	f := fx.reporter.findings
	if len(f) != 1 || f[0].Reason != verify.ReasonAnchorHeadMismatch || f[0].DivergentID != newest {
		t.Fatalf("findings = %+v, want the first pass's %s at id %d", f, verify.ReasonAnchorHeadMismatch, newest)
	}
	if !fx.m.Halted() {
		t.Fatal("a proven rewrite did not halt the monitor because re-checking every anchor failed")
	}
}

func TestAnUnsignedAcceptanceDoesNotWidenTheFullVerify(t *testing.T) {
	fx := newCostFixture(t)
	anchors := fx.withThreeAnchors(t)
	junk := worm.Acceptance{
		DivergentID: anchors[0].UpToID, Reason: verify.ReasonAnchorHeadMismatch,
		Expected: "aa", Actual: "bb", ResumeHash: "bb",
		Signature: base64.StdEncoding.EncodeToString([]byte("forged")), KeyID: "k1",
	}
	if err := worm.WriteAcceptance(fx.store, junk); err != nil {
		t.Fatalf("write acceptance: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}

	fx.resetCounts()
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	if fx.signer.verifies != 2 {
		t.Fatalf("a full verify with one unsigned acceptance made %d Verify calls, want 2 (the newest anchor and the acceptance)",
			fx.signer.verifies)
	}
}

func TestAcceptedAnchorBreaksStayVisibleAndResume(t *testing.T) {
	fx := newCostFixture(t)
	anchors := fx.withThreeAnchors(t)
	fx.rewriteFromGenesis(t)
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}

	for range anchors {
		d, err := fx.m.Diagnose(fx.ctx)
		if err != nil {
			t.Fatalf("diagnose: %v", err)
		}
		if d.Finding == nil {
			break
		}
		if _, err := fx.m.AcceptBreak(fx.ctx, *d.Finding); err != nil {
			t.Fatalf("accept break at %d: %v", d.Finding.DivergentID, err)
		}
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	if fx.m.Halted() {
		t.Fatal("still halted after every divergence was accepted")
	}
	d, err := fx.m.Diagnose(fx.ctx)
	if err != nil || d.Finding != nil {
		t.Fatalf("diagnose after accepting = %+v, %v; want no finding", d.Finding, err)
	}
	if len(d.Accepted) != len(anchors) {
		t.Fatalf("diagnose lists %d accepted breaks, want %d (one per anchor the rewrite reached): %+v",
			len(d.Accepted), len(anchors), d.Accepted)
	}
}

func TestAForgedOldAnchorDoesNotKeepAHaltLatched(t *testing.T) {
	fx := newCostFixture(t)
	anchors := fx.withThreeAnchors(t)
	if _, err := fx.pool.Exec(fx.ctx, "UPDATE audit_event SET principal = 'mallory' WHERE id = 1"); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	if !fx.m.Halted() {
		t.Fatal("monitor did not halt on the tamper")
	}

	forged := anchors[0]
	forged.Signature = base64.StdEncoding.EncodeToString([]byte("forged"))
	body, err := json.Marshal(forged)
	if err != nil {
		t.Fatalf("marshal anchor: %v", err)
	}
	if err := fx.store.Put("checkpoints/"+strconv.FormatInt(forged.UpToID, 10)+".json", body); err != nil {
		t.Fatalf("forge anchor: %v", err)
	}
	if _, err := fx.pool.Exec(fx.ctx, "UPDATE audit_event SET principal = 'alice' WHERE id = 1"); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	if fx.m.Halted() {
		t.Fatal("a forged anchor below the newest valid one kept the halt latched, though the newest anchor " +
			"witnesses every row below it")
	}
}

func TestAKeyThatStopsVerifyingStopsVouchingAfterTheNextFullVerify(t *testing.T) {
	fx := newCostFixture(t)
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}

	fx.signer.failWith = errors.New("kms: key is disabled")
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(fx.reporter.findings) != 0 {
		t.Fatalf("a poll with a cached verdict raised findings: %+v", fx.reporter.findings)
	}

	if err := fx.m.FullVerify(fx.ctx); err == nil {
		t.Fatal("a full verify that could not verify any anchor returned no error")
	}
	if len(fx.reporter.findings) != 0 || fx.m.Halted() {
		t.Fatalf("a signer failure was judged a forgery: findings=%+v halted=%v", fx.reporter.findings, fx.m.Halted())
	}
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(fx.reporter.findings) != 1 || fx.reporter.findings[0].Reason != monitor.ReasonAnchorVerifyError {
		t.Fatalf("findings = %+v, want one %s once the key stops verifying", fx.reporter.findings, monitor.ReasonAnchorVerifyError)
	}
}

func TestANewAnchorCostsOneGetAndOneVerify(t *testing.T) {
	fx := newCostFixture(t)
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	fx.appendAndSign(t, "select 3")
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}

	fx.appendAndSign(t, "select 4")
	fx.resetCounts()
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if fx.signer.verifies != 1 || fx.store.gets != 1 {
		t.Fatalf("poll after one new anchor made %d Verify calls and %d anchor GETs, want 1 and 1",
			fx.signer.verifies, fx.store.gets)
	}
}

func TestAnAnchorReplacedAtItsKeyIsVerifiedAgain(t *testing.T) {
	fx := newCostFixture(t)
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	anchors, err := worm.ReadAnchors(fx.store)
	if err != nil || len(anchors) != 1 {
		t.Fatalf("read anchors = %+v, %v; want one", anchors, err)
	}

	forged := anchors[0]
	forged.Signature = "Zm9yZ2Vk"
	body, err := json.Marshal(forged)
	if err != nil {
		t.Fatalf("marshal anchor: %v", err)
	}
	if err := fx.store.Put("checkpoints/"+strconv.FormatInt(forged.UpToID, 10)+".json", body); err != nil {
		t.Fatalf("replace anchor: %v", err)
	}

	fx.resetCounts()
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if fx.signer.verifies != 1 {
		t.Fatalf("replaced anchor was verified %d times, want 1", fx.signer.verifies)
	}
	if len(fx.reporter.findings) != 1 || fx.reporter.findings[0].Reason != monitor.ReasonAnchorSignatureInvalid {
		t.Fatalf("findings = %+v, want one %s for the replaced anchor", fx.reporter.findings, monitor.ReasonAnchorSignatureInvalid)
	}
}

func TestASignerErrorIsRetriedOnTheNextPoll(t *testing.T) {
	fx := newCostFixture(t)
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}

	fx.signer.failWith = errors.New("kms: throttled")
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(fx.reporter.findings) != 1 || fx.reporter.findings[0].Reason != monitor.ReasonAnchorVerifyError {
		t.Fatalf("findings = %+v, want one %s", fx.reporter.findings, monitor.ReasonAnchorVerifyError)
	}

	fx.signer.failWith = nil
	fx.resetCounts()
	if err := fx.m.Poll(fx.ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if fx.signer.verifies != 1 {
		t.Fatalf("poll after a signer error made %d Verify calls, want 1 (the error must not be cached)", fx.signer.verifies)
	}
	if len(fx.reporter.findings) != 1 {
		t.Fatalf("recovered poll raised new findings: %+v", fx.reporter.findings[1:])
	}
}
