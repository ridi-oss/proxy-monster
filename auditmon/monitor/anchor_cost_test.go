package monitor_test

import (
	"context"
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
	gets int
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

func TestPollAndFullVerifyNeverRecheckAnUnchangedAnchor(t *testing.T) {
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
	if err := fx.m.FullVerify(fx.ctx); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	if fx.signer.verifies != 0 || fx.store.gets != 0 {
		t.Fatalf("idle polls and a full verify made %d Verify calls and %d anchor GETs, want 0 and 0",
			fx.signer.verifies, fx.store.gets)
	}
	if len(fx.reporter.findings) != 0 {
		t.Fatalf("unexpected findings: %+v", fx.reporter.findings)
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
