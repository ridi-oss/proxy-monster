// Package monitor is the CP-independent loop that reads the committed trail, re-verifies the hash chain,
// exports redacted event batches, and periodically signs an off-box anchor. It is fail-safe: every error is
// logged, never fatal, so it can never block or slow a decision. Anomaly detection and out-of-band alert
// delivery enter through the Detector and IntegrityReporter interfaces, which cmd/auditmon wires to the
// config-driven rule detector and the webhook reporter.
package monitor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/ridi-oss/proxy-monster/auditmon/config"
	"github.com/ridi-oss/proxy-monster/auditmon/sign"
	"github.com/ridi-oss/proxy-monster/auditmon/store"
	"github.com/ridi-oss/proxy-monster/auditmon/verify"
	"github.com/ridi-oss/proxy-monster/auditmon/worm"
)

// Detector inspects each polled batch for abuse patterns. cmd/auditmon supplies the config-driven rule
// detector (detect.New); NoopDetector is the do-nothing implementation for tests and for a build that
// deliberately runs without rules.
type Detector interface {
	Inspect(events []store.StoredEvent) error
	InspectCatchUp(fresh []store.StoredEvent) error
}

// NoopDetector does nothing.
type NoopDetector struct{}

// Inspect is a no-op.
func (NoopDetector) Inspect([]store.StoredEvent) error { return nil }

func (NoopDetector) InspectCatchUp([]store.StoredEvent) error { return nil }

// IntegrityReporter delivers an integrity finding. cmd/auditmon supplies the webhook reporter
// (alert.NewReporter); LoggingReporter (slog) is the fallback that only records it.
type IntegrityReporter interface {
	Report(f verify.Finding)
}

// LoggingReporter reports findings to a slog logger.
type LoggingReporter struct {
	Logger *slog.Logger
}

// Report logs the finding at error level.
func (r LoggingReporter) Report(f verify.Finding) {
	logger := r.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Error("audit chain integrity finding",
		"divergent_id", f.DivergentID,
		"reason", f.Reason,
		"expected", hex.EncodeToString(f.Expected),
		"actual", hex.EncodeToString(f.Actual),
	)
}

// Reasons the monitor reports for a bad off-box anchor, distinct from the in-chain verify.Reason* set: the
// anchor is the monitor's own prior signature, so these fire when that signature no longer trusts the head
// it covers (tampered/replaced anchor, or a signer that cannot verify).
const (
	ReasonAnchorSignatureInvalid = "anchor_signature_invalid"
	ReasonAnchorVerifyError      = "anchor_verify_error"
)

// Monitor wires the read side, signer, and off-box store together.
type Monitor struct {
	reader  *store.Reader
	signer  sign.Signer
	store   worm.ObjectStore
	genesis []byte
	cfg     config.MonitorConfig
	detect  Detector
	report  IntegrityReporter
	log     *slog.Logger

	// exportedThrough is the highest event id already written to the off-box SIEM store. Both Poll and
	// SignHead advance it (via processFresh) so a growing tail is exported once rather than re-exported on
	// every poll, and so an event is never anchored-over before it is exported. The off-box anchor is never
	// advanced ahead of it (exportedThrough >= anchor.UpToID always), which is what makes it safe to floor
	// the tail read at the anchor. In-memory only: after a restart it re-exports from the last anchor, which
	// the downstream SIEM dedupes by id. (Detection sees the re-exported rows too, so a per-event rule like
	// off_hours can re-alert once after a restart; the alert sink's dedup collapses a burst but not a
	// cross-restart repeat. Persisting a watermark would remove it.)
	exportedThrough int64

	// halted latches true when a full re-verification finds the chain broken. A halted monitor stops
	// exporting and stops signing new anchors, so it can never lend its signature to — or ship to the SIEM —
	// a chain it has already proven tampered. It never blocks a decision (the monitor is read-side only).
	halted atomic.Bool
}

// New builds a Monitor.
func New(reader *store.Reader, signer sign.Signer, os worm.ObjectStore, genesis []byte, cfg config.MonitorConfig, detect Detector, report IntegrityReporter) *Monitor {
	return &Monitor{
		reader:  reader,
		signer:  signer,
		store:   os,
		genesis: genesis,
		cfg:     cfg,
		detect:  detect,
		report:  report,
		log:     slog.Default(),
	}
}

// verifiedTail is the outcome of re-verifying the committed tail against the last off-box anchor: the events
// read after it, and the head that walk proves — the anchored (or, on the first run, genesis) head advanced
// over every intact row. head is the ONLY head the monitor will ever sign; it is derived from the events
// themselves, never from a raw audit_chain_head read.
type verifiedTail struct {
	anchorPresent bool
	head          store.ChainHead
	events        []store.StoredEvent
}

// anchorVerify reports whether an anchor is a trustworthy witness of its own (up_to_id, head_hash): it
// recomputes the signed digest binding BOTH fields and verifies it under a configured key (never the
// anchor's self-declared key_id on its own). A malformed hex/base64 field is a definitive non-verification
// (valid=false, err=nil) so a junk object is skipped, not fatal; a signer error is returned so the caller
// can treat it as an infrastructure problem rather than silently trusting or distrusting the anchor.
func (m *Monitor) anchorVerify(a worm.Anchor) (headHash []byte, valid bool, err error) {
	headHash, err = hex.DecodeString(a.HeadHash)
	if err != nil {
		return nil, false, nil
	}
	sig, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil {
		return nil, false, nil
	}
	valid, err = m.signer.Verify(sign.AnchorDigest(a.UpToID, headHash), sig, a.KeyID)
	if err != nil {
		return nil, false, err
	}
	return headHash, valid, nil
}

// selectBaseline picks the trusted head the tail walk starts from: the highest-up_to_id anchor whose
// signature validates. A junk or bad-signature anchor at a higher id is skipped rather than allowed to wedge
// the monitor. When NO anchor validates but one is present and tampered/unverifiable, that is itself a
// finding (present=false, finding set) — the monitor must not silently fall back to a from-genesis first run
// and launder over it. With no anchors at all it is the genuine first run (genesis head, present=false).
func (m *Monitor) selectBaseline() (baseline store.ChainHead, present bool, finding *verify.Finding, err error) {
	anchors, err := worm.ReadAnchors(m.store)
	if err != nil {
		return store.ChainHead{}, false, nil, fmt.Errorf("monitor: read anchors: %w", err)
	}
	var (
		best        *worm.Anchor
		bestHead    []byte
		sawInvalid  bool
		invalidID   int64
		verifyErr   error
		verifyErrID int64
	)
	for i := range anchors {
		a := anchors[i]
		head, valid, verr := m.anchorVerify(a)
		switch {
		case verr != nil:
			if verifyErr == nil || a.UpToID >= verifyErrID {
				verifyErr, verifyErrID = verr, a.UpToID
			}
		case valid:
			if best == nil || a.UpToID > best.UpToID {
				best, bestHead = &anchors[i], head
			}
		default:
			if !sawInvalid || a.UpToID >= invalidID {
				sawInvalid, invalidID = true, a.UpToID
			}
		}
	}
	if best != nil {
		return store.ChainHead{LastID: best.UpToID, HeadHash: bestHead}, true, nil, nil
	}
	if verifyErr != nil {
		m.log.Error("monitor: anchor signature could not be verified", "err", verifyErr, "up_to_id", verifyErrID)
		return store.ChainHead{}, false, &verify.Finding{DivergentID: verifyErrID, Reason: ReasonAnchorVerifyError}, nil
	}
	if sawInvalid {
		return store.ChainHead{}, false, &verify.Finding{DivergentID: invalidID, Reason: ReasonAnchorSignatureInvalid}, nil
	}
	return store.ChainHead{LastID: 0, HeadHash: m.genesis}, false, nil, nil
}

// tailBatch bounds each tail read; the config default applies when a caller (tests) left it zero.
func (m *Monitor) tailBatch() int {
	if m.cfg.TailBatch > 0 {
		return m.cfg.TailBatch
	}
	return 5000
}

// ReasonTailTruncated: rows the walk pinned as its target before the first page were gone by the time it
// got there — a deletion between page reads, which a short final read must not pass off as completion.
const ReasonTailTruncated = "tail_truncated"

// verifyChain selects the trusted baseline anchor, pins the walk's target (the highest committed id at the
// start), then reads and re-walks the tail after the anchor in bounded batches, calling each on every
// verified batch — so peak memory depends on the batch size, never on how far behind the monitor is (a long
// outage used to OOM here and crash-loop unrecoverably). Rows appended after the pin are left for the next
// poll, so a sustained writer cannot keep the walk from returning. A walk that ends short of its pinned
// target means rows were deleted between page reads (each page is its own snapshot) — reported as a finding,
// never returned as success. A verified batch is exported/anchored by each BEFORE the next page is read:
// never a byte of an unverified segment, but a clean prefix does commit before a later batch's break is
// found (that prefix is exactly what a restart resumes from).
func (m *Monitor) verifyChain(ctx context.Context, each func(verifiedTail) error) (verifiedTail, bool, error) {
	head, present, finding, err := m.selectBaseline()
	if err != nil {
		return verifiedTail{}, false, err
	}
	if finding != nil {
		m.report.Report(*finding)
		return verifiedTail{}, false, nil
	}

	target, err := m.reader.MaxEventID(ctx)
	if err != nil {
		return verifiedTail{}, false, fmt.Errorf("monitor: pin tail target: %w", err)
	}

	batch := m.tailBatch()
	for {
		events, err := m.reader.TailEvents(ctx, head.LastID, batch)
		if err != nil {
			return verifiedTail{}, false, fmt.Errorf("monitor: read tail: %w", err)
		}

		f, err := verify.VerifyTail(head, events)
		if err != nil {
			return verifiedTail{}, false, fmt.Errorf("monitor: verify tail: %w", err)
		}
		if f != nil {
			m.report.Report(*f)
			return verifiedTail{}, false, nil
		}

		if len(events) > 0 {
			last := events[len(events)-1]
			head = store.ChainHead{LastID: last.ID, HeadHash: last.RowHash}
		}
		vt := verifiedTail{anchorPresent: present, head: head, events: events}
		if each != nil && len(events) > 0 {
			if err := each(vt); err != nil {
				return verifiedTail{}, false, err
			}
		}
		if head.LastID >= target {
			return vt, true, nil
		}
		if len(events) < batch {
			m.report.Report(verify.Finding{DivergentID: head.LastID + 1, Reason: ReasonTailTruncated})
			return verifiedTail{}, false, nil
		}
	}
}

// catchUpBatch is the per-batch work of a verified tail walk: detection + export of the batch's fresh rows,
// and — while catching up through a full batch (a backlog) — a checkpoint anchor over the verified head, so
// a crash mid-catch-up resumes from the last exported batch instead of re-walking (and re-exporting) the
// whole backlog; the first-ever walk checkpoints the same way. The export always precedes the anchor, so no
// row is ever stranded below an anchor. A checkpoint the store refuses (a conflicting object already at
// that id) is logged and skipped, not fatal: the checkpoint only buys resume granularity, and wedging the
// walk on it would trade the backlog's export for a nicer restart. Steady-state batches (shorter than the
// batch size) leave anchor cadence to SignHead.
func (m *Monitor) catchUpBatch(vt verifiedTail) error {
	catchUp := len(vt.events) == m.tailBatch()
	if err := m.processFreshMode(vt, catchUp); err != nil {
		return err
	}
	if catchUp {
		if err := m.signAnchor(vt.head); err != nil {
			m.log.Warn("monitor: catch-up checkpoint not written; continuing", "up_to_id", vt.head.LastID, "err", err)
		}
	}
	return nil
}

// Poll re-verifies the committed tail against the last anchor in bounded batches, running detection on and
// exporting each verified batch as it goes. On the very first run (no anchor yet) it verifies from genesis,
// checkpointing full batches the same way, and writes the final anchor at the head. A verification break or
// a bad anchor signature is reported and the poll stops — nothing of the broken batch (or beyond) is
// exported or signed; batches verified before it remain committed, which is what a retry resumes from. A
// returned error is an infrastructure failure (DB/store unreachable), which the Run loop logs and retries.
func (m *Monitor) Poll(ctx context.Context) error {
	if m.halted.Load() {
		return nil
	}
	vt, ok, err := m.verifyChain(ctx, m.catchUpBatch)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	// First run: establish the initial signed anchor over the verified head so later polls have a baseline
	// to verify against instead of re-walking from genesis every time.
	if !vt.anchorPresent {
		if err := m.signAnchor(vt.head); err != nil {
			return fmt.Errorf("monitor: write initial anchor: %w", err)
		}
	}
	return nil
}

// processFresh runs detection on and exports the verified rows past the export watermark, then advances the
// watermark. Both Poll and SignHead call it: because SignHead runs on its own (slower) cadence and moves the
// off-box anchor forward, it must flush any rows that arrived since the last poll BEFORE the anchor advances
// past them — otherwise the next poll (which reads the tail only after the anchor) would never see them, and
// they would be silently dropped from the SIEM/detection feed. Running it before every signAnchor keeps the
// anchor from ever getting ahead of the export (exportedThrough >= anchor.UpToID), which is the invariant
// that makes the anchor safe to floor the tail read at.
func (m *Monitor) processFresh(vt verifiedTail) error { return m.processFreshMode(vt, false) }

// processFreshMode: catchUp batches run only the per-event rules (InspectCatchUp) — the window rules would
// re-read the whole durable window per batch and see rows the walk has not verified yet; the walk's final
// batch runs the full Inspect over a window that then covers everything the catch-up shipped.
func (m *Monitor) processFreshMode(vt verifiedTail, catchUp bool) error {
	// Only the rows past the export watermark are new work; the rest were already shipped.
	fresh := eventsAfter(vt.events, m.exportedThrough)
	if len(fresh) == 0 {
		return nil
	}

	inspect := m.detect.Inspect
	if catchUp {
		inspect = m.detect.InspectCatchUp
	}
	if err := inspect(fresh); err != nil {
		m.log.Warn("monitor: detector error", "err", err)
	}

	records := make([]worm.ExportRecord, 0, len(fresh))
	for _, ev := range fresh {
		records = append(records, exportRecord(ev))
	}
	if err := worm.WriteEventBatch(m.store, fresh[0].ID, fresh[len(fresh)-1].ID, records); err != nil {
		return fmt.Errorf("monitor: export batch: %w", err)
	}
	m.exportedThrough = fresh[len(fresh)-1].ID
	return nil
}

// SignHead re-verifies the committed tail and, only if it is intact, signs the verified head into a new
// off-box anchor. It signs the head the chain walk proves — never a raw audit_chain_head read — and never
// advances the anchor past a detected break, so a forged tail can never be laundered under the monitor's own
// signature. It flushes any not-yet-exported rows first, so advancing the anchor can never strand rows that
// arrived since the last poll below the anchor, out of reach of every future tail read.
func (m *Monitor) SignHead(ctx context.Context) error {
	if m.halted.Load() {
		return nil
	}
	vt, ok, err := m.verifyChain(ctx, m.catchUpBatch)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	return m.signAnchor(vt.head)
}

// signAnchor signs a verified head and appends it as a new off-box anchor. The signature covers a digest
// binding both the anchored up_to_id and the head hash, so neither can be re-labeled after signing.
func (m *Monitor) signAnchor(head store.ChainHead) error {
	sig, keyID, err := m.signer.Sign(sign.AnchorDigest(head.LastID, head.HeadHash))
	if err != nil {
		return fmt.Errorf("monitor: sign head: %w", err)
	}
	return worm.WriteAnchor(m.store, worm.Anchor{
		UpToID:    head.LastID,
		HeadHash:  hex.EncodeToString(head.HeadHash),
		Signature: base64.StdEncoding.EncodeToString(sig),
		KeyID:     keyID,
	})
}

// FullVerify re-walks the entire chained trail from the pinned genesis and cross-checks the recomputed head
// at every valid signed anchor against the head that anchor witnessed. It runs on boot and on
// full_verify_interval, alongside the per-poll incremental tail verify, so a rewrite of a row at or below an
// already-anchored head — which the tail walk (rows after the anchor only) never sees — is caught. A
// partial rewrite breaks the row-walk; an internally-consistent full rewrite from genesis passes the
// row-walk but diverges from the off-box signed anchor.
//
// A finding an operator has not accepted is reported and latches the monitor halted: it then stops exporting
// and signing so it can never witness a chain it has proven tampered. A finding covered by a signed
// acceptance is logged (an accepted break stays visible forever) but does not halt, and the walk continues
// past it — so tampering ABOVE an accepted break is still caught rather than hidden behind the old one. The
// halt is also CLEARED when nothing unaccepted remains, which is what lets a separate operator process
// (`auditmon accept-break`) resume this running daemon: acceptance lives in the shared object store, not in
// one process's memory.
//
// A returned error is an infrastructure failure the Run loop logs and retries; it never blocks a decision.
func (m *Monitor) FullVerify(ctx context.Context) error {
	w, err := m.witnesses("full verify")
	if err != nil {
		return err
	}

	// With every off-box anchor unusable there is nothing left to contradict an internally-consistent rewrite,
	// so treat that as the finding it is rather than letting a clean row-walk pass.
	f, trustErr := m.anchorTrustFinding(len(w.checks))
	if trustErr != nil {
		return trustErr
	}
	var waived []verify.Finding
	if f == nil {
		f, waived, err = verify.VerifyFromGenesisAccepting(ctx, m.reader, m.genesis, w.checks, w.accepted)
		if err != nil {
			return fmt.Errorf("monitor: full verify: %w", err)
		}
	}
	for _, wf := range waived {
		m.log.Warn("monitor: chain divergence stands, previously accepted by an operator",
			"divergent_id", wf.DivergentID, "reason", wf.Reason)
	}
	if f != nil {
		m.report.Report(*f)
		m.halted.Store(true)
		m.log.Error("monitor: full re-verification found a chain break; halting export and signing",
			"divergent_id", f.DivergentID, "reason", f.Reason)
		return nil
	}
	// Nothing unaccepted remains. Resuming additionally requires that the evidence was COMPLETE: if a signer
	// or object-store failure left an anchor unverifiable, this pass ran with fewer witnesses than exist, and
	// a rewrite could have slipped through a check that simply did not happen. Clearing the halt on that would
	// mean an outage silently ends a halt — so a halted monitor stays halted until it can see everything.
	if !w.complete {
		if m.halted.Load() {
			m.log.Warn("monitor: staying halted: some off-box evidence could not be verified this pass, so a " +
				"clean result does not prove the trail is whole")
		}
		return nil
	}
	// This is the only place the halt clears, and only after a complete from-genesis pass proved there is
	// nothing left to halt on — either the trail was restored, or every divergence carries a signed acceptance.
	if m.halted.CompareAndSwap(true, false) {
		m.log.Warn("monitor: no unaccepted chain break remains; resuming export and signing")
	}
	return nil
}

// evidence is the off-box material a from-genesis verification judges against: the signed anchors to
// cross-check, and the signed operator acceptances to honor. complete is false when any anchor or acceptance
// could not be verified at all (a signer or store failure, as opposed to a signature that definitively does
// not validate) — a clean pass over incomplete evidence proves less than a clean pass over all of it.
type evidence struct {
	checks   []verify.AnchorCheck
	accepted []verify.Accepted
	complete bool
}

// witnesses reads and signature-verifies the off-box evidence. An unsigned or badly-signed acceptance is NOT
// honored, so writing an acceptance object is useless to anyone who cannot sign with the monitor's key.
func (m *Monitor) witnesses(what string) (evidence, error) {
	anchors, err := worm.ReadAnchors(m.store)
	if err != nil {
		return evidence{}, fmt.Errorf("monitor: %s: read anchors: %w", what, err)
	}
	out := evidence{complete: true}
	for _, a := range anchors {
		head, valid, verr := m.anchorVerify(a)
		if verr != nil {
			// Cannot confirm this one anchor now; skip cross-checking it rather than aborting the whole pass.
			// The row-walk still runs and the next full pass retries — but the evidence is incomplete, so a
			// clean result from this pass must not be read as proof the trail is whole.
			m.log.Warn("monitor: "+what+" could not verify an anchor", "err", verr, "up_to_id", a.UpToID)
			out.complete = false
			continue
		}
		if !valid {
			// A checkpoint object that does not validate is not a harmless stray. It occupies the key where a
			// real witness belongs, and on a versioned store it may be a forgery placed over one — so the
			// witness it should have provided is missing from this pass. Treat the evidence as incomplete
			// rather than quietly cross-checking against whatever older anchors remain, which is what would let
			// a rewritten tail above them verify clean.
			m.log.Error("monitor: ignoring a checkpoint whose signature does not validate; evidence is incomplete",
				"up_to_id", a.UpToID)
			out.complete = false
			continue
		}
		out.checks = append(out.checks, verify.AnchorCheck{UpToID: a.UpToID, HeadHash: head})
	}

	records, err := worm.ReadAcceptances(m.store)
	if err != nil {
		return evidence{}, fmt.Errorf("monitor: %s: read acceptances: %w", what, err)
	}
	for _, r := range records {
		a, ok, verr := m.acceptanceVerify(r)
		if verr != nil {
			// Fail closed: an acceptance that cannot be verified right now is not honored, so the monitor stays
			// halted rather than resuming on evidence it could not check.
			m.log.Warn("monitor: "+what+" could not verify an acceptance", "err", verr, "divergent_id", r.DivergentID)
			out.complete = false
			continue
		}
		if !ok {
			m.log.Error("monitor: ignoring an acceptance whose signature does not validate",
				"divergent_id", r.DivergentID, "reason", r.Reason)
			continue
		}
		out.accepted = append(out.accepted, a)
	}
	return out, nil
}

// acceptanceVerify reports whether an acceptance record is genuinely signed by a configured key. As with
// anchors, malformed hex/base64 is a definitive non-verification rather than an error, so one junk object
// cannot wedge the monitor.
func (m *Monitor) acceptanceVerify(r worm.Acceptance) (verify.Accepted, bool, error) {
	expected, err := hex.DecodeString(r.Expected)
	if err != nil {
		return verify.Accepted{}, false, nil
	}
	actual, err := hex.DecodeString(r.Actual)
	if err != nil {
		return verify.Accepted{}, false, nil
	}
	resume, err := hex.DecodeString(r.ResumeHash)
	if err != nil {
		return verify.Accepted{}, false, nil
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil {
		return verify.Accepted{}, false, nil
	}
	valid, err := m.signer.Verify(sign.AcceptanceDigest(r.DivergentID, r.Reason, expected, actual, resume), sig, r.KeyID)
	if err != nil {
		return verify.Accepted{}, false, err
	}
	if !valid {
		return verify.Accepted{}, false, nil
	}
	return verify.Accepted{
		DivergentID: r.DivergentID,
		Reason:      r.Reason,
		Expected:    expected,
		Actual:      actual,
		ResumeHash:  resume,
	}, true, nil
}

// Halted reports whether a chain break has latched this monitor into its halted state.
func (m *Monitor) Halted() bool { return m.halted.Load() }

// Diagnosis is what an operator inspecting a halted monitor needs to see: the divergence that is still
// unaccepted (Finding, nil when the trail holds), plus the divergences already waived by a signed acceptance
// so an accepted break never silently disappears from the report.
type Diagnosis struct {
	Finding  *verify.Finding
	Accepted []verify.Finding
}

// Diagnose re-runs the from-genesis verification and returns what it found WITHOUT reporting an alert or
// changing the halt. It is the read-only half of recovery: an operator needs to know which row diverged and
// why (a content rewrite reads differently from a truncation) before deciding what to do, and asking that
// question must not itself emit another critical alert.
//
// It fails closed on the witnesses themselves: if anchors exist but NONE validates, the trail cannot be
// judged intact — the off-box witness is exactly what proves an internally-consistent rewrite — so that is
// reported as a finding rather than letting a clean row-walk print "intact".
func (m *Monitor) Diagnose(ctx context.Context) (Diagnosis, error) {
	w, err := m.witnesses("diagnose")
	if err != nil {
		return Diagnosis{}, err
	}
	if f, err := m.anchorTrustFinding(len(w.checks)); err != nil {
		return Diagnosis{}, err
	} else if f != nil {
		return Diagnosis{Finding: f}, nil
	}
	f, waived, err := verify.VerifyFromGenesisAccepting(ctx, m.reader, m.genesis, w.checks, w.accepted)
	if err != nil {
		return Diagnosis{}, fmt.Errorf("monitor: diagnose: %w", err)
	}
	return Diagnosis{Finding: f, Accepted: waived}, nil
}

// anchorTrustFinding reports a finding when anchor objects exist but none of them validates. A row-walk over
// an internally-consistent rewrite comes back clean, so with every witness unusable there is nothing left to
// contradict it: reporting "intact" there would be a false all-clear. With no anchors at all it is a genuine
// first run, which is not a finding.
func (m *Monitor) anchorTrustFinding(validChecks int) (*verify.Finding, error) {
	if validChecks > 0 {
		return nil, nil
	}
	anchors, err := worm.ReadAnchors(m.store)
	if err != nil {
		return nil, fmt.Errorf("monitor: diagnose: read anchors: %w", err)
	}
	if len(anchors) == 0 {
		return nil, nil
	}
	highest := anchors[len(anchors)-1].UpToID
	return &verify.Finding{DivergentID: highest, Reason: ReasonAnchorSignatureInvalid}, nil
}

// AcceptBreak is the deliberate operator decision to ACCEPT a specific chain divergence and resume
// monitoring. It writes a signed ACCEPTANCE record — a new object under its own prefix — and never touches
// the signed anchors: the anchor that witnessed the break is the evidence of it, so accepting a break must
// never be able to overwrite the very witness that proved it. An acceptance is scoped to the exact bytes that
// diverged, so it waives that one divergence and nothing else; a later tamper at the same row produces
// different bytes, is not covered, and halts the monitor again.
//
// It does not repair anything, and it must not be run casually. The rows that diverged stay divergent — the
// break is a permanent fact of the history, the acceptance is a permanent record of the decision, and the
// alert stays in the WORM bucket. What this restores is forward coverage: without it a halted monitor
// witnesses nothing at all, so an incident that began with tampering would be followed by an unmonitored
// window, which is strictly worse. The judgement of whether the divergence was an attack, a restore from
// backup, or a test harness rewriting the chain belongs to the human running this, and the reason it is
// out-of-band (an operator command on the monitor host, never an API the control plane can call) is that the
// watched system must never be able to silence its own watcher.
//
// Because the acceptance is durable and signature-verified, a SEPARATE operator process resumes the running
// daemon: the daemon's next full pass reads the same acceptance from the store and clears its own halt.
//
// f must be the finding the operator actually reviewed. It is re-derived and compared before anything is
// signed, so a divergence that changed between diagnosis and acceptance is refused rather than waived
// sight-unseen.
func (m *Monitor) AcceptBreak(ctx context.Context, f verify.Finding) (worm.Acceptance, error) {
	// Re-diagnose and require the SAME finding: between the operator reading it and accepting it, a writer
	// with DB access could have changed the trail again, and a blind accept would waive whatever is there now.
	current, err := m.Diagnose(ctx)
	if err != nil {
		return worm.Acceptance{}, err
	}
	if current.Finding == nil {
		return worm.Acceptance{}, errNothingToAccept
	}
	if !sameFinding(*current.Finding, f) {
		return worm.Acceptance{}, fmt.Errorf("monitor: accept: the divergence changed since it was diagnosed "+
			"(reviewed id=%d reason=%s, now id=%d reason=%s); re-run verify and review it again",
			f.DivergentID, f.Reason, current.Finding.DivergentID, current.Finding.Reason)
	}

	// The head the walk resumes from is the row_hash actually stored at the divergent row. Read it from the
	// events themselves, never from audit_chain_head — that row is write-path coordination and is not a trust
	// anchor, so signing it would notarize a value no event proves.
	resume, err := m.resumeHashAt(ctx, f.DivergentID)
	if err != nil {
		return worm.Acceptance{}, err
	}

	sig, keyID, err := m.signer.Sign(sign.AcceptanceDigest(f.DivergentID, f.Reason, f.Expected, f.Actual, resume))
	if err != nil {
		return worm.Acceptance{}, fmt.Errorf("monitor: accept: sign: %w", err)
	}
	rec := worm.Acceptance{
		DivergentID: f.DivergentID,
		Reason:      f.Reason,
		Expected:    hex.EncodeToString(f.Expected),
		Actual:      hex.EncodeToString(f.Actual),
		ResumeHash:  hex.EncodeToString(resume),
		Signature:   base64.StdEncoding.EncodeToString(sig),
		KeyID:       keyID,
	}
	if err := worm.WriteAcceptance(m.store, rec); err != nil {
		return worm.Acceptance{}, err
	}
	m.log.Warn("monitor: chain break ACCEPTED by operator; acceptance recorded off-box",
		"divergent_id", f.DivergentID, "reason", f.Reason)
	return rec, nil
}

// errNothingToAccept means the trail verified clean, so there is no divergence to waive.
var errNothingToAccept = errors.New("monitor: accept: no unaccepted chain break to accept")

// ErrNothingToAccept reports whether err is the no-break-to-accept case, so a caller can treat it as a
// benign outcome rather than a failure.
func ErrNothingToAccept(err error) bool { return errors.Is(err, errNothingToAccept) }

// sameFinding compares two findings by every field that identifies the divergence, so an acceptance can only
// ever be written for the exact divergence that was reviewed.
func sameFinding(a, b verify.Finding) bool {
	return a.DivergentID == b.DivergentID && a.Reason == b.Reason &&
		bytes.Equal(a.Expected, b.Expected) && bytes.Equal(a.Actual, b.Actual)
}

// resumeHashAt returns the row_hash stored at the divergent row — the head a resumed walk continues from.
// A finding derived from an anchor (a witnessed row that no longer exists) has no such row, in which case the
// resume head is the anchor's own witnessed head and the walk simply continues from where it was.
func (m *Monitor) resumeHashAt(ctx context.Context, id int64) ([]byte, error) {
	events, err := m.reader.ChainedEventsAfter(ctx, id-1, 1)
	if err != nil {
		return nil, fmt.Errorf("monitor: accept: read row %d: %w", id, err)
	}
	if len(events) == 1 && events[0].ID == id {
		return events[0].RowHash, nil
	}
	return nil, nil
}

// ResumeCoverage brings the off-box record forward after a break was accepted: it exports the rows that
// accumulated while the monitor was halted, then signs a fresh anchor over the verified head.
//
// Exporting FIRST is the invariant the whole design rests on (exportedThrough >= anchor.UpToID). An anchor
// advanced past un-exported rows would strand them below it forever: every later tail read starts after the
// anchor, so those rows would never reach the SIEM or the anomaly rules. A halted monitor is exactly when a
// backlog accumulates, which makes this the one place that mistake would do the most damage.
func (m *Monitor) ResumeCoverage(ctx context.Context) error {
	if m.halted.Load() {
		return fmt.Errorf("monitor: resume coverage: still halted by an unaccepted break")
	}
	vt, ok, err := m.verifyChain(ctx, m.catchUpBatch)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("monitor: resume coverage: the tail no longer verifies")
	}
	return m.signAnchor(vt.head)
}

// eventsAfter returns the events whose id exceeds afterID. events must be in ascending id order (store
// returns them so); the result shares the input's backing array.
func eventsAfter(events []store.StoredEvent, afterID int64) []store.StoredEvent {
	for i, ev := range events {
		if ev.ID > afterID {
			return events[i:]
		}
	}
	return nil
}

// Run drives Poll on the poll interval, SignHead on the sign interval, and FullVerify on the full-verify
// interval until ctx is canceled. A full re-verification also runs once on boot — before anything is
// advanced — so tampering that happened while the monitor was down is caught first. Every error is logged
// and swallowed so the monitor never couples query availability to itself.
func (m *Monitor) Run(ctx context.Context) error {
	pollTicker := time.NewTicker(m.cfg.PollInterval)
	defer pollTicker.Stop()
	signTicker := time.NewTicker(m.cfg.SignInterval)
	defer signTicker.Stop()
	fullTicker := time.NewTicker(m.fullVerifyInterval())
	defer fullTicker.Stop()

	if err := m.FullVerify(ctx); err != nil {
		m.log.Error("monitor: initial full verify failed", "err", err)
	}
	if err := m.Poll(ctx); err != nil {
		m.log.Error("monitor: initial poll failed", "err", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-pollTicker.C:
			if err := m.Poll(ctx); err != nil {
				m.log.Error("monitor: poll failed", "err", err)
			}
		case <-signTicker.C:
			if err := m.SignHead(ctx); err != nil {
				m.log.Error("monitor: sign failed", "err", err)
			}
		case <-fullTicker.C:
			if err := m.FullVerify(ctx); err != nil {
				m.log.Error("monitor: full verify failed", "err", err)
			}
		}
	}
}

// fullVerifyInterval is the configured full re-verification cadence, defaulting to hourly when unset so the
// ticker is never constructed with a non-positive interval.
func (m *Monitor) fullVerifyInterval() time.Duration {
	if m.cfg.FullVerifyInterval > 0 {
		return m.cfg.FullVerifyInterval
	}
	return time.Hour
}

// exportRecord maps a stored event to its redacted SIEM record, hashing the statement here because worm has
// no statement field (the SQL text is structurally excluded from the off-box store).
func exportRecord(ev store.StoredEvent) worm.ExportRecord {
	sum := sha256.Sum256([]byte(ev.Event.Statement))
	return worm.ExportRecord{
		ID:                 ev.ID,
		Kind:               ev.Event.Kind,
		TSMicros:           ev.Event.TSMicros,
		Principal:          ev.Event.Principal,
		Roles:              ev.Event.Roles,
		Datasource:         ev.Event.Datasource,
		ClientAddr:         ev.Event.ClientAddr,
		Decision:           ev.Event.Decision,
		FailedStage:        ev.Event.FailedStage,
		StatementSHA256:    hex.EncodeToString(sum[:]),
		EffectiveNamespace: ev.Event.EffectiveNamespace,
		MaskedColumns:      ev.Event.MaskedColumns,
		PIITouched:         ev.Event.PIITouched,
		LatencyMs:          ev.Event.LatencyMs,
		Channel:            ev.Event.Channel,
		ContextTags:        ev.Event.ContextTags,
		AuthzAction:        ev.Event.AuthzAction,
		AuthzResource:      ev.Event.AuthzResource,
		Outcome:            ev.Event.Outcome,
		RowsReturned:       ev.Event.RowsReturned,
		BytesReturned:      ev.Event.BytesReturned,
		DecisionID:         ev.Event.DecisionID,
	}
}
