// Package verify re-walks the committed hash chain and reports the first divergence. It recomputes every
// row_hash from the stored event and checks that each row's prev_hash equals the running head, so any
// modification, deletion, or reordering of a historical row surfaces as a finding.
package verify

import (
	"bytes"
	"context"
	"fmt"

	"github.com/ridi-oss/proxy-monster/auditmon/canon"
	"github.com/ridi-oss/proxy-monster/auditmon/store"
)

// Finding is the first point at which the chain diverges from what the events prove. Expected and Actual
// carry the two hashes that disagree (their meaning depends on Reason).
type Finding struct {
	DivergentID int64
	Reason      string
	Expected    []byte
	Actual      []byte
}

// Reasons a verification can diverge.
const (
	ReasonPrevHashMismatch    = "prev_hash_mismatch"
	ReasonRowHashMismatch     = "row_hash_mismatch"
	ReasonMissingChainVersion = "missing_chain_version"
	// ReasonAnchorHeadMismatch: the head recomputed at a signed anchor's up_to_id differs from the head_hash
	// that anchor witnessed. This is what catches an internally-consistent rewrite from genesis (every
	// row_hash recomputed) that the row-walk alone cannot — the off-box signed anchor is the external witness.
	ReasonAnchorHeadMismatch = "anchor_head_mismatch"
	// ReasonAnchorRowMissing: a signed anchor witnessed an up_to_id the chain no longer reaches, i.e. rows at
	// or below an anchored head were deleted/truncated.
	ReasonAnchorRowMissing = "anchor_row_missing"
)

// VerifyTail walks events (in id order) starting from head, recomputing each row_hash. It returns the first
// Finding, or (nil, nil) if the segment is intact. A non-nil error is an internal problem (e.g. a bad
// stored hash length), not a tamper finding.
func VerifyTail(head store.ChainHead, events []store.StoredEvent) (*Finding, error) {
	running := head.HeadHash
	for _, ev := range events {
		if !bytes.Equal(ev.PrevHash, running) {
			return &Finding{DivergentID: ev.ID, Reason: ReasonPrevHashMismatch, Expected: running, Actual: ev.PrevHash}, nil
		}
		// A chained tail row must carry its version; a NULL here is a pre-chain row appearing after an
		// anchored head, which is itself anomalous (fail closed rather than skip).
		if ev.ChainVersion == nil {
			return &Finding{DivergentID: ev.ID, Reason: ReasonMissingChainVersion}, nil
		}
		recomputed, err := canon.RowHash(ev.ID, ev.Event, uint32(*ev.ChainVersion), ev.PrevHash)
		if err != nil {
			return nil, fmt.Errorf("verify: recompute row %d: %w", ev.ID, err)
		}
		if !bytes.Equal(recomputed, ev.RowHash) {
			return &Finding{DivergentID: ev.ID, Reason: ReasonRowHashMismatch, Expected: ev.RowHash, Actual: recomputed}, nil
		}
		running = ev.RowHash
	}
	return nil, nil
}

// ChainedEventSource is the paging read side VerifyFromGenesis walks: chained rows only (chain_version IS
// NOT NULL), in id order, at most limit per call. Satisfied by *store.Reader.
type ChainedEventSource interface {
	ChainedEventsAfter(ctx context.Context, afterID int64, limit int) ([]store.StoredEvent, error)
}

// pageSize bounds each read of the from-genesis walk, so peak memory depends on the page, not on how long
// the trail is.
const pageSize = 5000

// AnchorCheck is a signed off-box witness to cross-check the walk against: the head_hash a valid anchor
// recorded at UpToID. A recomputed head that no longer matches, or an UpToID the chain no longer reaches,
// is a finding.
type AnchorCheck struct {
	UpToID   int64
	HeadHash []byte
}

// Accepted is a divergence an operator has explicitly waived, bound to the exact bytes that disagreed. The
// walk reports it (so it stays visible forever) but does not stop there: it adopts ResumeHash as the running
// head and keeps verifying, so tampering ABOVE an accepted break is still caught. Without that, one accepted
// break would permanently blind full verification to everything after it — the tail walk never looks below
// its anchor, and the full walk would stop at the old break every time.
type Accepted struct {
	DivergentID int64
	Reason      string
	Expected    []byte
	Actual      []byte
	// ResumeHash is the head the walk continues from: the row_hash actually stored at DivergentID.
	ResumeHash []byte
}

// covers reports whether this acceptance waives exactly the divergence f describes. Every field must match:
// an acceptance of one row's edit must never waive a different edit to the same row, so a second tamper at an
// already-accepted id still halts the monitor.
func (a Accepted) covers(f Finding) bool {
	return a.DivergentID == f.DivergentID &&
		a.Reason == f.Reason &&
		bytes.Equal(a.Expected, f.Expected) &&
		bytes.Equal(a.Actual, f.Actual)
}

// VerifyFromGenesis walks the entire chained trail from the pinned genesis, paging through src, recomputing
// every row_hash and checking each prev_hash linkage — so it catches a retroactive edit to an
// already-anchored row that an incremental tail-only verify would miss. It also cross-checks the recomputed
// head at each supplied anchor's up_to_id against that anchor's witnessed head_hash: a divergence there
// catches an internally-consistent full rewrite from genesis, which the row-walk alone cannot. anchors may
// be nil (row-walk only).
//
// It returns the first divergence NOT covered by an accepted waiver. Accepted divergences are collected into
// the returned Findings so callers still see them, while the walk continues past each one.
func VerifyFromGenesis(ctx context.Context, src ChainedEventSource, genesis []byte, anchors []AnchorCheck) (*Finding, error) {
	f, _, err := VerifyFromGenesisAccepting(ctx, src, genesis, anchors, nil)
	return f, err
}

// VerifyFromGenesisAccepting is VerifyFromGenesis with operator-accepted divergences honored. It returns the
// first UNaccepted finding (nil if none) plus every accepted divergence the walk passed through, so an
// accepted break stays reportable rather than becoming invisible.
func VerifyFromGenesisAccepting(ctx context.Context, src ChainedEventSource, genesis []byte, anchors []AnchorCheck, accepted []Accepted) (*Finding, []Finding, error) {
	// remaining maps an anchored up_to_id still to be reached to the head it witnessed. up_to_id 0 (the
	// genesis-only initial anchor) needs no row cross-check — its head is the genesis by construction.
	remaining := make(map[int64][]byte, len(anchors))
	for _, a := range anchors {
		if a.UpToID > 0 {
			remaining[a.UpToID] = a.HeadHash
		}
	}

	// waive reports whether f is covered by an acceptance, and if so the head to resume the walk from.
	waive := func(f Finding) ([]byte, bool) {
		for _, a := range accepted {
			if a.covers(f) {
				return a.ResumeHash, true
			}
		}
		return nil, false
	}

	var passed []Finding
	head := store.ChainHead{LastID: 0, HeadHash: genesis}
	cursor := int64(0)
	for {
		events, err := src.ChainedEventsAfter(ctx, cursor, pageSize)
		if err != nil {
			return nil, nil, fmt.Errorf("verify: read chained tail after %d: %w", cursor, err)
		}
		if len(events) == 0 {
			break
		}
		// Walk this page, honoring acceptances: an accepted divergence is recorded and stepped over (resuming
		// from the head the operator accepted), so verification continues to the rows above it.
		for i := 0; i < len(events); {
			f, err := VerifyTail(head, events[i:])
			if err != nil {
				return nil, nil, err
			}
			if f == nil {
				break
			}
			resume, ok := waive(*f)
			if !ok {
				return f, passed, nil
			}
			passed = append(passed, *f)
			at := indexOfID(events, f.DivergentID)
			if at < 0 {
				// The finding names a row not in this page (anchor-derived): it cannot be stepped over here.
				return f, passed, nil
			}
			// A waiver covers the divergence it names and nothing more. The row-walk reports a broken LINK
			// before it ever recomputes the row's content hash, so stepping straight past the row would leave
			// that row's contents unverified forever — turning an accepted deletion into a standing licence to
			// rewrite the row that followed it. Re-check the content here, against the accepted predecessor.
			if f.Reason == ReasonPrevHashMismatch {
				ev := events[at]
				if cf, err := verifyRowContent(ev); err != nil {
					return nil, nil, err
				} else if cf != nil {
					if _, ok := waive(*cf); !ok {
						return cf, passed, nil
					}
					passed = append(passed, *cf)
				}
			}
			// Resume immediately after the accepted row, with the accepted head as the running head.
			head = store.ChainHead{LastID: f.DivergentID, HeadHash: resume}
			i = at + 1
		}
		// The rows this page proved intact let each anchored up_to_id be cross-checked against its witnessed
		// head. Rows at or below an accepted divergence are excluded: their recomputed head is by definition
		// the accepted one, so cross-checking them would re-report the same waived break.
		for _, ev := range events {
			want, ok := remaining[ev.ID]
			if !ok {
				continue
			}
			if !bytes.Equal(ev.RowHash, want) {
				f := Finding{DivergentID: ev.ID, Reason: ReasonAnchorHeadMismatch, Expected: want, Actual: ev.RowHash}
				if _, ok := waive(f); !ok {
					return &f, passed, nil
				}
				passed = append(passed, f)
			}
			delete(remaining, ev.ID)
		}
		last := events[len(events)-1]
		head = store.ChainHead{LastID: last.ID, HeadHash: last.RowHash}
		cursor = last.ID
	}

	// Any anchored up_to_id the walk never reached means rows at/below a witnessed head are gone. Report the
	// lowest such id for a stable finding.
	if len(remaining) > 0 {
		var lowest int64
		first := true
		for id := range remaining {
			if first || id < lowest {
				lowest, first = id, false
			}
		}
		// Actual records the head the walk actually reached. Without it the finding would be identical however
		// much of the trail is gone — the anchor id and the head it witnessed are fixed — so accepting one
		// truncation would silently waive every deeper truncation afterwards. Binding where the chain now ends
		// makes a further deletion a DIFFERENT divergence, which no existing acceptance covers.
		f := Finding{DivergentID: lowest, Reason: ReasonAnchorRowMissing, Expected: remaining[lowest], Actual: head.HeadHash}
		if _, ok := waive(f); !ok {
			return &f, passed, nil
		}
		passed = append(passed, f)
	}
	return nil, passed, nil
}

// verifyRowContent recomputes one row's hash from its own stored fields and reports a finding if the stored
// row_hash disagrees. It judges the row's CONTENT only — the link to its predecessor is a separate question —
// so it can be used to keep checking a row whose link mismatch an operator has waived.
func verifyRowContent(ev store.StoredEvent) (*Finding, error) {
	if ev.ChainVersion == nil {
		return &Finding{DivergentID: ev.ID, Reason: ReasonMissingChainVersion}, nil
	}
	recomputed, err := canon.RowHash(ev.ID, ev.Event, uint32(*ev.ChainVersion), ev.PrevHash)
	if err != nil {
		return nil, fmt.Errorf("verify: recompute row %d: %w", ev.ID, err)
	}
	if !bytes.Equal(recomputed, ev.RowHash) {
		return &Finding{DivergentID: ev.ID, Reason: ReasonRowHashMismatch, Expected: ev.RowHash, Actual: recomputed}, nil
	}
	return nil, nil
}

// indexOfID returns the position of the row with the given id, or -1.
func indexOfID(events []store.StoredEvent, id int64) int {
	for i, ev := range events {
		if ev.ID == id {
			return i
		}
	}
	return -1
}
