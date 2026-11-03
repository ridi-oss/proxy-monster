package worm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const acceptancePrefix = "acceptances/"

// Acceptance is a signed, permanent record that an operator ACCEPTED a specific chain divergence rather than
// restoring the trail. It waives exactly one divergence, identified down to the bytes that disagreed, so it
// can never be read as blanket permission for a different break.
//
// It is a record ADDED to the store, never a replacement of anything: an acceptance and an anchor are
// different objects under different prefixes, so accepting a break can never overwrite the signed anchor that
// witnessed it. That separation is the point — the anchor is the evidence, and evidence must outlive the
// decision to move on from it.
type Acceptance struct {
	DivergentID int64  `json:"divergent_id"`
	Reason      string `json:"reason"`
	Expected    string `json:"expected"` // hex; the hash the chain should have had
	Actual      string `json:"actual"`   // hex; the hash it actually had
	// ResumeHash is the head the walk adopts to continue PAST this divergence: the row_hash actually stored at
	// DivergentID. Verification needs it to keep checking rows above an accepted break instead of stopping at
	// it forever — an accepted break must not blind the monitor to later tampering.
	ResumeHash string `json:"resume_hash"`
	Signature  string `json:"signature"` // base64 over sign.AcceptanceDigest
	KeyID      string `json:"key_id"`
}

// AcceptanceKey is the object key an acceptance is stored under: acceptances/<divergent_id>-<digest>.json,
// where digest is derived from the full signed content. Two acceptances of genuinely different divergences
// therefore land on different keys and both survive, and re-accepting the identical divergence is idempotent
// (same key, same bytes) rather than destructive. Nothing under acceptances/ can ever collide with a
// checkpoints/ anchor key.
func AcceptanceKey(a Acceptance) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		a.Reason, a.Expected, a.Actual, a.ResumeHash, a.Signature,
	}, "\x00")))
	return fmt.Sprintf("%s%d-%s.json", acceptancePrefix, a.DivergentID, hex.EncodeToString(sum[:8]))
}

// WriteAcceptance appends a signed acceptance. It never writes to an existing anchor key, and its own key is
// content-derived, so it cannot overwrite a different acceptance either.
func WriteAcceptance(os ObjectStore, a Acceptance) error {
	body, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("worm: marshal acceptance: %w", err)
	}
	return os.Put(AcceptanceKey(a), body)
}

// ReadAcceptances returns every parseable acceptance under acceptances/, ascending by divergent id. As with
// anchors, an unparseable object is skipped rather than fatal: a single junk object (undeletable under
// Object-Lock) must never wedge the monitor. Signature validity is NOT judged here — that needs the signer,
// so the caller verifies each one before honoring it.
func ReadAcceptances(os ObjectStore) ([]Acceptance, error) {
	return NewReader(os).Acceptances()
}
