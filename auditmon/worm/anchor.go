package worm

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const checkpointPrefix = "checkpoints/"

// Anchor is a signed off-box witness of the chain head up to UpToID. HeadHash is hex; Signature is base64.
type Anchor struct {
	UpToID    int64  `json:"up_to_id"`
	HeadHash  string `json:"head_hash"`
	Signature string `json:"signature"`
	KeyID     string `json:"key_id"`
}

// WriteAnchor stores a at checkpoints/<up_to_id>.json.
//
// It REFUSES to replace an existing anchor at that id with a different head. An anchor is the monitor's
// off-box witness, and for an internally-consistent rewrite from genesis it is the ONLY evidence that the
// trail changed — the row-walk alone comes back clean. Overwriting it would replace that evidence with a
// signature over whatever the trail says now, which is precisely how a rewrite gets laundered under the
// monitor's own key. One object per id is the storage model, so a differing head at an id that already has a
// witness is a conflict to report, never a write to perform.
//
// Re-writing the IDENTICAL anchor is allowed and is a no-op in effect: a monitor that signs the same head
// twice (a poll and a sign tick at an unchanged head) must not fail.
func WriteAnchor(os ObjectStore, a Anchor) error {
	body, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("worm: marshal anchor: %w", err)
	}
	key := checkpointPrefix + strconv.FormatInt(a.UpToID, 10) + ".json"
	existing, err := os.Get(key)
	switch {
	case err == nil:
		var prior Anchor
		if uerr := json.Unmarshal(existing, &prior); uerr != nil {
			// An UNPARSEABLE object here is not proof that no witness exists. On a versioned bucket a writer
			// can put junk over a real anchor: the retained version still holds the evidence, but every read
			// path here sees only the current version. Replacing the junk would then sign a fresh head over a
			// key whose real witness is invisible — laundering, with an extra step. Refuse and let a human look.
			return fmt.Errorf("worm: refusing to write the anchor at up_to_id %d: the object already there is "+
				"not a readable anchor, which may be concealing a retained witness rather than meaning none "+
				"exists: %w", a.UpToID, uerr)
		}
		if prior.HeadHash != a.HeadHash {
			return fmt.Errorf("worm: refusing to overwrite the anchor at up_to_id %d: it witnesses head %s, "+
				"not %s — a differing anchor at the same id would destroy the only off-box evidence that the "+
				"trail changed", a.UpToID, prior.HeadHash, a.HeadHash)
		}
	case errors.Is(err, ErrNotFound):
		// Nothing there: no witness to protect.
	default:
		// The object could not be READ, which is not the same as absent. Writing now could destroy a witness
		// this call never got to see, so fail closed and let the caller retry — a missed anchor is recoverable,
		// an overwritten one is not.
		return fmt.Errorf("worm: refusing to write the anchor at up_to_id %d: cannot read what is already "+
			"there, so an existing witness could be destroyed: %w", a.UpToID, err)
	}
	return os.Put(key, body)
}

// ReadAnchors returns every parseable anchor object under checkpoints/, ascending by up_to_id. Objects whose
// key is not a checkpoint id or whose body is not a valid Anchor are skipped, not failed: a single junk
// object (undeletable under Object-Lock) must never wedge the monitor. Signature validity is NOT judged here
// — that needs the signer, so the caller selects the highest VALID anchor.
func ReadAnchors(os ObjectStore) ([]Anchor, error) {
	return NewReader(os).Anchors()
}

func parseCheckpointID(key string) (int64, bool) {
	rest, ok := strings.CutPrefix(key, checkpointPrefix)
	if !ok {
		return 0, false
	}
	rest, ok = strings.CutSuffix(rest, ".json")
	if !ok {
		return 0, false
	}
	id, err := strconv.ParseInt(rest, 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}
