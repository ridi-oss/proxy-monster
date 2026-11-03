// Package worm is the write-once off-box object store that holds the trail's authority: signed checkpoint
// anchors and the redacted event batches the SIEM ingests. The store is the sole authority (never the DB,
// which shares the attacker's trust boundary). The exported record type deliberately omits the statement
// text so a SQL literal can never reach the permanent store.
package worm

import "errors"

// ObjectStore is the minimal object API the monitor needs. The production impl is an S3-compatible
// Object-Lock bucket (compliance mode); tests use an in-memory fake.
//
// Get must return an error wrapping ErrNotFound when — and only when — the object genuinely does not exist.
// Callers distinguish "absent" from "could not read" to decide whether it is safe to write: treating a
// transport or permission failure as absence would let a write proceed over evidence the caller never saw.
type ObjectStore interface {
	Put(key string, body []byte) error
	List(prefix string) ([]string, error)
	ListObjects(prefix string) ([]ObjectInfo, error)
	Get(key string) ([]byte, error)
}

type ObjectInfo struct {
	Key     string
	Version string
}

// ErrNotFound reports that an object does not exist, as distinct from being unreadable.
var ErrNotFound = errors.New("worm: object not found")
