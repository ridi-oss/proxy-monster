package result

import (
	"bytes"
	"encoding/json"
	"sync"
)

// QueryResultMeta is the child row's metadata as the wire sees it (QueryResultStore.kt:15-25;
// 07-tasks-approvals-results.md §2). Every timestamp is a Java Instant.toString() string — see
// internal/instant.
//
// INV-A1-4: an optional Kotlin field is *T + omitempty, so an unset one is ABSENT from the JSON
// rather than null; `columns` is a non-null `List<String> = emptyList()`, so it carries no omitempty
// and is normalised to [] by MarshalJSON.
type QueryResultMeta struct {
	TaskID     int64    `json:"taskId"`
	ExecutedBy *string  `json:"executedBy,omitempty"`
	ExecutedAt *string  `json:"executedAt,omitempty"`
	RowCount   *int     `json:"rowCount,omitempty"`
	ExpiresAt  *string  `json:"expiresAt,omitempty"`
	Status     *string  `json:"status,omitempty"`
	ErrorCode  *string  `json:"errorCode,omitempty"`
	Columns    []string `json:"columns"`
}

type queryResultMetaJSON QueryResultMeta

// MarshalJSON normalises the nil `columns` slice to [] (INV-A1-4 rule 2). A nil slice is a Go
// artifact with no Kotlin counterpart, so removing it REPRODUCES emptyList() rather than changing
// anything.
func (m QueryResultMeta) MarshalJSON() ([]byte, error) {
	v := queryResultMetaJSON(m)
	if v.Columns == nil {
		v.Columns = []string{}
	}
	return marshalNoEscape(v)
}

// DecryptedResult is the payload that gets encrypted: the released columns and rows
// (QueryResultStore.kt:28). A cell is `String?` — NULL survives the round trip as a JSON null, which
// is why the Go type is [][]*string and not [][]string.
type DecryptedResult struct {
	Columns []string    `json:"columns"`
	Rows    [][]*string `json:"rows"`
}

type decryptedResultJSON DecryptedResult

// MarshalJSON keeps both lists as arrays. This one is load-bearing beyond the wire: the marshalled
// bytes ARE the ciphertext's plaintext, and Kotlin's `DecryptedResult` declares both fields
// non-nullable, so a blob written by Go with `"rows":null` would fail to decode in a Kotlin instance
// during a rolling cutover.
func (r DecryptedResult) MarshalJSON() ([]byte, error) {
	v := decryptedResultJSON(r)
	if v.Columns == nil {
		v.Columns = []string{}
	}
	if v.Rows == nil {
		v.Rows = [][]*string{}
	}
	return marshalNoEscape(v)
}

// ResultAccess is a single-read snapshot of a task's latest result child: its Meta, the child's own
// SQL (the exact statement that produced the ciphertext), plus a payload decrypted LAZILY
// (QueryResultStore.kt:31-42).
//
// 🔒 INV-A7-9, two distinct properties:
//
//   - Lazy decrypt. A caller that rejects on Meta alone — an unauthorized viewer, a not-ready status
//     — never triggers a decrypt. Kotlin gets this from `by lazy`; Go gets it from sync.Once behind
//     [ResultAccess.Decrypted].
//   - One read. Meta, SQL and the ciphertext come from ONE row read in [Store.AccessFor], so a
//     concurrent re-execute cannot swap the row between the authorization check on Meta and the
//     decrypt (TOCTOU).
//
// Reading SQL from the SAME row as the ciphertext binds the view's re-decision to the released bytes;
// the task's first-child SQL diverges once a task holds plural children (QueryResultStoreDbTest 7).
//
// ⚠️ Deviation, language-forced: Kotlin's `by lazy` does not cache a thrown initializer, so a second
// read re-runs it; sync.Once caches the error and returns the same one. Unobservable to the routes —
// a failed decrypt is a 500 either way — and re-running an authenticated-decrypt failure would only
// repeat it.
type ResultAccess struct {
	Meta QueryResultMeta
	// SQL is the released child's own `sql` column. Nullable: a child seeded without one (a WIRE
	// task has no child at all, but a test can seed a bare row) reads null.
	SQL *string

	once      sync.Once
	decrypt   func() (*DecryptedResult, error)
	decrypted *DecryptedResult
	err       error
}

// Decrypted runs the deferred decrypt at most once and returns its result. It is nil, with no error,
// whenever [Store.AccessFor] captured no payload — a not-ready, expired or already-purged child —
// so the route surfaces 409/410 rather than any bytes.
func (a *ResultAccess) Decrypted() (*DecryptedResult, error) {
	a.once.Do(func() { a.decrypted, a.err = a.decrypt() })
	return a.decrypted, a.err
}

// marshalNoEscape encodes without encoding/json's HTML escaping, which kotlinx does not perform.
// Result columns and SQL are user data — `WHERE a < 5` is escaped by the stdlib default — and
// types.MarshalWire (the response encoder) turns escaping off at the outer level, so an inner
// Marshaler that escaped would leak < into an otherwise unescaped body.
//
// ⚠️ This is a copy of internal/types' unexported marshalJSON. It is duplicated rather than exported
// from there so this package does not edit one another area is concurrently porting; TODO: collapse
// the two once the DTO packages settle.
func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
