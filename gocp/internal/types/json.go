package types

import (
	"bytes"
	"encoding/json"
)

// MarshalWire is the port's analogue of the application-wide Kotlin `Json` instance configured at
// App.kt:340 — `Json { ignoreUnknownKeys = true; encodeDefaults = true; explicitNulls = false }`
// (INV-A1-4). Every HTTP response body the control plane writes MUST go through this, not through a
// bare json.Marshal, for two reasons:
//
//  1. HTML escaping. encoding/json rewrites '<', '>' and '&' as <, >, & by default;
//     kotlinx.serialization does not. Semantically the two are the same JSON, but the bytes differ,
//     and `statement` on an AuditEvent is raw SQL — `WHERE a < 5 AND b > 3` is escaped on essentially
//     every comparison predicate the product exists to inspect. Byte-identical output is what keeps a
//     Kotlin↔Go diff during cutover readable, and it is free.
//     Unverified: kotlinx's non-escaping of '<'/'>'/'&' is reasoned from its escape table, not
//     measured — there is no JVM/kotlinx toolchain on this box (`gradle not found`, no ~/.gradle).
//     TODO(A1): confirm against a running Kotlin control plane during cutover.
//  2. It is the single seam where the two INV-A1-4 rules can be enforced for types that do not carry
//     their own MarshalJSON.
//
// A custom MarshalJSON on a nested type CANNOT defeat the escaping on its own: encoding/json runs
// compact(escapeHTML) over whatever a Marshaler returns, so the outer encoder always has the last
// word. That is why this is a top-level helper rather than a per-type detail.
//
// The trailing newline json.Encoder.Encode appends is stripped — a response body has none.
func MarshalWire(v any) ([]byte, error) { return marshalJSON(v, false) }

// Ptr returns a pointer to v. INV-A1-4 makes *T the representation of every optional field in the
// port, so building one inline — Ptr("wire"), Ptr(int64(42)) — is the single most repeated expression
// in the whole DTO layer. Kotlin needs no equivalent because a nullable there is just a value.
func Ptr[T any](v T) *T { return &v }

// marshalJSON encodes v with HTML escaping under the caller's control. escapeHTML=true reproduces
// encoding/json's default; false reproduces kotlinx's.
func marshalJSON(v any, escapeHTML bool) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(escapeHTML)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
