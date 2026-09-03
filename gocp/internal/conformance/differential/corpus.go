// Package differential is the two-implementation harness: replay one request corpus against BOTH the
// Kotlin control-plane and the Go control-plane, then diff the answers.
//
// WHY THIS EXISTS, and why the traceability count does not make it redundant. Every other test
// in this series asserts the Go control-plane against a TRANSCRIPTION — someone read the Kotlin, wrote
// down what they believed it asserted, and checked Go against that. A misreading of the Kotlin becomes
// a Go test that encodes the misreading and passes. The two implementations have never been compared to
// each other, so "1:1" is currently a claim about test bookkeeping, not a measurement of behaviour.
//
// This harness is the measurement. It cannot be fooled by a misread spec, because neither side is the
// spec: the Kotlin's own response IS the oracle.
//
// 🔒 WHAT IT MUST NOT DO: normalise away a real difference. The normaliser below is the only place a
// divergence can be hidden, so every rule in it is justified at its definition and scoped as narrowly
// as the field allows. A rule like "ignore all numbers" would make the harness green and worthless.
package differential

import "net/http"

// Case is one request replayed against both control-planes.
type Case struct {
	// Name is the diff report's label.
	Name string
	// Method / Path are sent verbatim to both.
	Method string
	Path   string
	// Body is a JSON request body; empty sends none.
	Body string
	// Authed sends the debug-login session cookie. Cases that assert the UNAUTHENTICATED shape leave it
	// false, which is a distinct and equally important comparison.
	Authed bool
	// WantDivergence marks a case where the two are KNOWN to differ, with the reason. The harness then
	// FAILS IF THEY AGREE — so a documented divergence that gets fixed cannot silently stay documented.
	WantDivergence string
}

// Corpus is the replay set. It GROWS with each ported slice: a PR adds the cases for the routes it
// brings over, and the gate is that every case in the corpus agrees. That is what stops a later slice
// from silently regressing an earlier one — the set only ever gets bigger.
//
// ⚠️ This slice ports no routes, so the corpus holds only the liveness probe and the harness cannot
// yet demonstrate equivalence of anything. The non-vacuity check in normalize_test.go is the real
// assertion here; the replay becomes meaningful in the slice that ports the HTTP surface.
var Corpus = []Case{
	{Name: "health", Method: http.MethodGet, Path: "/health"},
}
