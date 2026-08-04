package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/ridi-oss/proxy-monster/analyzer/probe"
)

// Dialect-aware SQL canonicalization for one-time query-grant hashing.
//
// ⚠️ F21 (index F79) — THIS WHOLE SUB-AREA IS PRODUCTION-DEAD. No control-plane, goproxy, pmon or
// auditmon caller exists for either function; the only production Dialect reference is an UNUSED LOCAL
// (Query.kt:308); and the sql_hash actually persisted on query_result is a RAW SHA-256 of the SQL bytes
// (Access.kt:127-129), never compared to anything. So the canonical-token grant hash this file describes
// is not wired to any grant decision, and 24 of the area's 56 test cases pin behaviour nothing consumes.
//
// Disposition is DEFER, not OMIT (13-engine.md Q4): the sub-area is production-dead but its 260 LOC of
// test are live, and a 24-case suite is not "dead code with no observable behaviour". Only an explicit
// "the one-time query grant is not being built" turns dropping this file AND its suite into a legitimate
// OMIT. Until then it is REPRODUCE, test surface included. Do not resolve F21 inside the port.
//
// The security contract, quoted from SqlNormalize.kt:8-16: "token-sequence equality with byte-exact
// literals: equivalent statements may differ only in canonical whitespace, comments, keyword case, and
// dialect-safe identifier case. Material differences in tables, columns, operators, literals, numbers, or
// quoted identifiers must remain distinct. … Invalid or unsupported input and every native load,
// descriptor, encoding, or invocation failure return null so grant decisions fail closed."
//
// Whose behaviour is this, actually? Almost none of it is Kotlin's. The Kotlin file is 34 lines of dialect
// string mapping + try/catch + SHA-256; every assertion in the 24-case suite is a property of
// analyzer/probe/sqlnormalize.go, which this now calls directly.

// Dialect ports `enum class Dialect { MYSQL, POSTGRES }`. Two values, no properties. A5's Engines.kt maps
// Engine → Dialect and error()s for ENGINE_UNSPECIFIED; that mapping is A5's, not this area's.
//
// This is the CANONICAL home. internal/datasource declared a temporary copy while A13 was unported, with
// its own TODO saying "move it and alias, do not fork it" — that alias is now available and is recorded in
// this increment's todos. The String() rendering below matches that copy's byte-for-byte so aliasing is
// seamless.
type Dialect int

const (
	// DialectMySQL is Dialect.MYSQL.
	DialectMySQL Dialect = iota
	// DialectPostgres is Dialect.POSTGRES.
	DialectPostgres
)

// String renders the Kotlin enum constant name, which the test suite's assertion messages interpolate.
func (d Dialect) String() string {
	switch d {
	case DialectMySQL:
		return "MYSQL"
	case DialectPostgres:
		return "POSTGRES"
	default:
		return fmt.Sprintf("Dialect(%d)", int(d))
	}
}

// probeName maps the enum to the probe's dialect string. Kotlin's `when` is exhaustive over the two
// values; an out-of-range Dialect here yields "", which probe.SqlNormalize rejects (its first guard is
// `dialect != "mysql" && dialect != "postgres"`) — i.e. fail-closed, the same direction as the Kotlin
// catch.
func (d Dialect) probeName() string {
	switch d {
	case DialectMySQL:
		return "mysql"
	case DialectPostgres:
		return "postgres"
	default:
		return ""
	}
}

// NormalizeSQL normalizes sql under dialect to its canonical token string; ok=false on any failure.
//
// 🔒 INV-A13-10 — EVERY failure yields "not ok", never a partially-normalized string. A salvaged
// canonicalization of unlexable input would let two materially different statements hash equal, which on
// a grant-matching path is a WRONG-GRANT. Fail-closed = absent = the caller refuses.
//
// INV-A13-11 — raw lexeme spellings are preserved BYTE-EXACTLY. The probe selects raw lexemes from the
// source (analyzer/probe/sqlnormalize.go slices the original runes between tokens), so decoded-equivalent
// literals stay distinct: 'a\'b' ≠ 'a”b', E'a\nb' ≠ E'a\012b', 1 ≠ 01, 0xAB ≠ 0xab, "Name" ≠ "name".
//
// The Kotlin's `catch (_: Throwable) -> null` has no Go analogue to write: probe.SqlNormalize is itself
// total (it recovers its own panics and returns ok=false), so the fail-closed guarantee moved into the
// callee rather than disappearing.
func NormalizeSQL(sql string, dialect Dialect) (string, bool) {
	return probe.SqlNormalize(sql, dialect.probeName())
}

// SQLGrantHash is the SHA-256 hex of NormalizeSQL's output; ok=false when the SQL cannot be normalized
// (fail-closed at the caller).
//
// INV-A13-12 — the hash is EXACTLY 64 lowercase hex characters, or absent. The absence propagates from
// NormalizeSQL unchanged: never an empty string, never a hash of "". Kotlin formats with "%02x" and Go's
// hex encoder emits lowercase, so the two agree byte-for-byte.
func SQLGrantHash(sql string, dialect Dialect) (string, bool) {
	norm, ok := NormalizeSQL(sql, dialect)
	if !ok {
		return "", false
	}
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:]), true
}
