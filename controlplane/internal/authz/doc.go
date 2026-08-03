// Package authz is the authorization boundary (docs/authz-model.md). Cedar, the schema, entity
// marshalling and the policy store all stay INTERNAL to this package; consumers see only the
// authorize* surface and the two route gates.
//
// Area doc: plans/proxy-monster-go-port/02-authz.md. Spike: 98-cedar-spike-report.md.
// Kotlin sources: authz/Authz.kt (915) · authz/CedarEngine.kt (217) · authz/CedarPolicyStore.kt (320).
//
// It owns the 24-value action vocabulary, resource → Cedar-entity marshalling, the per-column /
// table / function / utility batch decisions, the two-pass derived-tag mechanism, policy CRUD with
// validate-on-write, and the compiled-PolicySet cache.
//
// This is the HIGHEST-RISK area in the port: everything here is a security control, and it is the only
// area whose behaviour depends on a third-party policy engine whose Go implementation is not
// feature-matched with the JVM one (02-authz.md §7).
//
// # Engine (D5)
//
// cedar-go v1.8.0, EXACT (not a range), in-process. cedar-go's own x/exp subtree — the directory inside
// the module that its README exempts from semantic versioning, NOT the separate golang.org/x/exp module
// — is firewalled into the xschema package so the unstable API surface has a single blast radius
// (firewall_test.go enforces it). The CI fingerprint gate 56af35d135a2649d975c9674 must cover decisions
// too, since cedar.Authorize reaches x/exp/ast transitively.
//
// Two required mappings, recorded as CORRECTNESS CONSTRAINTS and not preferences. Both fail OPEN if
// they are got wrong.
//
// 1. ERRORS-FIRST. cedar-go's Diagnostic.Errors is per-policy and NON-FATAL, so cedar-go can return
// Allow AND an error simultaneously — a state cedar-java's present-or-absent success payload cannot
// express. Replayed against the SHIPPED policy set with the Request entity omitted, the
// system:no-self-approval FORBID (-2) errors out, cedar-go drops it, and the system:admin PERMIT (-3)
// stands: verdict-first therefore lets a system-admin approve their own request, exactly the hole
// AuthzTest case 6 exists to close. RULE: any len(Diagnostic.Errors) > 0 means DENY, applied in
// toAuthzDecision, at all five batch call sites (Authz.kt:525, 603, 672, 737, 825) and in
// resolveContextTags (INV-A2-13). No Kotlin test pins this, so it is REPRODUCE + PIN — write the test.
//
// 2. TWO-STAGE IP CHECK. Keep the L1 charset allowlist and the '/' range guard BEFORE
// types.ParseIPAddr. Faithful = 16/16 of DebugRequesterIpDbTest.kt:156-195; naive (delegate wholly to
// ParseIPAddr) = 15/16, failing on 100.100.1.0/24, which ParseIPAddr accepts as an ipaddr value and
// the Kotlin allowlist rejects. The one place Go's parser is LAXER is exactly where the allowlist is
// load-bearing, so "Go is stricter, collapse the layers" is wrong. Corollaries: evaluatesInCedar
// collapses to types.ParseIPAddr (its probe request matches no policy scope, so len(Errors) == 0 for
// every parseable IP); and NEVER persist IPAddr.String() — it is not round-trip safe for v4-mapped v6.
//
// Three further build constraints from the spike: cache the RESOLVED schema, not the AST; schemaFor
// stays TEXT concatenation and does NOT become an AST merge (the AST path removes the
// malformed-declaration rejection, which is observable); and reject multi-statement policy source
// explicitly, because UnmarshalCedar silently keeps statement 1 and would drop a forbid. W2 requires
// that last one in TWO places — CedarSchema.Validate (the write path) and CedarEngine.snapshot (the
// policy-LOAD path). Validate alone is not enough: an out-of-band edit to the `policy` table reaches the
// rebuild without revalidation, and there the dropped forbid is silent.
//
// # Schema
//
// schema.cedarschema is embedded (see schema.go) byte-for-byte from
// control-plane/src/main/resources/authz/schema.cedarschema. Entity types: System, Role, Group,
// Datasource, Table, Column, Tag, Function, Utility, User, Request, AccessGrant, Token, AuditRecord,
// AuditLog. Tag is a LEAF ENTITY TYPE holding freeform labels ("pii", system:*) — it is NOT Cedar's
// entity-tags language feature (verified: no getTag/hasTag anywhere in control-plane/src or
// engine/src), so cedar-go needs no entity-tag support. ipaddr is the only Cedar extension type used:
// no decimal, no datetime, no duration.
//
// # What has landed
//
//	action.go       the 24-value AuthzAction vocabulary (§2)
//	resource.go     AuthzResource's 6 variants + marshalResource, the EUID contract table (§3)
//	refs.go         ColumnRef / TableRef / FunctionRef / UtilityRef and their verdict enums (§4)
//	context.go      AuthzContext + ToCedarMap, AuthzDecision, RoleSource (§6)
//	entities.go     tag type-scoping (§5), the first-wins dedupe, the two delimiter guards
//	cedarschema.go  CedarSchema: schemaFor, validate, tag extraction, the dangling-tag lint (§7)
//	engine.go       CedarEngine: the version-gated PolicySet + vocabulary cache (§7)
//	authz.go        the whole authorize* surface, the batch paths, the two-pass tag mechanism
//	xschema/        the firewall — the ONLY package importing cedar-go's x/exp subtree (D5)
//
// Tests: the 53 no-DB cases of §10 (AuthzTest 14, AuthzDatasourceActionTest 6, ColumnAuthzTest 11,
// AdminGateTest 2, ChannelContextAuthzTest 4, ElevationContextTagTest 7, TagResolutionTest 9), plus the
// REPRODUCE + PIN assertions the Kotlin suite never had: errors_first_test.go (the errors-first
// mapping), ip_test.go (why the L1 allowlist must stay in front), firewall_test.go (the x/exp firewall,
// W2's multi-statement reject, W4's generated-context shape, W5's Java blankness, W7's collision guard).
//
// # Not yet ported
//
// TODO(A2): CedarPolicyStore — policy CRUD with validate-on-write, the origin guards under a row lock
// (INV-A2-20), enable-revalidates (INV-A2-21) and the SYSTEM-toggle sentinel audit row (INV-A2-22).
// 02-authz.md §8. Its 29 DB-backed test cases need containerised Postgres per D13. Note the corpus
// correction to §1: V8__seed.sql carries 40 statements, not 52, and V20/V24/V32 do not exist as
// migration files (V1-V10 only) — the negative-id rows all live in V8.
//
// TODO(A2): the route gates requireAdmin / requireAuthz (§6) — they need Config.authDebug,
// userSession() and ApiError, which A1/A4/D6 own. INV-A2-16 is the contract.
//
// TODO(A2): W9 — setEnabled's revalidation must be SELF-AUGMENTING. The spike measured that shipped row
// -300 (context.trusted-network-tailscale) is REJECTED against the base schema and accepted only against
// the self-augmented one, so a setEnabled that validates against the base schema would make -300
// permanently un-enableable, breaking INV-A2-21 for the shipped seed. CedarSchema.Validate already
// self-augments; the store must call it and not a base-schema variant.
//
// TODO(A12): isStorableIpLiteral's L1 charset allowlist — see EvaluatesInCedar and ip_test.go.
// TODO(A6): effectiveAuthzContext, which makes the query channel authoritative and discards
// caller-supplied tags (INV-A2-9) — 06-query-decision.md §3.
package authz
