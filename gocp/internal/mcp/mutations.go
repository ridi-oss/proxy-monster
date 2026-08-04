package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/gocp/internal/management"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// A11 §4 — `McpMutationExecutor`: idempotency, the advisory lock, and the atomic audit row.
// ---------------------------------------------------------------------------------------------

// AuditWriter is the two `AuditStore` methods this area uses. The `On` variant is not a convenience:
// 🔒 INV-A11-10 requires the mutation and its audit row to commit in ONE transaction, which is only
// expressible by handing the audit store the caller's handle. *audit.Store satisfies it.
type AuditWriter interface {
	Insert(ctx context.Context, rec types.AuditEvent) (int64, error)
	InsertOn(ctx context.Context, c store.Queryer, rec types.AuditEvent) (int64, error)
}

// PolicyVersions is `cedarPolicyStore.markCommittedMutation()` — A2's in-memory state-version counter,
// the thing CedarEngine watches to decide whether to recompile its PolicySet.
// *policy.CedarPolicyStore satisfies it via Bump.
type PolicyVersions interface {
	Bump()
}

// policyMutationTools is `POLICY_MUTATION_TOOLS` (McpServer.kt:75-77).
//
// ⚠️ FIVE TOOLS, and the list is narrower than "every tool that touches internal/policy": `create_role`,
// `assign_role` and the mask-function tools are NOT here, because a role or a mask function is not a
// Cedar policy source and changing one cannot invalidate a compiled PolicySet. Widening the set would
// only cost cache rebuilds; narrowing it would serve stale decisions.
var policyMutationTools = map[string]struct{}{
	"create_policy":  {},
	"update_policy":  {},
	"enable_policy":  {},
	"disable_policy": {},
	"delete_policy":  {},
}

// errIdempotencyConflict is `private class IdempotencyConflictException`. It never leaves this file:
// the catch chain converts it to `mcp.idempotency_conflict` after auditing.
var errIdempotencyConflict = errors.New("mcp: idempotency conflict")

// advisoryLockSeparator is 🔴 F20, REPRODUCED AS-IS.
//
// The Kotlin writes `joinToString("\\u0000")`, and in Kotlin source `"\\u0000"` is the SIX-CHARACTER
// STRING `\u0000` — a backslash, a `u`, and four zeros — not the NUL byte the author almost certainly
// meant. 00-INDEX.md F20: "Almost certainly unintended, but it is part of the hash input for the
// advisory lock — harmless in isolation, but a Go port 'fixing' it to \x00 changes which calls
// serialize against each other. Replicate as-is."
//
// Concretely: the key is hashed by Postgres into an advisory-lock id, so changing the separator
// changes which (principal, client, tool, key) tuples collide on a lock. During a rolling cutover a
// Go instance using `\x00` and a Kotlin instance using `\u0000` would compute DIFFERENT lock ids for
// the same logical call and would not serialize against each other at all — two concurrent
// first-attempts on one idempotency key could both run the mutation, which is exactly what
// INV-A11-11's lock exists to prevent.
//
// ⚠️ Contrast §6's consent CSRF token, which uses a REAL NUL (`"mcp-oauth-consent\u0000<principal>"`
// in a Kotlin string template, where `\u0000` IS the escape). Two separators, one file apart, and only
// one of them is a literal. Do not unify them.
//
// The Go literal below is `"\\u0000"`, which — exactly like the Kotlin's — is SIX CHARACTERS, not one.
// TestTheAdvisoryLockSeparatorIsTheSixCharacterLiteralNotANulByte asserts both its length and its
// bytes, because "someone tidied the double backslash" is a one-character edit that silently breaks
// cross-instance mutual exclusion and no other test would notice.
const advisoryLockSeparator = "\\u0000"

// MutationExecutor is `private class McpMutationExecutor(dataSource, auditStore, cedarPolicyStore,
// authorizer)`.
type MutationExecutor struct {
	db         store.Beginner
	audit      AuditWriter
	policies   PolicyVersions
	authorizer *Authorizer
}

// NewMutationExecutor builds the executor. Argument order is the Kotlin's.
func NewMutationExecutor(db store.Beginner, audit AuditWriter, policies PolicyVersions, authorizer *Authorizer) *MutationExecutor {
	return &MutationExecutor{db: db, audit: audit, policies: policies, authorizer: authorizer}
}

// mutationOutcome is the Kotlin's `Pair<JsonObject, Boolean>` — the response and whether it came from
// a replay. The bool is not cosmetic: 🔒 INV-A11-12 keys `markCommittedMutation()` off it.
type mutationOutcome struct {
	payload []byte
	replay  bool
}

// Execute is `fun execute(context, capability, arguments, datasource, detail, mutation)`.
//
// The five steps, in order, with what each one audits:
//
//  1. authorize          fail ⇒ audit DENY/<code>,              throw ManagementException(<same code>)
//  2. validateArguments  fail ⇒ audit ERROR/mcp.invalid_request, rethrow
//  3. key + requestHash  (no audit)
//  4. ONE transaction:   advisory lock ⇒ prior row ⇒ replay-or-conflict ⇒ mutation ⇒ audit ⇒ row
//  5. post-commit:       markCommittedMutation, only for a real policy mutation
//
// 🔒 INV-A11-10 — THE MUTATION AND ITS AUDIT ROW COMMIT IN ONE TRANSACTION. `auditStore.InsertOn` runs
// on the same tx as `mutation`, so a failed audit insert ROLLS THE MUTATION BACK. An audit trail with
// a missing row for a change that happened is worse than a refused change; McpServerDbTest case 8 is
// exactly this and is ported as TestAFailedAuditInsertRollsBackItsManagementMutation.
//
// 🔒 INV-A11-11 — idempotency is keyed on (principal, clientId, toolName, key) AND guarded by a
// request HASH. A replayed key with DIFFERENT arguments is a CONFLICT, never a silent replay of the
// old response: a client that changed its mind about the arguments and reused the key must be told,
// not quietly handed the previous answer.
//
// ⚠️ Step 1's failure is converted to a ManagementException carrying the SAME ApiError, so a WRITE
// denial and a READ denial render identically at the edge even though they travel as different types.
//
// ⚠️ Every failure audit goes through [auditFailure], which SWALLOWS its own error (`runCatching`): an
// audit failure on an already-failing path must not mask the original error. That is deliberate and it
// is the one place in this area where a lost audit row is tolerated — the alternative is reporting
// "audit insert failed" to a client whose real problem was an invalid argument.
func (m *MutationExecutor) Execute(
	ctx context.Context,
	rc RequestContext,
	capability Capability,
	arguments argValue,
	datasource string,
	detail string,
	mutation func(ctx context.Context, tx store.Queryer) ([]byte, error),
) ([]byte, error) {
	roles, err := m.authorizer.Authorize(ctx, rc, capability)
	if err != nil {
		var authErr *authorizationError
		if errors.As(err, &authErr) {
			m.auditFailure(ctx, rc, capability, authErr.roles, datasource, detail, types.DecisionDeny, authErr.err.Code)
			return nil, &management.Error{Err: authErr.err}
		}
		// A role-resolution failure is not an authorization verdict; it reaches the handler's
		// catch-all as mcp.internal_error, unaudited, exactly as the Kotlin's escaping SQLException
		// does.
		return nil, err
	}

	if err := validateArguments(capability, arguments); err != nil {
		m.auditFailure(ctx, rc, capability, roles, datasource, detail, types.DecisionError, "mcp.invalid_request")
		return nil, err
	}

	// `arguments["idempotencyKey"]?.jsonPrimitive?.contentOrNull?.takeIf(String::isNotBlank)`.
	// validateArguments has already refused a non-string or blank value, so this only ever yields a
	// usable key or nothing.
	var key string
	if v, ok := arguments.stringPrimitive("idempotencyKey"); ok && !isBlank(v) {
		key = v
	}
	requestHash := session.SHA256Hex(canonicalJSON(arguments.without("idempotencyKey")))

	outcome, err := store.InTx(ctx, m.db, func(ctx context.Context, tx pgx.Tx) (mutationOutcome, error) {
		if key != "" {
			if err := m.lockIdempotencyKey(ctx, tx, rc, capability, key); err != nil {
				return mutationOutcome{}, err
			}
			prior, priorHash, found, err := m.priorResponse(ctx, tx, rc, capability, key)
			if err != nil {
				return mutationOutcome{}, err
			}
			if found {
				if priorHash != requestHash {
					return mutationOutcome{}, errIdempotencyConflict
				}
				rec := auditRecord(rc, capability, roles, datasource, detail, types.DecisionAllow, "IDEMPOTENT_REPLAY")
				if _, err := m.audit.InsertOn(ctx, tx, rec); err != nil {
					return mutationOutcome{}, err
				}
				return mutationOutcome{payload: prior, replay: true}, nil
			}
		}

		payload, err := mutation(ctx, tx)
		if err != nil {
			return mutationOutcome{}, err
		}
		rec := auditRecord(rc, capability, roles, datasource, detail, types.DecisionAllow, "ALLOW")
		if _, err := m.audit.InsertOn(ctx, tx, rec); err != nil {
			return mutationOutcome{}, err
		}
		if key != "" {
			if _, err := tx.Exec(ctx,
				`INSERT INTO mcp_mutation_idempotency
				   (principal, client_id, tool_name, idempotency_key, request_hash, response_json)
				   VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
				rc.Principal, rc.ClientID, capability.ToolName, key, requestHash, string(payload),
			); err != nil {
				return mutationOutcome{}, err
			}
		}
		return mutationOutcome{payload: payload, replay: false}, nil
	})
	if err != nil {
		return nil, m.auditAndTranslate(ctx, rc, capability, roles, datasource, detail, err)
	}

	// 🔒 INV-A11-12 — markCommittedMutation fires ONLY on a real (non-replay) policy mutation, and
	// ONLY after the transaction committed. Both halves matter: bumping before commit would publish a
	// version for rows another connection cannot see yet (INV-A2-19), and bumping on a replay would
	// invalidate every Cedar cache in the fleet for a call that changed nothing.
	if !outcome.replay {
		if _, ok := policyMutationTools[capability.ToolName]; ok {
			m.policies.Bump()
		}
	}
	return outcome.payload, nil
}

// lockIdempotencyKey is the `pg_advisory_xact_lock(hashtextextended(?, 0))` call.
//
// 🔒 It SERIALIZES CONCURRENT FIRST-ATTEMPTS ON THE SAME KEY. Without it, two racing calls both find
// no prior row (the `SELECT … FOR UPDATE` locks nothing when there is nothing to lock) and both run
// the mutation; the loser then fails on the primary key, after its side effect has already happened.
// The lock is TRANSACTION-scoped, so it releases on commit or rollback with no unlock path to forget.
//
// 🔒 The key is hashed BY POSTGRES (`hashtextextended`), never in Go — the same rule
// store.AdvisoryLockPrincipal states for `hashtext`: a Go-side hash would not agree with a
// still-running Kotlin instance's, and a rolling cutover would lose mutual exclusion silently.
//
// See [advisoryLockSeparator] for F20, the six-character separator.
func (m *MutationExecutor) lockIdempotencyKey(
	ctx context.Context, tx store.Queryer, rc RequestContext, capability Capability, key string,
) error {
	lockKey := strings.Join([]string{rc.Principal, rc.ClientID, capability.ToolName, key}, advisoryLockSeparator)
	var locked bool
	// The Kotlin runs `executeQuery().use { it.next() }` and discards the value; the row must still be
	// consumed for the function to have been evaluated.
	return tx.QueryRow(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0)) IS NULL`, lockKey).Scan(&locked)
}

// priorResponse is the `SELECT request_hash, response_json … FOR UPDATE`.
//
// ⚠️ `FOR UPDATE` on top of the advisory lock is not redundant even though the advisory lock already
// serializes this tuple: the row lock is what a DIFFERENT code path (or a Kotlin instance mid-cutover)
// would still contend on, and it is what makes the read-then-insert safe if the advisory lock ever
// changes shape.
//
// 🔴 The stored response comes back through JSONB, which NORMALISES: Postgres re-orders object keys
// (by key length, then bytewise) and re-renders numbers, then prints with `": "` and `", "`
// separators. The Kotlin re-parses that text into a JsonObject and re-serialises it compactly, so a
// REPLAY's bytes differ from the original call's bytes in both ports, in the same way — key order is
// jsonb's, not the DTO's. `json.Compact` here is the equivalent of that re-serialisation: it strips
// jsonb's whitespace while preserving its key order and its (kotlinx-identical) escape forms.
// McpServerDbTest case 5 compares the two responses as PARSED objects, not as bytes, which is why the
// normalisation is invisible to it and is called out here instead.
func (m *MutationExecutor) priorResponse(
	ctx context.Context, tx store.Queryer, rc RequestContext, capability Capability, key string,
) (payload []byte, hash string, found bool, err error) {
	var stored []byte
	row := tx.QueryRow(ctx,
		`SELECT request_hash, response_json FROM mcp_mutation_idempotency
		   WHERE principal=$1 AND client_id=$2 AND tool_name=$3 AND idempotency_key=$4 FOR UPDATE`,
		rc.Principal, rc.ClientID, capability.ToolName, key,
	)
	if err := row.Scan(&hash, &stored); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", false, nil
		}
		return nil, "", false, err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, stored); err != nil {
		return nil, "", false, err
	}
	return compact.Bytes(), hash, true, nil
}

// auditAndTranslate is the Kotlin's catch chain, in its order. Each arm audits with a DIFFERENT
// `outcome` string and those strings are what the trail is queried by:
//
//	IdempotencyConflictException           IDEMPOTENCY_CONFLICT   -> mcp.idempotency_conflict
//	ManagementException                    <the failure's code>   -> rethrown unchanged
//	CedarValidationManagementException     CEDAR_VALIDATION       -> rethrown unchanged
//	McpInputException                      mcp.invalid_request    -> rethrown unchanged
//	any other                              INTERNAL_ERROR         -> rethrown unchanged
//
// ⚠️ Only the FIRST arm changes the error; the rest audit and rethrow. So the caller distinguishes a
// Cedar validation failure from a management failure by TYPE, which is what lets the tool handler
// render `{errors: [...]}` for one and a localized ApiError for the other.
//
// ⚠️ The conflict arm's audit uses the roles resolved in step 1 — a conflict is a fully-authorized
// call that was refused for a different reason, so the row is honest about the authority it had.
func (m *MutationExecutor) auditAndTranslate(
	ctx context.Context,
	rc RequestContext,
	capability Capability,
	roles []string,
	datasource, detail string,
	err error,
) error {
	switch {
	case errors.Is(err, errIdempotencyConflict):
		m.auditFailure(ctx, rc, capability, roles, datasource, detail, types.DecisionError, "IDEMPOTENCY_CONFLICT")
		return management.Fail("mcp.idempotency_conflict", nil)
	case isManagementError(err):
		var me *management.Error
		errors.As(err, &me)
		m.auditFailure(ctx, rc, capability, roles, datasource, detail, types.DecisionError, me.Err.Code)
		return err
	case isCedarValidationError(err):
		m.auditFailure(ctx, rc, capability, roles, datasource, detail, types.DecisionError, "CEDAR_VALIDATION")
		return err
	case errors.Is(err, errInvalidInput):
		m.auditFailure(ctx, rc, capability, roles, datasource, detail, types.DecisionError, "mcp.invalid_request")
		return err
	default:
		m.auditFailure(ctx, rc, capability, roles, datasource, detail, types.DecisionError, "INTERNAL_ERROR")
		return err
	}
}

// auditFailure is `private fun auditFailure(...)` — `runCatching { auditStore.insert(...) }`.
//
// 🔒 IT RUNS ON ITS OWN TRANSACTION, not the caller's. That is the whole point: the caller's
// transaction has just been rolled back (or is about to be), so a failure audit written on it would
// vanish with the mutation it is recording. INV-A11-10's atomicity is for the SUCCESS path; the
// failure path deliberately breaks it in the other direction.
//
// The error is discarded, as `runCatching` discards it.
func (m *MutationExecutor) auditFailure(
	ctx context.Context,
	rc RequestContext,
	capability Capability,
	roles []string,
	datasource, detail string,
	decision types.Decision,
	outcome string,
) {
	_, _ = m.audit.Insert(ctx, auditRecord(rc, capability, roles, datasource, detail, decision, outcome))
}

func isManagementError(err error) bool {
	var me *management.Error
	return errors.As(err, &me)
}

func isCedarValidationError(err error) bool {
	var ce *management.CedarValidationError
	return errors.As(err, &ce)
}
