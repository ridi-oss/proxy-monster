package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
)

// ---------------------------------------------------------------------------------------------
// 🔴 NEW COVERAGE — the four-gate pipeline (§2) and the mutation executor (§4) as PROPERTIES rather
// than as steps inside a longer case.
//
// `McpServerDbTest` reaches most of these incidentally. "Incidentally" is the problem: case 5 would
// still pass with the advisory lock deleted, because it never runs two calls at once, and case 1 would
// still pass with gates 2 and 3 swapped, because it never sends a bad Origin AND a bad token together.
// Each case below isolates one property and, where the property is an ORDERING or a CONCURRENCY claim,
// includes the control that distinguishes "the invariant holds" from "the test never exercised it".
// ---------------------------------------------------------------------------------------------

// TestOriginIsRefusedWithoutTheTokenEverBeingResolved is 🔒 INV-A11-5, proved by OBSERVATION rather
// than by reading the source.
//
// Gate 2 precedes gate 3, so a cross-origin browser request is refused without its token ever being
// resolved — which is why a malicious page cannot use timing or error shape to probe whether a token it
// replayed is still live. The counter on the token seam is the whole assertion: if the gates were
// swapped, the request would still be a 403 and the code would still be `mcp.invalid_origin` (the
// origin check would just run second), and only `tokens.calls` would tell the difference.
func TestOriginIsRefusedWithoutTheTokenEverBeingResolved(t *testing.T) {
	f := newMcpFixture(t)
	f.grantRole("mcp-order@example.com", "system:admin")
	token := f.mintToken("mcp-order@example.com", ScopeRead)

	before := f.tokens.calls.Load()
	res := f.post(toolCall(1, "list_roles", nil), bearer(token), header("Origin", "https://evil.example"))
	if res.status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%s)", res.status, res.rawBody)
	}
	if got := res.apiErrorCode(t); got != "mcp.invalid_origin" {
		t.Fatalf("code = %q, want mcp.invalid_origin", got)
	}
	if after := f.tokens.calls.Load(); after != before {
		t.Errorf("the token was resolved %d time(s) on a cross-origin request; gate 2 must precede gate 3",
			after-before)
	}

	// And the same for gate 1: a foreign HOST is refused before the token too.
	before = f.tokens.calls.Load()
	res = f.post(toolCall(2, "list_roles", nil), bearer(token), header("Host", "evil.example"))
	if got := res.apiErrorCode(t); got != "mcp.invalid_host" {
		t.Fatalf("code = %q, want mcp.invalid_host", got)
	}
	if after := f.tokens.calls.Load(); after != before {
		t.Errorf("the token was resolved on a foreign-host request; gate 1 must precede gate 3")
	}

	// The control: with a good Origin, the SAME request DOES resolve the token. Without this, a test
	// whose token seam was simply never wired would pass the two assertions above.
	before = f.tokens.calls.Load()
	if res = f.post(toolCall(3, "list_roles", nil), bearer(token),
		header("Origin", "http://localhost")); res.status != http.StatusOK {
		t.Fatalf("same-origin status = %d, want 200 (%s)", res.status, res.rawBody)
	}
	if after := f.tokens.calls.Load(); after != before+1 {
		t.Errorf("token resolutions on the accepted request = %d, want 1", after-before)
	}
}

// TestADeactivatedPrincipalIsRefusedExactlyLikeAnUnknownToken is gate 3's second half.
//
// 🔒 The bodies must be INDISTINGUISHABLE. `mcp.principal_deactivated` exists in the bundle and is
// deliberately not used here: telling a token holder that their account was deprovisioned confirms the
// principal exists. This asserts the two responses are byte-identical rather than merely both 401.
func TestADeactivatedPrincipalIsRefusedExactlyLikeAnUnknownToken(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-deactivated@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead)
	f.exec(`INSERT INTO app_user (principal, active) VALUES ($1, TRUE)`, principal)

	if live := f.post(toolCall(1, "list_roles", nil), bearer(token)); live.status != http.StatusOK {
		t.Fatalf("the live token was refused: %d %s", live.status, live.rawBody)
	}

	f.exec(`UPDATE app_user SET active = FALSE WHERE principal = $1`, principal)

	deactivated := f.post(toolCall(2, "list_roles", nil), bearer(token))
	unknown := f.post(toolCall(3, "list_roles", nil), bearer("no-such-token"))
	if deactivated.status != http.StatusUnauthorized {
		t.Fatalf("deactivated status = %d, want 401 (%s)", deactivated.status, deactivated.rawBody)
	}
	if deactivated.rawBody != unknown.rawBody {
		t.Errorf("the two 401 bodies differ; a deactivated principal must be indistinguishable"+
			"\n deactivated %s\n unknown     %s", deactivated.rawBody, unknown.rawBody)
	}
	if deactivated.header.Get("WWW-Authenticate") != unknown.header.Get("WWW-Authenticate") {
		t.Error("the two 401 challenges differ")
	}
	if strings.Contains(deactivated.rawBody, "deactivated") {
		t.Errorf("the 401 body discloses the deactivation: %s", deactivated.rawBody)
	}
}

// TestATokenStoreFailureIsAFiveHundredNotASilentUnauthorized pins the SQLException path.
//
// The Kotlin lets `resolveAccess`'s SQLException escape the interceptor into StatusPages as a 500.
// Answering 401 instead would be strictly worse: an outage of the token table would look to every
// client like a credential problem and they would all re-run their OAuth flow against a database that
// is already down.
func TestATokenStoreFailureIsAFiveHundredNotASilentUnauthorized(t *testing.T) {
	f := newMcpFixture(t)
	f.tokens.err = errors.New("the token table is unavailable")

	res := f.post(toolCall(1, "list_roles", nil), bearer("anything"))
	if res.status == http.StatusUnauthorized {
		t.Fatalf("a token-store failure answered 401; it must not look like a bad credential (%s)", res.rawBody)
	}
	if res.status < 500 {
		t.Errorf("status = %d, want a 5xx (%s)", res.status, res.rawBody)
	}
}

// TestABearerForAnotherResourceIsNoTokenAtAll is 🔒 INV-A11-18's audience binding at gate 3.
//
// The check lives in the token store's own query (`WHERE t.resource = ?`), which this area does not
// own — so what is asserted here is that the pipeline PASSES the configured resource down and treats a
// nil identity as "no token", rather than resolving against whatever the caller asked for.
func TestABearerForAnotherResourceIsNoTokenAtAll(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-audience@example.com"
	f.grantRole(principal, "system:admin")
	// A live token whose audience is a DIFFERENT resource.
	f.tokens.byToken["foreign-audience"] = &AccessIdentity{
		Principal: principal, ClientID: testClientID,
		Resource: "http://localhost/some-other-resource", Scopes: []string{ScopeRead},
	}

	res := f.post(toolCall(1, "list_roles", nil), bearer("foreign-audience"))
	if res.status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (%s)", res.status, res.rawBody)
	}
	if got := res.apiErrorCode(t); got != "common.invalid_token" {
		t.Errorf("code = %q, want common.invalid_token", got)
	}
}

// TestTheAdvisoryLockSerialisesTwoConcurrentFirstAttemptsOnOneKey is 🔒 INV-A11-11's concurrency half —
// "exactly the kind of thing that passes single-threaded and corrupts under load" (§9's words about
// the sibling invariant in replaceDirectRoles; the same reasoning applies verbatim here).
//
// Without the lock both callers find no prior row — `SELECT … FOR UPDATE` locks nothing when there is
// nothing to lock — and both run the mutation; the loser then fails on the idempotency primary key,
// AFTER its side effect has already happened.
//
// The pairing with TestWithoutTheAdvisoryLockTheSameSequenceWouldConflict is what makes this
// meaningful: a green concurrency test whose goroutines never actually overlapped is indistinguishable
// from one whose invariant holds.
func TestTheAdvisoryLockSerialisesTwoConcurrentFirstAttemptsOnOneKey(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-lock@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead, ScopeIdentityWrite)

	const rounds = 12
	for round := range rounds {
		name := "locked-group-" + string(rune('a'+round))
		args := map[string]any{"name": name, "idempotencyKey": "lock-key-" + name}

		start := make(chan struct{})
		var wg sync.WaitGroup
		results := make([]callResult, 2)
		for i := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, results[i] = f.call(token, "create_group", args)
			}()
		}
		close(start)
		wg.Wait()

		for i, r := range results {
			if r.isError {
				t.Fatalf("round %d caller %d failed: %s", round, i, r.text)
			}
		}
		// One winner, one replay — never two mutations and never a primary-key explosion.
		if n := f.scalar(`SELECT count(*) FROM app_group WHERE name=$1`, name); n != 1 {
			t.Fatalf("round %d: app_group rows = %d, want exactly 1", round, n)
		}
		if got := f.strings(
			`SELECT outcome FROM audit_event WHERE statement='[MCP create_group]' AND detail=$1 ORDER BY id`,
			"create_group name="+name); !slices.Equal(got, []string{"ALLOW", "IDEMPOTENT_REPLAY"}) {
			t.Fatalf("round %d: outcomes = %v, want [ALLOW IDEMPOTENT_REPLAY]", round, got)
		}
	}
}

// TestWithoutTheAdvisoryLockTheSameSequenceWouldConflict is the CONTROL for the case above.
//
// It runs the executor's own read-then-insert against `mcp_mutation_idempotency` in two transactions,
// interleaved by a barrier and with NO advisory lock, and asserts the second INSERT fails on the
// primary key. That failure is precisely the outcome the lock exists to prevent, and it is what proves
// the goroutines in the case above genuinely overlap: if they did not, this control would be green for
// the wrong reason too — so it also asserts that the FIRST insert succeeded.
func TestWithoutTheAdvisoryLockTheSameSequenceWouldConflict(t *testing.T) {
	f := newMcpFixture(t)
	ctx := context.Background()

	txA, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin A: %v", err)
	}
	defer func() { _ = txA.Rollback(ctx) }()
	txB, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin B: %v", err)
	}
	defer func() { _ = txB.Rollback(ctx) }()

	const sel = `SELECT request_hash FROM mcp_mutation_idempotency
	               WHERE principal=$1 AND client_id=$2 AND tool_name=$3 AND idempotency_key=$4 FOR UPDATE`
	const ins = `INSERT INTO mcp_mutation_idempotency
	               (principal, client_id, tool_name, idempotency_key, request_hash, response_json)
	               VALUES ($1, $2, $3, $4, $5, $6::jsonb)`
	key := []any{"p", testClientID, "create_group", "shared-key"}

	// Both read first — the interleaving the lock forbids — and both find nothing.
	var hash string
	if err := txA.QueryRow(ctx, sel, key...).Scan(&hash); err == nil {
		t.Fatal("A found a prior row where there is none")
	}
	if err := txB.QueryRow(ctx, sel, key...).Scan(&hash); err == nil {
		t.Fatal("B found a prior row where there is none")
	}

	if _, err := txA.Exec(ctx, ins, append(slices.Clone(key), "hash-a", `{"result":"a"}`)...); err != nil {
		t.Fatalf("A's insert failed; the control proves nothing: %v", err)
	}
	if err := txA.Commit(ctx); err != nil {
		t.Fatalf("A's commit failed: %v", err)
	}

	// B ran its mutation on the strength of a read that is now stale. Its insert must collide.
	_, err = txB.Exec(ctx, ins, append(slices.Clone(key), "hash-b", `{"result":"b"}`)...)
	if err == nil {
		t.Fatal("🔴 the unlocked interleaving committed cleanly — this control no longer proves the lock matters")
	}
	if !strings.Contains(err.Error(), "23505") && !strings.Contains(err.Error(), "duplicate key") {
		t.Errorf("B failed with %v, want a unique-violation", err)
	}
}

// TestTheIdempotencyKeyIsScopedByPrincipalClientAndTool is 🔒 INV-A11-11's KEY half.
//
// The same literal key from a different principal, a different client, or against a different tool is
// a DIFFERENT idempotency record. A port that keyed on the string alone would let one client's replay
// hand another client's response back — a cross-tenant disclosure through a cache.
func TestTheIdempotencyKeyIsScopedByPrincipalClientAndTool(t *testing.T) {
	f := newMcpFixture(t)
	alice, bob := "mcp-idem-alice@example.com", "mcp-idem-bob@example.com"
	f.grantRole(alice, "system:admin")
	f.grantRole(bob, "system:admin")
	aliceToken := f.mintToken(alice, ScopeRead, ScopeIdentityWrite, ScopePoliciesWrite)
	bobToken := f.mintToken(bob, ScopeRead, ScopeIdentityWrite)

	// A second client id for the same principal — the `client_id` column of the key.
	f.tokens.byToken["alice-other-client"] = &AccessIdentity{
		Principal: alice, ClientID: "https://other.example/mcp.json", Resource: testResource,
		Scopes: []string{ScopeRead, ScopeIdentityWrite},
	}

	const key = "one-shared-key"
	if _, r := f.call(aliceToken, "create_group", map[string]any{
		"name": "idem-alice", "idempotencyKey": key}); r.isError {
		t.Fatalf("alice's create_group failed: %s", r.text)
	}
	// Same key, DIFFERENT principal — runs, does not replay.
	if _, r := f.call(bobToken, "create_group", map[string]any{
		"name": "idem-bob", "idempotencyKey": key}); r.isError {
		t.Fatalf("bob's create_group failed: %s", r.text)
	}
	// Same key, same principal, DIFFERENT client — runs.
	if _, r := f.call("alice-other-client", "create_group", map[string]any{
		"name": "idem-other-client", "idempotencyKey": key}); r.isError {
		t.Fatalf("the other client's create_group failed: %s", r.text)
	}
	// Same key, same principal, same client, DIFFERENT tool — runs.
	if _, r := f.call(aliceToken, "create_role", map[string]any{
		"name": "idem-role", "idempotencyKey": key}); r.isError {
		t.Fatalf("create_role failed: %s", r.text)
	}

	for _, name := range []string{"idem-alice", "idem-bob", "idem-other-client"} {
		if n := f.scalar(`SELECT count(*) FROM app_group WHERE name=$1`, name); n != 1 {
			t.Errorf("group %q rows = %d, want 1 — the key scoping collapsed", name, n)
		}
	}
	if n := f.scalar(`SELECT count(*) FROM app_role WHERE name='idem-role'`); n != 1 {
		t.Error("the role was not created; the key scoping collapsed across tools")
	}
	if n := f.scalar(`SELECT count(*) FROM mcp_mutation_idempotency WHERE idempotency_key=$1`, key); n != 4 {
		t.Errorf("idempotency rows for one key = %d, want 4 (principal × client × tool)", n)
	}

	// And the replay still works within one scope.
	if _, r := f.call(aliceToken, "create_group", map[string]any{
		"name": "idem-alice", "idempotencyKey": key}); r.isError {
		t.Fatalf("the in-scope replay failed: %s", r.text)
	}
	if n := f.scalar(`SELECT count(*) FROM app_group WHERE name='idem-alice'`); n != 1 {
		t.Error("the in-scope replay ran the mutation again")
	}
}

// TestMarkCommittedMutationFiresOnlyForARealPolicyMutation is 🔒 INV-A11-12, both halves.
//
// Bumping on a replay would invalidate every Cedar cache in the fleet for a call that changed nothing
// (A2 INV-A2-19), and bumping for a non-policy tool would do the same for a role or a mask function
// that cannot affect a compiled PolicySet.
func TestMarkCommittedMutationFiresOnlyForARealPolicyMutation(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-bump@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead, ScopePoliciesWrite, ScopeIdentityWrite)

	// A non-policy write: no bump, however many times it runs.
	if _, r := f.call(token, "create_role", map[string]any{"name": "bump-role"}); r.isError {
		t.Fatalf("create_role failed: %s", r.text)
	}
	if _, r := f.call(token, "create_group", map[string]any{"name": "bump-group"}); r.isError {
		t.Fatalf("create_group failed: %s", r.text)
	}
	if _, r := f.call(token, "create_mask_fn", map[string]any{"name": "bump-mask", "kind": "FIXED"}); r.isError {
		t.Fatalf("create_mask_fn failed: %s", r.text)
	}
	if f.versions.bumps != 0 {
		t.Fatalf("bumps after three non-policy writes = %d, want 0", f.versions.bumps)
	}

	src := `permit(principal in Role::"bump-role", action == Action::"admin.identity", resource);`
	args := map[string]any{"name": "bump-policy", "cedarSrc": src, "idempotencyKey": "bump-once"}
	if _, r := f.call(token, "create_policy", args); r.isError {
		t.Fatalf("create_policy failed: %s", r.text)
	}
	if f.versions.bumps != 1 {
		t.Fatalf("bumps after one policy mutation = %d, want 1", f.versions.bumps)
	}

	// 🔒 The REPLAY must not bump. This is the difference between 1 and 2, which is why the double is
	// a counter and not a bool.
	if _, r := f.call(token, "create_policy", args); r.isError {
		t.Fatalf("the replay failed: %s", r.text)
	}
	if f.versions.bumps != 1 {
		t.Errorf("bumps after a REPLAY = %d, want 1 — a replay changed nothing", f.versions.bumps)
	}

	// A FAILED policy mutation must not bump either: the bump is post-commit.
	if _, r := f.call(token, "create_policy", map[string]any{
		"name": "bump-policy", "cedarSrc": src}); !r.isError {
		t.Fatal("a duplicate policy name was accepted")
	}
	if f.versions.bumps != 1 {
		t.Errorf("bumps after a FAILED mutation = %d, want 1", f.versions.bumps)
	}

	// And a real second policy mutation does bump.
	if _, r := f.call(token, "disable_policy", map[string]any{"name": "bump-policy"}); r.isError {
		t.Fatalf("disable_policy failed: %s", r.text)
	}
	if f.versions.bumps != 2 {
		t.Errorf("bumps after a second policy mutation = %d, want 2", f.versions.bumps)
	}
}

// TestTheRequestHashIgnoresArgumentOrderAndTheIdempotencyKeyItself is `canonicalJson`'s contract seen
// from the outside: the hash is computed over the arguments MINUS `idempotencyKey`, canonicalised, so
// re-sending the same call with its keys in a different JSON order is a replay and not a conflict.
//
// canonical_test.go pins the serializer's bytes. This pins that the executor feeds it the right input,
// which is a separate claim and the one a client actually depends on.
func TestTheRequestHashIgnoresArgumentOrderAndTheIdempotencyKeyItself(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-hash@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead, ScopeIdentityWrite)

	// Two JSON bodies with the same pairs in a different textual order. Go's map iteration would not
	// reliably produce a difference, so the bodies are written out by hand.
	first := `{"jsonrpc":"2.0","id":901,"method":"tools/call","params":{"name":"create_user",` +
		`"arguments":{"principal":"hash-user@example.com","displayName":"H","idempotencyKey":"hash-key"}}}`
	second := `{"jsonrpc":"2.0","id":902,"method":"tools/call","params":{"name":"create_user",` +
		`"arguments":{"idempotencyKey":"hash-key","displayName":"H","principal":"hash-user@example.com"}}}`

	if r := f.toolResultOf(f.post(first, bearer(token))); r.isError {
		t.Fatalf("first call failed: %s", r.text)
	}
	replay := f.toolResultOf(f.post(second, bearer(token)))
	if replay.isError {
		t.Fatalf("the reordered replay was refused: %s", replay.text)
	}
	if got := f.auditOutcomes(principal, "[MCP create_user]"); !slices.Equal(
		got, []string{"ALLOW", "IDEMPOTENT_REPLAY"}) {
		t.Errorf("outcomes = %v, want [ALLOW IDEMPOTENT_REPLAY] — key order changed the hash", got)
	}

	// Only ONE row exists, so the stored hash covers arguments-minus-key and nothing else.
	if n := f.scalar(`SELECT count(*) FROM mcp_mutation_idempotency WHERE idempotency_key='hash-key'`); n != 1 {
		t.Errorf("idempotency rows = %d, want 1", n)
	}
}

// TestAnIdempotencyKeyIsRefusedWhenItIsBlankOrTooLong pins validateArguments' second rule at the
// transport, including the ≤128 bound. A 129-code-unit key would otherwise be stored and truncated or
// rejected by the column, and the failure would be an internal error instead of a stated one.
func TestAnIdempotencyKeyIsRefusedWhenItIsBlankOrTooLong(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-key-bounds@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead, ScopeIdentityWrite)

	for _, key := range []any{"", "   ", strings.Repeat("k", maxIdempotencyKeyLength+1), 7, nil} {
		_, result := f.call(token, "create_group",
			map[string]any{"name": "key-bounds-group", "idempotencyKey": key})
		if !result.isError {
			t.Errorf("idempotencyKey %#v was accepted", key)
			continue
		}
		if got := result.errorCode(t); got != "mcp.invalid_request" {
			t.Errorf("idempotencyKey %#v: code = %q, want mcp.invalid_request", key, got)
		}
	}
	// The boundary itself is legal.
	if _, r := f.call(token, "create_group", map[string]any{
		"name": "key-bounds-group", "idempotencyKey": strings.Repeat("k", maxIdempotencyKeyLength),
	}); r.isError {
		t.Errorf("a %d-character key was refused: %s", maxIdempotencyKeyLength, r.text)
	}
}

// TestAWriteWithoutAnIdempotencyKeyStoresNoRowAndNeverReplays. The key is OPTIONAL, and a client that
// omits it gets at-least-once semantics — two identical calls run twice. Reproducing that matters
// because the alternative (hashing the arguments as an implicit key) would silently turn a deliberate
// second call into a no-op.
func TestAWriteWithoutAnIdempotencyKeyStoresNoRowAndNeverReplays(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-nokey@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead, ScopePoliciesWrite)

	if _, r := f.call(token, "create_role", map[string]any{"name": "nokey-role"}); r.isError {
		t.Fatalf("first call failed: %s", r.text)
	}
	_, again := f.call(token, "create_role", map[string]any{"name": "nokey-role"})
	if !again.isError {
		t.Fatal("the second keyless call was silently replayed")
	}
	if got := again.errorCode(t); got != "common.already_exists" {
		t.Errorf("code = %q, want common.already_exists — the mutation must have RUN again", got)
	}
	if n := f.scalar(`SELECT count(*) FROM mcp_mutation_idempotency`); n != 0 {
		t.Errorf("a keyless write stored %d idempotency rows, want 0", n)
	}
	if got := f.auditOutcomes(principal, "[MCP create_role]"); !slices.Equal(
		got, []string{"ALLOW", "common.already_exists"}) {
		t.Errorf("outcomes = %v, want [ALLOW common.already_exists]", got)
	}
}

// TestAuthDebugSkipsCedarEndToEndButNeverTheScope is INV-A2-16's shape on this surface, over the wire.
//
// `PM_AUTH_DEBUG` short-circuits all four gate helpers on the REST side and Cedar here — but NOT the
// scope check, which is a property of the OAuth grant rather than of the deployment's auth mode. A
// port that folded the scope test into the same `if (!config.authDebug)` block would make a dev box
// accept any scope, and the difference would only show up in production.
func TestAuthDebugSkipsCedarEndToEndButNeverTheScope(t *testing.T) {
	f := newMcpFixture(t, func(c *config.Config) { c.AuthDebug = true })
	// No role, no policy, nothing: under authDebug Cedar is not consulted at all.
	principal := "mcp-authdebug@example.com"
	writeToken := f.mintToken(principal, ScopeRead, ScopePoliciesWrite)

	if _, r := f.call(writeToken, "create_role", map[string]any{"name": "authdebug-role"}); r.isError {
		t.Fatalf("authDebug did not bypass Cedar: %s", r.text)
	}

	readOnly := f.mintToken(principal, ScopeRead)
	res, result := f.call(readOnly, "create_role", map[string]any{"name": "must-not-exist"})
	if res.status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — authDebug must not bypass the SCOPE (%s)", res.status, res.rawBody)
	}
	if got := result.errorCode(t); got != "mcp.insufficient_scope" {
		t.Errorf("code = %q, want mcp.insufficient_scope", got)
	}
	if n := f.scalar(`SELECT count(*) FROM app_role WHERE name='must-not-exist'`); n != 0 {
		t.Error("the scope-refused call still wrote a row")
	}
}

// TestTheInsufficientScopeDenialAuditsWithNoRoles is INV-A11-9.
//
// The scope check runs BEFORE role resolution, so the exception carries an empty role set and the
// audit row is honest about what was known — it does not backfill roles the server never looked up.
func TestTheInsufficientScopeDenialAuditsWithNoRoles(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-scope-audit@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead)

	if _, r := f.call(token, "create_role", map[string]any{"name": "scope-audit-role"}); !r.isError {
		t.Fatal("the read scope reached a write tool")
	}
	var roles []string
	var outcome string
	if err := f.pool.QueryRow(f.ctx,
		`SELECT roles, outcome FROM audit_event WHERE principal=$1`, principal).Scan(&roles, &outcome); err != nil {
		t.Fatalf("read the audit row: %v", err)
	}
	if outcome != "mcp.insufficient_scope" {
		t.Errorf("outcome = %q, want mcp.insufficient_scope", outcome)
	}
	if len(roles) != 0 {
		t.Errorf("roles = %v, want [] — they were never resolved", roles)
	}

	// The control: a CEDAR denial for the same principal DOES carry the roles, because they were
	// resolved before Cedar was asked. Without this the assertion above would also pass if the audit
	// row simply never recorded roles at all.
	f.unassignRole(principal, "system:admin")
	f.grantRole(principal, "system:admin")
	writeToken := f.mintToken(principal, ScopeRead, ScopeIdentityWrite)
	f.exec(`DELETE FROM policy WHERE id = -1`)
	if _, r := f.call(writeToken, "create_user", map[string]any{"principal": "nobody@example.com"}); !r.isError {
		t.Fatal("the call was allowed after its policy was deleted")
	}
	if err := f.pool.QueryRow(f.ctx,
		`SELECT roles, outcome FROM audit_event WHERE principal=$1 AND statement='[MCP create_user]'`,
		principal).Scan(&roles, &outcome); err != nil {
		t.Fatalf("read the Cedar-denial row: %v", err)
	}
	if outcome != "common.forbidden" {
		t.Errorf("outcome = %q, want common.forbidden", outcome)
	}
	if !slices.Contains(roles, "system:admin") {
		t.Errorf("roles on the Cedar denial = %v, want them to include system:admin", roles)
	}
}

// TestTheStatelessPostIsFramedAsAnEventStream pins the transport framing, which is the one place this
// port's wire bytes differ in SHAPE from the Kotlin's.
//
// 🔴 RECORDED. `McpServerDbTest` parses `response.bodyAsText()` straight into a JsonObject, so the
// Kotlin SDK answers `application/json`. The Go SDK's `StreamableHTTPHandler` frames the same JSON-RPC
// response as `text/event-stream` unless `StreamableHTTPOptions.JSONResponse` is set. Both are legal
// under the Streamable HTTP transport and a conformant client accepts either, so the port has not
// flipped it on a guess — but the choice is asserted HERE rather than assumed everywhere, so that
// deciding to match the Kotlin is a one-line change with one failing test to update.
func TestTheStatelessPostIsFramedAsAnEventStream(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-framing@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead)

	res := f.post(toolCall(1, "list_roles", nil), bearer(token))
	if res.status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", res.status, res.rawBody)
	}
	if got := res.header.Get("Content-Type"); !strings.HasPrefix(got, "text/event-stream") {
		t.Errorf("Content-Type = %q; the Kotlin answers application/json and the port answers SSE — "+
			"if this changed, update the note on jsonRPCPayload", got)
	}
	if !strings.Contains(res.rawBody, "data: ") {
		t.Errorf("the SSE body carries no data frame: %q", res.rawBody)
	}

	// A GATE rejection is NOT framed by the SDK — it never reaches it — so it is a plain JSON ApiError,
	// exactly as every other control-plane error is. The two shapes coexisting on one path is worth
	// pinning: a client that only knows how to read SSE would miss the 401 body entirely.
	unauth := f.post(toolCall(2, "list_roles", nil))
	if got := unauth.header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("gate rejection Content-Type = %q, want application/json", got)
	}
}

// TestNonPostVerbsStillPassTheGatesAndAreRefusedByTheTransport is why `/mcp` is registered WITHOUT a
// method.
//
// Ktor's interceptor is scoped by PATH, so a GET to /mcp goes through the host/origin/bearer gates and
// is then refused by the SDK. Registering `POST /mcp` on Go's mux would make an unauthenticated GET a
// 405 from the MUX — a probe could then distinguish a live /mcp from a missing one without a token.
func TestNonPostVerbsStillPassTheGatesAndAreRefusedByTheTransport(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-verbs@example.com"
	token := f.mintToken(principal, ScopeRead)

	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodPut} {
		req, err := http.NewRequest(method, f.server.URL+"/mcp", nil)
		if err != nil {
			t.Fatalf("build %s: %v", method, err)
		}
		req.Host = f.defaultHost

		// Unauthenticated: the BEARER gate answers, not the mux.
		resp, err := f.server.Client().Do(req)
		if err != nil {
			t.Fatalf("%s /mcp: %v", method, err)
		}
		status := resp.StatusCode
		challenge := resp.Header.Get("WWW-Authenticate")
		resp.Body.Close()
		if status != http.StatusUnauthorized {
			t.Errorf("%s unauthenticated status = %d, want 401 (a 405 here leaks that /mcp exists)",
				method, status)
		}
		if challenge == "" {
			t.Errorf("%s: no WWW-Authenticate challenge", method)
		}

		// Authenticated: now the TRANSPORT refuses it, because stateless streamable HTTP is POST-only.
		req, _ = http.NewRequest(method, f.server.URL+"/mcp", nil)
		req.Host = f.defaultHost
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err = f.server.Client().Do(req)
		if err != nil {
			t.Fatalf("%s /mcp authenticated: %v", method, err)
		}
		status = resp.StatusCode
		resp.Body.Close()
		if status == http.StatusUnauthorized || status == http.StatusOK {
			t.Errorf("%s authenticated status = %d, want a transport-level refusal", method, status)
		}
	}
}

// TestTheDiscoveryRoutesAreUnauthenticatedAndUngated is the other half of the mount: the two
// well-known documents are NOT behind the interceptor, because a client that has just been 401'd
// fetches one to learn where to get a token. Gating them would break RFC 9728's discovery loop.
func TestTheDiscoveryRoutesAreUnauthenticatedAndUngated(t *testing.T) {
	f := newMcpFixture(t)
	before := f.tokens.calls.Load()
	for _, path := range []string{
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-protected-resource/mcp",
	} {
		res := f.get(path)
		if res.status != http.StatusOK {
			t.Errorf("%s status = %d, want 200", path, res.status)
		}
		if res.header.Get("WWW-Authenticate") != "" {
			t.Errorf("%s emitted a challenge; it must be unauthenticated", path)
		}
	}
	if after := f.tokens.calls.Load(); after != before {
		t.Errorf("the discovery routes resolved %d token(s); they must not touch gate 3", after-before)
	}
}

// TestAToolResultCarriesTheSameJSONAsTextAndAsStructure pins the MCP protocol's duplication, which the
// port builds from one byte slice so the two cannot disagree. A client that predates
// `structuredContent` renders `content[0].text`; one that does not reads the structure.
func TestAToolResultCarriesTheSameJSONAsTextAndAsStructure(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-envelope@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead, ScopePoliciesWrite)

	_, result := f.call(token, "create_role", map[string]any{"name": "envelope-role"})
	if result.isError {
		t.Fatalf("create_role failed: %s", result.text)
	}
	structured, err := json.Marshal(result.structured)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !sameJSON(t, json.RawMessage(result.text), structured) {
		t.Errorf("content[0].text and structuredContent disagree:\n text %s\n struct %s",
			result.text, structured)
	}
	// The envelope is `{"result": …}`, not the value bare.
	if _, ok := result.structured["result"]; !ok {
		t.Errorf("the tool result is not wrapped in a `result` envelope: %v", result.structured)
	}
}

// TestTwoConcurrentRequestsGetTheirOwnServerAndIdentity is the stateless per-request-server model's
// security consequence, which is the reason it is not an efficiency choice.
//
// Each server closes over ITS request's RequestContext. If the construction were hoisted out — a
// natural-looking optimisation, since building 38 tools per request is real work — two in-flight
// requests would share one identity and the second caller would act as the first.
func TestTwoConcurrentRequestsGetTheirOwnServerAndIdentity(t *testing.T) {
	f := newMcpFixture(t)
	alice, bob := "mcp-parallel-alice@example.com", "mcp-parallel-bob@example.com"
	f.grantRole(alice, "system:admin")
	f.grantRole(bob, "system:admin")
	aliceToken := f.mintToken(alice, ScopeRead, ScopeIdentityWrite)
	bobToken := f.mintToken(bob, ScopeRead, ScopeIdentityWrite)

	const rounds = 16
	var wg sync.WaitGroup
	for round := range rounds {
		for _, who := range []struct {
			token, principal, group string
		}{
			{aliceToken, alice, "parallel-alice-"},
			{bobToken, bob, "parallel-bob-"},
		} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, result := f.call(who.token, "create_group",
					map[string]any{"name": who.group + string(rune('a'+round))})
				if result.isError {
					t.Errorf("%s round %d: %s", who.principal, round, result.text)
				}
			}()
		}
	}
	wg.Wait()

	// Every audit row must name the principal whose token made the call.
	for _, who := range []struct{ principal, prefix string }{
		{alice, "create_group name=parallel-alice-"},
		{bob, "create_group name=parallel-bob-"},
	} {
		n := f.scalar(
			`SELECT count(*) FROM audit_event WHERE principal=$1 AND detail LIKE $2`, who.principal, who.prefix+"%")
		if n != rounds {
			t.Errorf("%s owns %d of its %d rows — an identity crossed requests", who.principal, n, rounds)
		}
	}
	if n := f.scalar(`SELECT count(*) FROM audit_event`); n != 2*rounds {
		t.Errorf("audit rows = %d, want %d", n, 2*rounds)
	}
}

// TestARequestWithNoOriginHeaderIsAccepted is gate 2's `?.let` — the check runs ONLY when the header
// is present. Demanding one would break every CLI, and a browser always sends one on a cross-origin
// request, which is the case the gate guards.
func TestARequestWithNoOriginHeaderIsAccepted(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-no-origin@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead)

	res := f.post(toolCall(1, "list_roles", nil), bearer(token))
	if res.status != http.StatusOK {
		t.Fatalf("a request with no Origin was refused: %d %s", res.status, res.rawBody)
	}
	// An UNPARSEABLE Origin, on the other hand, is refused — `runCatching { URI(raw) }.getOrNull()`
	// on the Kotlin side, `url.Parse` here. The value is an unterminated IPv6 literal, which BOTH
	// parsers reject ("missing ']' in host" / URISyntaxException) and which is still a legal HTTP
	// header value, so the parse-failure arm is genuinely reached rather than blocked by the client.
	bad := f.post(toolCall(2, "list_roles", nil), bearer(token), header("Origin", "http://[::1"))
	if bad.status != http.StatusForbidden {
		t.Errorf("an unparseable Origin was accepted: %d %s", bad.status, bad.rawBody)
	}
}

// TestNewRefusesToBootOnAnUnclassifiedAuthzAction is 🔒 INV-A11-1 asserted where it actually bites.
//
// registry_test.go's TestVerifyRejectsAnUnclassifiedAuthzAction proves [Verify] catches the drift, and
// TestNewRefusesToBootOnACatalogMismatch proves the CONSTRUCTOR propagates INV-A11-2's failure. This is
// the missing corner of that pair: INV-A11-1's failure through [New]. Adding a Cedar action to A2's
// enum must fail the boot, not just a unit test that a wiring change could stop calling.
//
// ⚠️ It mutates a package-level var, so it must never be `t.Parallel()`. No test in this package is.
func TestNewRefusesToBootOnAnUnclassifiedAuthzAction(t *testing.T) {
	restoreCatalog(t)
	ExcludedActions = slices.Clone(ExcludedActions)[1:]

	cfg := config.Defaults()
	cfg.MCPResource = testResource
	if _, err := New(Options{Config: cfg}); err == nil {
		t.Fatal("New booted with an unclassified AuthzAction; INV-A11-1's check must abort startup")
	} else if !strings.Contains(err.Error(), "explicitly MCPA in-scope or deferred") {
		t.Errorf("error = %v, want the registry's own message", err)
	}
}

// TestATimedOutContextDoesNotLeaveAHalfAppliedMutation is a sanity net around INV-A11-10's transaction:
// a client that hangs up mid-mutation must leave nothing behind. It is not in the Kotlin suite, and it
// is cheap here because the whole tool body runs on one transaction.
func TestATimedOutContextDoesNotLeaveAHalfAppliedMutation(t *testing.T) {
	f := newMcpFixture(t)
	principal := "mcp-cancel@example.com"
	f.grantRole(principal, "system:admin")
	token := f.mintToken(principal, ScopeRead, ScopeIdentityWrite)

	// Hold the row `create_group` will need to write against, then cancel the caller.
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(f.ctx,
		`INSERT INTO app_group (name, source) VALUES ('cancelled-group', 'LOCAL')`); err != nil {
		t.Fatalf("hold the name: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.server.URL+"/mcp",
		strings.NewReader(toolCall(1, "create_group", map[string]any{"name": "cancelled-group"})))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Host = f.defaultHost
	resp, err := f.server.Client().Do(req)
	if err == nil {
		resp.Body.Close()
	}

	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatalf("rollback the holder: %v", err)
	}
	if n := f.scalar(`SELECT count(*) FROM app_group WHERE name='cancelled-group'`); n != 0 {
		t.Errorf("the cancelled mutation left %d rows behind", n)
	}
}
