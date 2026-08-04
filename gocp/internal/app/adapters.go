package app

// ---------------------------------------------------------------------------------------------
// The composition root's SEAM ADAPTERS.
//
// Every type in this file exists for one of exactly three reasons, and each one says which:
//
//	(1) THE IMPORT GRAPH. Two ported packages describe the same thing with two structurally
//	    identical types because neither may import the other (internal/management imports
//	    internal/datasource, so A5's routes cannot name a management type; internal/token does not
//	    know A5 exists). Go satisfies interfaces by signature, so the translation is a method here.
//	    These collapse the day a shared identity type lands.
//
//	(2) A CONVENTION SEAM. Two ported packages agree on the behaviour and disagree on the argument
//	    ORDER or the RESULT SHAPE — `(ctx, principal, c)` versus the port's `…On(ctx, c, …)`, or a
//	    generic `*T` versus a bool. Two defensible conventions meeting at one point; the closure is
//	    where they meet.
//
//	(3) A MULTI-AREA SEAM. One Kotlin callback that calls into TWO ported areas, so neither area can
//	    own it: [onWebSessionEnded] is A4's hook and its body is A7's result store plus A7's run
//	    transport. The composition root is the only place that holds both.
//
//	    ⚠️ This section used to be "UNPORTED-area stubs", and its rule — answer what a live control
//	    plane in the corresponding degraded state would answer, never a lie and never a panic — was
//	    written for `unportedRunExec`. That stub is GONE (internal/runexec landed), and the last
//	    stand-in on this surface is the nil management.TableDetails, which lives at its own call site
//	    in http.go rather than here.
// ---------------------------------------------------------------------------------------------

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/ridi-oss/proxy-monster/gocp/internal/approval"
	"github.com/ridi-oss/proxy-monster/gocp/internal/core"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/device"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
	"github.com/ridi-oss/proxy-monster/gocp/internal/management"
	"github.com/ridi-oss/proxy-monster/gocp/internal/mcp"
	"github.com/ridi-oss/proxy-monster/gocp/internal/oauth"
	"github.com/ridi-oss/proxy-monster/gocp/internal/policy"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/token"
)

// ---------------------------------------------------------------------------------------------
// (1) Import-graph adapters
// ---------------------------------------------------------------------------------------------

// wireTokens is (1) — `tokenStore.resolve(token)` as A5's bearer path consumes it.
//
// [datasource.TokenResolver] returns *datasource.WireTokenIdentity, a two-field reduction of
// token.Identity that internal/datasource declares itself because internal/token does not import A5
// and A5 will not import internal/token for one struct. The roles are DROPPED here and that is not a
// loss: `bearerWirePrincipal` reads the principal and the kind and nothing else.
//
//	TODO(A1): collapse when a shared wire-identity type lands. See datasource.WireTokenIdentity.
type wireTokens struct{ store *token.Store }

func (a wireTokens) Resolve(ctx context.Context, tok string) (*datasource.WireTokenIdentity, error) {
	id, err := a.store.Resolve(ctx, tok)
	if err != nil || id == nil {
		return nil, err
	}
	return &datasource.WireTokenIdentity{Principal: id.Principal, Kind: id.Kind}, nil
}

// mcpTokens is (1) — `McpTokenStore.resolveAccess` as A11's gate 3 consumes it.
//
// internal/oauth owns the query (INV-A14-9's audience binding is a WHERE clause there) and returns
// its own [oauth.AccessIdentity]; internal/mcp declares [mcp.AccessIdentity] because it must not
// depend on the OAuth token family's package. Same five fields, same order, no logic.
type mcpTokens struct{ store *oauth.MCPTokenStore }

func (a mcpTokens) ResolveAccess(ctx context.Context, tok, expectedResource string) (*mcp.AccessIdentity, error) {
	id, err := a.store.ResolveAccess(ctx, tok, expectedResource)
	if err != nil || id == nil {
		return nil, err
	}
	return &mcp.AccessIdentity{
		Principal: id.Principal, ClientID: id.ClientID, Resource: id.Resource,
		Scopes: id.Scopes, ConsentID: id.ConsentID,
	}, nil
}

// deviceWebSessions is (1) — `ApplicationCall.webSession()` as internal/device consumes it.
//
// 🔒 IT MUST GO THROUGH [httpapi.Sessions], NOT session.Store.ResolveWeb DIRECTLY. Sessions.Install
// caches the resolution per request, and A4's device-authorize branch 6 depends on the CACHED
// resolution being the same row the gates saw. Calling the store here would resolve a second time,
// re-run the idle/absolute clocks against a later instant, and could answer a different row than the
// gate on the same request.
type deviceWebSessions struct{ sessions *httpapi.Sessions }

func (a deviceWebSessions) WebSession(_ context.Context, r *http.Request) (*device.WebSession, error) {
	row, err := a.sessions.WebSession(r)
	if err != nil || row == nil {
		return nil, err
	}
	return &device.WebSession{ID: row.ID, Principal: row.Principal}, nil
}

// approvalRoleLister is (1) — `policyStore.listRoles()` as A7's role discovery consumes it.
//
// [approval.Role] is (id, name); policy.Role carries a description too. internal/approval declares
// its own so it need not import internal/policy.
//
// ⚠️ The ORDER is internal/policy's `ORDER BY name`, not the `ORDER BY id` A7's own fixture uses.
// `discoverRoles` iterates this list and the FIRST role that unlocks the query wins ties, so the
// order is observable in `suggestedRoles`. Production must be the store's order; the fixture's is a
// fixture detail.
func approvalRoleLister(store *policy.PolicyStore) approval.RoleLister {
	return func(ctx context.Context) ([]approval.Role, error) {
		rows, err := store.ListRoles(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]approval.Role, 0, len(rows))
		for _, r := range rows {
			out = append(out, approval.Role{ID: r.ID, Name: r.Name})
		}
		return out, nil
	}
}

// maskFnsForQuery is (1) — `policyStore.listMaskFns()` reduced to A6 step 19's (name, kind) pairs.
// It is exactly core.MaskFns, named here so the Decider's field reads as the seam it is.
func maskFnsForQuery(c *core.ControlPlaneCore) query.MaskFnLister { return c.MaskFns }

// ---------------------------------------------------------------------------------------------
// (2) Convention seams
// ---------------------------------------------------------------------------------------------

// activePrincipalMinter is (2) — A3's `mintForActivePrincipalLocked` as internal/device consumes it.
//
// 🔒 IT WRAPS THE REAL IMPLEMENTATION, [token.MintForActivePrincipalLocked], and adds nothing: the
// advisory lock, the on-transaction deprovisioning re-check and the single-transaction property
// (INV-A3-7 / INV-A4-50) all come from there. The only translation is the RESULT SHAPE — the generic
// returns `*T` because its callers need the minted value, while the device seam's body writes through
// its own closure and only needs "did it run".
//
// A `struct{}` type parameter is what makes that explicit: there is no value to carry.
//
//	TODO(A3/A4): when token.MintForActivePrincipalLocked relocates into internal/identity's
//	deprovision.go — which internal/identity/deprovision.go already reserves a comment for — this
//	adapter moves with it and should be re-pointed, not re-implemented.
type activePrincipalMinter struct {
	db    store.Beginner
	users *identity.UserGroupStore
}

func (m activePrincipalMinter) MintForActivePrincipalLocked(
	ctx context.Context, principal string, body func(ctx context.Context, c store.Queryer) error,
) (bool, error) {
	out, err := token.MintForActivePrincipalLocked(ctx, m.db, m.users, principal,
		func(ctx context.Context, c store.Queryer) (struct{}, error) {
			return struct{}{}, body(ctx, c)
		})
	if err != nil {
		return false, err
	}
	// nil is the Kotlin's null return: the principal is deprovisioned and NOTHING was written.
	return out != nil, nil
}

// isDeactivatedOnLockedConn is (2) — A3's deactivation read with [session.RenewLocked]'s argument
// order.
//
// RenewLocked takes `(ctx, principal, c)` because Kotlin's callback is `{ principal, c -> … }`;
// internal/identity follows the port's `…On(ctx, c, …)` convention. Two defensible conventions
// meeting at one seam.
//
// 🔒 It MUST run on `c`, the locked transaction RenewLocked opened — that is the whole point of the
// seam being a func rather than a store method (INV-A4-31).
func isDeactivatedOnLockedConn(users *identity.UserGroupStore) func(context.Context, string, store.Queryer) (bool, error) {
	return func(ctx context.Context, principal string, c store.Queryer) (bool, error) {
		return users.IsDeactivatedOn(ctx, c, principal)
	}
}

// renewalMint is (2) — `tokenStore.issue(SESSION, fresh.principal, emptyList(), name = null,
// ttlSeconds = fresh.ttlSeconds, c)` (DaemonSession.kt:656) as [session.RenewRoutes.Mint].
//
// 🔒 ALL FOUR OF RenewRoutes.Mint's CONTRACT POINTS ARE THIS FUNCTION'S BODY, and a wiring that gets
// any of them wrong still compiles:
//
//  1. the kind is [token.KindSession] — a renewed credential must pass `validate`, so it cannot be
//     one of the two ephemeral kinds (INV-A4-56);
//  2. the roles snapshot is EMPTY (nil) — INV-A4-2, effective roles are re-resolved at decide time;
//  3. the TTL is `fresh.TTLSeconds`, off the row read UNDER THE LOCK, never the pre-lock row the
//     route resolved by hash (INV-A4-31);
//  4. it issues on `c`, the locked transaction.
//
// [session.Minted] is a two-field reduction of token.Issued for the reason RenewLocked is generic:
// internal/session must not depend on the token store.
func renewalMint(tokens *token.Store) func(context.Context, session.DaemonRow, store.Queryer) (session.Minted, error) {
	return func(ctx context.Context, fresh session.DaemonRow, c store.Queryer) (session.Minted, error) {
		issued, err := tokens.Issue(ctx, c, token.KindSession, fresh.Principal, nil, nil, fresh.TTLSeconds)
		if err != nil {
			return session.Minted{}, err
		}
		return session.Minted{Token: issued.Token, ExpiresAt: issued.ExpiresAt}, nil
	}
}

// datasourceLiveness is (2) — `management.getDatasourceLiveness(name).attached`, the ONE field
// `POST /api/datasources/{id}/test` reads off the liveness DTO.
//
// A func because `management.DatasourceLiveness` is declared in internal/management, which imports
// internal/datasource: A5 has no way to name the type. The REAL management call still runs, including
// its by-NAME re-lookup — whose `common.not_found{resource: datasource}` the `{id}/test` route
// deliberately does NOT catch, so it reaches StatusPages as 500 common.fallback.
func datasourceLiveness(mgmt *management.DatasourceService) datasource.LivenessFunc {
	return func(ctx context.Context, name string) (bool, error) {
		live, err := mgmt.GetDatasourceLiveness(ctx, name)
		if err != nil {
			return false, err
		}
		return live.Attached, nil
	}
}

// oauthWebSessions is (2) — [oauth.WebSessions] over the same session store and cookie writer
// [oidcWebSessions] uses.
//
// 🔒 IT IS A SECOND ADAPTER RATHER THAN A SHARED ONE FOR EXACTLY ONE PARAMETER: `debugRequesterIP`.
// INV-A11-19 is entirely about that argument surviving the OAuth debug branch's session remint, and
// [oidc.WebSessions] cannot express it — an SSO login has a real peer and passes nothing. The Kotlin
// has one `mintWeb` with the parameter defaulted and two callers that differ; Go needs two
// interfaces, and giving them one implementation each is clearer than one type with a dead argument.
//
// Both adapters share the SAME *session.Store and the SAME *httpapi.Sessions, so the newest-wins
// displacement and the tracker link behave identically whichever login path ran.
type oauthWebSessions struct {
	store    *session.Store
	sessions *httpapi.Sessions
}

func (a *oauthWebSessions) MintWeb(
	ctx context.Context, principal string, refreshToken *string,
	absoluteSeconds, idleSeconds int64, deviceID string, debugRequesterIP *string,
) (int64, error) {
	return a.store.MintWeb(ctx, nil, session.MintWebInput{
		Principal:        principal,
		RefreshToken:     refreshToken,
		AbsoluteSeconds:  absoluteSeconds,
		IdleSeconds:      idleSeconds,
		DeviceID:         &deviceID,
		DebugRequesterIP: debugRequesterIP,
	})
}

func (a *oauthWebSessions) SetSessionCookie(w http.ResponseWriter, r *http.Request, sessionID int64) error {
	return a.sessions.SetWebSession(r.Context(), w, sessionID)
}

func (a *oauthWebSessions) EnsureDeviceCookie(w http.ResponseWriter, r *http.Request, secure bool) (string, error) {
	return session.EnsureDeviceCookie(w, r, secure)
}

// ---------------------------------------------------------------------------------------------
// (3) Multi-area seams
// ---------------------------------------------------------------------------------------------

// onWebSessionEnded is the `OnWebSessionEnded` seam App.kt:385-399 registers on the session store.
//
// 🔒 INV-A4-30 — IT WRITES ON THE CONNECTION THE SEAM HANDS IT, never on the pool. A deprovision
// teardown that later aborts must roll this deletion back with it; a second connection would commit
// the delete independently and leave the session row alive with its results gone.
//
// The Kotlin calls TWO things here and so does this, in the same order:
//
//	queryResultStore.deleteEditorResultsForPrincipal(principal, c)
//	runExecService.closeSessionsForPrincipal(principal)
//
// 🔒 The second is what makes a sign-out release the BACKEND CONNECTIONS the principal's editor tabs
// were holding, and revoke each session's ephemeral token. Without it a logged-out user's held
// connections survive until the 30-minute idle sweep, each with a live EDITOR credential.
//
// ⚠️ It runs OUTSIDE the transaction, unavoidably: closing a session is in-memory work plus its own
// token revoke, so it cannot join `c`. The consequence to accept is the Kotlin's — a teardown that
// later aborts leaves the streams closed and the tokens revoked while the session row is restored. The
// asymmetry is safe in the fail-closed direction (credentials gone, row alive), which is why the
// ordering is: DB write first, so a failing delete aborts before any stream is dropped.
func onWebSessionEnded(
	results resultDeleter, sessions runSessionCloser, log *slog.Logger,
) func(context.Context, string, store.Queryer) error {
	return func(ctx context.Context, principal string, c store.Queryer) error {
		if results != nil {
			// PM_RESULT_KEY unset ⇒ no result storage ⇒ nothing was ever written to delete.
			n, err := results.DeleteEditorResultsForPrincipalOn(ctx, c, principal)
			if err != nil {
				return err
			}
			if n > 0 {
				log.Info("web session ended: editor results deleted", "principal", principal, "rows", n)
			}
		}
		if sessions != nil {
			sessions.CloseSessionsForPrincipal(principal)
		}
		return nil
	}
}

// runSessionCloser is the one method [onWebSessionEnded] needs from A7's run transport. Declared as an
// interface for the same reason [resultDeleter] is: a nil is a legal state a test can express.
type runSessionCloser interface {
	CloseSessionsForPrincipal(principal string)
}

// resultDeleter is the one method [onWebSessionEnded] needs from A7's result store. It is an
// interface so a nil result store (PM_RESULT_KEY unset) is a genuinely nil interface rather than a
// typed nil pointer — the difference between "no results were ever stored" and a nil dereference.
type resultDeleter interface {
	DeleteEditorResultsForPrincipalOn(ctx context.Context, c store.Queryer, principal string) (int64, error)
}
