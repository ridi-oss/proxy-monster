package app

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"time"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/audit"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/authz"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/config"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/core"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/oidc"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/policy"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/queryhistory"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/result"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/session"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// IngestTokenHeader is the header POST /api/ingest/decision is gated by. It carries the SAME shared
// secret as the gRPC transport (PM_SECRET_TOKEN) under a different header name, because the ingest
// caller is the same proxy.
const IngestTokenHeader = "X-PM-Ingest-Token"

// SystemAdminRole is the role /health reports on. A clean install has the role but no assignee, and
// that state is REPORTED, not marked down.
const SystemAdminRole = "system:admin"

// noActiveAssigneeDiagnostic is the exact string ReadinessDiagnosticDbTest case 2 asserts
// (03-identity-scim.md §7): `diagnostics = ["system:admin role has no active assignee"]` on a clean
// install, and an empty list once a direct assignment exists.
const noActiveAssigneeDiagnostic = SystemAdminRole + " role has no active assignee"

// HealthResponse is GET /health's body.
//
// 🔒 INV-A1-4 — `diagnostics` is a non-null Kotlin List, so with encodeDefaults = true it is ALWAYS
// PRESENT, as [] at minimum. Go's nil slice marshals as null, which is a different shape, so the
// handler normalises it. No omitempty on either field.
type HealthResponse struct {
	Status      string   `json:"status"`
	Diagnostics []string `json:"diagnostics"`
}

// IngestResponse is POST /api/ingest/decision's 202 body.
type IngestResponse struct {
	Status string `json:"status"`
}

// HTTPSurface is what `Application.module(config, core)` builds: the plugin stack, the shared
// request-time dependencies every route group needs, and the mux they register on.
//
// It exists as a value (rather than everything being local to a constructor) for one reason: a route
// group needs [Sessions] and [Gates], and both must be the SAME instances every other group holds.
// Ktor gets that from the application object and its attributes; here it is this struct.
type HTTPSurface struct {
	// Router is the mux plus the CallLogging/StatusPages/Sessions stack.
	Router *httpapi.Router
	// Sessions is the Sessions + Authentication plugin pair over the one PrincipalSessionStore.
	Sessions *httpapi.Sessions
	// Gates is requireApi / requireAdmin / requireAuthz / requireScimAuth.
	Gates *httpapi.Gates
	// SessionStore is `principalSessionStore` (App.kt:385) — the PRINCIPAL_SESSION_STORE attribute.
	SessionStore *session.Store
}

// NewHTTPSurface is `Application.module(config, core)`'s composition, minus the routes themselves.
//
// INV-A1-3 — reconcileOrphanedExecutions runs here as well as in Boot. Idempotent by design; the
// Kotlin keeps both calls (Main.kt:50 and App.kt:351) and so does this.
func NewHTTPSurface(ctx context.Context, cfg config.Config, c *core.ControlPlaneCore, log *slog.Logger) *HTTPSurface {
	if log == nil {
		log = slog.Default()
	}
	if err := c.AccessStore.ReconcileOrphanedExecutions(ctx); err != nil {
		log.Warn("reconcile orphaned executions (module)", "err", err)
	}

	// Startup warning, NON-FATAL: a malformed trusted-proxy entry fails CLOSED (that hop is
	// untrusted), which presents as "forwarded headers stopped working" with nothing pointing at the
	// cause. Log it; do not refuse to boot, since a narrower trust set is the safer failure.
	// TODO(A12): unusableTrustedProxyEntries — see 12-request-context.md.

	// `resultCrypto` (App.kt:372): AES-256-GCM at rest for the PII-bearing rows the control plane
	// persists — query results AND the encrypted refresh tokens on principal sessions. Nil when
	// PM_RESULT_KEY is unset, and 🔒 INV-A4-14 makes that mean the refresh token is DROPPED rather
	// than stored in plaintext.
	var crypto session.Crypto
	if cfg.ResultKey != nil {
		// Config rule V11 already proved the key base64-decodes to exactly 32 bytes, so the only way
		// this fails is a bug in that validation. Logging and continuing without crypto would silently
		// re-enter the INV-A4-14 posture on a deployment that DID configure a key, so it is loud.
		rc, err := result.NewCrypto(cfg.ResultKey)
		if err != nil {
			log.Error("PM_RESULT_KEY did not yield a cipher; refresh tokens will not be persisted", "err", err)
		} else {
			crypto = rc
		}
	}

	// `principalSessionStore` (App.kt:385-399). The end seam is deliberately unwired:
	//
	//	TODO(A1): OnWebSessionEnded must call queryResultStore.deleteEditorResultsForPrincipal and
	//	runExecService.closeSessionsForPrincipal (both A7, both unported). 🔒 INV-A4-30 — whatever is
	//	registered must write on the CONNECTION the seam hands it, so a deprovision teardown that
	//	later aborts rolls the deletion back with it. internal/session pins that property already.
	sessionStore := session.NewStore(c.DB.Pool, session.Options{
		Crypto:                 crypto,
		WebSessionIdleSeconds:  cfg.WebSessionIdleSeconds,
		WebSessionSlideSeconds: cfg.WebSessionSlideSeconds,
	})

	// The `install(Sessions)` block's five signed cookies all share one codec: `path=/`, `httpOnly`,
	// `secure = mcpIssuer.startsWith("https://")`, `SameSite=Lax`, MAC'd with sessionSecret's bytes.
	codec := session.NewCookieCodec(cfg.SessionSecret, cfg.MCPIssuer())

	sessions := &httpapi.Sessions{
		Codec:           codec,
		Storage:         httpapi.StoreSessionStorage{Store: sessionStore},
		Resolver:        sessionStore,
		AbsoluteSeconds: cfg.WebSessionAbsoluteSeconds,
		Log:             log,
	}

	gates := &httpapi.Gates{
		Config: cfg,
		// 🔒 INV-A1-1 — the SHARED Authz. A second graph would keep its own policy-cache counter and
		// go silently stale the first time a policy is edited on the other one.
		Authz:    c.Authz,
		Sessions: sessions,
		Log:      log,
		// Context is left nil: A12's httpAuthzContext is unported, so gate decisions carry no
		// requester_ip. Fail-closed, and documented on httpapi.Gates.Context.
		//	TODO(A12): 12-request-context.md.
	}

	router := httpapi.NewRouter(httpapi.RouterOptions{Sessions: sessions, Log: log})

	surface := &HTTPSurface{Router: router, Sessions: sessions, Gates: gates, SessionStore: sessionStore}

	// `PolicyManagementService(CedarPolicyStore(dataSource), policyStore)` — ONE instance, shared by
	// every route group that reaches it (A1's /auth/debug, A2's /api/policies, A9's roles and mask
	// functions). It is stateless over the two stores, so a second instance would not be wrong the way
	// a second CedarPolicyStore would (INV-A1-1) — but it would be a second place to keep in step, and
	// the whole point of `c.CedarPolicyStore` being on the core is that there is exactly one.
	management := policy.NewPolicyManagement(c.CedarPolicyStore, c.PolicyStore)

	// The route table. Every area mounts as one RouteGroup, so adding an area is a line HERE and a
	// Register method THERE — no edit to the plugin stack, and no edit to app.go.
	router.Mount(
		coreRoutes(cfg, c, log),

		// A1's own auth + session surface — the seven routes App.kt declares directly in module().
		&authRoutes{
			config:   cfg,
			gates:    gates,
			sessions: sessions,
			store:    sessionStore,
			// 🔒 INV-A1-1 — the SAME Authz the gates hold. computeMePermissions and requireAdmin must
			// agree on one policy-cache counter, or the console renders an admin area whose every call
			// 403s.
			authz:            c.Authz,
			evaluatesInCedar: c.Authz.EvaluatesInCedar,
			roles:            c.RoleResolver,
			management:       management,
			db:               c.DB.Pool,
			log:              log,
		},

		// A2 §8 — `/api/policies`, eight routes, every one requireAdmin(ADMIN_POLICIES).
		policy.NewCedarPolicyRoutes(gates, management, log),

		// A9 §3 — roles, role assignments and mask functions, eleven routes.
		// ⚠️ NOT uniformly gated: `GET /api/roles` is requireApi (🔒 INV-A9-3, deliberate — two
		// non-admin web surfaces drive JIT elevation off it), assignments are ADMIN_IDENTITY, the rest
		// ADMIN_POLICIES. The map is in policy.Routes' doc comment and swept by its route suite.
		policy.NewRoutes(gates, management, log),

		// A8 §3 — the two audit read routes, both requireApi with the authorization INSIDE
		// (🔒 INV-A8-6, INV-A8-7).
		//
		// 🔒 THE SAME `cfg.AuthDebug` GOES TO BOTH the Reader and (through Config) the gates, and it
		// must. They are two fields with no enforced agreement: gate-on + reader-off admits a
		// sessionless request the reader cannot then serve, and the handler answers 500
		// common.fallback. Fail-closed, but a 500 on a live surface — audit's
		// TestTheGateAndTheReaderMustAgreeAboutAuthDebug measures it, and
		// TestAuditRoutesGetOneAuthDebugValue below pins this line.
		audit.NewRoutes(gates, &audit.Reader{
			Store: c.AuditStore,
			// 🔒 INV-A1-1 — the SHARED Authz again. The audit read model is a Cedar decision like any
			// other, and a second graph here would answer from a stale policy set.
			Authz:     c.Authz,
			AuthDebug: cfg.AuthDebug,
		}, log),

		// A7 §9 — `/api/query-history`, two routes, requireApi, principal-scoped from the session and
		// only from the session.
		queryhistory.NewRoutes(gates, queryhistory.New(c.DB.Pool), log),

		// `oidcRoutes(config, discovery, validator, oidcHttp, userGroupStore, roleResolver,
		// principalSessionStore, log)` (App.kt:599-602). Nil when OIDC is unconfigured — [Router.Mount]
		// skips nils, which is what lets the optional area mount without a branch here.
		oidcRoutes(cfg, c, sessions, sessionStore, log),

		// The remaining ~110 routes of App.kt's composition root. Each is a whole area, listed so the
		// gap is a visible inventory rather than an assumed one.
		//
		//	TODO(A1):  the SSE /api/tasks/events stream, and the two background timer loops
		//	           (purge/sweep every 15 min, sweepSessionLiveness every idpRecheckInterval).
		//	           Both need A7's RunExecService / QueryResultStore.
		//	TODO(A3):  identity + SCIM routes                      — 03-identity-scim.md
		//	TODO(A4):  wire tokens, device auth, /auth/session/renew — 04-auth-session-tokens.md
		//	           (internal/device already exposes Register(mux) and mounts here once its store
		//	           lands.)
		//	TODO(A5):  datasource + catalog admin routes           — 05-datasources-catalog.md
		//	TODO(A6):  queryRoutes, editorSessionRoutes, accessRoutes — 06-query-decision.md
		//	TODO(A7):  tasks, approvals, results (minus §9's query history, mounted above)
		//	                                                       — 07-tasks-approvals-results.md
		//	TODO(A11): MCP, OAuth, management                      — 11-mcp-oauth-management.md
		//
		// ⚠️ SSE is deliberately NOT installed by App.kt (the MCP SDK's mount installs it and Ktor
		// throws on a duplicate install). A Go port that replaces the MCP mount must supply SSE itself.
	)

	return surface
}

// oidcRoutes builds `Route.oidcRoutes(...)` (App.kt:599-602). It ALWAYS returns a group.
//
// 🔒 THE GROUP MOUNTS UNCONDITIONALLY, and that is the fix for a real divergence this file used to
// carry. Ktor mounts `oidcRoutes` with no condition and each handler runs the guard
// `config.oidc == null || discovery == null || validator == null` ⇒ 501
// `ApiError("common.oidc_not_configured")` (04-auth-session-tokens.md:281-282; OidcCallbackTest case
// 2 asserts that 501). An earlier shape here returned nil when `cfg.OIDC == nil`, which
// [Router.Mount] skips — so an unconfigured deployment answered 404 where the Kotlin answers 501,
// i.e. a console showing "that page does not exist" instead of "SSO is not set up on this
// deployment". [oidc.Routes] already reproduces the guard, so the faithful shape is simply to hand
// it nil Discovery/Validator and let the guard answer.
//
// Discovery and Validator are nil ONLY when `cfg.OIDC` is nil, because both need the issuer URL that
// `cfg.OIDC` carries. That is exactly the condition the guard checks, so the three nils never
// disagree.
//
// Pinned by TestOidcRoutesAnswer501WhenOidcIsUnconfigured and by TestTheModuleMountsEveryA1Route.
func oidcRoutes(
	cfg config.Config, c *core.ControlPlaneCore, sessions *httpapi.Sessions,
	sessionStore *session.Store, log *slog.Logger,
) httpapi.RouteGroup {
	routes := &oidc.Routes{
		Config:     cfg,
		Cookies:    sessions.Codec,
		UserGroups: &oidcUserGroups{provisioner: oidc.NewDirectoryProvisioner(c.DB.Pool)},
		Roles:      c.RoleResolver,
		Sessions:   &oidcWebSessions{store: sessionStore, sessions: sessions},
		Log:        log,
	}
	if cfg.OIDC != nil {
		hc := oidc.NewHTTPClient()
		discovery := oidc.NewDiscovery(hc, cfg.OIDC.Issuer)
		routes.Discovery = discovery
		routes.Validator = oidc.NewIDTokenValidator(discovery, cfg.OIDC.Issuer, cfg.OIDC.ClientID, hc, log)
		routes.HTTP = hc
	}
	return routes
}

// oidcWebSessions is the adapter internal/oidc's seams.go asks A1 for: "the adapter A1 writes is
// three lines each".
//
// 🔒 SetSessionCookie is BOTH HALVES — the storage link AND the cookie — and that is the whole
// reason the seam exists rather than the callback writing a cookie itself. Ktor's session storage
// does the link implicitly on `sessions.set`; a Go port that wrote only the cookie would leave
// `principal_session.session_key` NULL, and `/auth/logout`'s EndWebBySessionKey would then end
// NOTHING (INV-A4-7, INV-A4-25) — a sign-out that silently leaves the row resolvable from a replayed
// cookie. [httpapi.Sessions.SetWebSession] keeps the two together and in the load-bearing order
// (link committed BEFORE Set-Cookie).
type oidcWebSessions struct {
	store    *session.Store
	sessions *httpapi.Sessions
}

func (a *oidcWebSessions) MintWeb(
	ctx context.Context, principal string, refreshToken *string, absoluteSeconds, idleSeconds int64, deviceID string,
) (int64, error) {
	return a.store.MintWeb(ctx, nil, session.MintWebInput{
		Principal:       principal,
		RefreshToken:    refreshToken,
		AbsoluteSeconds: absoluteSeconds,
		IdleSeconds:     idleSeconds,
		DeviceID:        &deviceID,
		// DebugRequesterIP stays nil: an SSO login has a real peer, and INV-A1-8 reports the simulated
		// address only for a debug login.
	})
}

func (a *oidcWebSessions) SetSessionCookie(w http.ResponseWriter, r *http.Request, sessionID int64) error {
	return a.sessions.SetWebSession(r.Context(), w, sessionID)
}

func (a *oidcWebSessions) EnsureDeviceCookie(w http.ResponseWriter, r *http.Request, secure bool) (string, error) {
	return session.EnsureDeviceCookie(w, r, secure)
}

// oidcUserGroups is `UserGroupStore.provisionFromOidc` (Users.kt:344-353), which is itself only:
//
//	val userId = OidcDirectoryProvisioner(dataSource).provision(principal, email, idpGroups, mapping)
//	return getUser(userId)!!
//
// The re-read exists solely to return an AppUser the OIDC callback never looks at, so the port drops
// it — [oidc.UserGroupProvisioner] returns error alone.
//
// 🔒 INV-A4-63 / INV-A14-37 — the reconciliation this delegates to is ADD **AND REMOVE**, not merge:
// dropping a user from the IdP admin group revokes their `system:admin` on their next login. That is
// the documented, accepted cost, and it lives in ONE implementation so web, device and MCP OAuth
// logins cannot drift on it.
//
//	TODO(A3): replace with identity.UserGroupStore.ProvisionFromOidc once A3 lands. It must be this
//	same two-line wrapper over [oidc.DirectoryProvisioner.Provision] — re-deriving the reconciliation
//	is how a second, subtly different membership semantics reaches production.
type oidcUserGroups struct{ provisioner *oidc.DirectoryProvisioner }

func (a *oidcUserGroups) ProvisionFromOidc(
	ctx context.Context, principal string, email *string, idpGroups []string, mapping oidc.GroupMapping,
) error {
	_, err := a.provisioner.Provision(ctx, principal, email, idpGroups, mapping)
	return err
}

// NewHTTPServer builds the HTTP surface over the SHARED core (INV-A1-1) and wraps it in a server.
func NewHTTPServer(ctx context.Context, cfg config.Config, c *core.ControlPlaneCore, log *slog.Logger) *http.Server {
	if log == nil {
		log = slog.Default()
	}
	surface := NewHTTPSurface(ctx, cfg, c, log)
	return &http.Server{
		Handler:           surface.Router.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

// coreRoutes are the two routes App.kt declares directly in `module()` that this increment carries:
// the readiness probe and the proxy's audit ingest. Both are ungated by any of the four gates —
// `/health` has no gate at all, and ingest has its own shared-secret header check.
func coreRoutes(cfg config.Config, c *core.ControlPlaneCore, log *slog.Logger) httpapi.RouteGroup {
	return httpapi.RouteGroupFunc(func(mux *http.ServeMux) {
		mux.HandleFunc("GET /health", healthHandler(c, log))
		mux.HandleFunc("POST /api/ingest/decision", ingestDecisionHandler(cfg, c, log))
	})
}

// healthHandler is `GET /health` — no gate.
//
// Diagnostics are two independent readiness signals:
//  1. whether system:admin has an ACTIVE ASSIGNEE (a clean install has none — the operator has not
//     opened the console yet);
//  2. authz.ContextTagLint over the enabled policy set — the dangling-tag lint of docs/authz-context.md,
//     which reports tag names produced with no consumer and consumed with no producer.
//
// 🔒 Status stays "ok" in both cases: an unopened install is REPORTED, not marked down. A readiness
// probe that failed on a fresh install would prevent the very first login that fixes it.
func healthHandler(c *core.ControlPlaneCore, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		diagnostics := []string{}

		hasAssignee, err := c.RoleResolver.HasActiveAssignee(r.Context(), SystemAdminRole)
		if err != nil {
			// A store failure is not a reason to report the install healthy-and-silent, but it is also
			// not the same fact as "no assignee". Report it as its own diagnostic.
			log.Warn("health: hasActiveAssignee failed", "role", SystemAdminRole, "err", err)
			diagnostics = append(diagnostics, "could not determine whether "+SystemAdminRole+" has an active assignee")
		} else if !hasAssignee {
			diagnostics = append(diagnostics, noActiveAssigneeDiagnostic)
		}

		diagnostics = append(diagnostics, authz.ContextTagLint(c.CedarPolicyStore.EnabledSources())...)

		writeJSON(w, http.StatusOK, HealthResponse{Status: "ok", Diagnostics: diagnostics}, log)
	}
}

// ingestDecisionHandler is `POST /api/ingest/decision` — the proxy's audit ingest.
//
// The gate is `X-PM-Ingest-Token == secretToken` WHEN SET; when PM_SECRET_TOKEN is unset the route is
// open, the same dev-only posture as the gRPC interceptor (INV-A10-2) and with the same production
// guard in Config. The comparison is constant-time for the same reason (INV-A10-3).
//
// INV-A8-3 — `rec.ts` is HONOURED WHEN SUPPLIED (proxy ingest may set it) and filled with the
// server's clock when absent. The store owns that; this handler passes the decoded event through
// verbatim so a replayed batch keeps its original timestamps.
//
// 202, not 200: ingest is an append to the hash chain, and the proxy fires it off the client
// session's critical path.
func ingestDecisionHandler(cfg config.Config, c *core.ControlPlaneCore, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg.SecretToken != nil {
			presented := r.Header.Get(IngestTokenHeader)
			if subtle.ConstantTimeCompare([]byte(presented), []byte(*cfg.SecretToken)) != 1 {
				writeJSON(w, http.StatusUnauthorized, types.ApiError{Code: "common.unauthenticated"}, log)
				return
			}
		}

		var event types.AuditEvent
		if err := httpapi.Receive(r, &event); err != nil {
			writeJSON(w, http.StatusBadRequest, types.ApiError{Code: "common.invalid_body"}, log)
			return
		}
		if _, err := c.AuditStore.Insert(r.Context(), event); err != nil {
			log.Error("audit ingest failed", "principal", event.Principal, "err", err)
			writeJSON(w, http.StatusInternalServerError, types.ApiError{Code: "common.internal_error"}, log)
			return
		}
		writeJSON(w, http.StatusAccepted, IngestResponse{Status: "accepted"}, log)
	}
}

// writeJSON is httpapi.RespondJSON with this package's logging convention. See httpapi.RespondJSON
// for why every body goes through types.MarshalWire rather than encoding/json (INV-A1-4).
func writeJSON(w http.ResponseWriter, code int, body any, log *slog.Logger) {
	if err := httpapi.RespondJSON(w, code, body); err != nil {
		log.Error("failed to write response", "status", code, "err", err)
	}
}
