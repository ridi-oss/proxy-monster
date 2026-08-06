package app

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/approval"
	"github.com/ridi-oss/proxy-monster/gocp/internal/audit"
	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/core"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/device"
	"github.com/ridi-oss/proxy-monster/gocp/internal/grpcsvc"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
	"github.com/ridi-oss/proxy-monster/gocp/internal/management"
	"github.com/ridi-oss/proxy-monster/gocp/internal/mcp"
	"github.com/ridi-oss/proxy-monster/gocp/internal/oauth"
	"github.com/ridi-oss/proxy-monster/gocp/internal/oidc"
	"github.com/ridi-oss/proxy-monster/gocp/internal/policy"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/queryhistory"
	"github.com/ridi-oss/proxy-monster/gocp/internal/result"
	"github.com/ridi-oss/proxy-monster/gocp/internal/runexec"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/tabledetail"
	"github.com/ridi-oss/proxy-monster/gocp/internal/token"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
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
	// RunExec is `runExecService` (App.kt:361).
	//
	// It is exposed for two reasons the other four fields do not share. First, A1's 15-minute purge
	// loop calls SweepIdleSessions on it, and that loop is still a TODO — leaving the service
	// unreachable would mean writing the loop could not find it. Second, and immediately: a DB test
	// that drives a fake proxy needs the SAME service instance the routes hold, so that openSession
	// and runOnSession can be called directly the way GrpcRunExecDbTest calls them.
	RunExec *runexec.Service
	// Liveness is the IdP revalidation sweep's dependency bundle, nil when no IdP is configured.
	// [App.StartLivenessSweep] is the timer that drives it (App.kt:430-443's loop 2).
	Liveness *oidc.LivenessDeps
}

// NewHTTPSurface is `Application.module(config, core)`'s composition: the plugin stack, the
// HTTP-only stores, the three management services, and every route group App.kt's `routing {}` block
// mounts.
//
// INV-A1-3 — reconcileOrphanedExecutions runs here as well as in Boot. Idempotent by design; the
// Kotlin keeps both calls (Main.kt:50 and App.kt:351) and so does this.
//
// 🔒 IT RETURNS AN ERROR BECAUSE `installMcp` CAN FAIL, and that failure is FATAL (INV-A11-1).
// [mcp.New] runs the capability-registry verification first — the check that the Cedar action set and
// the MCP tool catalog have not drifted apart — and A11 §2 says to "port it as a real startup check,
// not a comment". Booting past a drift either exposes an unreviewed action over MCP or silently hides
// a new one, so this propagates like a failed migration rather than logging and mounting the rest.
func NewHTTPSurface(
	ctx context.Context, cfg config.Config, c *core.ControlPlaneCore, log *slog.Logger,
) (*HTTPSurface, error) {
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
	var resultCrypto *result.Crypto
	if cfg.ResultKey != nil {
		// Config rule V11 already proved the key base64-decodes to exactly 32 bytes, so the only way
		// this fails is a bug in that validation. Logging and continuing without crypto would silently
		// re-enter the INV-A4-14 posture on a deployment that DID configure a key, so it is loud.
		rc, err := result.NewCrypto(cfg.ResultKey)
		if err != nil {
			log.Error("PM_RESULT_KEY did not yield a cipher; refresh tokens will not be persisted", "err", err)
		} else {
			resultCrypto = rc
		}
	}
	// `crypto` is the same object seen through internal/session's narrow interface. It must stay a
	// GENUINELY NIL interface when there is no key — a typed nil *result.Crypto in a non-nil interface
	// is not nil, and internal/session tests `crypto != nil` to decide whether to persist.
	var crypto session.Crypto
	if resultCrypto != nil {
		crypto = resultCrypto
	}

	// `queryResultStore` (App.kt:374): "Result storage is only available when PM_RESULT_KEY is set;
	// otherwise APPROVER_EXEC execution is refused fail-closed (no plaintext PII persisted)."
	//
	// 🔒 Nil for the same interface reason as `crypto`: approval.Deps.Results and [resultDeleter] both
	// test the interface for nil, and A7 answers 503 `approval.result_storage_not_configured` on it.
	var (
		resultStore  *result.Store
		resultsSeam  approval.ResultStore
		resultsPurge resultDeleter
	)
	if resultCrypto != nil {
		resultStore = result.NewStore(c.DB.Pool, resultCrypto)
		resultsSeam = resultStore
		resultsPurge = resultStore
	}

	// `runExecService = RunExecService(core, config.queryTimeoutSeconds)` (App.kt:361) — the CP-driven
	// run transport (internal/runexec).
	//
	// 🔒 IT TAKES THE SAME `c` THE gRPC SURFACE HOLDS, and that is not a convenience. The service
	// REGISTERS a pending run session on c.RunChannels and nudges c.ProxyEventsHub; the proxy's Ready
	// then arrives on the gRPC RunExec handler, which CLAIMS it from c.RunChannels. Two cores means the
	// nudge goes to a hub no proxy is attached to and the claim looks for a session nobody registered —
	// every query would answer 503 `query.no_proxy_attached` with a proxy sitting right there.
	//
	// 🔒 The second argument is PM_QUERY_TIMEOUT, and it is what makes the ephemeral token outlive the
	// statement it authorizes (INV-A7-30, conditionally — see config.RunTokenTTLSeconds's F26 note).
	// Dropping it silently falls back to the 600s default and a deployment with a longer timeout gets
	// UNAUTHENTICATED mid-run.
	runExec := runexec.New(runexec.Deps{
		Core:                c,
		QueryTimeoutSeconds: cfg.QueryTimeoutSeconds,
		Log:                 log,
	})

	// `principalSessionStore` (App.kt:385-399).
	//
	// 🔒 INV-A4-30 — the end seam writes on the CONNECTION it is handed, so a deprovision teardown
	// that later aborts rolls the editor-result deletion back with it. [onWebSessionEnded] carries
	// that, plus the run transport's own half — closing the principal's held editor streams.
	//
	// ⚠️ THAT IS WHY `runExec` IS BUILT ABOVE THIS AND NOT BELOW IT. The session store takes the end
	// seam as a constructor argument, so the transport has to exist first. App.kt has the same order
	// (runExecService at :361, principalSessionStore at :385) and it is load-bearing here rather than
	// incidental.
	sessionStore := session.NewStore(c.DB.Pool, session.Options{
		Crypto:                 crypto,
		WebSessionIdleSeconds:  cfg.WebSessionIdleSeconds,
		WebSessionSlideSeconds: cfg.WebSessionSlideSeconds,
		OnWebSessionEnded:      onWebSessionEnded(resultsPurge, runExec, log),
	})

	// The `install(Sessions)` block's five signed cookies all share one codec: `path=/`, `httpOnly`,
	// `secure = mcpIssuer.startsWith("https://")`, `SameSite=Lax`, MAC'd with sessionSecret's bytes.
	// The sixth, `pm_oauth_pending`, is App.kt:527's and rides the same codec.
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
		// Context is left nil DELIBERATELY: nil selects A12's real httpAuthzContext, so every gate
		// decision carries requester_ip. Setting it here would override the derivation. See
		// httpapi.Gates.Context.
	}

	// ---- HTTP-only stores (App.kt:360-374) ----------------------------------------------------
	//
	// "not on the gRPC decision path" — everything the decision path needs is already on `core`.
	queryHistoryStore := queryhistory.New(c.DB.Pool)
	deviceLoginStore := device.NewLoginStore(c.DB.Pool, resultCrypto)
	oauthStore := oauth.NewAuthorizationStore(c.DB.Pool)
	mcpTokenStore := oauth.NewMCPTokenStore(c.DB.Pool)

	// `taskCompletionHub` (App.kt:365): the in-process push of task terminal transitions to the SSE
	// stream. ONE instance — the approval routes and the editor routes publish onto it and
	// [approval.TaskEventsRoute] consumes it, and a second hub would mean a tab that never updates.
	taskCompletionHub := approval.NewTaskCompletionHub()

	// `revokeActiveCredentials`'s three stores, collapsed into one object (Deprovision.kt:57).
	//
	// 🔒 INV-A3-6 — THE SAME INSTANCE GOES TO BOTH THE SCIM ROUTES AND THE IDENTITY MANAGEMENT
	// SERVICE, and neither may receive nil. A nil there makes every SCIM/admin deactivate, rename and
	// deprovision commit its directory write with NO credential teardown: the directory says the
	// principal is gone while their wire tokens, JIT grants, daemon renewal windows and browser
	// sessions all keep working.
	credentials := identity.NewCredentials(c.DB.Pool, c.TokenStore, c.AccessStore, sessionStore)

	// ---- The three management services (App.kt:547-552) ---------------------------------------
	//
	// "MCPA transport adapters share these service instances with the REST surface and the one live
	// core." ONE of each, handed to both the REST route groups and `installMcp`.
	//
	// `tableDetailService` (App.kt:366) — the proxy-dialed live table introspection, with the
	// classification overlay the control plane owns.
	//
	// 🔒 IT TAKES core's OWN Channels AND Hub. The proxy's `TableDetailReady` arrives on the gRPC
	// surface and is routed by session id through [core.TableDetailChannelRegistry]; a second registry
	// here would leave the producer waiting on a slot nobody claims, so every table detail would time
	// out into a 502 that looks exactly like "no proxy attached".
	tableDetails := &tabledetail.Service{
		Channels:    c.TableDetailChannels,
		Hub:         c.ProxyEventsHub,
		Datasources: c.DatasourceStore,
	}
	datasourceManagement := management.NewDatasourceService(c.DatasourceStore, c.ProxyEventsHub, tableDetails)

	// `PolicyManagementService(CedarPolicyStore(dataSource), policyStore)` — ONE instance, shared by
	// every route group that reaches it (A1's /auth/debug, A2's /api/policies, A9's roles and mask
	// functions, and A11's MCP policy tools). It is stateless over the two stores, so a second instance
	// would not be wrong the way a second CedarPolicyStore would (INV-A1-1) — but it would be a second
	// place to keep in step, and the whole point of `c.CedarPolicyStore` being on the core is that
	// there is exactly one.
	policyManagement := policy.NewPolicyManagement(c.CedarPolicyStore, c.PolicyStore)

	identityManagement := management.NewIdentityService(c.DB.Pool, c.UserGroupStore, c.PolicyStore, credentials)

	// ---- `installMcp(config, core, …)` (App.kt:552) --------------------------------------------
	//
	// It runs BEFORE `routing {}` in the Kotlin and it is FATAL on error — see this function's doc.
	mcpRoutes, err := mcp.New(mcp.Options{
		Config:        cfg,
		DB:            c.DB.Pool,
		Tokens:        mcpTokens{store: mcpTokenStore},
		Deactivations: c.UserGroupStore,
		// 🔒 INV-A11-8 — the LIVE resolver, re-read per call, never a snapshot from the token.
		Roles: c.RoleResolver,
		// 🔒 INV-A1-1 again — the shared graph.
		Cedar:    c.Authz,
		Audit:    c.AuditStore,
		Policies: c.CedarPolicyStore,
		Services: mcp.Services{
			Datasources: datasourceManagement,
			Policies:    policyManagement,
			Identities:  identityManagement,
			MaskFns:     c.PolicyStore,
		},
		Log: log,
	})
	if err != nil {
		return nil, fmt.Errorf("boot: installMcp: %w", err)
	}

	// ---- The plugin stack ----------------------------------------------------------------------
	//
	// `installMcpOAuthProtocolGuard()` (App.kt:544) goes in as the INNERMOST wrapper. internal/oauth
	// also wraps each of its own handlers, deliberately; the pipeline-level install is what additionally
	// covers a 404 under `/oauth/`, which a mux cannot route to a handler at all.
	router := httpapi.NewRouter(httpapi.RouterOptions{
		Sessions:  sessions,
		Log:       log,
		Innermost: []httpapi.Middleware{oauth.ProtocolGuard},
	})

	// `oidcRoutes(...)` also yields the liveness sweep's dependency bundle, because it is what
	// constructs the Discovery/Validator/HTTP triple the sweep must SHARE with the login path.
	oidcGroup, liveness := oidcRoutes(cfg, c, sessions, sessionStore, log)

	surface := &HTTPSurface{
		Router: router, Sessions: sessions, Gates: gates, SessionStore: sessionStore, RunExec: runExec,
		Liveness: liveness,
	}

	// ---- The shared re-decision bundle ---------------------------------------------------------
	//
	// `decideResultView`, the compose preview and role discovery all need these eight seams; the
	// Kotlin threads them positionally through five call sites. ONE [approval.Decider] goes to BOTH
	// the approval group and the editor group, which is what makes it impossible to hand the two
	// different classifiers or different Cedar graphs.
	decider := &approval.Decider{
		Datasources: c.DatasourceStore,
		// Decide is left nil ⇒ query.DecideQuery, the production pipeline.
		MaskFns:    maskFnsForQuery(c),
		UserGroups: c.UserGroupStore,
		Roles:      c.RoleResolver,
		Authz:      c.Authz,
		// 🔒 INV-A5-60 — the REAL classifier, so a view or a preview classifies system tables exactly
		// as execution does. core.New already failed the boot if a manifest was malformed (INV-A5-55).
		SystemClassification: c.SystemClassification,
	}

	// `approvalRoutes(...)` and `editorSessionRoutes(...)` take overlapping parameter lists; one Deps
	// value goes to both for the same reason the Decider does.
	approvalDeps := approval.Deps{
		Gates:       gates,
		Decider:     decider,
		Access:      c.AccessStore,
		Audit:       c.AuditStore,
		Results:     resultsSeam,
		RunExec:     runExec,
		Roles:       approvalRoleLister(c.PolicyStore),
		SelfApprove: c,
		Hub:         taskCompletionHub,
		// Scope nil ⇒ `go f()`, the production `appScope.launch`.
		ExchangeTimeoutMs: cfg.QueryExchangeTimeoutMS(),
		Log:               log,
	}

	// ---- The route table -----------------------------------------------------------------------
	//
	// THE ORDER IS `App.kt`'s `routing {}` BLOCK (App.kt:554-770), top to bottom, with `installMcp`
	// hoisted above it exactly as the Kotlin hoists it above `routing`.
	//
	// ⚠️ The order is DOCUMENTATION, not dispatch. Ktor resolves overlapping paths by registration
	// order; Go 1.22+ patterns resolve them by SPECIFICITY, and a genuine conflict PANICS AT
	// REGISTRATION. So `/api/datasources/live` beating `/api/datasources/{id}`, and
	// `/api/approvals/inbox` beating `/api/approvals/{id}`, hold here regardless of where they are
	// mounted — each is pinned by its own package's suite. Keeping App.kt's order is what makes this
	// block diffable against the source, and nothing else.
	//
	// ⚠️ A1's own routes do NOT form one contiguous run in App.kt: `/health` and `/auth/config` open
	// the block, and `/api/ingest/decision`, `/auth/debug`, `mePermissionsRoute`, the three
	// session-authenticated routes and `/auth/logout` close it. The Go port has them as two groups
	// ([coreRoutes] and [authRoutes]) mounted here at the top, because a RouteGroup is the unit of
	// mounting and splitting either one across the list would buy nothing.
	router.Mount(
		// `installMcp(config, core, datasourceManagement, policyManagement, identityManagement)`
		// (App.kt:552) — the `/mcp` interceptor plus the two protected-resource discovery documents.
		//
		// 🔴 THE TWO `/.well-known/oauth-protected-resource[/mcp]` PATHS HAVE EXACTLY ONE OWNER AND IT
		// IS THIS GROUP (McpServer.kt:143-144). internal/oauth can serve them too — its
		// `MountProtectedResourceMetadata` flag — and that flag MUST stay false here: registering the
		// same pattern twice on a ServeMux panics at startup.
		mcpRoutes,

		// `get("/health")` (App.kt:561) and `post("/api/ingest/decision")` (App.kt:668).
		coreRoutes(cfg, c, log),

		// A1's own auth + session surface — `get("/auth/config")` (App.kt:581), `post("/auth/debug")`
		// (App.kt:686), `mePermissionsRoute` (App.kt:734), the three `authenticate(WEB_SESSION_AUTH)`
		// routes (App.kt:736-767) and `post("/auth/logout")` (App.kt:768).
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
			management:       policyManagement,
			db:               c.DB.Pool,
			log:              log,
		},

		// `oidcRoutes(...)` (App.kt:599-602) — /auth/oidc/login, /auth/oidc/callback.
		oidcGroup,

		// `mcpOAuthRoutes(config, dataSource, principalSessionStore)` (App.kt:606) — the OAuth 2.1 /
		// CIMD authorization server, nine routes.
		//
		// 🔒 INV-A11-20 — ONE ORIGIN, ONE SIGNED SESSION, NO SERVICE CREDENTIAL. It gets the SAME
		// session store, the SAME cookie codec and the SAME httpapi.Sessions as every other surface,
		// because the authorization server and the resource server are this one process.
		oauth.NewRoutes(cfg, oauthStore, codec, sessions,
			&oauthWebSessions{store: sessionStore, sessions: sessions},
			// Resolver nil ⇒ HttpCimdResolver(productionChecks = !authDebug), the Kotlin's default.
			nil, log),

		// `deviceSessionRoutes(...)` (App.kt:610) — the CLI/daemon login surface, four routes.
		&device.Routes{
			Config:   cfg,
			Store:    deviceLoginStore,
			Web:      deviceWebSessions{sessions: sessions},
			Sessions: sessionStore,
			Tokens:   c.TokenStore,
			// 🔒 INV-A4-50 — the REAL locked minter, not a check-then-create.
			Minter:  activePrincipalMinter{db: c.DB.Pool, users: c.UserGroupStore},
			Cookies: codec,
		},

		// ⚠️ `sessionRenewRoutes(...)` is registered from INSIDE `deviceSessionRoutes` in the Kotlin
		// (DeviceAuth.kt:359). internal/device deliberately does not do that, so it is mounted here —
		// immediately after the group that hosts it, so the two stay visibly adjacent. Forgetting this
		// line is silent: no compile error, no failing test, just a daemon fleet that stops renewing
		// twelve hours later.
		session.NewRenewRoutes(sessionStore,
			isDeactivatedOnLockedConn(c.UserGroupStore), renewalMint(c.TokenStore), log),

		// `scimRoutes(config, userGroupStore, tokenStore, accessStore, principalSessionStore, log)`
		// (App.kt:618) — SCIM 2.0 provisioning, fifteen routes, bearer+TLS gated.
		//
		// 🔒 The Kotlin's three credential stores are `credentials` here — see INV-A3-6 above.
		identity.NewScimRoutes(gates, c.UserGroupStore, credentials, log),

		// `datasourceRoutes(...)` (App.kt:623) — thirteen routes.
		datasource.NewRoutes(datasource.RouteDeps{
			Gates:        gates,
			Authz:        c.Authz,
			RoleResolver: c.RoleResolver,
			Store:        c.DatasourceStore,
			// 🔒 The REAL hub — `attached()` is in-memory liveness ("the open stream IS the liveness
			// signal"), so this must be the instance the gRPC Events handler registers on.
			Events:            c.ProxyEventsHub,
			Tokens:            wireTokens{store: c.TokenStore},
			Users:             c.UserGroupStore,
			Management:        datasourceManagement,
			Liveness:          datasourceLiveness(datasourceManagement),
			InspectTrustChain: grpcsvc.InspectTrustChain,
			Log:               log,
		}),

		// `policyRoutes(config, authz, policyStore, policyManagement)` (App.kt:627) — A9's eleven
		// routes: roles, role assignments and mask functions.
		//
		// ⚠️ NOT uniformly gated: `GET /api/roles` is requireApi (🔒 INV-A9-3, deliberate — two
		// non-admin web surfaces drive JIT elevation off it), assignments are ADMIN_IDENTITY, the rest
		// ADMIN_POLICIES. The map is in policy.Routes' doc comment and swept by its route suite.
		policy.NewRoutes(gates, policyManagement, log),

		// `userGroupRoutes(...)` (App.kt:633) — A3's fourteen admin routes over local users, groups
		// and the group→role map, every one ADMIN_IDENTITY.
		identity.NewRoutes(gates, c.UserGroupStore, identityManagement, log),

		// `accessRoutes(config, accessStore, authz, datasourceStore, roleResolver)` (App.kt:638) —
		// the six routes of the JIT role-elevation lifecycle.
		access.NewRoutes(gates, c.AccessStore, c.Authz, c.DatasourceStore, c.RoleResolver, log),

		// `approvalRoutes(...)` (App.kt:642) — A7's ten routes, every one requireApi with the real
		// authorization INSIDE (🔒 INV-A7-19: approver eligibility is a Cedar policy, never an
		// admin gate).
		approval.NewRoutes(approvalDeps),

		// `queryRoutes(config, datasourceStore, queryHistoryStore, runExecService)` (App.kt:648) —
		// `POST /api/datasources/{id}/query`, the synchronous query path.
		//
		// ⚠️ REGISTERED BY internal/query, NOT internal/datasource, even though the path sits under
		// A5's prefix — see query.Routes' doc and datasource.Routes.Register's warning. A duplicate
		// pattern PANICS ServeMux at boot, so the two groups must not both claim it.
		query.NewRoutes(query.RouteDeps{
			Gates:       gates,
			Datasources: c.DatasourceStore,
			History:     queryHistoryStore,
			RunExec:     runExec,
			// 🔒 The exchange budget is the DEPLOYMENT's, not the transport's fallback: the Kotlin
			// passes `config.queryExchangeTimeoutMs` at this exact call site so the proxy's own
			// PM_QUERY_TIMEOUT watchdog always fires first and the CP reports a timeout it can
			// attribute (INV-A7-31) rather than a bare stream abort.
			ExchangeTimeoutMs: cfg.QueryExchangeTimeoutMS(),
			Log:               log,
		}),

		// `editorSessionRoutes(...)` (App.kt:651) — A6's seven editor routes, built out of A7's parts.
		approval.NewEditorRoutes(approvalDeps),

		// `taskEventsRoute(config, taskCompletionHub, accessStore, authz, datasourceStore,
		// principalSessionStore, appJson)` (App.kt:657).
		//
		// 🔒 SSE: THE KTOR COUPLING DOES NOT EXIST HERE, AND NOTHING REPLACES IT. App.kt:464 does not
		// `install(SSE)` because the MCP SDK's mount installs it unconditionally and Ktor throws on a
		// duplicate install — so in Ktor this route's transport is a side effect of `installMcp`. In
		// Go there is no SSE plugin at all: [approval.TaskEventsRoute.stream] writes the
		// `text/event-stream` framing itself and flushes through http.NewResponseController. The two
		// mounts are therefore INDEPENDENT — removing `mcpRoutes` above would not break this stream,
		// which is the one behavioural difference and a strictly safer one. What DOES couple them is
		// httpapi's middleware: statusRecorder wraps every response and implements `Unwrap()` so the
		// controller can reach the real writer. Dropping that Unwrap silently buffers the stream.
		&approval.TaskEventsRoute{
			Gates:       gates,
			Hub:         taskCompletionHub,
			Access:      c.AccessStore,
			Datasources: c.DatasourceStore,
			Authz:       c.Authz,
			Sessions:    sessionStore,
			Log:         log,
		},

		// `queryHistoryRoutes(config, queryHistoryStore)` (App.kt:659) — two routes, requireApi,
		// principal-scoped from the session and only from the session.
		queryhistory.NewRoutes(gates, queryHistoryStore, log),

		// `tokenRoutes(config, tokenStore, userGroupStore, authz)` (App.kt:662) — wire-auth token
		// issuance and revocation, four routes.
		token.NewRoutes(gates, c.TokenStore, c.UserGroupStore, log),

		// `cedarPolicyRoutes(config, authz, cedarPolicyStore, policyManagement)` (App.kt:665) — A2's
		// eight routes, every one requireAdmin(ADMIN_POLICIES).
		policy.NewCedarPolicyRoutes(gates, policyManagement, log),

		// `auditRoutes(config, store, authz)` (App.kt:683) — the two read routes, both requireApi with
		// the authorization INSIDE (🔒 INV-A8-6, INV-A8-7).
		//
		// 🔒 THE SAME `cfg.AuthDebug` GOES TO BOTH the Reader and (through Config) the gates, and it
		// must. They are two fields with no enforced agreement: gate-on + reader-off admits a
		// sessionless request the reader cannot then serve, and the handler answers 500
		// common.fallback. Fail-closed, but a 500 on a live surface — audit's
		// TestTheGateAndTheReaderMustAgreeAboutAuthDebug measures it, and
		// TestAuditRoutesGetOneAuthDebugValue pins this line.
		audit.NewRoutes(gates, &audit.Reader{
			Store: c.AuditStore,
			// 🔒 INV-A1-1 — the SHARED Authz again. The audit read model is a Cedar decision like any
			// other, and a second graph here would answer from a stale policy set.
			Authz:     c.Authz,
			AuthDebug: cfg.AuthDebug,
		}, log),
	)

	// What App.kt:405-445 still has and this does not:
	//
	//	TODO(A1): the two background timer loops, both cancelled on application stop.
	//	  Loop 1, every RESULT_PURGE_INTERVAL_MS (15 min), each step wrapped so one failure does not
	//	  kill the loop: deviceLoginStore.purgeExpired → 🔒 INV-A1-5 queryResultStore
	//	  .purgeExpiredEditorChildren BEFORE .purgeExpired (purgeExpired NULLs expires_at on every
	//	  expired child, so an editor sweep after it never matches and those rows linger
	//	  payload-stripped forever) → runExecService.sweepIdleSessions(30 min) → connectionCatalog
	//	  .sweepIdle(60 min). ALL FOUR of the loop's steps now exist as methods — runexec.Service
	//	  .SweepIdleSessions landed with A7 — so what is missing is only the LOOP.
	//	  ⚠️ Consequence to accept meanwhile: an editor tab that is closed without a DELETE holds its
	//	  backend connection and its EDITOR token until the principal's web session ends
	//	  ([onWebSessionEnded] closes them), rather than 30 minutes after its last query.
	//	  Loop 2, every config.idpRecheckIntervalSeconds: sweepSessionLiveness — the SOLE revalidator
	//	  for web and daemon sessions, and itself unported (internal/oidc/refresh.go's TODO(A4)).
	//	  Consequence to accept meanwhile: expired device-login and result rows are reclaimed only
	//	  opportunistically on reads, and a session whose IdP refresh token has been revoked stays live
	//	  until its own absolute window closes.

	return surface, nil
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
) (httpapi.RouteGroup, *oidc.LivenessDeps) {
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
	if cfg.OIDC == nil {
		// No IdP configured: there is nothing to revalidate against, and SweepSessionLiveness would
		// return immediately anyway. Returning nil keeps the caller from starting a pointless ticker.
		return routes, nil
	}
	// 🔒 THE SWEEP SHARES THE ROUTES' Discovery/Validator/HTTP, deliberately. A second Discovery would
	// keep its own document cache, so the sweep and the login path could disagree about the IdP's
	// token endpoint after a rotation — and the sweep is the half that REVOKES on a bad answer.
	return routes, &oidc.LivenessDeps{
		RecheckIntervalSeconds: cfg.IdpRecheckIntervalSeconds,
		OIDC: &oidc.OIDCSettings{
			ClientID:     cfg.OIDC.ClientID,
			ClientSecret: cfg.OIDC.ClientSecret,
			GroupMapping: oidc.FromConfig(cfg.OIDC.GroupMapping),
		},
		Discovery: routes.Discovery,
		Validator: routes.Validator,
		HTTP:      routes.HTTP,
		Sessions:  sessionStore,
		Groups:    routes.UserGroups,
		Roles:     routes.Roles,
		Log:       log,
	}
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
//
// It propagates [NewHTTPSurface]'s error for the reason stated there: `installMcp` failing is a boot
// failure, not a degraded route.
func NewHTTPServer(
	ctx context.Context, cfg config.Config, c *core.ControlPlaneCore, log *slog.Logger,
) (*http.Server, *HTTPSurface, error) {
	if log == nil {
		log = slog.Default()
	}
	surface, err := NewHTTPSurface(ctx, cfg, c, log)
	if err != nil {
		return nil, nil, err
	}
	return &http.Server{
		Handler:           surface.Router.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}, surface, nil
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
				// 🔒 `call.invalidToken("ingest")` (App.kt:673) — 401 `common.invalid_token` with
				// `params.kind = "ingest"`, NOT `common.unauthenticated`. AuthAndIngestRoutesDbTest's
				// third case asserts both the code and the param, and the param is the whole point: the
				// proxy's ingest credential is PM_SECRET_TOKEN, a different secret from anything a
				// browser or a daemon holds, so "which credential did you get wrong" is the one piece of
				// information an operator reading a 401 here needs.
				if err := httpapi.RespondAPIError(w, types.InvalidToken(types.Ptr("ingest"))); err != nil {
					log.Error("failed to write response", "status", http.StatusUnauthorized, "err", err)
				}
				return
			}
		}

		var event types.AuditEvent
		if err := httpapi.Receive(r, &event); err != nil {
			// 🔒 415 BEFORE THE invalid_body 400, and before this route's own secret gate has anything to
			// say — measured: `POST /api/ingest/decision` with no Content-Type is 415 on the Kotlin
			// (r3-ingest-anon-nobody), while a proper JSON body agrees on both (r3-ingest-anon-withbody),
			// so the data plane's real path is untouched.
			if errors.Is(err, httpapi.ErrUnsupportedMediaType) {
				httpapi.RespondUnsupportedMediaType(w)
				return
			}
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
