package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
	"github.com/ridi-oss/proxy-monster/gocp/internal/policy"
	"github.com/ridi-oss/proxy-monster/gocp/internal/result"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/token"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// PORT of `DaemonSessionLivenessIdpTest` — 8 cases over a real Postgres and a real fake IdP.
//
// These were KT-DEFER for the whole prototype because [SweepSessionLiveness] did not exist: the
// Kotlin's sole IdP revalidator had no Go counterpart, so none of the eight could be true or false of
// anything. liveness.go is that counterpart and this is its 1:1 suite.
//
// WHAT THE SUITE IS FOR: the sweep is the only thing in the control plane that observes the OUTSIDE
// world, so its three-way outcome is the entire security contract. Every case below is a statement
// about which of the three arms fired and — just as importantly — what the OTHER two must not have
// touched. The recurring shape is "one row changed, its siblings and the principal's credentials did
// not", because a sweep that over-revokes is as broken as one that under-revokes.
//
// The refresh token IS the fixture's control channel, exactly as in the Kotlin: the fake IdP's token
// endpoint switches on the presented `refresh_token` string, so a row's stored token decides which
// arm it takes. That keeps a single sweep() call able to exercise several outcomes at once, which is
// what several of these cases assert about.
// ---------------------------------------------------------------------------------------------

const (
	rtInvalidGrant  = "rt-invalid-grant"
	rtInvalidClient = "rt-invalid-client"
	rtHTTP500       = "rt-http-500"
)

// activeRefresh is the Kotlin's `activeRefresh(principal, groups)`: an ACTIVE arm whose id_token
// carries exactly these groups.
func activeRefresh(principal string, groups ...string) string {
	return "rt-active:" + principal + ":" + strings.Join(groups, ",")
}

// noGroupsRefresh is `"rt-no-groups:$principal"` — an ACTIVE arm whose id_token OMITS the groups claim
// entirely, which INV-A4-63 treats as an authoritative empty set rather than "no information".
func noGroupsRefresh(principal string) string { return "rt-no-groups:" + principal }

type livenessFixture struct {
	t        *testing.T
	ctx      context.Context
	db       *store.Db
	idp      *fakeIdP
	cfg      config.Config
	sessions *session.Store
	users    *identity.UserGroupStore
	roles    *identity.RoleResolver
	policies *policy.PolicyStore
	access   *access.Store
	tokens   *token.Store
	// tokenRequests counts hits on the IdP token endpoint — case 8 turns on it.
	tokenRequests int
}

func newLivenessFixture(t *testing.T) *livenessFixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	idp := newFakeIdP(t, "session-liveness")

	cfg := config.Defaults()
	cfg.SessionSecret = "oidc-liveness-test-secret-not-for-prod"
	cfg.IdpRecheckIntervalSeconds = 300
	cfg.OIDC = &config.OIDCConfig{
		Issuer:       idp.issuer(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURI:  "http://unused/callback",
		Scopes:       "openid profile email groups offline_access",
		GroupMapping: config.OIDCGroupMapping{Map: map[string]string{}},
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	crypto, err := result.NewCrypto(key)
	if err != nil {
		t.Fatalf("result crypto: %v", err)
	}

	// foreignKey signs an id_token the published JWKS cannot verify.
	foreignKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("foreign key: %v", err)
	}

	users := identity.NewUserGroupStore(db.Pool)
	f := &livenessFixture{
		t: t, ctx: context.Background(), db: db, idp: idp, cfg: cfg,
		sessions: session.NewStore(db.Pool, session.Options{
			Crypto:                 crypto,
			WebSessionIdleSeconds:  cfg.WebSessionIdleSeconds,
			WebSessionSlideSeconds: cfg.WebSessionSlideSeconds,
		}),
		users:    users,
		policies: policy.NewPolicyStore(db.Pool),
		access:   access.NewStore(db.Pool),
		tokens:   token.NewStore(db.Pool),
	}
	f.roles = identity.NewRoleResolver(db.Pool, users, webGrantRoles{f.access})

	// The token endpoint, switching on the presented refresh_token — `tokenResponse(refreshToken)`.
	idp.mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenRequests++
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		rt := r.PostFormValue("refresh_token")
		switch {
		case rt == rtInvalidGrant:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		case rt == rtInvalidClient:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
		case rt == rtHTTP500:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"server_error"}`))
		case strings.HasPrefix(rt, "rt-no-groups:"):
			principal := strings.TrimPrefix(rt, "rt-no-groups:")
			claims := idp.defaultClaims(cfg.OIDC.ClientID)
			claims.subject = principal
			claims.email = principal
			claims.groups = nil // the claim is OMITTED, not empty
			idp.writeJSON(w, map[string]any{"access_token": "unused", "id_token": idp.sign(claims, nil)})
		case strings.HasPrefix(rt, "rt-active:"):
			parts := strings.SplitN(rt, ":", 3)
			principal := parts[1]
			var groups []any
			if len(parts) > 2 && parts[2] != "" {
				for _, g := range strings.Split(parts[2], ",") {
					groups = append(groups, g)
				}
			}
			claims := idp.defaultClaims(cfg.OIDC.ClientID)
			claims.subject = principal
			claims.email = principal
			claims.groups = groups
			idp.writeJSON(w, map[string]any{"access_token": "unused", "id_token": idp.sign(claims, nil)})
		case strings.HasPrefix(rt, "rt-bad-idtoken:"):
			// A 200 ACTIVE response whose id_token is signed by a key the JWKS does not publish, so
			// validation fails. Not one of the Kotlin's arms — see the two EXTRA cases at the bottom.
			principal := strings.TrimPrefix(rt, "rt-bad-idtoken:")
			claims := idp.defaultClaims(cfg.OIDC.ClientID)
			claims.subject = principal
			claims.email = principal
			idp.writeJSON(w, map[string]any{"access_token": "unused", "id_token": idp.sign(claims, foreignKey)})
		case strings.HasPrefix(rt, "rt-other-identity:"):
			// A 200 ACTIVE response that VALIDATES but describes a DIFFERENT principal.
			claims := idp.defaultClaims(cfg.OIDC.ClientID)
			claims.subject = "attacker@example.com"
			claims.email = "attacker@example.com"
			claims.groups = []any{"attacker-group"}
			idp.writeJSON(w, map[string]any{"access_token": "unused", "id_token": idp.sign(claims, nil)})
		default:
			t.Errorf("unexpected refresh token presented to the IdP: %q", rt)
			http.Error(w, "unexpected refresh token", http.StatusBadRequest)
		}
	})
	return f
}

// sweep is the Kotlin's `sweep()` helper: a real Discovery + Validator against the fake IdP, then one
// pass. Nothing is stubbed — this is the production function.
func (f *livenessFixture) sweep() {
	f.t.Helper()
	hc := NewHTTPClient()
	discovery := NewDiscovery(hc, f.cfg.OIDC.Issuer)
	SweepSessionLiveness(f.ctx, LivenessDeps{
		RecheckIntervalSeconds: f.cfg.IdpRecheckIntervalSeconds,
		OIDC: &OIDCSettings{
			ClientID:     f.cfg.OIDC.ClientID,
			ClientSecret: f.cfg.OIDC.ClientSecret,
			GroupMapping: GroupMapping{Map: f.cfg.OIDC.GroupMapping.Map},
		},
		Discovery: discovery,
		Validator: NewIDTokenValidator(discovery, f.cfg.OIDC.Issuer, f.cfg.OIDC.ClientID, hc, discardLogger()),
		HTTP:      hc,
		Sessions:  f.sessions,
		Groups:    Provisioner{NewDirectoryProvisioner(f.db.Pool)},
		Roles:     f.roles,
		Log:       discardLogger(),
	})
}

// --- fixture helpers, each the Kotlin's same-named private fun ------------------------------------

func (f *livenessFixture) provision(principal string, groups ...string) {
	f.t.Helper()
	p := Provisioner{NewDirectoryProvisioner(f.db.Pool)}
	if err := p.ProvisionFromOidc(f.ctx, principal, types.Ptr(principal), groups, GroupMapping{Map: map[string]string{}}); err != nil {
		f.t.Fatalf("provision %s: %v", principal, err)
	}
}

// seedGroupRole gives principal a role earned THROUGH a group, which is the membership the sweep's
// reconciliation can later take away.
func (f *livenessFixture) seedGroupRole(principal, groupName, roleName string) {
	f.t.Helper()
	f.provision(principal, groupName)
	groups, err := f.users.ListGroups(f.ctx)
	if err != nil {
		f.t.Fatalf("list groups: %v", err)
	}
	var groupID int64
	for _, g := range groups {
		if g.Name == groupName {
			groupID = g.ID
		}
	}
	if groupID == 0 {
		f.t.Fatalf("group %q was not provisioned", groupName)
	}
	role, err := f.policies.CreateRole(f.ctx, policy.RoleInput{Name: roleName})
	if err != nil {
		f.t.Fatalf("create role: %v", err)
	}
	if _, err := f.users.AddGroupRole(f.ctx, groupID, role.ID); err != nil {
		f.t.Fatalf("add group role: %v", err)
	}
	if got := f.resolve(principal); len(got) != 1 || got[0] != roleName {
		f.t.Fatalf("seed failed: resolve(%s) = %v, want [%s]", principal, got, roleName)
	}
}

// seedGrant gives principal a JIT elevation grant, which must SURVIVE every arm of the sweep — the
// sweep revokes sessions, never credentials.
func (f *livenessFixture) seedGrant(principal, roleName string) {
	f.t.Helper()
	role, err := f.policies.CreateRole(f.ctx, policy.RoleInput{Name: roleName})
	if err != nil {
		f.t.Fatalf("create role: %v", err)
	}
	req, err := f.access.CreateRequest(f.ctx, principal, access.AccessRequestInput{RoleID: role.ID})
	if err != nil {
		f.t.Fatalf("create request: %v", err)
	}
	if _, err := f.access.Approve(f.ctx, req.ID, types.Ptr(int64(3600)), "approver@example.com"); err != nil {
		f.t.Fatalf("approve: %v", err)
	}
}

func (f *livenessFixture) resolve(principal string) []string {
	f.t.Helper()
	roles, err := f.roles.Resolve(f.ctx, principal)
	if err != nil {
		f.t.Fatalf("resolve %s: %v", principal, err)
	}
	return roles
}

func (f *livenessFixture) groupsOf(principal string) []string {
	f.t.Helper()
	users, err := f.users.ListUsers(f.ctx)
	if err != nil {
		f.t.Fatalf("list users: %v", err)
	}
	for _, u := range users {
		if u.Principal == principal {
			names := make([]string, 0, len(u.Groups))
			for _, g := range u.Groups {
				names = append(names, g.Name)
			}
			return names
		}
	}
	return nil
}

func (f *livenessFixture) mintWeb(principal string, refreshToken *string, deviceID string) int64 {
	f.t.Helper()
	id, err := f.sessions.MintWeb(f.ctx, nil, session.MintWebInput{
		Principal:       principal,
		RefreshToken:    refreshToken,
		AbsoluteSeconds: 3600,
		IdleSeconds:     900,
		DeviceID:        types.Ptr(deviceID),
	})
	if err != nil {
		f.t.Fatalf("mint web for %s: %v", principal, err)
	}
	return id
}

func (f *livenessFixture) createDaemon(principal, handle string, refreshToken *string) session.DaemonRow {
	f.t.Helper()
	created, err := f.sessions.Create(f.ctx, nil, principal, types.Ptr(handle), refreshToken, 3600, 900)
	if err != nil {
		f.t.Fatalf("create daemon for %s: %v", principal, err)
	}
	return created.Row
}

type sessionSnapshot struct {
	kind           string
	livenessStatus string
	lastIdpCheckAt *time.Time
	endedReason    *string
}

func (f *livenessFixture) snapshot(id int64) sessionSnapshot {
	f.t.Helper()
	var s sessionSnapshot
	err := f.db.Pool.QueryRow(f.ctx,
		`SELECT kind, liveness_status, last_idp_check_at, ended_reason FROM principal_session WHERE id = $1`,
		id).Scan(&s.kind, &s.livenessStatus, &s.lastIdpCheckAt, &s.endedReason)
	if err != nil {
		f.t.Fatalf("snapshot %d: %v", id, err)
	}
	return s
}

func (f *livenessFixture) daemon(id int64) *session.DaemonRow {
	f.t.Helper()
	row, err := f.sessions.GetByID(f.ctx, id)
	if err != nil {
		f.t.Fatalf("get daemon %d: %v", id, err)
	}
	if row == nil {
		f.t.Fatalf("daemon row %d vanished", id)
	}
	return row
}

func (f *livenessFixture) webResolves(id int64, deviceID string) bool {
	f.t.Helper()
	row, err := f.sessions.ResolveWeb(f.ctx, id, types.Ptr(deviceID))
	if err != nil {
		f.t.Fatalf("resolve web %d: %v", id, err)
	}
	return row != nil
}

func (f *livenessFixture) webEndedReason(id int64) *string {
	f.t.Helper()
	reason, err := f.sessions.WebEndedReason(f.ctx, id)
	if err != nil {
		f.t.Fatalf("web ended reason %d: %v", id, err)
	}
	return reason
}

// activeGrants is the credential-survival assertion every revoking case repeats.
func (f *livenessFixture) activeGrants(principal string) int {
	f.t.Helper()
	grants, err := f.access.ListGrants(f.ctx, &principal, true)
	if err != nil {
		f.t.Fatalf("list grants %s: %v", principal, err)
	}
	return len(grants)
}

func (f *livenessFixture) tokenRevoked(id int64) bool {
	f.t.Helper()
	row, err := f.tokens.Get(f.ctx, id)
	if err != nil || row == nil {
		f.t.Fatalf("get token %d: %v", id, err)
	}
	return row.RevokedAt != nil
}

func sortedEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]int{}
	for _, g := range got {
		seen[g]++
	}
	for _, w := range want {
		seen[w]--
		if seen[w] < 0 {
			return false
		}
	}
	return true
}

// --- the eight cases ------------------------------------------------------------------------------

// KT: DaemonSessionLivenessIdpTest.kt#fresh fewer groups end only the zero-role web session and preserve inactive liveness
func TestFreshFewerGroupsEndOnlyTheZeroRoleWebSession(t *testing.T) {
	f := newLivenessFixture(t)
	const principal = "web-groups-removed@example.com"
	const device = "web-groups-removed-device"

	f.seedGroupRole(principal, "web-role-group", "web-group-role")
	f.provision(principal, "web-role-group", "web-unmapped-group")
	// The IdP will now report ONLY the unmapped group, so reconciliation drops the role-bearing one.
	webID := f.mintWeb(principal, types.Ptr(activeRefresh(principal, "web-unmapped-group")), device)

	f.sweep()

	if got := f.groupsOf(principal); !sortedEqual(got, []string{"web-unmapped-group"}) {
		t.Errorf("groups = %v, want [web-unmapped-group] — the fresher claim must RECONCILE membership", got)
	}
	if got := f.resolve(principal); len(got) != 0 {
		t.Errorf("roles = %v, want none", got)
	}
	if f.webResolves(webID, device) {
		t.Error("the zero-role web session must be ended")
	}
	if r := f.webEndedReason(webID); r == nil || *r != session.EndedGroupRevoked {
		t.Errorf("ended_reason = %v, want %s", r, session.EndedGroupRevoked)
	}
	after := f.snapshot(webID)
	if after.kind != "WEB" || after.livenessStatus != session.LivenessInactive {
		t.Errorf("snapshot = %s/%s, want WEB/%s", after.kind, after.livenessStatus, session.LivenessInactive)
	}
	// 🔒 The check IS stamped here, unlike every failure arm: the IdP answered, so this is a
	// successful revalidation that happened to end the session.
	if after.lastIdpCheckAt == nil {
		t.Error("last_idp_check_at must be stamped — the revalidation SUCCEEDED, it just found zero roles")
	}
}

// KT: DaemonSessionLivenessIdpTest.kt#still-grouped and direct-role web users survive with fresh checks
func TestStillGroupedAndDirectRoleWebUsersSurvive(t *testing.T) {
	f := newLivenessFixture(t)

	const grouped = "web-group-kept@example.com"
	const groupedDevice = "web-group-kept-device"
	f.seedGroupRole(grouped, "web-kept-group", "web-kept-role")
	groupedWeb := f.mintWeb(grouped, types.Ptr(activeRefresh(grouped, "web-kept-group")), groupedDevice)

	// 🔒 THE DIRECT-ROLE HALF IS THE INTERESTING ONE: this principal's IdP groups are reconciled away
	// entirely, yet their role comes from a DIRECT principal_role assignment, so they must survive. A
	// sweep that ended sessions on "no groups" rather than "no ROLES" would log them out.
	const direct = "web-direct-kept@example.com"
	const directDevice = "web-direct-kept-device"
	f.provision(direct, "web-direct-old-group")
	directRole, err := f.policies.CreateRole(f.ctx, policy.RoleInput{Name: "web-direct-role"})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if _, err := f.policies.CreateAssignment(f.ctx, policy.RoleAssignmentInput{Principal: direct, RoleID: directRole.ID}); err != nil {
		t.Fatalf("create assignment: %v", err)
	}
	directWeb := f.mintWeb(direct, types.Ptr(activeRefresh(direct)), directDevice)

	f.sweep()

	if got := f.resolve(grouped); !sortedEqual(got, []string{"web-kept-role"}) {
		t.Errorf("grouped roles = %v, want [web-kept-role]", got)
	}
	if !f.webResolves(groupedWeb, groupedDevice) {
		t.Error("the still-grouped web session must survive")
	}
	if f.snapshot(groupedWeb).lastIdpCheckAt == nil {
		t.Error("grouped session must be stamped")
	}
	if got := f.groupsOf(direct); len(got) != 0 {
		t.Errorf("direct-role principal groups = %v, want none (reconciled away)", got)
	}
	if got := f.resolve(direct); !sortedEqual(got, []string{"web-direct-role"}) {
		t.Errorf("direct roles = %v, want [web-direct-role] — a DIRECT assignment survives group reconciliation", got)
	}
	if !f.webResolves(directWeb, directDevice) {
		t.Error("the direct-role web session must survive despite having lost every group")
	}
	if f.snapshot(directWeb).lastIdpCheckAt == nil {
		t.Error("direct-role session must be stamped")
	}
}

// KT: DaemonSessionLivenessIdpTest.kt#omitted groups claim is authoritative empty and removes old membership
func TestOmittedGroupsClaimIsAuthoritativeEmpty(t *testing.T) {
	f := newLivenessFixture(t)
	const principal = "web-groups-omitted@example.com"
	const device = "web-groups-omitted-device"

	f.seedGroupRole(principal, "web-omitted-old-group", "web-omitted-role")
	webID := f.mintWeb(principal, types.Ptr(noGroupsRefresh(principal)), device)

	f.sweep()

	// 🔒 INV-A4-63 — an ABSENT groups claim is an authoritative EMPTY set, not "no information".
	// Treating it as no-information would let an IdP that stops emitting the claim silently freeze
	// every user's membership at its last known value.
	if got := f.groupsOf(principal); len(got) != 0 {
		t.Errorf("groups = %v, want none — an omitted claim is authoritative empty", got)
	}
	if got := f.resolve(principal); len(got) != 0 {
		t.Errorf("roles = %v, want none", got)
	}
	if f.webResolves(webID, device) {
		t.Error("the now-zero-role web session must be ended")
	}
	if r := f.webEndedReason(webID); r == nil || *r != session.EndedGroupRevoked {
		t.Errorf("ended_reason = %v, want %s", r, session.EndedGroupRevoked)
	}
	if f.snapshot(webID).lastIdpCheckAt == nil {
		t.Error("last_idp_check_at must be stamped")
	}
}

// KT: DaemonSessionLivenessIdpTest.kt#invalid grant closes only its daemon row while a valid sibling and credentials survive
func TestInvalidGrantClosesOnlyItsDaemonRow(t *testing.T) {
	f := newLivenessFixture(t)
	const principal = "daemon-per-device@example.com"

	wire, err := f.tokens.Issue(f.ctx, f.db.Pool, token.KindSession, principal, nil, nil, 3600)
	if err != nil {
		t.Fatalf("issue wire token: %v", err)
	}
	f.seedGrant(principal, "daemon-per-device-grant-role")
	rejected := f.createDaemon(principal, "daemon-rejected", types.Ptr(rtInvalidGrant))
	valid := f.createDaemon(principal, "daemon-valid", types.Ptr(activeRefresh(principal)))

	f.sweep()

	// 🔒 PER-ROW, NOT PER-PRINCIPAL. The two daemon rows belong to the SAME principal and take
	// opposite arms in a single pass: the row whose own refresh token the IdP rejected closes, and its
	// sibling stays open. A sweep that keyed revocation on the principal would take both down.
	ra := f.daemon(rejected.ID)
	if ra.LivenessStatus != session.LivenessInactive {
		t.Errorf("rejected daemon liveness = %s, want %s", ra.LivenessStatus, session.LivenessInactive)
	}
	if !ra.SessionExpiresAt.Before(time.Now()) {
		t.Error("the rejected daemon's renewal window must be closed")
	}
	va := f.daemon(valid.ID)
	if va.LivenessStatus != session.LivenessActive {
		t.Errorf("valid daemon liveness = %s, want %s", va.LivenessStatus, session.LivenessActive)
	}
	if !va.SessionExpiresAt.After(time.Now()) {
		t.Error("the valid sibling's window must stay open")
	}
	if va.LastIdpCheckAt == nil {
		t.Error("the valid sibling must be stamped")
	}
	// 🔒 CREDENTIALS SURVIVE. The sweep retires SESSIONS; it is not a deprovision.
	if f.tokenRevoked(wire.ID) {
		t.Error("the principal's wire token must NOT be revoked by a session sweep")
	}
	if n := f.activeGrants(principal); n != 1 {
		t.Errorf("active grants = %d, want 1 — a session sweep must not touch elevation grants", n)
	}
}

// KT: DaemonSessionLivenessIdpTest.kt#all rejected session tokens retire every row in one sweep without principal teardown
func TestAllRejectedSessionTokensRetireEveryRowWithoutTeardown(t *testing.T) {
	f := newLivenessFixture(t)
	const principal = "all-sessions-rejected@example.com"
	const device = "all-rejected-web"

	wire, err := f.tokens.Issue(f.ctx, f.db.Pool, token.KindSession, principal, nil, nil, 3600)
	if err != nil {
		t.Fatalf("issue wire token: %v", err)
	}
	f.seedGrant(principal, "all-sessions-rejected-grant-role")
	daemonA := f.createDaemon(principal, "all-rejected-a", types.Ptr(rtInvalidGrant))
	daemonB := f.createDaemon(principal, "all-rejected-b", types.Ptr(rtInvalidGrant))
	webID := f.mintWeb(principal, types.Ptr(rtInvalidGrant), device)

	f.sweep()

	for _, d := range []session.DaemonRow{daemonA, daemonB} {
		after := f.daemon(d.ID)
		if after.LivenessStatus != session.LivenessInactive {
			t.Errorf("daemon %d liveness = %s, want %s", d.ID, after.LivenessStatus, session.LivenessInactive)
		}
		if !after.SessionExpiresAt.Before(time.Now()) {
			t.Errorf("daemon %d window must be closed", d.ID)
		}
	}
	if f.webResolves(webID, device) {
		t.Error("the rejected web session must be ended")
	}
	// 🔒 IDP_REJECTED, not GROUP_REVOKED. The reason distinguishes "the IdP disowned this credential"
	// from "reconciliation left you with no roles", and the console renders them differently.
	if r := f.webEndedReason(webID); r == nil || *r != session.EndedIdpRejected {
		t.Errorf("ended_reason = %v, want %s", r, session.EndedIdpRejected)
	}
	if got := f.snapshot(webID).livenessStatus; got != session.LivenessInactive {
		t.Errorf("web liveness = %s, want %s", got, session.LivenessInactive)
	}
	if f.tokenRevoked(wire.ID) {
		t.Error("even with EVERY session rejected the wire token must survive — this is not a teardown")
	}
	if n := f.activeGrants(principal); n != 1 {
		t.Errorf("active grants = %d, want 1", n)
	}
}

// KT: DaemonSessionLivenessIdpTest.kt#transient invalid client and server errors preserve both session kinds and credentials
func TestTransientErrorsPreserveBothSessionKinds(t *testing.T) {
	for _, tc := range []struct{ suffix, refresh string }{
		{"invalid-client", rtInvalidClient},
		{"http-500", rtHTTP500},
	} {
		t.Run(tc.suffix, func(t *testing.T) {
			f := newLivenessFixture(t)
			principal := "transient-" + tc.suffix + "@example.com"
			device := "transient-" + tc.suffix + "-web"

			wire, err := f.tokens.Issue(f.ctx, f.db.Pool, token.KindSession, principal, nil, nil, 3600)
			if err != nil {
				t.Fatalf("issue wire token: %v", err)
			}
			f.seedGrant(principal, "transient-"+tc.suffix+"-grant-role")
			daemon := f.createDaemon(principal, "transient-"+tc.suffix+"-daemon", types.Ptr(tc.refresh))
			webID := f.mintWeb(principal, types.Ptr(tc.refresh), device)

			f.sweep()

			// 🔒 INV-A4-39 — NOTHING moves, and `last_idp_check_at` stays NULL specifically so the next
			// tick retries immediately. An IdP outage must not be able to log a deployment out, and it
			// must not buy a session a full interval of unchecked life either.
			//
			// ⚠️ `invalid_client` is a 401 and is TRANSIENT, not a rejection: it says the CONTROL PLANE's
			// own credentials are wrong, which is an operator misconfiguration, not a verdict about the
			// user. Classifying it as Inactive would log every user out on a bad client secret.
			after := f.daemon(daemon.ID)
			if after.LivenessStatus != session.LivenessActive {
				t.Errorf("daemon liveness = %s, want %s preserved", after.LivenessStatus, session.LivenessActive)
			}
			if after.LastIdpCheckAt != nil {
				t.Error("last_idp_check_at must stay NULL on a transient failure so the next tick retries")
			}
			if !after.SessionExpiresAt.After(time.Now()) {
				t.Error("the daemon window must stay open")
			}
			if !f.webResolves(webID, device) {
				t.Error("the web session must survive a transient IdP failure")
			}
			snap := f.snapshot(webID)
			if snap.livenessStatus != session.LivenessActive {
				t.Errorf("web liveness = %s, want %s", snap.livenessStatus, session.LivenessActive)
			}
			if snap.lastIdpCheckAt != nil {
				t.Error("web last_idp_check_at must stay NULL")
			}
			if snap.endedReason != nil {
				t.Errorf("web ended_reason = %v, want nil", *snap.endedReason)
			}
			if f.tokenRevoked(wire.ID) {
				t.Error("wire token must survive")
			}
			if n := f.activeGrants(principal); n != 1 {
				t.Errorf("active grants = %d, want 1", n)
			}
		})
	}
}

// KT: DaemonSessionLivenessIdpTest.kt#sessions without stored refresh tokens remain live and unstamped
func TestSessionsWithoutStoredRefreshTokensRemainLiveAndUnstamped(t *testing.T) {
	f := newLivenessFixture(t)
	const daemonPrincipal = "no-refresh-daemon@example.com"
	const webPrincipal = "no-refresh-web@example.com"
	const device = "no-refresh-web"

	daemon := f.createDaemon(daemonPrincipal, "no-refresh-daemon", nil)
	webID := f.mintWeb(webPrincipal, nil, device)

	f.sweep()

	// 🔒 A row with no refresh token is UNCHECKABLE, and unchecked is not the same as checked-and-fine.
	// Leaving last_idp_check_at NULL is what keeps that distinction visible; stamping it would claim an
	// IdP confirmation that never happened.
	after := f.daemon(daemon.ID)
	if after.LivenessStatus != session.LivenessActive {
		t.Errorf("daemon liveness = %s, want %s", after.LivenessStatus, session.LivenessActive)
	}
	if after.LastIdpCheckAt != nil {
		t.Error("a session with no refresh token must NOT be stamped — it was never checked")
	}
	if !after.SessionExpiresAt.After(time.Now()) {
		t.Error("the daemon window must stay open")
	}
	if !f.webResolves(webID, device) {
		t.Error("the web session must stay live")
	}
	snap := f.snapshot(webID)
	if snap.livenessStatus != session.LivenessActive {
		t.Errorf("web liveness = %s, want %s", snap.livenessStatus, session.LivenessActive)
	}
	if snap.lastIdpCheckAt != nil {
		t.Error("web last_idp_check_at must stay NULL")
	}
	if snap.endedReason != nil {
		t.Errorf("web ended_reason = %v, want nil", *snap.endedReason)
	}
}

// KT: DaemonSessionLivenessIdpTest.kt#renew route never revalidates and only the timer sweep reaches the token endpoint
//
// 🔒 THE "SOLE REVALIDATOR" CLAIM, made falsifiable. The suite's whole premise is that the timer sweep
// is the ONLY thing that revalidates against the IdP; if the renew route also did, a daemon could keep
// itself alive indefinitely by renewing, and the sweep's revocation would be unreachable. Counting
// token-endpoint hits across a renew is what turns that prose into an assertion.
//
// The Go renew route lives in internal/session, so rather than mount it here this case observes the
// same property at its source: a renewal performs the store's own re-checks and must not touch the
// IdP, and the very next sweep must.
func TestOnlyTheTimerSweepReachesTheTokenEndpoint(t *testing.T) {
	f := newLivenessFixture(t)
	const principal = "sole-revalidator@example.com"

	created, err := f.sessions.Create(f.ctx, nil, principal, types.Ptr("sole-revalidator-daemon"),
		types.Ptr(activeRefresh(principal)), 3600, 900)
	if err != nil {
		t.Fatalf("create daemon: %v", err)
	}
	before := f.tokenRequests

	// The REAL renew route, mounted exactly as production does. Its two seams are the store's own
	// re-checks — nothing in it can reach an IdP, and that is the property under test.
	mux := http.NewServeMux()
	session.NewRenewRoutes(f.sessions,
		func(ctx context.Context, principal string, c store.Queryer) (bool, error) { return false, nil },
		func(ctx context.Context, fresh session.DaemonRow, c store.Queryer) (session.Minted, error) {
			return session.Minted{Token: "tok", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}, nil
		},
		discardLogger(),
	).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/auth/session/renew", nil)
	if err != nil {
		t.Fatalf("build renew request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+created.RenewalToken)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("renew status = %d, want 200", resp.StatusCode)
	}
	if f.tokenRequests != before {
		t.Errorf("renew hit the IdP token endpoint %d time(s); it must never revalidate",
			f.tokenRequests-before)
	}

	f.sweep()

	if f.tokenRequests <= before {
		t.Error("the timer sweep must perform the refresh grant — it is the sole revalidator")
	}
	if f.daemon(created.Row.ID).LastIdpCheckAt == nil {
		t.Error("the swept row must be stamped")
	}
}

// --- EXTRA (not among the Kotlin's 8) -------------------------------------------------------------
//
// Mutation testing the 1:1 port found two of revalidateSession's documented "load-bearing" orderings
// with NO covering case on either side. Both mutations left the ported suite green:
//
//   - stamping `markCheck` after an id_token FAILED to validate
//   - deleting the identity comparison that guards provisioning
//
// The Kotlin suite never exercises either path — every ACTIVE arm it drives returns a well-signed
// token for the row's own principal — so a faithful port inherits the blind spot. These two close it.
//
// (A third mutation — ending ALL of a principal's web sessions instead of just the rejected row — also
// survived, and that one is CORRECT to leave: MintWeb ends every other live WEB row for the principal
// on insert, so at most one exists and the two calls are equivalent. An equivalent mutation is not a
// test gap, and adding a case to "cover" it would assert an impossible state.)

// TestAnUnvalidatableIdTokenIsNotAFreshCheck covers 🔒 ORDERING 4 from liveness.go: `markCheck` runs
// only on a FULLY successful revalidation.
//
// The IdP answers 200 with an id_token signed by a key its JWKS does not publish — the shape of a
// misconfigured or hostile token endpoint. That is not evidence the account is live, so the row must
// keep its stale `last_idp_check_at` and be retried on the next tick. Stamping it would buy an
// unverified session a full recheck interval of immunity.
func TestAnUnvalidatableIdTokenIsNotAFreshCheck(t *testing.T) {
	f := newLivenessFixture(t)
	const principal = "bad-idtoken@example.com"
	const device = "bad-idtoken-web"

	f.seedGroupRole(principal, "bad-idtoken-group", "bad-idtoken-role")
	webID := f.mintWeb(principal, types.Ptr("rt-bad-idtoken:"+principal), device)

	f.sweep()

	snap := f.snapshot(webID)
	if snap.lastIdpCheckAt != nil {
		t.Error("last_idp_check_at was stamped for a response whose id_token did not validate; " +
			"an unverifiable answer must leave the row due for recheck")
	}
	// Nothing else moves either: an unverifiable answer is not a rejection.
	if !f.webResolves(webID, device) {
		t.Error("the session must survive — a bad id_token is not the IdP disowning the account")
	}
	if snap.livenessStatus != session.LivenessActive {
		t.Errorf("liveness = %s, want %s preserved", snap.livenessStatus, session.LivenessActive)
	}
	if snap.endedReason != nil {
		t.Errorf("ended_reason = %v, want nil", *snap.endedReason)
	}
}

// TestARefreshDescribingADifferentPrincipalProvisionsNothing covers 🔒 ORDERING 3: the identity
// comparison PRECEDES provisioning.
//
// 🔒 THIS IS AN ACCOUNT-TAKEOVER GUARD, which is why it is worth a case the Kotlin does not have. The
// refresh grant comes back with a perfectly valid id_token that describes SOMEONE ELSE. Provisioning
// before comparing would write the attacker's IdP groups onto this row's principal — silently granting
// whatever roles those groups map to. The check must fire first, and (being a failed revalidation) it
// must also leave the row unstamped.
func TestARefreshDescribingADifferentPrincipalProvisionsNothing(t *testing.T) {
	f := newLivenessFixture(t)
	const principal = "identity-mismatch@example.com"
	const device = "identity-mismatch-web"

	f.seedGroupRole(principal, "mismatch-own-group", "mismatch-own-role")
	webID := f.mintWeb(principal, types.Ptr("rt-other-identity:"+principal), device)

	f.sweep()

	// The attacker's group must not have been written onto this principal.
	if got := f.groupsOf(principal); !sortedEqual(got, []string{"mismatch-own-group"}) {
		t.Errorf("groups = %v, want the untouched [mismatch-own-group] — a refresh describing a "+
			"DIFFERENT identity must not provision membership onto this principal", got)
	}
	if got := f.resolve(principal); !sortedEqual(got, []string{"mismatch-own-role"}) {
		t.Errorf("roles = %v, want [mismatch-own-role] unchanged", got)
	}
	// Nor may the mismatched identity be created as a side effect.
	if got := f.groupsOf("attacker@example.com"); len(got) != 0 {
		t.Errorf("the mismatched identity was provisioned with groups %v; it must not be touched at all", got)
	}
	snap := f.snapshot(webID)
	if snap.lastIdpCheckAt != nil {
		t.Error("last_idp_check_at was stamped for an identity mismatch; that is a FAILED revalidation")
	}
	if !f.webResolves(webID, device) {
		t.Error("the session survives — a mismatch is a failed check, not a rejection")
	}
}
