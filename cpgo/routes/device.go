package routes

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

const (
	devicePollInterval = 2
	deviceLoginTTL     = 600 * time.Second
	verifyCookie       = "pm_device_verify"
	userCodeAlphabet   = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	pmonClientID       = "pmon"
)

// defaultScopes is what a pmon login grants when it names none; anything else is elevated and time-boxed.
var defaultScopes = []string{"mcp:query", "mcp:read"}

// supportedScopes is every scope an MCP tool requires (McpCapabilityRegistry.supportedScopes).
var supportedScopes = []string{
	"mcp:approvals:write", "mcp:datasources:write", "mcp:identity:write", "mcp:policies:write",
	"mcp:query", "mcp:read", "mcp:tokens",
}

// device serves pmon's login (/auth/device/*) and its daemon session (/auth/session/{renew,logout,mcp-token}).
type device struct {
	auth
}

type verifySession struct {
	UserCode     string `json:"userCode"`
	WebSessionID int64  `json:"webSessionId"`
}

type deviceLogin struct {
	id            int64
	handle        string
	userCode      *string
	ttlSeconds    int64
	status        string
	principal     *string
	refreshEnc    []byte
	expiresAt     time.Time
	scopes        []string
	elevatedUntil *time.Time
}

// canonicalScopes is the stored form: trimmed, non-empty, sorted, distinct, space-joined.
func canonicalScopes(scopes []string) string {
	var out []string
	for _, s := range scopes {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return strings.Join(slices.Compact(out), " ")
}

func parseScopes(raw string) []string {
	return strings.Fields(canonicalScopes(strings.Split(raw, " ")))
}

func elevated(scopes []string) bool {
	return slices.ContainsFunc(scopes, func(s string) bool { return !slices.Contains(defaultScopes, s) })
}

// normalizeUserCode folds a typed code to the stored "XXXX-XXXX": uppercase, alphabet characters only.
func normalizeUserCode(raw string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(raw) {
		if strings.ContainsRune(userCodeAlphabet, r) {
			b.WriteRune(r)
		}
	}
	if bare := b.String(); len(bare) == 8 {
		return bare[:4] + "-" + bare[4:]
	}
	return b.String()
}

func newUserCode() string {
	var b strings.Builder
	raw := make([]byte, 8)
	_, _ = rand.Read(raw)
	for i, v := range raw {
		if i == 4 {
			b.WriteByte('-')
		}
		b.WriteByte(userCodeAlphabet[int(v)%len(userCodeAlphabet)])
	}
	return b.String()
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// encodeURLParameter is Ktor's String.encodeURLParameter: percent-encoding with %20 for a space.
func encodeURLParameter(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func (d device) deviceLogin(ctx context.Context, where string, arg string) (*deviceLogin, error) {
	var (
		row db.DeviceLoginByHandleRow
		err error
	)
	if where == "user_code" {
		var byCode db.DeviceLoginByUserCodeRow
		byCode, err = db.New(d.pool).DeviceLoginByUserCode(ctx, &arg)
		row = db.DeviceLoginByHandleRow(byCode)
	} else {
		row, err = db.New(d.pool).DeviceLoginByHandle(ctx, arg)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	l := deviceLogin{row.ID, row.Handle, row.UserCode, row.TtlSeconds, row.Status, row.Principal, row.RefreshTokenEnc,
		row.ExpiresAt, parseScopes(row.Scopes), row.ElevatedUntil}
	return &l, err
}

// start opens a PENDING login for pmon to poll and returns the console page where a person approves it.
func (d device) start(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TTLSeconds *int64    `json:"ttlSeconds"`
		Scopes     *[]string `json:"scopes"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		in.TTLSeconds, in.Scopes = nil, nil
	}
	ttl := int64(sessionTokenTTL)
	if in.TTLSeconds != nil {
		ttl = *in.TTLSeconds
	}
	ttl = min(max(ttl, tokenMinTTL), tokenMaxTTL)
	scopes := defaultScopes
	if in.Scopes != nil {
		scopes = nil
		for _, s := range *in.Scopes {
			if s = strings.TrimSpace(s); s != "" && !slices.Contains(scopes, s) {
				scopes = append(scopes, s)
			}
		}
	}
	if len(scopes) == 0 {
		api.WriteError(w, http.StatusBadRequest, "device.no_scopes", nil)
		return
	}
	for _, s := range scopes {
		if !slices.Contains(supportedScopes, s) {
			api.WriteError(w, http.StatusBadRequest, "device.unknown_scope", map[string]string{"scope": truncate(s, 200)})
			return
		}
	}
	handle := "dvc_" + randomToken(24)
	var userCode string
	for attempt := 1; ; attempt++ {
		userCode = newUserCode()
		err := db.New(d.pool).CreateDeviceLogin(r.Context(), db.CreateDeviceLoginParams{Handle: handle, UserCode: &userCode,
			IntervalSec: devicePollInterval, TtlSeconds: ttl, ExpiresAt: time.Now().Add(deviceLoginTTL), Scopes: canonicalScopes(scopes)})
		var pgErr *pgconn.PgError
		if err == nil {
			break
		}
		if !errors.As(err, &pgErr) || pgErr.Code != "23505" || attempt >= 5 {
			fail(w, err)
			return
		}
	}
	verifyURI := d.sessions.Settings().WebBase() + "/device"
	api.WriteJSON(w, http.StatusOK, struct {
		VerificationURI         string `json:"verificationUri"`
		VerificationURIComplete string `json:"verificationUriComplete"`
		UserCode                string `json:"userCode"`
		Handle                  string `json:"handle"`
		Interval                int    `json:"interval"`
	}{verifyURI, verifyURI + "?user_code=" + encodeURLParameter(userCode), userCode, handle, devicePollInterval})
}

// liveSession is the request's web session, ending it when the device cookie does not match.
func (d device) liveSession(r *http.Request) (*session.Web, error) {
	s, err := d.sessions.Resolve(r.Context(), r)
	if errors.Is(err, session.ErrDeviceMismatch) {
		d.endSession(r.Context(), s.ID, session.EndedDeviceMismatch)
		return nil, nil
	}
	return s, err
}

func pending(l *deviceLogin) bool {
	return l != nil && l.userCode != nil && l.expiresAt.After(time.Now()) && l.status == "PENDING"
}

// confirm binds this browser and its web session to the code the signed-in person confirmed on /device.
func (d device) confirm(w http.ResponseWriter, r *http.Request) {
	s, err := d.liveSession(r)
	if err != nil {
		fail(w, err)
		return
	}
	if s == nil {
		api.WriteError(w, http.StatusUnauthorized, "common.unauthenticated", nil)
		return
	}
	var in struct {
		UserCode *string `json:"userCode"`
	}
	var l *deviceLogin
	if json.NewDecoder(r.Body).Decode(&in) == nil && in.UserCode != nil {
		if l, err = d.deviceLogin(r.Context(), "user_code", normalizeUserCode(strings.TrimSpace(*in.UserCode))); err != nil {
			fail(w, err)
			return
		}
	}
	if !pending(l) {
		api.WriteError(w, http.StatusBadRequest, "device.unknown_or_expired_login", nil)
		return
	}
	if err := d.sessions.SetSigned(w, verifyCookie, verifySession{*l.userCode, s.ID}, int64(deviceLoginTTL/time.Second)); err != nil {
		fail(w, err)
		return
	}
	ack := struct {
		OK                 bool     `json:"ok"`
		Scopes             []string `json:"scopes"`
		ElevatedTTLSeconds *int64   `json:"elevatedTtlSeconds,omitempty"`
	}{OK: true, Scopes: l.scopes}
	if elevated(l.scopes) {
		ttl := d.sessions.Settings().ElevatedScopeTTL
		ack.ElevatedTTLSeconds = &ttl
	}
	api.WriteJSON(w, http.StatusOK, ack)
}

// authorize approves the confirmed code with the same live web session that confirmed it, or sends the
// browser back to /device to authenticate and confirm again.
func (d device) authorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userCode := strings.TrimSpace(r.URL.Query().Get("user_code"))
	back := "/device"
	if userCode != "" {
		back += "?user_code=" + encodeURLParameter(userCode)
	}
	back = d.sessions.Settings().WebRedirect(back)
	var verified verifySession
	if userCode == "" || !d.sessions.ReadSigned(r, verifyCookie, &verified) || verified.UserCode != userCode {
		found(w, back)
		return
	}
	bounce := func() {
		d.sessions.Clear(w, r, verifyCookie)
		found(w, back)
	}
	l, err := d.deviceLogin(ctx, "user_code", normalizeUserCode(userCode))
	if err != nil {
		fail(w, err)
		return
	}
	if !pending(l) {
		bounce()
		return
	}
	s, err := d.liveSession(r)
	if err != nil {
		fail(w, err)
		return
	}
	if s == nil || s.ID != verified.WebSessionID {
		bounce()
		return
	}
	// The session's IdP refresh token moves onto the login, so the daemon session keeps its liveness recheck.
	refreshEnc, err := db.New(d.pool).WebSessionRefreshToken(ctx, s.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		bounce()
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	var elevatedUntil *time.Time
	if elevated(l.scopes) {
		t := time.Now().Add(time.Duration(d.sessions.Settings().ElevatedScopeTTL) * time.Second)
		elevatedUntil = &t
	}
	approved := false
	err = pgx.BeginFunc(ctx, d.pool, func(tx pgx.Tx) error {
		n, err := db.New(tx).ApproveDeviceLogin(ctx, db.ApproveDeviceLoginParams{Principal: &s.Principal, RefreshTokenEnc: refreshEnc,
			ElevatedUntil: elevatedUntil, Handle: l.handle})
		if err != nil || n == 0 {
			return err
		}
		approved = true
		// The row id, never the handle: the handle alone is enough to poll for the token.
		return audit.Auth(ctx, tx, audit.Actor{Principal: s.Principal, ClientAddr: d.requesterIP(r), Channel: "device"},
			"auth.device.approve", audit.Entity("DeviceLogin", strconv.FormatInt(l.id, 10)), "Device login approved")
	})
	if err != nil {
		fail(w, err)
		return
	}
	d.sessions.Clear(w, r, verifyCookie)
	if approved {
		found(w, d.sessions.Settings().WebRedirect("/device/success"))
		return
	}
	found(w, back)
}

type pollResult struct {
	Token            string   `json:"token"`
	ExpiresAt        string   `json:"expiresAt"`
	Principal        string   `json:"principal"`
	SessionExpiresAt string   `json:"sessionExpiresAt"`
	RenewalToken     string   `json:"renewalToken"`
	Scopes           []string `json:"scopes"`
	ElevatedUntil    *string  `json:"elevatedUntil,omitempty"`
}

// poll answers 202 until the login is approved, then mints its one daemon session and SESSION token.
func (d device) poll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in struct {
		Handle *string `json:"handle"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Handle == nil {
		api.WriteError(w, http.StatusInternalServerError, "common.fallback", nil)
		return
	}
	l, err := d.deviceLogin(ctx, "handle", *in.Handle)
	if err != nil {
		fail(w, err)
		return
	}
	if l == nil || l.expiresAt.Before(time.Now()) {
		api.WriteError(w, http.StatusBadRequest, "device.unknown_or_expired_login", nil)
		return
	}
	if l.status == "PENDING" || l.principal == nil {
		api.WriteJSON(w, http.StatusAccepted, struct {
			Status string `json:"status"`
		}{"authorization_pending"})
		return
	}
	principal := *l.principal
	actor := audit.Actor{Principal: principal, ClientAddr: d.requesterIP(r), Channel: "device"}
	var out pollResult
	err = pgx.BeginFunc(ctx, d.pool, func(tx pgx.Tx) error {
		if err := lockActive(ctx, tx, principal); err != nil {
			return err
		}
		q := db.New(tx)
		n, err := q.ConsumeDeviceLogin(ctx, l.handle)
		if err != nil {
			return err
		}
		if n == 0 {
			return badRequest("device.login_already_completed")
		}
		renewal := "pmr_" + randomToken(32)
		renewalHash, scopes := sha256Hex(renewal), canonicalScopes(l.scopes)
		created, err := q.CreateDaemonSession(ctx, db.CreateDaemonSessionParams{Principal: principal, Handle: &l.handle,
			RefreshTokenEnc: l.refreshEnc, TtlSeconds: &l.ttlSeconds, WindowSeconds: float64(d.sessions.Settings().SessionWindowSeconds),
			RenewalTokenHash: &renewalHash, Scopes: &scopes, ElevatedUntil: l.elevatedUntil})
		if err != nil {
			return err
		}
		sessionID, window := created.ID, created.AbsoluteExpiresAt
		tok, err := issueSession(ctx, tx, principal, l.ttlSeconds, sessionID)
		if err != nil {
			return err
		}
		out = pollResult{tok.Token, tok.ExpiresAt, principal, javaInstant(window), renewal, l.scopes, optInstant(l.elevatedUntil)}
		return audit.Auth(ctx, tx, actor, "auth.device.mint", audit.Entity("Token", strconv.FormatInt(tok.ID, 10)),
			"Device login minted SESSION token")
	})
	if err != nil {
		writeMutationError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusOK, out)
}

// lockActive takes the principal's advisory lock, which every credential teardown also takes, and refuses
// a deprovisioned principal under it.
func lockActive(ctx context.Context, tx pgx.Tx, principal string) error {
	if err := lockPrincipal(ctx, tx, principal); err != nil {
		return err
	}
	deactivated, err := isDeactivated(ctx, tx, principal)
	if err == nil && deactivated {
		err = forbidden("auth.principal_deprovisioned", nil)
	}
	return err
}

func isDeactivated(ctx context.Context, tx pgx.Tx, principal string) (bool, error) {
	return db.New(tx).IsDeactivated(ctx, principal)
}

// issueSession inserts a SESSION wire token owned by a daemon session.
func issueSession(ctx context.Context, tx pgx.Tx, principal string, ttl, sessionID int64) (*issuedToken, error) {
	token := "pmt_" + randomToken(32)
	out := issuedToken{Token: token, Kind: "SESSION"}
	row, err := db.New(tx).IssueSessionToken(ctx, db.IssueSessionTokenParams{TokenHash: sha256Hex(token), Principal: principal,
		Ttl: min(max(ttl, tokenMinTTL), tokenMaxTTL), PrincipalSessionID: &sessionID})
	out.ID, out.ExpiresAt = row.ID, javaInstant(row.ExpiresAt)
	return &out, err
}

type daemonSession struct {
	id            int64
	principal     string
	ttlSeconds    int64
	liveness      string
	createdAt     time.Time
	scopes        []string
	elevatedUntil *time.Time
}

func scanDaemon(row db.DaemonSessionRow, err error) (*daemonSession, error) {
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	s := daemonSession{row.ID, row.Principal, row.TtlSeconds, row.LivenessStatus, row.CreatedAt, parseScopes(row.Scopes), row.ElevatedUntil}
	return &s, err
}

// bearerSession is the daemon session whose renewal secret the request carries, nil when it matches none.
// false means the response is written: no bearer at all, or a store error.
func (d device) bearerSession(w http.ResponseWriter, r *http.Request) (*daemonSession, bool) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		api.WriteError(w, http.StatusUnauthorized, "auth.missing_renewal_token", nil)
		return nil, false
	}
	hash := sha256Hex(strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")))
	row, err := db.New(d.pool).DaemonSessionByRenewal(r.Context(), &hash)
	s, err := scanDaemon(db.DaemonSessionRow(row), err)
	if err != nil {
		fail(w, err)
		return nil, false
	}
	return s, true
}

var errWindowExpired = &managementError{code: "auth.session_window_expired", status: http.StatusUnauthorized}

// lockedDaemon re-reads the session under its principal's lock and refuses it once ended or deprovisioned.
func lockedDaemon(ctx context.Context, tx pgx.Tx, s *daemonSession) (*daemonSession, error) {
	if err := lockPrincipal(ctx, tx, s.principal); err != nil {
		return nil, err
	}
	fresh, err := scanDaemon(db.New(tx).DaemonSession(ctx, s.id))
	if err != nil {
		return nil, err
	}
	if fresh == nil {
		return nil, errWindowExpired
	}
	deactivated, err := isDeactivated(ctx, tx, fresh.principal)
	if err != nil {
		return nil, err
	}
	if deactivated || fresh.liveness == "INACTIVE" {
		return nil, errWindowExpired
	}
	return fresh, nil
}

// renew mints a fresh SESSION token while the daemon session's window is open.
func (d device) renew(w http.ResponseWriter, r *http.Request) {
	s, ok := d.bearerSession(w, r)
	if !ok {
		return
	}
	if s == nil {
		api.WriteError(w, http.StatusUnauthorized, "common.unauthenticated", nil)
		return
	}
	ctx := r.Context()
	actor := audit.Actor{Principal: s.principal, ClientAddr: d.requesterIP(r), Channel: "pmon"}
	var tok *issuedToken
	err := pgx.BeginFunc(ctx, d.pool, func(tx pgx.Tx) error {
		fresh, err := lockedDaemon(ctx, tx, s)
		if err != nil {
			return err
		}
		// clock_timestamp, not now(): the lock wait may have outlasted the window.
		within, err := db.New(tx).DaemonWithinWindow(ctx, fresh.id)
		if err != nil {
			return err
		}
		if !within {
			return errWindowExpired
		}
		if tok, err = issueSession(ctx, tx, fresh.principal, fresh.ttlSeconds, fresh.id); err != nil {
			return err
		}
		actor.Principal = fresh.principal
		return audit.Auth(ctx, tx, actor, "auth.session.renew", audit.Entity("Token", strconv.FormatInt(tok.ID, 10)),
			"Daemon session renewed SESSION token")
	})
	if err != nil {
		writeMutationError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusOK, struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expiresAt"`
	}{tok.Token, tok.ExpiresAt})
}

// logout ends the daemon session and revokes its tokens; ?replaced=true only retires its wire tokens, so
// open connections keep working. 204 whether or not the bearer matched anything.
func (d device) logout(w http.ResponseWriter, r *http.Request) {
	s, ok := d.bearerSession(w, r)
	if !ok {
		return
	}
	if s != nil {
		ctx := r.Context()
		replaced := r.URL.Query().Get("replaced") == "true"
		summary := "pmon session signed out"
		if replaced {
			summary = "pmon session replaced by a new login"
		}
		actor := audit.Actor{ClientAddr: d.requesterIP(r), Channel: "pmon"}
		err := pgx.BeginFunc(ctx, d.pool, func(tx pgx.Tx) error {
			if err := lockPrincipal(ctx, tx, s.principal); err != nil {
				return err
			}
			owner, err := endDaemon(ctx, tx, s.id, replaced)
			if err != nil || owner == "" {
				return err
			}
			actor.Principal = owner
			return audit.Auth(ctx, tx, actor, "auth.logout", audit.Entity("Session", strconv.FormatInt(s.id, 10)), summary)
		})
		if err != nil {
			fail(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// endDaemon ends daemon session id and revokes its tokens, or retires its SESSION tokens when replaced,
// then revokes each consent left with no live token. "" when it had already ended.
func endDaemon(ctx context.Context, tx pgx.Tx, id int64, replaced bool) (string, error) {
	q := db.New(tx)
	principal, err := q.EndDaemonSession(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if replaced {
		if err := q.RetireSessionTokens(ctx, &id); err != nil {
			return "", err
		}
	}
	consents, err := q.RevokeDaemonTokens(ctx, db.RevokeDaemonTokensParams{PrincipalSessionID: &id, Replaced: replaced})
	if err != nil {
		return "", err
	}
	ids := []int64{}
	for _, c := range consents {
		if c != nil {
			ids = append(ids, *c)
		}
	}
	return principal, q.RevokeOrphanConsents(ctx, ids)
}

// mcpToken trades a pmon renewal secret for an MCP access token carrying the session's current scopes.
func (d device) mcpToken(w http.ResponseWriter, r *http.Request) {
	s, ok := d.bearerSession(w, r)
	if !ok {
		return
	}
	if s == nil {
		api.WriteError(w, http.StatusUnauthorized, "common.unauthenticated", nil)
		return
	}
	ctx := r.Context()
	settings := d.sessions.Settings()
	actor := audit.Actor{ClientAddr: d.requesterIP(r), Channel: "pmon"}
	var out struct {
		AccessToken string `json:"accessToken"`
		ExpiresAt   string `json:"expiresAt"`
		Scope       string `json:"scope"`
	}
	err := pgx.BeginFunc(ctx, d.pool, func(tx pgx.Tx) error {
		fresh, err := lockedDaemon(ctx, tx, s)
		if err != nil {
			return err
		}
		now := time.Now().Truncate(time.Microsecond)
		loginEnds := fresh.createdAt.Add(time.Duration(fresh.ttlSeconds) * time.Second)
		if !now.Before(loginEnds) {
			return errWindowExpired
		}
		scopes := mcpScopes(fresh, now)
		if len(scopes) == 0 {
			return forbidden("auth.scopes_expired", nil)
		}
		expires := now.Add(time.Duration(settings.MCPAccessTTL) * time.Second)
		caps := []time.Time{loginEnds}
		if elevated(scopes) {
			caps = append(caps, *fresh.elevatedUntil)
		}
		for _, c := range caps {
			if c.Before(expires) {
				expires = c
			}
		}
		scope := canonicalScopes(scopes)
		q := db.New(tx)
		consentID, err := q.PmonConsent(ctx, db.PmonConsentParams{Principal: fresh.principal, ClientID: pmonClientID, Resource: settings.MCPResource, Scope: scope})
		if err != nil {
			return err
		}
		access := "pma_" + randomToken(32)
		clientID, family := pmonClientID, "pmf_"+randomToken(24)
		tokenID, err := q.MintMcpAccessToken(ctx, db.MintMcpAccessTokenParams{TokenHash: sha256Hex(access), Principal: fresh.principal,
			ExpiresAt: expires, Resource: &settings.MCPResource, ClientID: &clientID, Scope: &scope, RefreshFamily: &family,
			ConsentID: &consentID, PrincipalSessionID: &fresh.id})
		if err != nil {
			return err
		}
		out.AccessToken, out.ExpiresAt, out.Scope = access, javaInstant(expires), scope
		actor.Principal = fresh.principal
		return audit.AuthDetail(ctx, tx, actor, "auth.session.mcp_token", audit.Entity("Token", strconv.FormatInt(tokenID, 10)),
			"pmon session minted MCP access token", "scope="+scope)
	})
	if err != nil {
		writeMutationError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusOK, out)
}

// mcpScopes is the session's MCP scopes at now: every granted one until elevated_until, then only the defaults.
func mcpScopes(s *daemonSession, now time.Time) []string {
	open := s.elevatedUntil != nil && now.Before(*s.elevatedUntil)
	var out []string
	for _, sc := range s.scopes {
		if (open || slices.Contains(defaultScopes, sc)) && slices.Contains(supportedScopes, sc) {
			out = append(out, sc)
		}
	}
	return out
}
