package routes

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/cedar-policy/cedar-go/types"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/authz"
	"github.com/ridi-oss/proxy-monster/cpgo/front"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

// auth serves the console's session routes: config, debug login, me, status, heartbeat and logout.
type auth struct {
	pool     *pgxpool.Pool
	sessions *session.Resolver
	kotlin   api.Kotlin
	edges    front.TrustedEdges
}

// userSession is Kotlin's UserSession.
type userSession struct {
	Principal   string   `json:"principal"`
	Roles       []string `json:"roles"`
	RequesterIP *string  `json:"requesterIp,omitempty"`
}

// sessionStatus is Kotlin's SessionStatus.
type sessionStatus struct {
	Now               string `json:"now"`
	IdleExpiresAt     string `json:"idleExpiresAt"`
	AbsoluteExpiresAt string `json:"absoluteExpiresAt"`
	Principal         string `json:"principal"`
	SessionID         int64  `json:"sessionId"`
}

func statusOf(w *session.Web) sessionStatus {
	return sessionStatus{javaInstant(w.Now), javaInstant(w.IdleExpiresAt), javaInstant(w.AbsoluteExpiresAt), w.Principal, w.ID}
}

// normalizedDuration is the absolute cap the console shows: whole hours, else whole minutes, else seconds.
func normalizedDuration(seconds int64) (int64, string) {
	switch {
	case seconds%3600 == 0:
		return seconds / 3600, "hours"
	case seconds%60 == 0:
		return seconds / 60, "minutes"
	}
	return seconds, "seconds"
}

func (a auth) config(w http.ResponseWriter, _ *http.Request) {
	s := a.sessions.Settings()
	amount, unit := normalizedDuration(s.AbsoluteSeconds)
	api.WriteJSON(w, http.StatusOK, struct {
		OIDCEnabled bool `json:"oidcEnabled"`
		AuthDebug   bool `json:"authDebug"`
		Session     struct {
			HeartbeatMs        int64  `json:"heartbeatMs"`
			IdleWarnLeadMs     int64  `json:"idleWarnLeadMs"`
			AbsoluteWarnLeadMs int64  `json:"absoluteWarnLeadMs"`
			AbsoluteCapAmount  int64  `json:"absoluteCapAmount"`
			AbsoluteCapUnit    string `json:"absoluteCapUnit"`
		} `json:"session"`
	}{
		OIDCEnabled: s.OIDCEnabled, AuthDebug: s.AuthDebug,
		Session: struct {
			HeartbeatMs        int64  `json:"heartbeatMs"`
			IdleWarnLeadMs     int64  `json:"idleWarnLeadMs"`
			AbsoluteWarnLeadMs int64  `json:"absoluteWarnLeadMs"`
			AbsoluteCapAmount  int64  `json:"absoluteCapAmount"`
			AbsoluteCapUnit    string `json:"absoluteCapUnit"`
		}{s.HeartbeatSeconds * 1000, s.IdleWarnLeadSeconds * 1000, s.AbsoluteWarnLeadSeconds * 1000, amount, unit},
	})
}

// sessionGate is Kotlin's web-session auth provider: a live session, else 401 {"reason"} saying why.
func (a auth) sessionGate(next func(http.ResponseWriter, *http.Request, *session.Web)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		ctx := r.Context()
		s, err := a.sessions.Resolve(ctx, r)
		if errors.Is(err, session.ErrDeviceMismatch) {
			a.endSession(ctx, s.ID, session.EndedDeviceMismatch)
			s, err = nil, nil
		}
		if err != nil {
			fail(w, err)
			return
		}
		if s != nil {
			next(w, r, s)
			return
		}
		ref, err := a.sessions.Ref(ctx, r)
		if err != nil {
			fail(w, err)
			return
		}
		a.unauthorized(w, ref)
	}
}

// unauthorized answers a request whose session did not resolve, naming why when it named one.
func (a auth) unauthorized(w http.ResponseWriter, ref *session.Ref) {
	reason := "none"
	if ref != nil && ref.ID != 0 {
		var err error
		if reason, err = a.sessions.EndedReason(context.Background(), ref.ID); err != nil {
			fail(w, err)
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	api.WriteJSON(w, http.StatusUnauthorized, struct {
		Reason string `json:"reason"`
	}{reason})
}

// endSession ends one web session outside any other write and tells Kotlin to close the editor runs.
func (a auth) endSession(ctx context.Context, id int64, reason string) {
	principal, err := a.sessions.EndNow(ctx, id, reason)
	if err == nil && principal != "" {
		err = a.kotlin.SessionsEnded(context.WithoutCancel(ctx), principal)
	}
	if err != nil {
		slog.Warn("auth: ending a web session", "session", id, "err", err)
	}
}

func (a auth) me(w http.ResponseWriter, r *http.Request, s *session.Web) {
	roles, err := authz.New(a.pool).Roles(r.Context(), s.Principal)
	if err != nil {
		fail(w, err)
		return
	}
	if roles == nil {
		roles = []string{}
	}
	slices.Sort(roles)
	out := userSession{Principal: s.Principal, Roles: roles}
	if a.sessions.Settings().AuthDebug && s.DebugRequesterIP != "" {
		out.RequesterIP = &s.DebugRequesterIP
	}
	api.WriteJSON(w, http.StatusOK, out)
}

func (a auth) status(w http.ResponseWriter, _ *http.Request, s *session.Web) {
	api.WriteJSON(w, http.StatusOK, statusOf(s))
}

// heartbeat is the one route that slides a session's idle deadline.
func (a auth) heartbeat(w http.ResponseWriter, r *http.Request, s *session.Web) {
	device, _ := session.Device(r)
	touched, err := a.sessions.Touch(r.Context(), s.ID, device)
	if err != nil {
		fail(w, err)
		return
	}
	if touched == nil {
		a.unauthorized(w, &session.Ref{ID: s.ID})
		return
	}
	api.WriteJSON(w, http.StatusOK, statusOf(touched))
}

// requesterIP is Kotlin's httpRequesterIp: the debug login's simulated address while debug login is on,
// else the edge-resolved address.
func (a auth) requesterIP(r *http.Request) string {
	if a.sessions.Settings().AuthDebug {
		s, err := a.sessions.Resolve(r.Context(), r)
		if errors.Is(err, session.ErrDeviceMismatch) {
			a.endSession(r.Context(), s.ID, session.EndedDeviceMismatch)
		} else if err == nil && s != nil && s.DebugRequesterIP != "" {
			return s.DebugRequesterIP
		}
	}
	return front.RequesterIP(r, a.edges)
}

// logout ends the cookie's session, live or idle-expired, and clears the cookie. A request naming a
// sessionId ends only that session, so an automatic logout cannot end a newer login.
func (a auth) logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in struct {
		SessionID *int64 `json:"sessionId"`
	}
	if r.ContentLength != 0 && r.Header.Get("Content-Type") != "" {
		body, err := io.ReadAll(r.Body)
		if err == nil && strings.TrimSpace(string(body)) != "" {
			err = json.Unmarshal(body, &in)
		}
		if err != nil {
			fail(w, err)
			return
		}
	}
	ref, err := a.sessions.Ref(ctx, r)
	if err != nil {
		fail(w, err)
		return
	}
	if in.SessionID != nil && ref != nil && ref.ID != 0 && ref.ID != *in.SessionID {
		api.WriteJSON(w, http.StatusOK, struct {
			Ended bool `json:"ended"`
		}{false})
		return
	}
	if ref != nil && ref.ID != 0 {
		addr := a.requesterIP(r)
		var owner string
		err := pgx.BeginFunc(ctx, a.pool, func(tx pgx.Tx) error {
			var err error
			if owner, err = a.sessions.End(ctx, tx, ref.ID, session.EndedSignedOut); err != nil || owner == "" {
				return err
			}
			return audit.Auth(ctx, tx, audit.Actor{Principal: owner, ClientAddr: addr, Channel: "session"}, "auth.logout",
				audit.Entity("Session", strconv.FormatInt(ref.ID, 10)), "Web session signed out")
		})
		if err == nil && owner == "" {
			owner, err = a.sessions.Owner(ctx, ref.ID)
		}
		if err == nil {
			err = a.kotlin.SessionsEnded(context.WithoutCancel(ctx), owner)
		}
		if err != nil {
			fail(w, err)
			return
		}
	}
	if ref != nil {
		a.sessions.ClearSessionCookie(w)
	}
	api.WriteJSON(w, http.StatusOK, struct {
		Ended bool `json:"ended"`
	}{true})
}

// debugLogin, under PM_AUTH_DEBUG only, signs in as any principal with exactly the given direct roles.
func (a auth) debugLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !a.sessions.Settings().AuthDebug {
		api.WriteError(w, http.StatusNotFound, "common.not_found", map[string]string{"resource": "endpoint"})
		return
	}
	var in struct {
		Principal   *string  `json:"principal"`
		Roles       []string `json:"roles"`
		RequesterIP *string  `json:"requesterIp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Principal == nil {
		api.WriteError(w, http.StatusInternalServerError, "common.fallback", nil)
		return
	}
	roles := []string{}
	for _, role := range in.Roles {
		if role = strings.TrimSpace(role); role != "" && !slices.Contains(roles, role) {
			roles = append(roles, role)
		}
	}
	var debugIP *string
	if in.RequesterIP != nil {
		if ip := strings.TrimSpace(*in.RequesterIP); ip != "" {
			if !storableIP(ip) {
				api.WriteError(w, http.StatusBadRequest, "auth.invalid_requester_ip", nil)
				return
			}
			debugIP = &ip
		}
	}
	device := a.sessions.EnsureDevice(w, r)
	addr := a.requesterIP(r)
	if debugIP != nil {
		addr = *debugIP
	}
	ref, err := a.sessions.Ref(ctx, r)
	if err != nil {
		fail(w, err)
		return
	}
	key := session.NewKey()
	if ref != nil {
		key = ref.Key
	}
	principal := *in.Principal
	var (
		displaced bool
		id        int64
	)
	err = pgx.BeginFunc(ctx, a.pool, func(tx pgx.Tx) error {
		if err := replaceDirectRoles(ctx, tx, principal, roles, audit.Actor{Principal: principal, ClientAddr: addr, Channel: "console"}); err != nil {
			return err
		}
		var err error
		id, displaced, err = a.sessions.Mint(ctx, tx, principal, nil, device, debugIP)
		return err
	})
	if err == nil {
		err = pgx.BeginFunc(ctx, a.pool, func(tx pgx.Tx) error { return a.sessions.Link(ctx, tx, id, key) })
	}
	if err == nil && displaced {
		err = a.kotlin.SessionsEnded(context.WithoutCancel(ctx), principal)
	}
	if err != nil {
		writeMutationError(w, err)
		return
	}
	a.sessions.SetSessionCookie(w, key)
	api.WriteJSON(w, http.StatusOK, userSession{Principal: principal, Roles: roles, RequesterIP: debugIP})
}

// replaceDirectRoles makes the principal's direct roles exactly roles, under the principal's lock.
func replaceDirectRoles(ctx context.Context, tx pgx.Tx, principal string, roles []string, actor audit.Actor) error {
	if err := required("principal", principal); err != nil {
		return err
	}
	if err := lockPrincipal(ctx, tx, principal); err != nil {
		return err
	}
	q := db.New(tx)
	ids := make([]int64, len(roles))
	for i, name := range roles {
		var err error
		ids[i], err = q.LiveRoleID(ctx, name)
		if errors.Is(err, pgx.ErrNoRows) {
			return notFound("role '" + name + "'")
		}
		if err != nil {
			return err
		}
	}
	if err := q.DeleteDirectRoles(ctx, principal); err != nil {
		return err
	}
	for _, id := range ids {
		if err := q.AddDirectRole(ctx, db.AddDirectRoleParams{Principal: principal, RoleID: id}); err != nil {
			return err
		}
	}
	return audit.Admin(ctx, tx, actor, "admin.identity", userEntity(principal),
		"replace direct roles of '"+principal+"' ["+strings.Join(roles, ", ")+"]")
}

// storableIP is Kotlin's isStorableIpLiteral: a plain IP literal Cedar's ip() accepts.
func storableIP(ip string) bool {
	if strings.Trim(ip, "0123456789.:abcdefABCDEF") != "" {
		return false
	}
	_, err := types.ParseIPAddr(ip)
	return err == nil
}
