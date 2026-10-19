// Package websession serves the console's web-session routes: config, debug login, me, status, heartbeat
// and logout.
package websession

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

func Register(mux *http.ServeMux, pool *pgxpool.Pool, gate api.Gate) Auth {
	au := Auth{Pool: pool, Sessions: gate.Sessions, kotlin: gate.Kotlin, edges: gate.Edges}
	mux.HandleFunc("GET /auth/config", api.Serve(au.config))
	mux.HandleFunc("POST /auth/debug", api.Serve(au.debugLogin))
	mux.HandleFunc("GET /auth/me", au.sessionGate(au.me))
	mux.HandleFunc("GET /auth/session/status", au.sessionGate(au.status))
	mux.HandleFunc("POST /auth/session/heartbeat", au.sessionGate(au.heartbeat))
	mux.HandleFunc("POST /auth/logout", api.Serve(au.logout))
	return au
}

// Auth serves the console's session routes and establishes the sessions other logins mint.
type Auth struct {
	Pool     *pgxpool.Pool
	Sessions *session.Resolver
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
	return sessionStatus{api.JavaInstant(w.Now), api.JavaInstant(w.IdleExpiresAt), api.JavaInstant(w.AbsoluteExpiresAt), w.Principal, w.ID}
}

type sessionUX struct {
	HeartbeatMs        int64  `json:"heartbeatMs"`
	IdleWarnLeadMs     int64  `json:"idleWarnLeadMs"`
	AbsoluteWarnLeadMs int64  `json:"absoluteWarnLeadMs"`
	AbsoluteCapAmount  int64  `json:"absoluteCapAmount"`
	AbsoluteCapUnit    string `json:"absoluteCapUnit"`
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

func (a Auth) config(w http.ResponseWriter, _ *http.Request) error {
	s := a.Sessions.Settings()
	amount, unit := normalizedDuration(s.AbsoluteSeconds)
	api.WriteJSON(w, http.StatusOK, struct {
		OIDCEnabled bool      `json:"oidcEnabled"`
		AuthDebug   bool      `json:"authDebug"`
		Session     sessionUX `json:"session"`
	}{s.OIDCEnabled, s.AuthDebug, sessionUX{s.HeartbeatSeconds * 1000, s.IdleWarnLeadSeconds * 1000, s.AbsoluteWarnLeadSeconds * 1000, amount, unit}})
	return nil
}

// sessionGate is Kotlin's web-session auth provider: a live session, else 401 {"reason"} saying why.
func (a Auth) sessionGate(next func(http.ResponseWriter, *http.Request, *session.Web) error) http.HandlerFunc {
	return api.Serve(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Cache-Control", "no-store")
		ctx := r.Context()
		s, err := a.Sessions.Resolve(ctx, r)
		if errors.Is(err, session.ErrDeviceMismatch) {
			a.EndSession(ctx, s.ID, session.EndedDeviceMismatch)
			s, err = nil, nil
		}
		if err != nil {
			return err
		}
		if s != nil {
			return next(w, r, s)
		}
		ref, err := a.Sessions.Ref(ctx, r)
		if err != nil {
			return err
		}
		return a.unauthorized(ctx, w, ref)
	})
}

// unauthorized answers a request whose session did not resolve, naming why when it named one.
func (a Auth) unauthorized(ctx context.Context, w http.ResponseWriter, ref *session.Ref) error {
	reason := "none"
	if ref != nil && ref.ID != 0 {
		var err error
		if reason, err = a.Sessions.EndedReason(ctx, ref.ID); err != nil {
			return err
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	api.WriteJSON(w, http.StatusUnauthorized, struct {
		Reason string `json:"reason"`
	}{reason})
	return nil
}

// EndSession ends one web session outside any other write and tells Kotlin to close the editor runs.
func (a Auth) EndSession(ctx context.Context, id int64, reason string) {
	principal, err := a.Sessions.EndNow(ctx, id, reason)
	if err == nil && principal != "" {
		err = a.kotlin.SessionsEnded(context.WithoutCancel(ctx), principal)
	}
	if err != nil {
		slog.Warn("auth: ending a web session", "session", id, "err", err)
	}
}

func (a Auth) me(w http.ResponseWriter, r *http.Request, s *session.Web) error {
	roles, err := authz.Roles(r.Context(), a.Pool, s.Principal)
	if err != nil {
		return err
	}
	out := userSession{Principal: s.Principal, Roles: api.NonNil(roles)}
	if a.Sessions.Settings().AuthDebug && s.DebugRequesterIP != "" {
		out.RequesterIP = &s.DebugRequesterIP
	}
	api.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a Auth) status(w http.ResponseWriter, _ *http.Request, s *session.Web) error {
	api.WriteJSON(w, http.StatusOK, statusOf(s))
	return nil
}

// heartbeat is the one route that slides a session's idle deadline.
func (a Auth) heartbeat(w http.ResponseWriter, r *http.Request, s *session.Web) error {
	device, _ := session.Device(r)
	touched, err := a.Sessions.Touch(r.Context(), s.ID, device)
	if err != nil {
		return err
	}
	if touched == nil {
		return a.unauthorized(r.Context(), w, &session.Ref{ID: s.ID})
	}
	api.WriteJSON(w, http.StatusOK, statusOf(touched))
	return nil
}

// RequesterIP is Kotlin's httpRequesterIp: the debug login's simulated address while debug login is on,
// else the edge-resolved address.
func (a Auth) RequesterIP(r *http.Request) string {
	if a.Sessions.Settings().AuthDebug {
		s, err := a.Sessions.Resolve(r.Context(), r)
		if errors.Is(err, session.ErrDeviceMismatch) {
			a.EndSession(r.Context(), s.ID, session.EndedDeviceMismatch)
		} else if err == nil && s != nil && s.DebugRequesterIP != "" {
			return s.DebugRequesterIP
		}
	}
	return front.RequesterIP(r, a.edges)
}

type logoutResponse struct {
	Ended bool `json:"ended"`
}

// logout ends the cookie's session, live or idle-expired, and clears the cookie. A request naming a
// sessionId ends only that session, so an automatic logout cannot end a newer login.
func (a Auth) logout(w http.ResponseWriter, r *http.Request) error {
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
			return err
		}
	}
	ref, err := a.Sessions.Ref(ctx, r)
	if err != nil {
		return err
	}
	if in.SessionID != nil && ref != nil && ref.ID != 0 && ref.ID != *in.SessionID {
		api.WriteJSON(w, http.StatusOK, logoutResponse{false})
		return nil
	}
	if ref != nil && ref.ID != 0 {
		addr := a.RequesterIP(r)
		var owner string
		err := pgx.BeginFunc(ctx, a.Pool, func(tx pgx.Tx) error {
			var err error
			if owner, err = a.Sessions.End(ctx, tx, ref.ID, session.EndedSignedOut); err != nil || owner == "" {
				return err
			}
			return audit.Auth(ctx, tx, audit.Actor{Principal: owner, ClientAddr: addr, Channel: "session"}, "auth.logout",
				audit.Entity("Session", strconv.FormatInt(ref.ID, 10)), "Web session signed out")
		})
		if err != nil {
			return err
		}
		if owner != "" {
			a.signalEnded(ctx, owner)
		}
	}
	if ref != nil {
		a.Sessions.ClearSessionCookie(w)
	}
	api.WriteJSON(w, http.StatusOK, logoutResponse{true})
	return nil
}

// debugLogin, under PM_AUTH_DEBUG only, signs in as any principal with exactly the given direct roles.
func (a Auth) debugLogin(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	if !a.Sessions.Settings().AuthDebug {
		return api.CodeNotFound.Err("resource", "endpoint")
	}
	var in struct {
		Principal   *string  `json:"principal"`
		Roles       []string `json:"roles"`
		RequesterIP *string  `json:"requesterIp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Principal == nil {
		// Kotlin answers a body that does not decode with 500.
		return errors.New("debug login body does not decode")
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
				return api.CodeInvalidRequesterIP.Err()
			}
			debugIP = &ip
		}
	}
	device := a.Sessions.EnsureDevice(w, r)
	addr := a.RequesterIP(r)
	if debugIP != nil {
		addr = *debugIP
	}
	principal := *in.Principal
	var (
		displaced bool
		id        int64
	)
	err := pgx.BeginFunc(ctx, a.Pool, func(tx pgx.Tx) error {
		if err := replaceDirectRoles(ctx, tx, principal, roles, audit.Actor{Principal: principal, ClientAddr: addr, Channel: "console"}); err != nil {
			return err
		}
		var err error
		id, displaced, err = a.Sessions.Mint(ctx, tx, principal, nil, device, debugIP)
		return err
	})
	if err != nil {
		return err
	}
	if err := a.Establish(w, r, id, principal, displaced); err != nil {
		return err
	}
	api.WriteJSON(w, http.StatusOK, userSession{Principal: principal, Roles: roles, RequesterIP: debugIP})
	return nil
}

// replaceDirectRoles makes the principal's direct roles exactly roles, under the principal's lock.
func replaceDirectRoles(ctx context.Context, tx pgx.Tx, principal string, roles []string, actor audit.Actor) error {
	if err := api.Required("principal", principal); err != nil {
		return err
	}
	q := db.New(tx)
	if err := q.LockPrincipal(ctx, principal); err != nil {
		return err
	}
	ids := make([]int64, len(roles))
	for i, name := range roles {
		var err error
		ids[i], err = q.LiveRoleID(ctx, name)
		if errors.Is(err, pgx.ErrNoRows) {
			return api.NotFound("role '" + name + "'")
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
	return audit.Admin(ctx, tx, actor, "admin.identity", audit.Entity("User", principal),
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

// signalEnded has Kotlin close the principal's editor runs after a committed session end. The end already
// stands, so a failed signal is logged rather than failing the request.
func (a Auth) signalEnded(ctx context.Context, principal string) {
	if err := a.kotlin.SessionsEnded(context.WithoutCancel(ctx), principal); err != nil {
		slog.Warn("auth: telling the control plane a session ended", "principal", principal, "err", err)
	}
}
