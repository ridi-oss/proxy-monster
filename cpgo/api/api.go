// Package api holds what every Go-served control-plane route shares: the ApiError wire shape, JSON
// responses, and the session gate.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/ridi-oss/proxy-monster/cpgo/front"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
)

// Error is the Kotlin ApiError: a stable code the web looks up as an i18n key, and its params.
type Error struct {
	Code   string            `json:"code"`
	Params map[string]string `json:"params"`
}

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("api: writing response", "err", err)
	}
}

func WriteError(w http.ResponseWriter, status int, code string, params map[string]string) {
	if params == nil {
		params = map[string]string{}
	}
	WriteJSON(w, status, Error{Code: code, Params: params})
}

type caller struct{ principal, requesterIP string }

type callerKey struct{}

// Principal is the caller RequireAPI authenticated.
func Principal(ctx context.Context) string {
	c, _ := ctx.Value(callerKey{}).(caller)
	return c.principal
}

// RequesterIP is the caller's address as Cedar's requester_ip, "" when unknown.
func RequesterIP(ctx context.Context) string {
	c, _ := ctx.Value(callerKey{}).(caller)
	return c.requesterIP
}

// Gate authenticates console requests for Go routes.
type Gate struct {
	Sessions *session.Resolver
	// EndMismatched has the Kotlin control plane end a session presented from the wrong device. Kotlin
	// owns that teardown because it also drops the principal's in-memory editor runs.
	EndMismatched func(*http.Request)
	Edges         front.TrustedEdges
	// AuthDebug lets a session carry the requester IP chosen at its debug login, as Kotlin does.
	AuthDebug bool
}

// KotlinSessionCheck resolves the request's session through Kotlin's /auth/session/status, which ends a
// device-mismatched session as a side effect.
func KotlinSessionCheck(upstream *url.URL) func(*http.Request) {
	client := &http.Client{Timeout: 10 * time.Second}
	status := upstream.JoinPath("/auth/session/status").String()
	return func(r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, status, nil)
		if err != nil {
			return
		}
		req.Header["Cookie"] = r.Header["Cookie"]
		resp, err := client.Do(req)
		if err != nil {
			slog.Warn("api: ending mismatched session", "err", err)
			return
		}
		_ = resp.Body.Close()
	}
}

// RequireAPI is Kotlin's requireApi: a live web session, or 401 common.unauthenticated.
func (g Gate) RequireAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := g.Sessions.Resolve(r.Context(), r)
		switch {
		case errors.Is(err, session.ErrDeviceMismatch):
			g.EndMismatched(r)
			WriteError(w, http.StatusUnauthorized, "common.unauthenticated", nil)
		case err != nil:
			slog.Error("api: resolving session", "err", err)
			WriteError(w, http.StatusInternalServerError, "common.fallback", nil)
		case s == nil:
			WriteError(w, http.StatusUnauthorized, "common.unauthenticated", nil)
		default:
			ip := front.RequesterIP(r, g.Edges)
			if g.AuthDebug && s.DebugRequesterIP != "" {
				ip = s.DebugRequesterIP
			}
			next(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, caller{s.Principal, ip})))
		}
	}
}
