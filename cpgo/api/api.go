// Package api holds what every Go-served control-plane route shares: the ApiError wire shape, JSON
// responses, and the session gate.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
	"github.com/ridi-oss/proxy-monster/cpgo/front"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
)

// Error is the Kotlin ApiError: a stable code the web looks up as an i18n key, and its params.
type Error struct {
	Code   string `json:"code"`
	Params Params `json:"params"`
}

// Params are an error's key/value pairs in insertion order, the order Kotlin's maps serialize in.
type Params [][2]string

func (p Params) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, kv := range p {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(jsonString(kv[0]))
		b.WriteByte(':')
		b.Write(jsonString(kv[1]))
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// WriteJSON writes v the way the Kotlin control plane's serializer does: no HTML escaping, no trailing newline.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		slog.Error("api: encoding response", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
}

func jsonString(s string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

// WriteError writes an ApiError; params holds at most one key, use WriteErrorParams for more.
func WriteError(w http.ResponseWriter, status int, code string, params map[string]string) {
	var p Params
	for k, v := range params {
		p = append(p, [2]string{k, v})
	}
	WriteErrorParams(w, status, code, p)
}

// WriteErrorParams writes an ApiError with params in the given order.
func WriteErrorParams(w http.ResponseWriter, status int, code string, params Params) {
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

// Authorizer is the Cedar decision a route asks for: allowed, or denied with Cedar's reason.
type Authorizer interface {
	Authorize(ctx context.Context, principal, action string, resource bridge.Resource, requesterIP string) (bool, string, error)
	AuthorizeEach(ctx context.Context, principal, action string, resources []bridge.Resource, requesterIP string) ([]bool, error)
	AuthorizeIn(ctx context.Context, principal, action string, resource bridge.Resource, requesterIP string, s bridge.Scope) (bool, string, error)
	MayRequest(ctx context.Context, principal string, datasourceID int64, requesterIP string) (bool, error)
	MayConnect(ctx context.Context, principal string, datasourceIDs []int64, requesterIP string) ([]bool, error)
	Validate(ctx context.Context, cedarSrc string) ([]string, error)
	PoliciesChanged(ctx context.Context) error
}

// Kotlin is what Go routes tell or ask the Kotlin control plane about the state it holds in memory.
type Kotlin interface {
	// SessionsEnded: a committed change revoked the principal's credentials; close its editor runs.
	SessionsEnded(ctx context.Context, principal string) error
	// ProxiesAttached names the datasources with a proxy on an open Events stream.
	ProxiesAttached(ctx context.Context) ([]string, error)
	// DatasourceDeleted: drop the in-memory catalog keyed by the deleted datasource's name.
	DatasourceDeleted(ctx context.Context, name string) error
}

// Gate authenticates console requests for Go routes.
type Gate struct {
	Sessions *session.Resolver
	Kotlin   Kotlin
	Edges    front.TrustedEdges
	// AuthDebug lets a session carry the requester IP chosen at its debug login, as Kotlin does.
	AuthDebug bool
	Authz     Authorizer
}

// RequireAPIOrBearer is Kotlin's requireApiOrBearer, for read-only datasource discovery: a web session,
// else pmon's native wire token (SESSION or USER) as an Authorization bearer.
func (g Gate) RequireAPIOrBearer(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := g.Sessions.Resolve(r.Context(), r)
		if errors.Is(err, session.ErrDeviceMismatch) {
			g.endMismatched(r.Context(), s)
			s, err = nil, nil
		}
		if err != nil {
			slog.Error("api: resolving session", "err", err)
			WriteError(w, http.StatusInternalServerError, "common.fallback", nil)
			return
		}
		if s != nil {
			next(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, g.sessionCaller(r, s))))
			return
		}
		principal := ""
		if token, ok := bearer(r); ok {
			if principal, err = g.Sessions.WirePrincipal(r.Context(), token); err != nil {
				slog.Error("api: resolving wire token", "err", err)
				WriteError(w, http.StatusInternalServerError, "common.fallback", nil)
				return
			}
		}
		if principal == "" {
			WriteError(w, http.StatusUnauthorized, "common.unauthenticated", nil)
			return
		}
		c := caller{principal, front.RequesterIP(r, g.Edges)}
		next(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, c)))
	}
}

// sessionCaller is the session's principal and requester IP, the debug-login address winning under AuthDebug.
func (g Gate) sessionCaller(r *http.Request, s *session.Web) caller {
	ip := front.RequesterIP(r, g.Edges)
	if g.AuthDebug && s.DebugRequesterIP != "" {
		ip = s.DebugRequesterIP
	}
	return caller{s.Principal, ip}
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "Bearer ") {
		return "", false
	}
	t := strings.TrimSpace(h[7:])
	return t, t != ""
}

// RequireAdmin is Kotlin's requireAdmin: a session, then Cedar's decision on action over the System
// resource, 403 common.forbidden with Cedar's reason on a deny.
func (g Gate) RequireAdmin(action string, next http.HandlerFunc) http.HandlerFunc {
	return g.RequireAPI(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ok, reason, err := g.Authz.Authorize(ctx, Principal(ctx), action, bridge.System, RequesterIP(ctx))
		switch {
		case err != nil:
			slog.Error("api: authorizing", "action", action, "err", err)
			WriteError(w, http.StatusInternalServerError, "common.fallback", nil)
		case !ok:
			WriteError(w, http.StatusForbidden, "common.forbidden", map[string]string{"detail": reason})
		default:
			next(w, r)
		}
	})
}

// endMismatched ends a session presented from a device other than the one it was opened on, as Kotlin's
// resolve does, and has Kotlin close the principal's editor runs.
func (g Gate) endMismatched(ctx context.Context, w *session.Web) {
	principal, err := g.Sessions.EndNow(ctx, w.ID, session.EndedDeviceMismatch)
	if err == nil && principal != "" {
		err = g.Kotlin.SessionsEnded(context.WithoutCancel(ctx), principal)
	}
	if err != nil {
		slog.Warn("api: ending a device-mismatched session", "session", w.ID, "err", err)
	}
}

// RequireAPI is Kotlin's requireApi: a live web session, or 401 common.unauthenticated.
func (g Gate) RequireAPI(next http.HandlerFunc) http.HandlerFunc {
	return g.RequireAPIElse(func(w http.ResponseWriter, _ *http.Request) {
		WriteError(w, http.StatusUnauthorized, "common.unauthenticated", nil)
	}, next)
}

// RequireAPIElse is RequireAPI with the answer to a request without a live session left to unauthenticated.
func (g Gate) RequireAPIElse(unauthenticated, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := g.Sessions.Resolve(r.Context(), r)
		switch {
		case errors.Is(err, session.ErrDeviceMismatch):
			g.endMismatched(r.Context(), s)
			unauthenticated(w, r)
		case err != nil:
			slog.Error("api: resolving session", "err", err)
			WriteError(w, http.StatusInternalServerError, "common.fallback", nil)
		case s == nil:
			unauthenticated(w, r)
		default:
			next(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, g.sessionCaller(r, s))))
		}
	}
}
