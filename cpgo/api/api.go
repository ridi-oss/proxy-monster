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
	"net/url"
	"strings"
	"time"

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

// WriteJSON writes v byte-identical to the Kotlin serializer (no HTML escaping, no trailing newline), so old-vs-new response diffs stay clean.
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

// Code is an ApiError code, the message key the web looks up, with the status it always answers.
type Code struct {
	key    string
	status int
}

var (
	CodeFallback              = Code{"common.fallback", http.StatusInternalServerError}
	CodeUnauthenticated       = Code{"common.unauthenticated", http.StatusUnauthorized}
	CodeForbidden             = Code{"common.forbidden", http.StatusForbidden}
	CodeNotFound              = Code{"common.not_found", http.StatusNotFound}
	CodeBadID                 = Code{"common.bad_id", http.StatusBadRequest}
	CodeInvalidValue          = Code{"common.invalid_value", http.StatusBadRequest}
	CodeFieldRequired         = Code{"common.field_required", http.StatusBadRequest}
	CodeAlreadyExists         = Code{"common.already_exists", http.StatusBadRequest}
	CodeRoleSystemImmutable   = Code{"role.system_immutable", http.StatusConflict}
	CodePolicySystemImmutable = Code{"policy.system_immutable", http.StatusConflict}
	CodePolicyReservedName    = Code{"policy.reserved_name", http.StatusBadRequest}
	CodeGroupSystemImmutable  = Code{"group.system_immutable", http.StatusConflict}
	CodeNotApprover           = Code{"approval.not_approver", http.StatusForbidden}
	CodeRequestNotPermitted   = Code{"approval.request_not_permitted", http.StatusForbidden}
	CodeUseQueryApproval      = Code{"approval.use_query_approval_endpoint", http.StatusBadRequest}
)

// WriteError writes an ApiError; kv is its params as alternating keys and values, kept in that order.
func WriteError(w http.ResponseWriter, c Code, kv ...string) { writeError(w, c, pairs(kv)) }

func writeError(w http.ResponseWriter, c Code, p Params) {
	WriteJSON(w, c.status, Error{Code: c.key, Params: p})
}

// pairs reads alternating keys and values; an odd count is a programming error.
func pairs(kv []string) Params {
	if len(kv)%2 != 0 {
		panic("api: error params need a value for every key")
	}
	p := make(Params, 0, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		p = append(p, [2]string{kv[i], kv[i+1]})
	}
	return p
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
}

// Kotlin is what Go routes tell the Kotlin control plane about the state it holds in memory.
type Kotlin interface {
	// PoliciesChanged: a committed policy write; Kotlin's query path rebuilds its cached policy set.
	PoliciesChanged(ctx context.Context) error
	// RequestNotified: a committed write opened or decided the request; send its notification.
	RequestNotified(ctx context.Context, id int64, event string) error
	// SessionsEnded: a committed change ended the principal's web sessions; close the editor runs held for them.
	SessionsEnded(ctx context.Context, principal string) error
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
	Authz     Authorizer
	Kotlin    Kotlin
}

// RequireAPIOrBearer is Kotlin's requireApiOrBearer, for read-only datasource discovery: a web session,
// else pmon's native wire token (SESSION or USER) as an Authorization bearer.
func (g Gate) RequireAPIOrBearer(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := g.Sessions.Resolve(r.Context(), r)
		if errors.Is(err, session.ErrDeviceMismatch) {
			g.EndMismatched(r)
			s, err = nil, nil
		}
		if err != nil {
			slog.Error("api: resolving session", "err", err)
			WriteError(w, CodeFallback)
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
				WriteError(w, CodeFallback)
				return
			}
		}
		if principal == "" {
			WriteError(w, CodeUnauthenticated)
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
			WriteError(w, CodeFallback)
		case !ok:
			WriteError(w, CodeForbidden, "detail", reason)
		default:
			next(w, r)
		}
	})
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
	return g.RequireAPIElse(func(w http.ResponseWriter, _ *http.Request) {
		WriteError(w, CodeUnauthenticated)
	}, next)
}

// RequireAPIElse is RequireAPI with the answer to a request without a live session left to unauthenticated.
func (g Gate) RequireAPIElse(unauthenticated, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := g.Sessions.Resolve(r.Context(), r)
		switch {
		case errors.Is(err, session.ErrDeviceMismatch):
			g.EndMismatched(r)
			unauthenticated(w, r)
		case err != nil:
			slog.Error("api: resolving session", "err", err)
			WriteError(w, CodeFallback)
		case s == nil:
			unauthenticated(w, r)
		default:
			next(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, g.sessionCaller(r, s))))
		}
	}
}
