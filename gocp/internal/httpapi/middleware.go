package httpapi

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// StatusPages — App.kt:454-462
// ---------------------------------------------------------------------------------------------

// OAuthMetadataPath is the ONE non-prefixed path StatusPages answers in the OAuth vocabulary
// (App.kt:458). It is checked with `==`, not a prefix, so `/.well-known/oauth-authorization-server/x`
// takes the ApiError branch. REPRODUCE the exact-match.
const OAuthMetadataPath = "/.well-known/oauth-authorization-server"

// OAuthPathPrefix is the other half of that branch: `call.request.path().startsWith("/oauth/")`.
// Note the TRAILING SLASH — a route at exactly `/oauth` (no slash) would take the ApiError branch.
const OAuthPathPrefix = "/oauth/"

// StatusPages is `install(StatusPages) { exception<Throwable> { … } }`.
//
// Ktor catches a thrown Throwable from anywhere in the pipeline; Go's equivalent for "the handler
// blew up in a way nobody planned for" is a panic, so this recovers. Handlers that fail in a way they
// DID plan for return their own status and never reach here — same as the Kotlin, where a caught
// exception is handled at its call site.
//
// Behaviour, in order:
//  1. log the cause at ERROR ("Unhandled exception"),
//  2. `/oauth/**` or exactly `/.well-known/oauth-authorization-server` ⇒ 500 OAuthError("server_error"),
//  3. otherwise ⇒ 500 ApiError("common.fallback").
//
// 🔒 THE CAUSE NEVER REACHES THE CLIENT. AuthAndIngestRoutesDbTest's catch-all case
// (AuthAndIngestRoutesDbTest.kt:91-111) asserts a sentinel string from the thrown exception's message
// is ABSENT from the body, precisely so that a regression re-serializing `cause.message` — a database
// error carrying connection details, say — is caught. The body here is a constant.
//
// ⚠️ F41 (99-reconciliation-report.md:245, = A3 F30) — THIS ALSO FIRES ON `/api/scim/v2/**`, so an
// uncaught exception in a SCIM route answers `{"code":"common.fallback"}` instead of a ScimError,
// breaking the documented SCIM error-body exemption exactly where an IdP is least able to parse it.
// It is a defect and the PORT POLICY says REPRODUCE it: there is deliberately NO SCIM branch below.
// TestStatusPagesAnswersApiErrorOnScimPaths is the PIN — a later fix has to change that test
// deliberately and visibly.
//
// A response that has ALREADY been written cannot be turned into a 500 (the status line is gone), so
// that case is logged and the connection dropped. Ktor has the same limitation and the same outcome:
// the client sees a truncated body rather than an incorrect status.
func StatusPages(log *slog.Logger) func(http.Handler) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := &statusRecorder{ResponseWriter: w}
			defer func() {
				cause := recover()
				if cause == nil {
					return
				}
				log.Error("Unhandled exception", "path", r.URL.Path, "method", r.Method, "cause", cause)
				if rec.wrote {
					log.Error("response already started; cannot answer the StatusPages fallback",
						"path", r.URL.Path, "status", rec.status)
					// Re-panic so net/http's own recovery closes the connection rather than leaving
					// the client waiting on a body that will never finish.
					panic(cause)
				}
				RespondFallback(rec, r, log, nil)
			}()
			next.ServeHTTP(rec, r)
		})
	}
}

// RespondFallback writes the StatusPages catch-all body for r's path — the ONE function both the
// panic recovery and the gates' store-failure paths go through, so the two produce byte-identical
// responses. In the Kotlin they are the same code by construction, because a store failure there IS
// an exception reaching StatusPages.
//
// cause may be nil (the panic path already logged it).
func RespondFallback(w http.ResponseWriter, r *http.Request, log *slog.Logger, cause error) {
	if log == nil {
		log = slog.Default()
	}
	if cause != nil {
		log.Error("Unhandled exception", "path", r.URL.Path, "method", r.Method, "err", cause)
	}
	var err error
	if IsOAuthSurface(r.URL.Path) {
		err = RespondOAuthError(w, types.OAuthServerError())
	} else {
		err = RespondAPIError(w, types.Fallback())
	}
	if err != nil {
		log.Error("failed to write the StatusPages fallback", "err", err)
	}
}

// IsOAuthSurface is StatusPages' path test: `path.startsWith("/oauth/") || path == "/.well-known/oauth-authorization-server"`.
//
// The path is the DECODED request path with no query string — Ktor's `call.request.path()`. Go's
// r.URL.Path is already decoded and query-free, so it is the direct equivalent.
func IsOAuthSurface(path string) bool {
	return strings.HasPrefix(path, OAuthPathPrefix) || path == OAuthMetadataPath
}

// statusRecorder tracks whether a handler has started the response, and with what status. Both facts
// are needed: StatusPages must not try to write a second status line, and CallLogging must log the
// status that actually went out.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(status int) {
	if !s.wrote {
		s.status = status
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(status)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wrote {
		// net/http's implicit 200 on a first Write — recorded so CallLogging does not report 0.
		s.status = http.StatusOK
		s.wrote = true
	}
	return s.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer, so a future SSE route can still
// Flush through this wrapper. Without it, wrapping silently disables flushing.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// ---------------------------------------------------------------------------------------------
// CallLogging — App.kt:453
// ---------------------------------------------------------------------------------------------

// CallLogging is `install(CallLogging) { level = Level.INFO }` — one INFO line per completed call
// carrying the status, the method and the path.
//
// Ktor's default formatter is `"${call.response.status()}: ${call.request.toLogString()}"`, i.e.
// `200 OK: GET - /health`. Unverified: reconstructed from Ktor's documented default, not measured —
// there is no JVM on this machine. The port emits the same three FACTS as structured slog attributes
// rather than that exact sentence, because a log line is not a wire contract and the port's other
// packages all log structurally. Nothing asserts on the text.
//
// It is the OUTERMOST wrapper so it observes the status StatusPages produced, not the one a panicking
// handler failed to write.
func CallLogging(log *slog.Logger) func(http.Handler) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec, ok := w.(*statusRecorder)
			if !ok {
				rec = &statusRecorder{ResponseWriter: w}
			}
			defer func() {
				status := rec.status
				if !rec.wrote {
					// A handler that wrote nothing at all: net/http will send 200 with an empty body.
					status = http.StatusOK
				}
				log.Info("http", "status", status, "method", r.Method, "path", r.URL.Path)
			}()
			next.ServeHTTP(rec, r)
		})
	}
}

// ---------------------------------------------------------------------------------------------

// Middleware is one wrapper in the plugin stack.
type Middleware func(http.Handler) http.Handler

// Chain composes middleware so that the FIRST argument is OUTERMOST — i.e. the same order Ktor's
// `install` calls run in, so the App.kt list can be transcribed top to bottom without inverting it.
func Chain(h http.Handler, mw ...Middleware) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}
