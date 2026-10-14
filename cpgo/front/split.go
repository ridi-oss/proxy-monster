package front

import (
	"net/http"
	"strings"
)

// controlPlanePrefixes are the console paths the control plane serves; every other path is the web console.
var controlPlanePrefixes = []string{"/api/", "/auth/", "/oauth/", "/mcp", "/.well-known/oauth-"}

// webPage is the one web page under a control-plane prefix: the reauth popup lands there after login.
const webPage = "/auth/reauth-complete"

// Split sends control-plane paths and /health to controlPlane and the rest to web.
func Split(controlPlane, web http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == webPage {
			web.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/health" {
			controlPlane.ServeHTTP(w, r)
			return
		}
		for _, p := range controlPlanePrefixes {
			if strings.HasPrefix(r.URL.Path, p) {
				controlPlane.ServeHTTP(w, r)
				return
			}
		}
		web.ServeHTTP(w, r)
	})
}
