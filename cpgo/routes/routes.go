// Package routes holds the control-plane HTTP routes served in Go. Anything not registered here is
// forwarded to the Kotlin control plane.
package routes

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
)

// locales is the closed set the message catalog carries (MessageCatalog.LOCALES).
var locales = []string{"en", "ko"}

// Register adds every Go-served route to mux.
func Register(mux *http.ServeMux, pool *pgxpool.Pool, gate api.Gate, authz Authorizer) {
	h := handlers{pool: pool}
	mux.HandleFunc("PUT /api/me/locale", gate.RequireAPI(h.putLocale))
	mux.HandleFunc("GET /api/query-history", gate.RequireAPI(h.getQueryHistory))
	mux.HandleFunc("DELETE /api/query-history", gate.RequireAPI(h.deleteQueryHistory))
	a := audit{pool: pool, authz: authz}
	mux.HandleFunc("GET /api/audit", gate.RequireAPI(a.list))
	mux.HandleFunc("GET /api/audit/{id}", gate.RequireAPI(a.get))
}

type handlers struct{ pool *pgxpool.Pool }

// putLocale stores the caller's display language, which notification delivery reads.
func (h handlers) putLocale(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Locale string `json:"locale"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		api.WriteError(w, http.StatusBadRequest, "common.invalid_value", map[string]string{"field": "locale"})
		return
	}
	locale := strings.ToLower(strings.TrimSpace(in.Locale))
	if !slices.Contains(locales, locale) {
		api.WriteError(w, http.StatusBadRequest, "common.invalid_value", map[string]string{"field": "locale"})
		return
	}
	// A principal with no directory row keeps the instance default; that is not an error.
	if _, err := h.pool.Exec(r.Context(), `UPDATE app_user SET locale = $1 WHERE principal = $2`,
		locale, api.Principal(r.Context())); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type historyEntry struct {
	SQL          string `json:"sql"`
	DatasourceID *int64 `json:"datasourceId,omitempty"`
	RanAt        string `json:"ranAt"`
}

// getQueryHistory returns the caller's most recent distinct queries, newest first.
func (h handlers) getQueryHistory(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil {
		limit = min(max(n, 1), 200)
	}
	rows, err := h.pool.Query(r.Context(), `
		SELECT sql, datasource_id, created_at FROM (
		    SELECT DISTINCT ON (sql) sql, datasource_id, created_at
		    FROM query_history WHERE principal = $1
		    ORDER BY sql, created_at DESC
		) q
		ORDER BY created_at DESC
		LIMIT $2`, api.Principal(r.Context()), limit)
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()
	out := []historyEntry{}
	for rows.Next() {
		var (
			e  historyEntry
			at time.Time
		)
		if err := rows.Scan(&e.SQL, &e.DatasourceID, &at); err != nil {
			fail(w, err)
			return
		}
		e.RanAt = javaInstant(at)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		fail(w, err)
		return
	}
	api.WriteJSON(w, http.StatusOK, out)
}

func (h handlers) deleteQueryHistory(w http.ResponseWriter, r *http.Request) {
	if _, err := h.pool.Exec(r.Context(), `DELETE FROM query_history WHERE principal = $1`,
		api.Principal(r.Context())); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func fail(w http.ResponseWriter, err error) {
	slog.Error("routes: store query failed", "err", err)
	api.WriteError(w, http.StatusInternalServerError, "common.fallback", nil)
}

// javaInstant formats t like java.time.Instant.toString: UTC, fractional seconds in groups of three
// digits, none when zero.
func javaInstant(t time.Time) string {
	t = t.UTC()
	s := t.Format("2006-01-02T15:04:05")
	switch ns := t.Nanosecond(); {
	case ns == 0:
	case ns%1_000_000 == 0:
		s += "." + leftPad(ns/1_000_000, 3)
	case ns%1_000 == 0:
		s += "." + leftPad(ns/1_000, 6)
	default:
		s += "." + leftPad(ns, 9)
	}
	return s + "Z"
}

func leftPad(n, width int) string {
	s := strconv.Itoa(n)
	return strings.Repeat("0", width-len(s)) + s
}
