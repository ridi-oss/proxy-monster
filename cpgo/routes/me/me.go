package me

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

func Register(mux *http.ServeMux, pool *pgxpool.Pool, gate api.Gate) {
	h := handlers{pool: pool}
	mux.HandleFunc("PUT /api/me/locale", gate.RequireAPI(api.Serve(h.putLocale)))
	mux.HandleFunc("GET /api/query-history", gate.RequireAPI(api.Serve(h.getQueryHistory)))
	mux.HandleFunc("DELETE /api/query-history", gate.RequireAPI(api.Serve(h.deleteQueryHistory)))
}

// locales is the closed set the message catalog carries (MessageCatalog.LOCALES).
var locales = []string{"en", "ko"}

type handlers struct{ pool *pgxpool.Pool }

// putLocale stores the caller's display language, which notification delivery reads.
func (h handlers) putLocale(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Locale string `json:"locale"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		return api.CodeInvalidValue.Err("field", "locale")
	}
	locale := strings.ToLower(strings.TrimSpace(in.Locale))
	if !slices.Contains(locales, locale) {
		return api.CodeInvalidValue.Err("field", "locale")
	}
	// A principal with no directory row keeps the instance default; that is not an error.
	if err := db.New(h.pool).SetLocale(r.Context(), db.SetLocaleParams{Locale: &locale, Principal: api.Principal(r.Context())}); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

type historyEntry struct {
	SQL          string `json:"sql"`
	DatasourceID *int64 `json:"datasourceId,omitempty"`
	RanAt        string `json:"ranAt"`
}

// getQueryHistory returns the caller's most recent distinct queries, newest first.
func (h handlers) getQueryHistory(w http.ResponseWriter, r *http.Request) error {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil {
		limit = min(max(n, 1), 200)
	}
	rows, err := db.New(h.pool).QueryHistory(r.Context(), db.QueryHistoryParams{Principal: api.Principal(r.Context()), Limit: int32(limit)})
	if err != nil {
		return err
	}
	out := []historyEntry{}
	for _, row := range rows {
		out = append(out, historyEntry{SQL: row.Sql, DatasourceID: row.DatasourceID, RanAt: api.JavaInstant(row.CreatedAt)})
	}
	api.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (h handlers) deleteQueryHistory(w http.ResponseWriter, r *http.Request) error {
	if err := db.New(h.pool).DeleteQueryHistory(r.Context(), api.Principal(r.Context())); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
