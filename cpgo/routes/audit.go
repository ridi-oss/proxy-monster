package routes

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

type auditEvent struct {
	ID                 int64    `json:"id"`
	TS                 string   `json:"ts"`
	Principal          string   `json:"principal"`
	Roles              []string `json:"roles"`
	Datasource         string   `json:"datasource"`
	ClientAddr         *string  `json:"clientAddr,omitempty"`
	Statement          string   `json:"statement"`
	Decision           string   `json:"decision"`
	FailedStage        *string  `json:"failedStage,omitempty"`
	EffectiveNamespace []string `json:"effectiveNamespace"`
	MaskedColumns      []string `json:"maskedColumns"`
	PIITouched         []string `json:"piiTouched"`
	LatencyMS          int64    `json:"latencyMs"`
	Detail             *string  `json:"detail,omitempty"`
	Channel            *string  `json:"channel,omitempty"`
	ContextTags        []string `json:"contextTags"`
	AuthzAction        *string  `json:"authzAction,omitempty"`
	AuthzResource      *string  `json:"authzResource,omitempty"`
	Outcome            *string  `json:"outcome,omitempty"`
	Kind               string   `json:"kind"`
	RowsReturned       *int64   `json:"rowsReturned,omitempty"`
	BytesReturned      *int64   `json:"bytesReturned,omitempty"`
	DecisionID         *int64   `json:"decisionId,omitempty"`
}

type auditLog struct {
	pool  *pgxpool.Pool
	authz api.Authorizer
}

// list returns the whole log to a caller Cedar grants audit.read on it, and the caller's own rows otherwise.
func (a auditLog) list(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if n, err := strconv.ParseInt(r.URL.Query().Get("limit"), 10, 32); err == nil {
		limit = min(max(int(n), 1), 500)
	}
	ctx := r.Context()
	principal := api.Principal(ctx)
	all, _, err := a.authz.Authorize(ctx, principal, "audit.read", bridge.AuditLog, api.RequesterIP(ctx))
	if err != nil {
		fail(w, err)
		return
	}
	q := db.New(a.pool)
	var rows []db.AuditEvent
	if all {
		rows, err = q.AuditLog(ctx, int32(limit))
	} else {
		rows, err = q.AuditLogOf(ctx, db.AuditLogOfParams{Principal: principal, Limit: int32(limit)})
	}
	if err != nil {
		fail(w, err)
		return
	}
	out := make([]auditEvent, 0, len(rows))
	for _, row := range rows {
		out = append(out, toAuditEvent(row))
	}
	api.WriteJSON(w, http.StatusOK, out)
}

// get answers a record Cedar hides exactly like a missing one, so the route is no existence oracle.
func (a auditLog) get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		api.WriteError(w, http.StatusBadRequest, "common.bad_id", nil)
		return
	}
	ctx := r.Context()
	row, err := db.New(a.pool).AuditEvent(ctx, id)
	e := toAuditEvent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		api.WriteError(w, http.StatusNotFound, "common.not_found", map[string]string{"resource": "audit record"})
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	ok, _, err := a.authz.Authorize(ctx, api.Principal(ctx), "audit.read", bridge.AuditRecord(e.Principal), api.RequesterIP(ctx))
	if err != nil {
		fail(w, err)
		return
	}
	if !ok {
		api.WriteError(w, http.StatusNotFound, "common.not_found", map[string]string{"resource": "audit record"})
		return
	}
	api.WriteJSON(w, http.StatusOK, e)
}

func toAuditEvent(r db.AuditEvent) auditEvent {
	e := auditEvent{
		ID: r.ID, TS: javaInstant(r.Ts), Principal: r.Principal, Roles: r.Roles, Datasource: r.Datasource,
		ClientAddr: r.ClientAddr, Statement: r.Statement, Decision: r.Decision, FailedStage: r.FailedStage,
		EffectiveNamespace: r.EffectiveNamespace, MaskedColumns: r.MaskedColumns, PIITouched: r.PiiTouched,
		LatencyMS: r.LatencyMs, Detail: r.Detail, Channel: r.Channel, ContextTags: r.ContextTags,
		AuthzAction: r.Action, AuthzResource: r.Resource, Outcome: r.Outcome, Kind: r.Kind,
		RowsReturned: r.RowsReturned, BytesReturned: r.BytesReturned, DecisionID: r.DecisionID,
	}
	for _, l := range []*[]string{&e.Roles, &e.MaskedColumns, &e.PIITouched, &e.EffectiveNamespace, &e.ContextTags} {
		if *l == nil {
			*l = []string{}
		}
	}
	return e
}
