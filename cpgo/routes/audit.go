package routes

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
)

// Authorizer is the Cedar decision a route asks for.
type Authorizer interface {
	Authorize(ctx context.Context, principal, action string, resource bridge.Resource, requesterIP string) (bool, error)
}

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

const auditSelect = `
	SELECT id, ts, principal, roles, datasource, client_addr, statement, decision,
	       failed_stage, masked_columns, pii_touched, latency_ms, detail, effective_namespace,
	       channel, context_tags, action, resource, outcome, kind, rows_returned, bytes_returned,
	       decision_id
	FROM audit_event`

type audit struct {
	pool  *pgxpool.Pool
	authz Authorizer
}

// list returns the whole log to a caller Cedar grants audit.read on it, and the caller's own rows otherwise.
func (a audit) list(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if n, err := strconv.ParseInt(r.URL.Query().Get("limit"), 10, 32); err == nil {
		limit = min(max(int(n), 1), 500)
	}
	ctx := r.Context()
	principal := api.Principal(ctx)
	all, err := a.authz.Authorize(ctx, principal, "audit.read", bridge.AuditLog, api.RequesterIP(ctx))
	if err != nil {
		fail(w, err)
		return
	}
	var rows pgx.Rows
	if all {
		rows, err = a.pool.Query(ctx, auditSelect+` ORDER BY ts DESC LIMIT $1`, limit)
	} else {
		rows, err = a.pool.Query(ctx, auditSelect+` WHERE principal = $1 ORDER BY ts DESC LIMIT $2`, principal, limit)
	}
	if err != nil {
		fail(w, err)
		return
	}
	out, err := pgx.CollectRows(rows, scanAuditEvent)
	if err != nil {
		fail(w, err)
		return
	}
	if out == nil {
		out = []auditEvent{}
	}
	api.WriteJSON(w, http.StatusOK, out)
}

// get answers a record Cedar hides exactly like a missing one, so the route is no existence oracle.
func (a audit) get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		api.WriteError(w, http.StatusBadRequest, "common.bad_id", nil)
		return
	}
	ctx := r.Context()
	rows, _ := a.pool.Query(ctx, auditSelect+` WHERE id = $1`, id)
	e, err := pgx.CollectExactlyOneRow(rows, scanAuditEvent)
	if errors.Is(err, pgx.ErrNoRows) {
		api.WriteError(w, http.StatusNotFound, "common.not_found", map[string]string{"resource": "audit record"})
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	ok, err := a.authz.Authorize(ctx, api.Principal(ctx), "audit.read", bridge.AuditRecord(e.Principal), api.RequesterIP(ctx))
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

func scanAuditEvent(row pgx.CollectableRow) (auditEvent, error) {
	var (
		e  auditEvent
		ts time.Time
	)
	err := row.Scan(&e.ID, &ts, &e.Principal, &e.Roles, &e.Datasource, &e.ClientAddr, &e.Statement, &e.Decision,
		&e.FailedStage, &e.MaskedColumns, &e.PIITouched, &e.LatencyMS, &e.Detail, &e.EffectiveNamespace,
		&e.Channel, &e.ContextTags, &e.AuthzAction, &e.AuthzResource, &e.Outcome, &e.Kind,
		&e.RowsReturned, &e.BytesReturned, &e.DecisionID)
	e.TS = javaInstant(ts)
	for _, l := range []*[]string{&e.Roles, &e.MaskedColumns, &e.PIITouched, &e.EffectiveNamespace, &e.ContextTags} {
		if *l == nil {
			*l = []string{}
		}
	}
	return e, err
}
