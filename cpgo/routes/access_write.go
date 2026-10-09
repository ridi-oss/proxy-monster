package routes

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

func forbidden(code string, params api.Params) error {
	return &managementError{code: code, params: params, status: http.StatusForbidden}
}

func badRequest(code string) error {
	return &managementError{code: code, status: http.StatusBadRequest}
}

func getRequest(ctx context.Context, q db.DBTX, id int64) (*accessRequest, error) {
	row, err := db.New(q).AccessRequest(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	req := toAccessRequest(db.AccessRequestsRow(row))
	return &req, err
}

func orNull(s *string) string {
	if s == nil {
		return "null"
	}
	return *s
}

type accessRequestInput struct {
	RoleID               *int64  `json:"roleId"`
	DatasourceID         *int64  `json:"datasourceId"`
	Reason               *string `json:"reason"`
	RequestedDurationSec *int64  `json:"requestedDurationSec"`
}

// createRequest opens a ROLE request; a datasource-less one has no Datasource to decide task.request on.
func (a access) createRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in accessRequestInput
	if err := decodeBody(r, &in); err != nil || in.RoleID == nil {
		api.WriteError(w, http.StatusBadRequest, "common.invalid_value", map[string]string{"field": "body"})
		return
	}
	duration := int64(3600)
	if in.RequestedDurationSec != nil {
		duration = *in.RequestedDurationSec
	}
	if in.DatasourceID != nil {
		live, err := db.New(a.pool).DatasourceLive(ctx, *in.DatasourceID)
		if err != nil {
			fail(w, err)
			return
		}
		if !live {
			api.WriteError(w, http.StatusNotFound, "common.not_found", map[string]string{"resource": "datasource"})
			return
		}
		ok, err := a.authz.MayRequest(ctx, api.Principal(ctx), *in.DatasourceID, api.RequesterIP(ctx))
		if err != nil {
			fail(w, err)
			return
		}
		if !ok {
			api.WriteError(w, http.StatusForbidden, "approval.request_not_permitted", nil)
			return
		}
	}
	a.created(w, r, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (int64, error) {
		q := db.New(tx)
		id, err := q.CreateRoleRequest(ctx, db.CreateRoleRequestParams{Principal: actor.Principal, RoleID: in.RoleID,
			DatasourceID: in.DatasourceID, Reason: in.Reason, RequestedDurationSec: duration})
		if err != nil {
			return 0, err
		}
		var role *string
		name, err := q.RoleNameOf(ctx, *in.RoleID)
		switch {
		case err == nil:
			role = &name
		case !errors.Is(err, pgx.ErrNoRows):
			return 0, err
		}
		idText := strconv.FormatInt(id, 10)
		return id, audit.Admin(ctx, tx, actor, "task.request", audit.Entity("AccessRequest", idText),
			"open access request #"+idText+" for role '"+orNull(role)+"'")
	})
}

// requestRateReset asks an approver to reset the caller's spent @cap rates; there is no datasource to decide
// task.request on, so authentication alone opens it.
func (a access) requestRateReset(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Reason     *string `json:"reason"`
		DenyReason *string `json:"denyReason"`
	}
	if err := decodeBody(r, &in); err != nil || in.Reason == nil {
		api.WriteError(w, http.StatusBadRequest, "common.invalid_value", map[string]string{"field": "body"})
		return
	}
	if strings.TrimSpace(*in.Reason) == "" {
		api.WriteError(w, http.StatusBadRequest, "common.field_required", map[string]string{"fields": "reason"})
		return
	}
	a.created(w, r, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (int64, error) {
		id, err := db.New(tx).CreateRateResetRequest(ctx, db.CreateRateResetRequestParams{Principal: actor.Principal,
			Reason: in.Reason, DenyReason: in.DenyReason})
		if err != nil {
			return 0, err
		}
		idText := strconv.FormatInt(id, 10)
		return id, audit.Admin(ctx, tx, actor, "task.request", audit.Entity("AccessRequest", idText), "open rate reset request #"+idText)
	})
}

// created commits write and answers 201 with the request it opened.
func (a access) created(w http.ResponseWriter, r *http.Request, write func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (int64, error)) {
	a.decided(w, r, http.StatusCreated, write)
}

// decided commits write, then answers status with the request it names as committed.
func (a access) decided(w http.ResponseWriter, r *http.Request, status int, write func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (int64, error)) {
	ctx := r.Context()
	var id int64
	err := pgx.BeginFunc(ctx, a.pool, func(tx pgx.Tx) error {
		var err error
		id, err = write(ctx, tx, actorOf(ctx))
		return err
	})
	var req *accessRequest
	if err == nil {
		if req, err = getRequest(ctx, a.pool, id); err == nil && req == nil {
			err = notFound("access request")
		}
	}
	if err != nil {
		writeMutationError(w, err)
		return
	}
	api.WriteJSON(w, status, req)
}

type rateReset struct {
	Principal string `json:"principal"`
	ResetAt   string `json:"resetAt"`
	ResetBy   string `json:"resetBy"`
	Reason    string `json:"reason"`
}

func insertRateReset(ctx context.Context, tx pgx.Tx, principal, by, reason string) (rateReset, error) {
	row, err := db.New(tx).InsertRateReset(ctx, db.InsertRateResetParams{Principal: principal, ResetBy: by, Reason: reason})
	return rateReset{Principal: row.Principal, ResetAt: javaInstant(row.ResetAt), ResetBy: row.ResetBy, Reason: row.Reason}, err
}

func principalParam(r *http.Request) (string, bool) {
	p := r.PathValue("principal")
	return p, strings.TrimSpace(p) != ""
}

// resetRate is an admin's direct reset of a principal's spent rates, reason required.
func (a access) resetRate(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalParam(r)
	if !ok {
		api.WriteError(w, http.StatusBadRequest, "common.bad_id", nil)
		return
	}
	var in struct {
		Reason *string `json:"reason"`
	}
	if err := decodeBody(r, &in); err != nil || in.Reason == nil {
		api.WriteError(w, http.StatusBadRequest, "common.invalid_value", map[string]string{"field": "body"})
		return
	}
	mutate(a.pool, w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		if err := required("reason", *in.Reason); err != nil {
			return nil, err
		}
		reset, err := insertRateReset(ctx, tx, principal, actor.Principal, *in.Reason)
		if err != nil {
			return nil, err
		}
		return reset, audit.Admin(ctx, tx, actor, "admin.identity", audit.Entity("User", principal),
			"reset spent result rates of '"+principal+"': "+*in.Reason)
	})
}

func (a access) lastRateReset(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalParam(r)
	if !ok {
		api.WriteError(w, http.StatusBadRequest, "common.bad_id", nil)
		return
	}
	row, err := db.New(a.pool).LastRateReset(r.Context(), principal)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		w.WriteHeader(http.StatusNoContent)
	case err != nil:
		fail(w, err)
	default:
		api.WriteJSON(w, http.StatusOK, rateReset{Principal: row.Principal, ResetAt: javaInstant(row.ResetAt), ResetBy: row.ResetBy, Reason: row.Reason})
	}
}

// requireApprover is Kotlin's: a ROLE or RATE_RESET request the caller may task.approve in the workflow
// viewer, with the request's datasource tags in scope. The no-self-approval rule is a shipped forbid.
func (a access) requireApprover(ctx context.Context, id int64) (*accessRequest, error) {
	req, err := getRequest(ctx, a.pool, id)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, notFound("access request")
	}
	if req.Kind == "QUERY" {
		return nil, badRequest("approval.use_query_approval_endpoint")
	}
	tags := []string{}
	if req.DatasourceID != nil {
		dsTags, err := db.New(a.pool).DatasourceTags(ctx, *req.DatasourceID)
		switch {
		case err == nil:
			tags = dsTags
		case !errors.Is(err, pgx.ErrNoRows):
			return nil, err
		}
	}
	ok, _, err := a.authz.AuthorizeIn(ctx, api.Principal(ctx), "task.approve", req.approvalResource(), api.RequesterIP(ctx),
		bridge.Scope{Channel: "workflow-viewer", Datasource: req.DatasourceName, DatasourceTags: tags})
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, forbidden("approval.not_approver", nil)
	}
	return req, nil
}

func (a access) approve(w http.ResponseWriter, r *http.Request, id int64) {
	var in struct {
		DurationSec *int64 `json:"durationSec"`
	}
	if body, err := io.ReadAll(r.Body); err == nil && json.Unmarshal(body, &in) != nil {
		in.DurationSec = nil
	}
	req, err := a.requireApprover(r.Context(), id)
	if err != nil {
		writeMutationError(w, err)
		return
	}
	duration := req.RequestedDurationSec
	if in.DurationSec != nil {
		duration = *in.DurationSec
	}
	a.decided(w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (int64, error) {
		if req.Kind != "RATE_RESET" && req.RoleID == nil {
			return id, nil
		}
		q := db.New(tx)
		n, err := q.ApproveRequest(ctx, db.ApproveRequestParams{DecidedBy: &actor.Principal, ID: id})
		if err != nil || n == 0 {
			return id, err
		}
		idText := strconv.FormatInt(id, 10)
		if req.Kind == "RATE_RESET" {
			reason := "approved rate reset request #" + idText
			if req.Reason != nil {
				reason = *req.Reason
			}
			if _, err := insertRateReset(ctx, tx, req.Principal, actor.Principal, reason); err != nil {
				return id, err
			}
			return id, audit.Admin(ctx, tx, actor, "task.approve", audit.Entity("AccessRequest", idText),
				"approve rate reset request #"+idText+": reset spent rates of '"+req.Principal+"'")
		}
		expires := time.Now().Add(time.Duration(duration) * time.Second)
		grant, err := q.InsertGrant(ctx, db.InsertGrantParams{RequestID: &id, Principal: req.Principal, RoleID: *req.RoleID,
			GrantedBy: &actor.Principal, ExpiresAt: &expires})
		if err != nil {
			return id, err
		}
		return id, audit.Admin(ctx, tx, actor, "task.approve", audit.Entity("AccessGrant", strconv.FormatInt(grant, 10)),
			"approve access request #"+idText+": grant role '"+orNull(req.RoleName)+"' to '"+req.Principal+"' for "+
				strconv.FormatInt(duration, 10)+"s")
	})
}

func (a access) reject(w http.ResponseWriter, r *http.Request, id int64) {
	req, err := a.requireApprover(r.Context(), id)
	if err == nil {
		var in struct {
			Reason *string `json:"reason"`
		}
		if err = decodeBody(r, &in); err == nil && in.Reason == nil {
			err = &managementError{code: "common.invalid_value", params: api.Params{{"field", "body"}}}
		}
		if err == nil {
			a.decided(w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (int64, error) {
				n, err := db.New(tx).RejectRequest(ctx, db.RejectRequestParams{RejectionReason: in.Reason, DecidedBy: &actor.Principal, ID: id})
				if err != nil || n == 0 {
					return id, err
				}
				idText := strconv.FormatInt(id, 10)
				return id, audit.Admin(ctx, tx, actor, "task.approve", audit.Entity("AccessRequest", idText),
					"reject access request #"+idText+" from '"+req.Principal+"'")
			})
			return
		}
	}
	writeMutationError(w, err)
}

func (a access) getGrant(ctx context.Context, id int64) (*accessGrant, error) {
	row, err := db.New(a.pool).AccessGrant(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	g := toGrant(db.AccessGrantsRow(row))
	return &g, err
}

// unauthenticatedRevoke answers a revoke without a session: 404 for a missing grant, as before any
// authorization, else 401.
func (a access) unauthenticatedRevoke(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		api.WriteError(w, http.StatusBadRequest, "common.bad_id", nil)
		return
	}
	g, err := a.getGrant(r.Context(), id)
	switch {
	case err != nil:
		fail(w, err)
	case g == nil:
		api.WriteError(w, http.StatusNotFound, "common.not_found", map[string]string{"resource": "access grant"})
	default:
		api.WriteError(w, http.StatusUnauthorized, "common.unauthenticated", nil)
	}
}

func (a access) revokeGrant(w http.ResponseWriter, r *http.Request, id int64) {
	ctx := r.Context()
	g, err := a.getGrant(ctx, id)
	if err != nil {
		fail(w, err)
		return
	}
	if g == nil {
		api.WriteError(w, http.StatusNotFound, "common.not_found", map[string]string{"resource": "access grant"})
		return
	}
	ok, reason, err := a.authz.Authorize(ctx, api.Principal(ctx), "grant.revoke",
		bridge.Resource{Type: "AccessGrant", Principal: g.Principal, ID: g.ID, RoleName: &g.RoleName}, api.RequesterIP(ctx))
	if err != nil {
		fail(w, err)
		return
	}
	if !ok {
		api.WriteError(w, http.StatusForbidden, "common.forbidden", map[string]string{"detail": reason})
		return
	}
	mutate(a.pool, w, r, http.StatusNoContent, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		n, err := db.New(tx).RevokeGrant(ctx, id)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, notFound("access grant")
		}
		idText := strconv.FormatInt(id, 10)
		return nil, audit.Admin(ctx, tx, actor, "grant.revoke", audit.Entity("AccessGrant", idText),
			"revoke access grant #"+idText+" (role '"+g.RoleName+"' from '"+g.Principal+"')")
	})
}
