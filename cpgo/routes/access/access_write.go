package access

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
	"github.com/ridi-oss/proxy-monster/cpgo/timeline"
)

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
func (a access) createRequest(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	var in accessRequestInput
	if err := api.DecodeBody(r, &in); err != nil || in.RoleID == nil {
		return api.CodeInvalidValue.Err("field", "body")
	}
	duration := int64(3600)
	if in.RequestedDurationSec != nil {
		duration = *in.RequestedDurationSec
	}
	if in.DatasourceID != nil {
		live, err := db.New(a.pool).DatasourceLive(ctx, *in.DatasourceID)
		if err != nil {
			return err
		}
		if !live {
			return api.CodeNotFound.Err("resource", "datasource")
		}
		ok, err := a.authz.MayRequest(ctx, api.Principal(ctx), *in.DatasourceID, api.RequesterIP(ctx))
		if err != nil {
			return err
		}
		if !ok {
			return api.CodeRequestNotPermitted.Err()
		}
	}
	return a.created(w, r, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (int64, notice, error) {
		q := db.New(tx)
		id, err := q.CreateRoleRequest(ctx, db.CreateRoleRequestParams{Principal: actor.Principal, RoleID: in.RoleID,
			DatasourceID: in.DatasourceID, Reason: in.Reason, RequestedDurationSec: duration})
		if err != nil {
			return 0, notice{}, err
		}
		var role *string
		name, err := q.RoleNameOf(ctx, *in.RoleID)
		switch {
		case err == nil:
			role = &name
		case !errors.Is(err, pgx.ErrNoRows):
			return 0, notice{}, err
		}
		idText := strconv.FormatInt(id, 10)
		if err := audit.Admin(ctx, tx, actor, "task.request", audit.Entity("AccessRequest", idText),
			"open access request #"+idText+" for role '"+orNull(role)+"'"); err != nil {
			return 0, notice{}, err
		}
		_, err = timeline.Record(ctx, tx, id, timeline.Requested, &actor.Principal, actor.Channel, nil)
		return id, notifyRequested, err
	})
}

// notice is the notification Kotlin sends once a write commits, as its services do after their own; the zero
// value sends none.
type notice struct{ event, principal string }

var (
	notifyRequested = notice{event: "requested"}
	notifyDecided   = notice{event: "decided"}
	notifyCancelled = notice{event: "cancelled"}
)

// requestWrite writes on tx and returns the request it names and the notification to send, if any.
type requestWrite func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (id int64, notify notice, err error)

// created commits write and answers 201 with the request it opened.
func (a access) created(w http.ResponseWriter, r *http.Request, write requestWrite) error {
	return a.decided(w, r, http.StatusCreated, write)
}

// signal asks Kotlin to send n for the committed request; a lost signal costs a notification, not the write.
func (a access) signal(ctx context.Context, id int64, n notice) {
	if err := api.Notify(ctx, func(ctx context.Context) error { return a.kotlin.RequestNotified(ctx, id, n.event, n.principal) }); err != nil {
		slog.Warn("access: notification not sent", "request", id, "event", n.event, "err", err)
	}
}

// decided commits write, asks Kotlin to send its notification, then answers status with the request as committed.
func (a access) decided(w http.ResponseWriter, r *http.Request, status int, write requestWrite) error {
	ctx := r.Context()
	var id int64
	var notify notice
	err := pgx.BeginFunc(ctx, a.pool, func(tx pgx.Tx) error {
		var err error
		id, notify, err = write(ctx, tx, api.ActorOf(ctx))
		return err
	})
	if err == nil && notify.event != "" {
		a.signal(ctx, id, notify)
	}
	var req *accessRequest
	if err == nil {
		if req, err = getRequest(ctx, a.pool, id); err == nil && req == nil {
			err = api.NotFound("access request")
		}
	}
	if err != nil {
		return err
	}
	api.WriteJSON(w, status, req)
	return nil
}

// requireApprover is Kotlin's: a ROLE request the caller may task.approve in the workflow viewer, with the
// request's datasource tags in scope. The no-self-approval rule is a shipped forbid.
func (a access) requireApprover(ctx context.Context, id int64) (*accessRequest, error) {
	req, err := getRequest(ctx, a.pool, id)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, api.NotFound("access request")
	}
	if req.Kind == "QUERY" {
		return nil, api.CodeUseQueryApproval.Err()
	}
	may, err := a.decider(ctx, req)
	if err != nil {
		return nil, err
	}
	ok, err := may("task.approve")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, api.CodeNotApprover.Err()
	}
	return req, nil
}

// decider is Kotlin's RequestThreads.may: the caller's action on req in the workflow viewer, with the tags of
// req's datasource even when it is deleted.
func (a access) decider(ctx context.Context, req *accessRequest) (func(action string) (bool, error), error) {
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
	scope := bridge.Scope{Channel: "workflow-viewer", Datasource: req.DatasourceName, DatasourceTags: tags}
	return func(action string) (bool, error) {
		ok, _, err := a.authz.AuthorizeIn(ctx, api.Principal(ctx), action, req.approvalResource(), api.RequesterIP(ctx), scope)
		return ok, err
	}, nil
}

func (a access) approve(w http.ResponseWriter, r *http.Request, id int64) error {
	var in struct {
		DurationSec *int64 `json:"durationSec"`
	}
	if body, err := io.ReadAll(r.Body); err == nil && json.Unmarshal(body, &in) != nil {
		in.DurationSec = nil
	}
	req, err := a.requireApprover(r.Context(), id)
	if err != nil {
		return err
	}
	duration := req.RequestedDurationSec
	if in.DurationSec != nil {
		duration = *in.DurationSec
	}
	return a.decided(w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (int64, notice, error) {
		if req.RoleID == nil {
			return id, notice{}, nil
		}
		q := db.New(tx)
		n, err := q.ApproveRequest(ctx, db.ApproveRequestParams{DecidedBy: &actor.Principal, ID: id})
		if err != nil || n == 0 {
			return id, notice{}, err
		}
		if _, err := timeline.Record(ctx, tx, id, timeline.Approved, &actor.Principal, actor.Channel, nil); err != nil {
			return id, notice{}, err
		}
		idText := strconv.FormatInt(id, 10)
		expires := time.Now().Add(time.Duration(duration) * time.Second)
		grant, err := q.InsertGrant(ctx, db.InsertGrantParams{RequestID: &id, Principal: req.Principal, RoleID: *req.RoleID,
			GrantedBy: &actor.Principal, ExpiresAt: &expires})
		if err != nil {
			return id, notice{}, err
		}
		return id, notifyDecided, audit.Admin(ctx, tx, actor, "task.approve", audit.Entity("AccessGrant", strconv.FormatInt(grant, 10)),
			"approve access request #"+idText+": grant role '"+orNull(req.RoleName)+"' to '"+req.Principal+"' for "+
				strconv.FormatInt(duration, 10)+"s")
	})
}

func (a access) reject(w http.ResponseWriter, r *http.Request, id int64) error {
	req, err := a.requireApprover(r.Context(), id)
	if err != nil {
		return err
	}
	var in struct {
		Reason *string `json:"reason"`
	}
	if err := api.DecodeBody(r, &in); err != nil {
		return err
	}
	if in.Reason == nil {
		return api.CodeInvalidValue.Err("field", "body")
	}
	return a.decided(w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (int64, notice, error) {
		n, err := db.New(tx).RejectRequest(ctx, db.RejectRequestParams{RejectionReason: in.Reason, DecidedBy: &actor.Principal, ID: id})
		if err != nil || n == 0 {
			return id, notice{}, err
		}
		if _, err := timeline.Record(ctx, tx, id, timeline.Rejected, &actor.Principal, actor.Channel, in.Reason); err != nil {
			return id, notice{}, err
		}
		idText := strconv.FormatInt(id, 10)
		return id, notifyDecided, audit.Admin(ctx, tx, actor, "task.approve", audit.Entity("AccessRequest", idText),
			"reject access request #"+idText+" from '"+req.Principal+"'")
	})
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
func (a access) unauthenticatedRevoke(w http.ResponseWriter, r *http.Request) error {
	id, ok := api.PathID(r)
	if !ok {
		return api.CodeBadID.Err()
	}
	g, err := a.getGrant(r.Context(), id)
	switch {
	case err != nil:
		return err
	case g == nil:
		return api.CodeNotFound.Err("resource", "access grant")
	default:
		return api.CodeUnauthenticated.Err()
	}
}

func (a access) revokeGrant(w http.ResponseWriter, r *http.Request, id int64) error {
	ctx := r.Context()
	g, err := a.getGrant(ctx, id)
	if err != nil {
		return err
	}
	if g == nil {
		return api.CodeNotFound.Err("resource", "access grant")
	}
	ok, reason, err := a.authz.Authorize(ctx, api.Principal(ctx), "grant.revoke",
		bridge.Resource{Type: "AccessGrant", Principal: g.Principal, ID: g.ID, RoleName: &g.RoleName}, api.RequesterIP(ctx))
	if err != nil {
		return err
	}
	if !ok {
		return api.CodeForbidden.Err("detail", reason)
	}
	return api.Mutate(a.pool, w, r, http.StatusNoContent, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		n, err := db.New(tx).RevokeGrant(ctx, id)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, api.NotFound("access grant")
		}
		idText := strconv.FormatInt(id, 10)
		return nil, audit.Admin(ctx, tx, actor, "grant.revoke", audit.Entity("AccessGrant", idText),
			"revoke access grant #"+idText+" (role '"+g.RoleName+"' from '"+g.Principal+"')")
	})
}
