package access

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
	"github.com/ridi-oss/proxy-monster/cpgo/timeline"
)

// approvalTTL is Kotlin's APPROVAL_TTL: an approval not run within it no longer runs.
const approvalTTL = 24 * time.Hour

var (
	notifyReopened = notice{event: "reopened"}

	// errBody is a body Kotlin's receive cannot read, which it answers 500 common.fallback.
	errBody = errors.New("access: unreadable request body")
)

func registerApprovals(mux *http.ServeMux, gate api.Gate, a access) {
	mux.HandleFunc("GET /api/approvals/inbox", gate.RequireAPI(api.Serve(a.inbox)))
	mux.HandleFunc("GET /api/approvals/{id}", gate.RequireAPI(api.Serve(api.WithID(a.approvalDetail))))
	mux.HandleFunc("POST /api/approvals/{id}/approve", gate.RequireAPI(api.Serve(api.WithID(a.approveQuery))))
	mux.HandleFunc("POST /api/approvals/{id}/reject", gate.RequireAPI(api.Serve(api.WithID(a.rejectQuery))))
	mux.HandleFunc("POST /api/approvals/{id}/unapprove", gate.RequireAPI(api.Serve(api.WithID(a.unapprove))))
}

func receive(r *http.Request, v any) error {
	if api.DecodeBody(r, v) != nil {
		return errBody
	}
	return nil
}

// queryApproval is the request, unless it is missing or not a workflow query request.
func (a access) queryApproval(ctx context.Context, id int64) (*accessRequest, error) {
	req, err := getRequest(ctx, a.pool, id)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Kind != "QUERY" || req.CreatorKind == nil || *req.CreatorKind != "WORKFLOW" {
		return nil, api.NotFound("query approval request")
	}
	return req, nil
}

func (r *accessRequest) fromPullRequest() bool { return r.Source == "github" }

func editable(status string) bool { return status == "PENDING" || status == "APPROVED" }

// inbox lists the PENDING query requests the caller may approve.
func (a access) inbox(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	rows, err := db.New(a.pool).PendingQueryRequests(ctx)
	if err != nil {
		return err
	}
	out := []accessRequest{}
	for _, row := range rows {
		req := toAccessRequest(db.AccessRequestsRow(row))
		may, err := a.decider(ctx, &req)
		if err != nil {
			return err
		}
		ok, err := may("task.approve")
		if err != nil {
			return err
		}
		if ok {
			out = append(out, req)
		}
	}
	api.WriteJSON(w, http.StatusOK, out)
	return nil
}

// resultMeta is Kotlin's QueryResultMeta: one statement's execution, without its rows.
type resultMeta struct {
	TaskID     int64    `json:"taskId"`
	Ordinal    int32    `json:"ordinal"`
	SQL        *string  `json:"sql,omitempty"`
	ExecutedBy *string  `json:"executedBy,omitempty"`
	ExecutedAt *string  `json:"executedAt,omitempty"`
	RowCount   *int32   `json:"rowCount,omitempty"`
	ExpiresAt  *string  `json:"expiresAt,omitempty"`
	Status     *string  `json:"status,omitempty"`
	ErrorCode  *string  `json:"errorCode,omitempty"`
	DenyReason *string  `json:"denyReason,omitempty"`
	DecisionID *int64   `json:"decisionId,omitempty"`
	Columns    []string `json:"columns"`
}

func toResultMeta(r db.ResultStatementsRow, rows bool) (resultMeta, error) {
	m := resultMeta{TaskID: r.TaskID, Ordinal: r.Ordinal, SQL: r.Sql, ExecutedBy: r.ExecutedBy, ExecutedAt: api.OptInstant(r.ExecutedAt),
		RowCount: r.RowCount, ExpiresAt: api.OptInstant(r.ExpiresAt), Status: r.Status, ErrorCode: r.ErrorCode, DenyReason: r.DenyReason,
		DecisionID: r.DecisionID, Columns: []string{}}
	if r.Columns != nil {
		if err := json.Unmarshal(r.Columns, &m.Columns); err != nil {
			return m, err
		}
	}
	// Row count and column shape are cardinality and existence oracles, so they need task.assume.
	if !rows {
		m.RowCount, m.Columns = nil, []string{}
	}
	return m, nil
}

// approvalDetail is Kotlin's QueryRequestDetail: the request, what the caller may do on it, and its statements.
type approvalDetail struct {
	Request          *accessRequest   `json:"request"`
	CanDecide        bool             `json:"canDecide"`
	CanApproveAndRun bool             `json:"canApproveAndRun"`
	CanReject        bool             `json:"canReject"`
	CanUnapprove     bool             `json:"canUnapprove"`
	CanClose         bool             `json:"canClose"`
	CanComment       bool             `json:"canComment"`
	CanCC            bool             `json:"canCc"`
	Timeline         []timeline.Event `json:"timeline"`
	Result           *resultMeta      `json:"result,omitempty"`
	Statements       []resultMeta     `json:"statements"`
	CanExecute       bool             `json:"canExecute"`
	CanCancel        bool             `json:"canCancel"`
	CanEdit          bool             `json:"canEdit"`
	CanForceRun      bool             `json:"canForceRun"`
}

func (a access) approvalDetail(w http.ResponseWriter, r *http.Request, id int64) error {
	ctx := r.Context()
	req, err := a.queryApproval(ctx, id)
	if err != nil {
		return err
	}
	decide, err := a.decider(ctx, req)
	if err != nil {
		return err
	}
	var failed error
	may := func(action string) bool {
		ok, err := decide(action)
		if err != nil && failed == nil {
			failed = err
		}
		return ok
	}
	isApprover := may("task.approve")
	if !may("task.read") && failed == nil {
		return api.NotFound("query approval request")
	}
	d := approvalDetail{Request: req, Statements: []resultMeta{}}
	if a.storesResults {
		rows := may("task.assume")
		q := db.New(a.pool)
		active, err := q.ActiveResult(ctx, id)
		switch {
		case err == nil:
			m, err := toResultMeta(db.ResultStatementsRow(active), rows)
			if err != nil {
				return err
			}
			d.Result = &m
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		all, err := q.ResultStatements(ctx, id)
		if err != nil {
			return err
		}
		for _, row := range all {
			m, err := toResultMeta(row, rows)
			if err != nil {
				return err
			}
			d.Statements = append(d.Statements, m)
		}
	}
	github := req.fromPullRequest()
	approved := req.Status == "APPROVED" && !github
	d.CanExecute = a.storesResults && approved && !approvalExpired(req) && may("task.run")
	mayCancel := may("task.cancel")
	d.CanCancel = req.Status == "EXECUTING" && mayCancel
	d.CanForceRun = github && editable(req.Status) && !req.ForceRun && may("task.force_run")
	d.CanDecide = req.Status == "PENDING" && isApprover
	d.CanApproveAndRun = req.Status == "PENDING" && isApprover && !github && a.storesResults && may("task.run")
	d.CanReject = editable(req.Status) && isApprover
	d.CanUnapprove = approved && isApprover
	d.CanClose = closable(req) && mayCancel
	d.CanComment = may("task.comment")
	d.CanCC = may("task.cc")
	d.CanEdit = req.Principal == api.Principal(ctx) && editable(req.Status) && !github
	if failed != nil {
		return failed
	}
	if d.Timeline, err = timeline.List(ctx, a.pool, id); err != nil {
		return err
	}
	api.WriteJSON(w, http.StatusOK, d)
	return nil
}

// approvalExpired: a console approval older than approvalTTL no longer runs.
func approvalExpired(req *accessRequest) bool {
	if req.fromPullRequest() || req.ApprovedAt == nil {
		return false
	}
	at, err := time.Parse(time.RFC3339Nano, *req.ApprovedAt)
	return err == nil && at.Before(time.Now().Add(-approvalTTL))
}

// approveQuery approves the revision the approver read; a later edit refuses it.
func (a access) approveQuery(w http.ResponseWriter, r *http.Request, id int64) error {
	ctx := r.Context()
	var in struct {
		Revision *int32 `json:"revision"`
	}
	if api.DecodeBody(r, &in) != nil || in.Revision == nil {
		return api.CodeFieldRequired.Err("fields", "revision")
	}
	req, err := a.queryApproval(ctx, id)
	if err != nil {
		return err
	}
	if req.Status != "PENDING" {
		return api.CodeAlreadyDecided.Err()
	}
	if err := a.require(ctx, req, "task.approve", api.CodeNotApprover); err != nil {
		return err
	}
	if req.Revision != *in.Revision {
		return api.CodeRequestChanged.Err()
	}
	return a.decided(w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (int64, notice, error) {
		n, err := db.New(tx).DecideQueryRequest(ctx, db.DecideQueryRequestParams{Status: "APPROVED", DecidedBy: &actor.Principal,
			ID: id, Revision: *in.Revision})
		if err != nil {
			return id, notice{}, err
		}
		if n == 0 {
			now, err := getRequest(ctx, tx, id)
			if err == nil && now != nil && now.Status == "PENDING" {
				err = api.CodeRequestChanged.Err()
			}
			if err == nil {
				err = api.CodeAlreadyDecided.Err()
			}
			return id, notice{}, err
		}
		if _, err := timeline.Record(ctx, tx, id, timeline.Approved, &actor.Principal, actor.Channel, nil); err != nil {
			return id, notice{}, err
		}
		idText := strconv.FormatInt(id, 10)
		return id, notifyDecided, audit.Admin(ctx, tx, actor, "task.approve", audit.Entity("AccessRequest", idText),
			"approve query request #"+idText+" revision "+strconv.Itoa(int(*in.Revision))+" under role '"+orNull(req.RoleName)+"'")
	})
}

// rejectQuery rejects a request that has not run, approved or not.
func (a access) rejectQuery(w http.ResponseWriter, r *http.Request, id int64) error {
	ctx := r.Context()
	var in struct {
		Reason *string `json:"reason"`
	}
	if err := receive(r, &in); err != nil || in.Reason == nil {
		return errBody
	}
	reason := strings.TrimSpace(*in.Reason)
	if reason == "" {
		return api.CodeFieldRequired.Err("fields", "reason")
	}
	req, err := a.queryApproval(ctx, id)
	if err != nil {
		return err
	}
	if !editable(req.Status) {
		return api.CodeAlreadyDecided.Err()
	}
	if err := a.require(ctx, req, "task.approve", api.CodeNotApprover); err != nil {
		return err
	}
	return a.decided(w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (int64, notice, error) {
		n, err := db.New(tx).DecideQueryRequest(ctx, db.DecideQueryRequestParams{Status: "REJECTED", DecidedBy: &actor.Principal,
			RejectionReason: &reason, ID: id, Revision: req.Revision})
		if err != nil {
			return id, notice{}, err
		}
		if n == 0 {
			return id, notice{}, api.CodeAlreadyDecided.Err()
		}
		if _, err := timeline.Record(ctx, tx, id, timeline.Rejected, &actor.Principal, actor.Channel, &reason); err != nil {
			return id, notice{}, err
		}
		idText := strconv.FormatInt(id, 10)
		return id, notifyDecided, audit.Admin(ctx, tx, actor, "task.approve", audit.Entity("AccessRequest", idText),
			"reject query request #"+idText+" revision "+strconv.Itoa(int(req.Revision)))
	})
}

// unapprove returns an approved request that has not run to PENDING; the same task.approve decision as approving it.
func (a access) unapprove(w http.ResponseWriter, r *http.Request, id int64) error {
	ctx := r.Context()
	req, err := a.queryApproval(ctx, id)
	if err != nil {
		return err
	}
	if err := a.require(ctx, req, "task.approve", api.CodeNotApprover); err != nil {
		return err
	}
	if req.Status != "APPROVED" || req.fromPullRequest() {
		return api.CodeNotApproved.Err()
	}
	return a.decided(w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (int64, notice, error) {
		n, err := db.New(tx).ReopenQueryRequest(ctx, id)
		if err != nil {
			return id, notice{}, err
		}
		if n == 0 {
			return id, notice{}, api.CodeNotApproved.Err()
		}
		idText := strconv.FormatInt(id, 10)
		if err := audit.Admin(ctx, tx, actor, "task.approve", audit.Entity("AccessRequest", idText),
			"withdraw the approval of query request #"+idText+" (unapproved by "+actor.Principal+")"); err != nil {
			return id, notice{}, err
		}
		_, err = timeline.Record(ctx, tx, id, timeline.Unapproved, &actor.Principal, actor.Channel, nil)
		return id, notifyReopened, err
	})
}
