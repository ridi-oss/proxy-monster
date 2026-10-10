package routes

import (
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

// accessRequest is one access_request row; fields in the Kotlin AccessRequest's order.
type accessRequest struct {
	ID                               int64    `json:"id"`
	Principal                        string   `json:"principal"`
	RoleID                           *int64   `json:"roleId,omitempty"`
	RoleName                         *string  `json:"roleName,omitempty"`
	DatasourceID                     *int64   `json:"datasourceId,omitempty"`
	DatasourceName                   *string  `json:"datasourceName,omitempty"`
	Reason                           *string  `json:"reason,omitempty"`
	RequestedDurationSec             int64    `json:"requestedDurationSec"`
	Status                           string   `json:"status"`
	DecidedBy                        *string  `json:"decidedBy,omitempty"`
	ExecutedBy                       *string  `json:"executedBy,omitempty"`
	DecidedAt                        *string  `json:"decidedAt,omitempty"`
	RejectionReason                  *string  `json:"rejectionReason,omitempty"`
	CreatedAt                        string   `json:"createdAt"`
	Kind                             string   `json:"kind"`
	SQL                              *string  `json:"sql,omitempty"`
	SQLHash                          *string  `json:"sqlHash,omitempty"`
	StatementCount                   int      `json:"statementCount"`
	DenyReason                       *string  `json:"denyReason,omitempty"`
	SourceDecisionID                 *int64   `json:"sourceDecisionId,omitempty"`
	Title                            *string  `json:"title,omitempty"`
	EvaluatedDecision                *string  `json:"evaluatedDecision,omitempty"`
	ApprovedAt                       *string  `json:"approvedAt,omitempty"`
	ExecutingAt                      *string  `json:"executingAt,omitempty"`
	ExecutedAt                       *string  `json:"executedAt,omitempty"`
	ExecuteAs                        []string `json:"executeAs"`
	CreatorKind                      *string  `json:"creatorKind,omitempty"`
	StatementCarriesProtectedLiteral *bool    `json:"statementCarriesProtectedLiteral,omitempty"`
}

func toAccessRequest(r db.AccessRequestsRow) accessRequest {
	a := accessRequest{ID: r.ID, Principal: r.Principal, RoleID: r.RoleID, RoleName: r.RoleName, DatasourceID: r.DatasourceID,
		DatasourceName: r.DatasourceName, Reason: r.Reason, RequestedDurationSec: r.RequestedDurationSec, Status: r.Status,
		DecidedBy: r.DecidedBy, ExecutedBy: r.ExecutedBy, DecidedAt: optInstant(r.DecidedAt), RejectionReason: r.RejectionReason,
		CreatedAt: javaInstant(r.CreatedAt), Kind: r.Kind, SQL: optText(r.Sql), SQLHash: r.SqlHash, StatementCount: int(r.StatementCount),
		DenyReason: r.DenyReason, SourceDecisionID: r.SourceDecisionID, Title: r.Title, EvaluatedDecision: r.EvaluatedDecision,
		ApprovedAt: optInstant(r.ApprovedAt), ExecutingAt: optInstant(r.ExecutingAt), ExecutedAt: optInstant(r.ExecutedAt),
		ExecuteAs: r.ExecuteAs, CreatorKind: r.CreatorKind, StatementCarriesProtectedLiteral: r.StatementCarriesProtectedLiteral}
	if a.ExecuteAs == nil {
		a.ExecuteAs = []string{}
	}
	return a
}

// approvalResource is Kotlin's AccessRequest.toApprovalResource.
func (a accessRequest) approvalResource() bridge.Resource {
	return bridge.Resource{Type: "ApprovalRequest", Principal: a.Principal, Approver: a.DecidedBy,
		ExecutedBy: a.ExecutedBy, DatasourceName: a.DatasourceName, RoleName: a.RoleName}
}

// ownApprovals lists the caller's own workflow approval requests; owning them is the whole check.
func (a access) ownApprovals(w http.ResponseWriter, r *http.Request) {
	q, principal := r.URL.Query(), api.Principal(r.Context())
	if q.Has("status") {
		rows, err := db.New(a.pool).OwnApprovalsByStatus(r.Context(), db.OwnApprovalsByStatusParams{Principal: principal, Status: q.Get("status")})
		writeRows(w, rows, err, func(r db.OwnApprovalsByStatusRow) accessRequest { return toAccessRequest(db.AccessRequestsRow(r)) })
		return
	}
	rows, err := db.New(a.pool).OwnApprovals(r.Context(), principal)
	writeRows(w, rows, err, func(r db.OwnApprovalsRow) accessRequest { return toAccessRequest(db.AccessRequestsRow(r)) })
}

type accessGrant struct {
	ID        int64   `json:"id"`
	Principal string  `json:"principal"`
	RoleID    int64   `json:"roleId"`
	RoleName  string  `json:"roleName"`
	GrantedBy *string `json:"grantedBy,omitempty"`
	GrantedAt string  `json:"grantedAt"`
	ExpiresAt *string `json:"expiresAt,omitempty"`
	RevokedAt *string `json:"revokedAt,omitempty"`
}

func toGrant(g db.AccessGrantsRow) accessGrant {
	return accessGrant{ID: g.ID, Principal: g.Principal, RoleID: g.RoleID, RoleName: g.RoleName, GrantedBy: g.GrantedBy,
		GrantedAt: javaInstant(g.GrantedAt), ExpiresAt: optInstant(g.ExpiresAt), RevokedAt: optInstant(g.RevokedAt)}
}

type access struct {
	pool  *pgxpool.Pool
	authz api.Authorizer
}

// requests lists the requests (status-filtered when asked) the caller may task.read.
func (a access) requests(w http.ResponseWriter, r *http.Request) {
	var (
		rows []db.AccessRequestsRow
		err  error
	)
	if q := r.URL.Query(); q.Has("status") {
		var byStatus []db.AccessRequestsByStatusRow
		byStatus, err = db.New(a.pool).AccessRequestsByStatus(r.Context(), q.Get("status"))
		for _, row := range byStatus {
			rows = append(rows, db.AccessRequestsRow(row))
		}
	} else {
		rows, err = db.New(a.pool).AccessRequests(r.Context())
	}
	if err != nil {
		fail(w, err)
		return
	}
	all := make([]accessRequest, len(rows))
	for i, row := range rows {
		all[i] = toAccessRequest(row)
	}
	resources := make([]bridge.Resource, len(all))
	for i, req := range all {
		resources[i] = req.approvalResource()
	}
	writeAllowed(w, r, a.authz, all, resources)
}

// grants lists the grants (by principal, live only when active=true) the caller may task.read.
func (a access) grants(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	queries, ctx := db.New(a.pool), r.Context()
	var (
		rows []db.AccessGrantsRow
		err  error
	)
	switch active := strings.EqualFold(q.Get("active"), "true"); {
	case q.Has("principal") && active:
		var live []db.LiveAccessGrantsOfRow
		live, err = queries.LiveAccessGrantsOf(ctx, q.Get("principal"))
		for _, row := range live {
			rows = append(rows, db.AccessGrantsRow(row))
		}
	case q.Has("principal"):
		var of []db.AccessGrantsOfRow
		of, err = queries.AccessGrantsOf(ctx, q.Get("principal"))
		for _, row := range of {
			rows = append(rows, db.AccessGrantsRow(row))
		}
	case active:
		var live []db.LiveAccessGrantsRow
		live, err = queries.LiveAccessGrants(ctx)
		for _, row := range live {
			rows = append(rows, db.AccessGrantsRow(row))
		}
	default:
		rows, err = queries.AccessGrants(ctx)
	}
	if err != nil {
		fail(w, err)
		return
	}
	all := make([]accessGrant, len(rows))
	for i, g := range rows {
		all[i] = toGrant(g)
	}
	resources := make([]bridge.Resource, len(all))
	for i, g := range all {
		resources[i] = bridge.Resource{Type: "AccessGrant", Principal: g.Principal, ID: g.ID, RoleName: &g.RoleName}
	}
	writeAllowed(w, r, a.authz, all, resources)
}

// writeAllowed answers with the rows whose resource the caller may task.read, decided without a requester
// IP as the Kotlin listings do.
func writeAllowed[T any](w http.ResponseWriter, r *http.Request, authz api.Authorizer, rows []T, resources []bridge.Resource) {
	ctx := r.Context()
	allowed, err := authz.AuthorizeEach(ctx, api.Principal(ctx), "task.read", resources, "")
	if err != nil {
		fail(w, err)
		return
	}
	out := []T{}
	for i, ok := range allowed {
		if ok {
			out = append(out, rows[i])
		}
	}
	api.WriteJSON(w, http.StatusOK, out)
}

func optInstant(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := javaInstant(*t)
	return &s
}

func optText(b []byte) *string {
	if b == nil {
		return nil
	}
	s := string(b)
	return &s
}
