package access

import (
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

func Register(mux *http.ServeMux, pool *pgxpool.Pool, gate api.Gate) {
	ac := access{pool: pool, authz: gate.Authz, kotlin: gate.Kotlin}
	mux.HandleFunc("GET /api/access-requests", gate.RequireAPI(ac.requests))
	mux.HandleFunc("GET /api/access-grants", gate.RequireAPI(ac.grants))
	mux.HandleFunc("GET /api/approvals", gate.RequireAPI(ac.ownApprovals))
	mux.HandleFunc("POST /api/access-requests", gate.RequireAPI(ac.createRequest))
	mux.HandleFunc("POST /api/access-requests/rate-reset", gate.RequireAPI(ac.requestRateReset))
	mux.HandleFunc("POST /api/access/principals/{principal}/rate-reset", gate.RequireAdmin("admin.identity", ac.resetRate))
	mux.HandleFunc("GET /api/access/principals/{principal}/rate-reset", gate.RequireAdmin("admin.identity", ac.lastRateReset))
	mux.HandleFunc("POST /api/access-requests/{id}/approve", gate.RequireAPI(api.WithID(ac.approve)))
	mux.HandleFunc("POST /api/access-requests/{id}/reject", gate.RequireAPI(api.WithID(ac.reject)))
	mux.HandleFunc("POST /api/access-grants/{id}/revoke", gate.RequireAPIElse(ac.unauthenticatedRevoke, api.WithID(ac.revokeGrant)))
}

// accessRequest is one access_request row; fields in the Kotlin AccessRequest's order.
type accessRequest struct {
	ID                               int64           `json:"id"`
	Principal                        string          `json:"principal"`
	RoleID                           *int64          `json:"roleId,omitempty"`
	RoleName                         *string         `json:"roleName,omitempty"`
	DatasourceID                     *int64          `json:"datasourceId,omitempty"`
	DatasourceName                   *string         `json:"datasourceName,omitempty"`
	Reason                           *string         `json:"reason,omitempty"`
	RequestedDurationSec             int64           `json:"requestedDurationSec"`
	Status                           string          `json:"status"`
	DecidedBy                        *string         `json:"decidedBy,omitempty"`
	ExecutedBy                       *string         `json:"executedBy,omitempty"`
	DecidedAt                        *string         `json:"decidedAt,omitempty"`
	RejectionReason                  *string         `json:"rejectionReason,omitempty"`
	CreatedAt                        string          `json:"createdAt"`
	Kind                             string          `json:"kind"`
	SQL                              *string         `json:"sql,omitempty"`
	SQLHash                          *string         `json:"sqlHash,omitempty"`
	StatementCount                   int             `json:"statementCount"`
	DenyReason                       *string         `json:"denyReason,omitempty"`
	SourceDecisionID                 *int64          `json:"sourceDecisionId,omitempty"`
	Title                            *string         `json:"title,omitempty"`
	EvaluatedDecision                *string         `json:"evaluatedDecision,omitempty"`
	ApprovedAt                       *string         `json:"approvedAt,omitempty"`
	ExecutingAt                      *string         `json:"executingAt,omitempty"`
	ExecutedAt                       *string         `json:"executedAt,omitempty"`
	ExecuteAs                        []string        `json:"executeAs"`
	CreatorKind                      *string         `json:"creatorKind,omitempty"`
	StatementCarriesProtectedLiteral *bool           `json:"statementCarriesProtectedLiteral,omitempty"`
	Source                           string          `json:"source"`
	Scope                            *string         `json:"scope,omitempty"`
	FileKey                          *string         `json:"fileKey,omitempty"`
	ChangeKey                        *string         `json:"changeKey,omitempty"`
	MergedAt                         *string         `json:"mergedAt,omitempty"`
	Revision                         int32           `json:"revision"`
	RevisedAt                        *string         `json:"revisedAt,omitempty"`
	ContentHash                      *string         `json:"contentHash,omitempty"`
	PullRequest                      *pullRequestRef `json:"pullRequest,omitempty"`
	ForceRun                         bool            `json:"forceRun"`
	ForceRunBy                       *string         `json:"forceRunBy,omitempty"`
	CCs                              []string        `json:"ccs"`
}

// pullRequestRef is Kotlin's PullRequestRef: the pull request a GitHub request came from.
type pullRequestRef struct {
	Repository       string  `json:"repository"`
	PR               int32   `json:"pr"`
	PRURL            *string `json:"prUrl,omitempty"`
	Path             *string `json:"path,omitempty"`
	HeadSHA          *string `json:"headSha,omitempty"`
	DefaultSchema    *string `json:"defaultSchema,omitempty"`
	KeyOrder         *string `json:"keyOrder,omitempty"`
	FiledHead        *string `json:"filedHead,omitempty"`
	MergeSHA         *string `json:"mergeSha,omitempty"`
	PRAutoMerge      bool    `json:"prAutoMerge"`
	ApprovedReviewID *string `json:"approvedReviewId,omitempty"`
}

func toAccessRequest(r db.AccessRequestsRow) accessRequest {
	a := accessRequest{ID: r.ID, Principal: r.Principal, RoleID: r.RoleID, RoleName: r.RoleName, DatasourceID: r.DatasourceID,
		DatasourceName: r.DatasourceName, Reason: r.Reason, RequestedDurationSec: r.RequestedDurationSec, Status: r.Status,
		DecidedBy: r.DecidedBy, ExecutedBy: r.ExecutedBy, DecidedAt: api.OptInstant(r.DecidedAt), RejectionReason: r.RejectionReason,
		CreatedAt: api.JavaInstant(r.CreatedAt), Kind: r.Kind, SQL: api.OptText(r.Sql), SQLHash: r.SqlHash, StatementCount: int(r.StatementCount),
		DenyReason: r.DenyReason, SourceDecisionID: r.SourceDecisionID, Title: r.Title, EvaluatedDecision: r.EvaluatedDecision,
		ApprovedAt: api.OptInstant(r.ApprovedAt), ExecutingAt: api.OptInstant(r.ExecutingAt), ExecutedAt: api.OptInstant(r.ExecutedAt),
		ExecuteAs: r.ExecuteAs, CreatorKind: &r.CreatorKind, StatementCarriesProtectedLiteral: r.StatementCarriesProtectedLiteral,
		Source: r.Source, Scope: r.Scope, FileKey: r.FileKey, ChangeKey: r.ChangeKey, MergedAt: api.OptInstant(r.MergedAt),
		Revision: r.Revision, RevisedAt: api.OptInstant(r.RevisedAt), ContentHash: r.ContentHash,
		ForceRun: r.ForceRun, ForceRunBy: r.ForceRunBy, CCs: r.Ccs}
	if r.Source == "github" && r.Repository != nil && r.Pr != nil {
		a.PullRequest = &pullRequestRef{Repository: *r.Repository, PR: *r.Pr, PRURL: r.PrUrl, Path: r.Path, HeadSHA: r.HeadSha,
			DefaultSchema: r.DefaultSchema, KeyOrder: r.KeyOrder, FiledHead: r.FiledHead, MergeSHA: r.MergeSha,
			PRAutoMerge: r.PrAutoMerge, ApprovedReviewID: r.ApprovedReviewID}
	}
	if a.ExecuteAs == nil {
		a.ExecuteAs = []string{}
	}
	if a.CCs == nil {
		a.CCs = []string{}
	}
	return a
}

// approvalResource is Kotlin's AccessRequest.toApprovalResource.
func (a accessRequest) approvalResource() bridge.Resource {
	return bridge.Resource{Type: "ApprovalRequest", Principal: a.Principal, Approver: a.DecidedBy,
		ExecutedBy: a.ExecutedBy, DatasourceName: a.DatasourceName, RoleName: a.RoleName, Source: a.Source, CCs: a.CCs}
}

// ownApprovals lists the caller's own workflow approval requests; owning them is the whole check.
func (a access) ownApprovals(w http.ResponseWriter, r *http.Request) {
	q, principal := r.URL.Query(), api.Principal(r.Context())
	if q.Has("status") {
		rows, err := db.New(a.pool).OwnApprovalsByStatus(r.Context(), db.OwnApprovalsByStatusParams{Principal: principal, Status: q.Get("status")})
		api.WriteRows(w, rows, err, func(r db.OwnApprovalsByStatusRow) accessRequest { return toAccessRequest(db.AccessRequestsRow(r)) })
		return
	}
	rows, err := db.New(a.pool).OwnApprovals(r.Context(), principal)
	api.WriteRows(w, rows, err, func(r db.OwnApprovalsRow) accessRequest { return toAccessRequest(db.AccessRequestsRow(r)) })
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
		GrantedAt: api.JavaInstant(g.GrantedAt), ExpiresAt: api.OptInstant(g.ExpiresAt), RevokedAt: api.OptInstant(g.RevokedAt)}
}

type access struct {
	pool   *pgxpool.Pool
	authz  api.Authorizer
	kotlin api.Kotlin
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
		api.Fail(w, err)
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
		api.Fail(w, err)
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
		api.Fail(w, err)
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
