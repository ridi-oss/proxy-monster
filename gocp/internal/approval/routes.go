package approval

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/engine"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/result"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// DebugPrincipal is `call.userSession()?.principal ?: "debug-user"` — the fallback EVERY route in
// this package takes when there is no session, which under `authDebug` is every request.
const DebugPrincipal = "debug-user"

// NotFoundApproval is the `resource` param on every 404 the approval routes answer:
// `notFound("query approval request")`.
//
// 🔒 IT IS ONE STRING FOR SEVEN DISTINCT FAILURES — absent row, non-WORKFLOW creator kind (INV-A7-5),
// `task.read` denied, `task.assume` denied (INV-A7-18), deactivated viewer, no result child, and a
// vanished request after a cancel. Byte-identical bodies mean none of them is an existence oracle. A
// const rather than seven literals so a future edit to one call site cannot split them.
const NotFoundApproval = "query approval request"

// ExecuteMaxRows is `/execute`'s hardcoded `maxRows = 5000` (Approvals.kt:728).
//
// ⚠️ The editor passes the CALLER's value while approver-exec is fixed here. 07 §11 Q3 asks whether
// that is a deliberate ceiling or an oversight; REPRODUCE either way.
const ExecuteMaxRows = 5000

// Deps is `Route.approvalRoutes(...)`'s eleven parameters plus the editor group's overlap. Kotlin
// passes them positionally with four defaults; a struct keeps every call site diffable against the
// source and makes the nil-legal ones (Results, Hub) visible at the wiring site.
type Deps struct {
	Gates *httpapi.Gates
	// Decider carries the live re-decision seams shared with the editor routes.
	Decider *Decider

	Access AccessStore
	Audit  AuditStore
	// Results is NIL when PM_RESULT_KEY is unset ⇒ execute-under-R and editor submit are refused
	// fail-closed rather than persisting plaintext PII.
	Results ResultStore
	RunExec RunExec
	// Roles lists every role for discovery — `policyStore.listRoles()`.
	Roles RoleLister
	// SelfApprove is A7's autoApproveTask, which lives on internal/core (see [SelfApprover]).
	SelfApprove SelfApprover
	// Hub is nil in the many Config-free constructions ⇒ publish is a no-op, exactly as Kotlin's
	// `taskCompletionHub?.publish(...)`.
	Hub *TaskCompletionHub
	// Scope is `appScope: CoroutineScope` — an INJECTED parameter in the Kotlin too. Production
	// passes nil, which runs the body on a new goroutine; a suite passes a synchronous or
	// completion-tracking implementation so the async body is observable without a sleep.
	Scope func(func())
	// ExchangeTimeoutMs is `config.queryExchangeTimeoutMs`.
	ExchangeTimeoutMs int64
	Log               *slog.Logger
}

// Routes is `Route.approvalRoutes(...)` (Approvals.kt:302-887) — ten routes, every one `requireApi`
// with the real authorization INSIDE.
//
// 🔒 requireApi, never requireAdmin. Approver eligibility is a Cedar POLICY (INV-A7-19), never a
// datasource's approver group and never an admin gate: an ordinary principal opens requests and reads
// their own, while `task.approve` decides who may decide.
type Routes struct {
	*Decider
	gates       *httpapi.Gates
	access      AccessStore
	audit       AuditStore
	results     ResultStore
	runExec     RunExec
	roleLister  RoleLister
	selfApprove SelfApprover
	hub         *TaskCompletionHub
	scope       func(func())
	exchangeMs  int64
	log         *slog.Logger
}

// NewRoutes builds the group. A nil logger defaults to slog.Default(); a nil Scope defaults to `go`.
func NewRoutes(d Deps) *Routes {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	scope := d.Scope
	if scope == nil {
		scope = func(f func()) { go f() }
	}
	return &Routes{
		Decider: d.Decider, gates: d.Gates, access: d.Access, audit: d.Audit, results: d.Results,
		runExec: d.RunExec, roleLister: d.Roles, selfApprove: d.SelfApprove, hub: d.Hub,
		scope: scope, exchangeMs: d.ExchangeTimeoutMs, log: log,
	}
}

var _ httpapi.RouteGroup = (*Routes)(nil)

// Register mounts the ten approval patterns.
//
// ⚠️ `GET /api/approvals/inbox` and `GET /api/approvals/{id}` are both three segments. Go's ServeMux
// resolves that by SPECIFICITY — a literal segment beats a wildcard — so `inbox` is never swallowed
// by `{id}`, and the two do not conflict (a conflict would panic at startup). Measured by
// TestInboxIsNotSwallowedByTheIdPattern; do not "disambiguate" it by renaming the route.
func (rt *Routes) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/approvals", rt.create)
	mux.HandleFunc("POST /api/approvals/discover-roles", rt.discover)
	mux.HandleFunc("GET /api/approvals", rt.list)
	mux.HandleFunc("GET /api/approvals/inbox", rt.inbox)
	mux.HandleFunc("GET /api/approvals/{id}", rt.detail)
	mux.HandleFunc("POST /api/approvals/{id}/approve", rt.approve)
	mux.HandleFunc("POST /api/approvals/{id}/reject", rt.reject)
	mux.HandleFunc("POST /api/approvals/{id}/cancel", rt.cancel)
	mux.HandleFunc("POST /api/approvals/{id}/execute", rt.execute)
	mux.HandleFunc("GET /api/approvals/{id}/result", rt.resultView)
}

// ---------------------------------------------------------------------------------------------
// The three closure gates — Approvals.kt:326-374
// ---------------------------------------------------------------------------------------------

// mayRequest is "may the caller open a query-approval request against this datasource"
// (`task.request` on the Datasource). The shipped global permit keeps it open by default; an operator
// can forbid it per datasource. authDebug BYPASSES.
func (rt *Routes) mayRequest(r *http.Request, principal string, ds datasource.Datasource) (bool, error) {
	if rt.gates.Config.AuthDebug {
		return true, nil
	}
	roles, err := rt.Decider.Roles.Resolve(r.Context(), principal)
	if err != nil {
		return false, err
	}
	raw := rt.authzContext(r)
	tags := rt.Decider.Authz.ResolveContextTags(principal, roles, ds.Name, raw, ds.Tags)
	return rt.Decider.Authz.AuthorizeDatasourceAction(
		principal, roles, authz.ActionTaskRequest, ds.Name, raw.WithTags(tags), ds.Tags,
	).Allowed, nil
}

// mayDecide is THE single authorization for a task action on a query-approval request: Cedar decides
// `task.approve` (approve / reject / execute) or `task.read` / `task.cancel` against the Request,
// scoped to its role and datasource.
//
// 🔒 INV-A7-19 — `requester != approver` comes from the shipped `no-self-approval` FORBID, not from
// app code, and approver eligibility is a Cedar policy, never the datasource's approver group. This
// function only ever asks "may this principal do this".
//
// 🔒 INV-A7-24 — REJECT ASKS THE SAME `task.approve` QUESTION AS APPROVE, so a role-scoped approval
// policy governs both. There is deliberately no `task.reject` action.
//
// authDebug BYPASSES, matching every other route's Cedar gate.
//
// ⚠️ It reads the datasource ROW on every call, only for its tags — so the inbox filter is an N+1
// over the pending queue. REPRODUCE: inefficiency is not grounds for OMIT (00-INDEX.md).
func (rt *Routes) mayDecide(r *http.Request, principal string, action authz.AuthzAction, req access.AccessRequest) (bool, error) {
	if rt.gates.Config.AuthDebug {
		return true, nil
	}
	tags, err := rt.datasourceTags(r.Context(), req.DatasourceID)
	if err != nil {
		return false, err
	}
	return rt.Decider.Authz.AuthorizeWithContext(
		principal, action, requestResource(req), rt.authzContext(r), req.DatasourceName, tags,
	).Allowed, nil
}

// mayReadResult is the ROW gate: Cedar authority to assume the task's R.
//
// 🔒 INV-A7-18 — THERE IS NO authDebug BYPASS HERE, unlike [Routes.mayRequest] and
// [Routes.mayDecide]. Result rows are data confidentiality, enforced in development too. The same
// rule as A6 INV-A6-25 for the editor result route. Adding a bypass would make every dev deployment
// hand any authenticated principal every stored result.
func (rt *Routes) mayReadResult(r *http.Request, principal string, req access.AccessRequest) (bool, error) {
	tags, err := rt.datasourceTags(r.Context(), req.DatasourceID)
	if err != nil {
		return false, err
	}
	return rt.Decider.Authz.AuthorizeWithContext(
		principal, authz.ActionTaskAssume, requestResource(req), rt.authzContext(r), req.DatasourceName, tags,
	).Allowed, nil
}

// requestResource builds the Cedar Request entity from a task row — the same five fields at all four
// gate call sites (and at the editor routes' and the SSE push filter's).
//
// 🔒 Approver and ExecutedBy stay POINTERS. Absence is what a `resource has approver` guard reads;
// emitting a placeholder would make a pre-decision task satisfy an approver-conditioned policy.
func requestResource(req access.AccessRequest) authz.ResourceApprovalRequest {
	return authz.ResourceApprovalRequest{
		Requester:      req.Principal,
		Approver:       req.DecidedBy,
		ExecutedBy:     req.ExecutedBy,
		DatasourceName: req.DatasourceName,
		RoleName:       req.RoleName,
	}
}

// datasourceTags is `req.datasourceId?.let(datasourceStore::get)?.tags.orEmpty()`.
func (rt *Routes) datasourceTags(ctx context.Context, datasourceID *int64) ([]string, error) {
	if datasourceID == nil {
		return nil, nil
	}
	ds, found, err := rt.Decider.Datasources.Get(ctx, *datasourceID)
	if err != nil || !found {
		return nil, err
	}
	return ds.Tags, nil
}

// e3Record is the lifecycle audit row (Approvals.kt:385-395):
// `statement = "approval #<id> <event>"`, decision ALLOW, `detail = "APPROVER_EXEC <event>"`,
// `kind = "approval_lifecycle"`, datasource = the resolved name or "?".
//
// 🔒 INV-A7-20 — IT DELIBERATELY CARRIES NO RESULT-DERIVED DATA. No row count, no requester name.
// `audit_decision` is exposed through the shared feed, so the row records only the event, the ACTOR
// (principal = whoever acted) and the approval id. The requester↔approval linkage stays
// reconstructable from `access_request` by an authorized auditor via that id, but is not broadcast
// inline.
func (rt *Routes) e3Record(ctx context.Context, principal string, req access.AccessRequest, event string, channel *query.Channel) types.AuditEvent {
	dsName := "?"
	if req.DatasourceID != nil {
		if ds, found, err := rt.Decider.Datasources.Get(ctx, *req.DatasourceID); err == nil && found {
			dsName = ds.Name
		}
	}
	ev := types.NewAuditEvent(principal, dsName, "approval #"+itoa(req.ID)+" "+event, types.DecisionAllow)
	detail := "APPROVER_EXEC " + event
	ev.Detail = &detail
	if channel != nil {
		value := channel.ContextValue()
		ev.Channel = &value
	}
	ev.Kind = "approval_lifecycle"
	return ev
}

// ---------------------------------------------------------------------------------------------
// POST /api/approvals — Approvals.kt:397-504
// ---------------------------------------------------------------------------------------------

// create opens a query-approval request through one of two mutually exclusive branches.
//
//	from-denied  — sourceDecisionId names a DENY the requester owns
//	proactive    — datasourceId + sql + title + reason, composed in the console
//
// 🔒 EXACTLY ONE. Both-set and neither-set answer the SAME 400
// `approval.exactly_one_source_required`, so the two branches can never be entered at once and a
// caller cannot smuggle a chosen datasource onto a decision-derived request.
//
// 🔒 INV-A7-21 — the `roleId == null` guard runs AFTER each branch's field validation, so an
// incomplete form names its missing field first. A query approval always runs under an elevation role
// R; a row with no R has no {R} to re-decide under and /result fails it closed.
func (rt *Routes) create(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	principal, ok := rt.principal(w, r)
	if !ok {
		return
	}
	body, err := readBody(r)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	input, err := DecodeCreateApproval(body)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if engine.IsBlank(input.Reason) {
		rt.respondError(w, types.FieldRequired("reason"))
		return
	}

	hasSource := input.SourceDecisionID != nil
	// ⚠️ `input.sql != null` — an EMPTY string still counts as "proactive fields present", so
	// `{"sourceDecisionId":1,"sql":""}` is the both-set 400 rather than a from-denied create.
	hasProactive := input.DatasourceID != nil || input.SQL != nil
	if hasSource == hasProactive { // both set, or neither
		rt.respondCode(w, http.StatusBadRequest, "approval.exactly_one_source_required", nil)
		return
	}

	if hasSource {
		rt.createFromDenied(w, r, principal, input)
		return
	}
	rt.createProactive(w, r, principal, input)
}

// createFromDenied is the `hasSource` branch (Approvals.kt:417-457).
func (rt *Routes) createFromDenied(w http.ResponseWriter, r *http.Request, principal string, input CreateApprovalInput) {
	ctx := r.Context()
	sourceDecisionID := *input.SourceDecisionID

	decision, err := rt.audit.Get(ctx, sourceDecisionID)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	switch ValidateApprovalSource(decision, principal) {
	case SourceOK:
	case SourceNotFound:
		// 🔒 A not-owned decision is 404, not 403 — no leaking other principals' decision ids.
		rt.respondError(w, types.NotFound("decision"))
		return
	case SourceNotDeny:
		rt.respondCode(w, http.StatusBadRequest, "approval.only_denied_queries", nil)
		return
	}
	source := *decision

	// The application-level pre-check. It is NOT the enforcement — CreateQueryRequest's partial-index
	// upsert is (INV-A6-21) — which is why the same 409 is answered twice below.
	exists, err := rt.access.PendingQueryRequestExists(ctx, sourceDecisionID)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if exists {
		rt.respondCode(w, http.StatusConflict, "approval.pending_request_exists", nil)
		return
	}

	// ⚠️ `datasourceStore.list().firstOrNull { it.name == source.datasource }` — a full list plus a
	// linear scan, where GetByName would do. REPRODUCE (inefficiency is not grounds for OMIT), and
	// note the 409 rather than 404: the audit row names a datasource that no longer exists, which is
	// a state conflict, not a bad request path.
	all, err := rt.Decider.Datasources.List(ctx)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	var ds *datasource.Datasource
	for i := range all {
		if all[i].Name == source.Datasource {
			ds = &all[i]
			break
		}
	}
	if ds == nil {
		rt.respondCode(w, http.StatusConflict, "common.not_found", map[string]string{"resource": "datasource"})
		return
	}
	allowed, err := rt.mayRequest(r, principal, *ds)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if !allowed {
		// A BARE common.forbidden — no `detail`. types.Forbidden(nil) is the other reachable family
		// (Approvals.kt:435 vs requireAuthz's detailed form); McpServer branches on the code alone, so
		// the two must keep the same code and differ only in params.
		rt.respondError(w, types.Forbidden(nil))
		return
	}
	if input.RoleID == nil { // INV-A7-21
		rt.respondCode(w, http.StatusBadRequest, "approval.role_required", nil)
		return
	}

	evaluated := "DENY"
	reason := trim(input.Reason)
	request, err := rt.access.CreateQueryRequest(ctx, access.CreateQueryRequestInput{
		Principal:            principal,
		DatasourceID:         ds.ID,
		SQL:                  source.Statement,
		DenyReason:           source.Detail,
		SourceDecisionID:     &sourceDecisionID,
		Reason:               &reason,
		Title:                trimmedTitle(input.Title),
		EvaluatedDecision:    &evaluated,
		RoleID:               input.RoleID,
		RequestedDurationSec: &input.RequestedDurationSec,
	})
	if errors.Is(err, access.ErrDuplicatePendingQueryRequest) {
		rt.respondCode(w, http.StatusConflict, "approval.pending_request_exists", nil)
		return
	}
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	rt.respond(w, r, http.StatusCreated, CreateApprovalResponse{Request: *request, WouldAllow: false})
}

// createProactive is the compose branch (Approvals.kt:459-503).
//
// 🔒 INV-A7-22 — the preview carries the SERVER-ATTESTED requester_ip and the system classifier. A
// preview that dropped either would report a DIFFERENT verdict than the real editor execution
// whenever a policy conditions on `requester_ip` (or a tag derived from it) or the statement touches
// a system table. Nothing executes and no audit row is written at compose time.
func (rt *Routes) createProactive(w http.ResponseWriter, r *http.Request, principal string, input CreateApprovalInput) {
	ctx := r.Context()
	if missing := ValidateProactiveCompose(input.DatasourceID, input.SQL, input.Title, &input.Reason); missing != "" {
		rt.respondError(w, types.FieldRequired(missing))
		return
	}
	ds, found, err := rt.Decider.Datasources.Get(ctx, *input.DatasourceID)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if !found {
		rt.respondError(w, types.NotFound("datasource"))
		return
	}
	sql := *input.SQL
	allowed, err := rt.mayRequest(r, principal, ds)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if !allowed {
		rt.respondError(w, types.Forbidden(nil))
		return
	}
	if input.RoleID == nil { // INV-A7-21
		rt.respondCode(w, http.StatusBadRequest, "approval.role_required", nil)
		return
	}

	catalog, err := rt.Decider.Datasources.Catalog(ctx, ds.ID)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	decision, err := rt.Decider.decide(ctx, query.DecideQueryInput{
		Principal:            principal,
		Datasource:           ds,
		SQL:                  sql,
		Channel:              query.ChannelEditor,
		Catalog:              catalog,
		MaskFns:              rt.Decider.MaskFns,
		UserGroups:           rt.Decider.UserGroups,
		Roles:                rt.Decider.Roles,
		Authz:                rt.Decider.Authz,
		Context:              rt.authzContext(r), // INV-A7-22
		SystemClassification: rt.Decider.SystemClassification,
	})
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}

	var denyReason *string
	if decision.Action == pb.EnfAction_DENY {
		denyReason = decision.DenyReason
		if denyReason == nil {
			denyReason = decision.Detail
		}
	}
	reason := trim(input.Reason)
	title := trim(*input.Title)
	evaluated := decision.Action.String()
	request, err := rt.access.CreateQueryRequest(ctx, access.CreateQueryRequestInput{
		Principal:            principal,
		DatasourceID:         ds.ID,
		SQL:                  sql,
		DenyReason:           denyReason,
		SourceDecisionID:     nil,
		Reason:               &reason,
		Title:                &title,
		EvaluatedDecision:    &evaluated,
		RoleID:               input.RoleID,
		RequestedDurationSec: &input.RequestedDurationSec,
	})
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	rt.respond(w, r, http.StatusCreated, CreateApprovalResponse{
		Request: *request, WouldAllow: decision.Action == pb.EnfAction_ALLOW,
	})
}

// ---------------------------------------------------------------------------------------------
// POST /api/approvals/discover-roles — Approvals.kt:509-528
// ---------------------------------------------------------------------------------------------

// discover previews Q under each candidate role. A DRY RUN: no audit row is written.
//
// 🔒 `discoverContext` is resolved ONCE, outside the closure that runs decideQuery per candidate, so
// every candidate is previewed under the SAME server-attested context the real editor execution will
// use. Resolving it per candidate would let a mid-loop change produce an inconsistent offer set.
func (rt *Routes) discover(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	principal, ok := rt.principal(w, r)
	if !ok {
		return
	}
	var input DiscoverRolesRequest
	if err := httpapi.Receive(r, &input); err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	ctx := r.Context()
	ds, found, err := rt.Decider.Datasources.Get(ctx, input.DatasourceID)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if !found {
		rt.respondError(w, types.NotFound("datasource"))
		return
	}
	ownRoles, err := rt.Decider.Roles.Resolve(ctx, principal)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	allRoles, err := rt.roleLister(ctx)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	catalog, err := rt.Decider.Datasources.Catalog(ctx, ds.ID)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	discoverContext := rt.authzContext(r)

	response, err := DiscoverRoles(ownRoles, allRoles, func(roles []string) (query.DecisionContext, error) {
		provided := roles
		return rt.Decider.decide(ctx, query.DecideQueryInput{
			Principal:            principal,
			Datasource:           ds,
			SQL:                  input.SQL,
			Channel:              query.ChannelEditor,
			Catalog:              catalog,
			MaskFns:              rt.Decider.MaskFns,
			UserGroups:           rt.Decider.UserGroups,
			Roles:                rt.Decider.Roles,
			Authz:                rt.Decider.Authz,
			ProvidedRoles:        &provided,
			Context:              discoverContext,
			SystemClassification: rt.Decider.SystemClassification,
		})
	})
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	rt.respond(w, r, http.StatusOK, response)
}

// ---------------------------------------------------------------------------------------------
// GET /api/approvals and GET /api/approvals/inbox — Approvals.kt:530-542
// ---------------------------------------------------------------------------------------------

// list is the caller's OWN requests, optionally filtered by `?status=`.
func (rt *Routes) list(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	principal, ok := rt.principal(w, r)
	if !ok {
		return
	}
	var status *string
	if q := r.URL.Query(); q.Has("status") {
		v := q.Get("status")
		status = &v
	}
	requests, err := rt.access.ListQueryRequests(r.Context(), status, &principal)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	rt.respond(w, r, http.StatusOK, emptyIfNil(requests))
}

// inbox is every PENDING request the caller may approve.
//
// 🔒 A FORWARD FILTER by Cedar, not a group-membership join: each row is kept only if
// `task.approve` permits it, so an operator-defined approval policy — role-scoped,
// datasource-scoped, zone-scoped — governs the queue with no code change. authDebug shows all.
//
// The WORKFLOW-only filter comes from [AccessStore.ListQueryRequests] itself (INV-A6-17), which is
// why no creator-kind check appears here.
func (rt *Routes) inbox(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	principal, ok := rt.principal(w, r)
	if !ok {
		return
	}
	pending := "PENDING"
	requests, err := rt.access.ListQueryRequests(r.Context(), &pending, nil)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	out := []access.AccessRequest{}
	for _, req := range requests {
		allowed, err := rt.mayDecide(r, principal, authz.ActionTaskApprove, req)
		if err != nil {
			httpapi.RespondFallback(w, r, rt.log, err)
			return
		}
		if allowed {
			out = append(out, req)
		}
	}
	rt.respond(w, r, http.StatusOK, out)
}

// ---------------------------------------------------------------------------------------------
// GET /api/approvals/{id} — Approvals.kt:544-574
// ---------------------------------------------------------------------------------------------

// detail is the task metadata plus the affordances the console renders.
//
// 🔒 INV-A7-23 — the result metadata is REDACTED (rowCount cleared, columns emptied) when the caller
// cannot assume R. `rowCount` and `columns` are cardinality/existence oracles the assume gate must
// close: a caller with only `task.read` learns status, executor, timestamps and error code — never
// the result's shape.
func (rt *Routes) detail(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	id := httpapi.IDParam(r)
	if id == nil {
		rt.respondError(w, types.BadID())
		return
	}
	principal, ok := rt.principal(w, r)
	if !ok {
		return
	}
	req, ok := rt.workflowRequest(w, r, *id)
	if !ok {
		return
	}

	isApprover, err := rt.mayDecide(r, principal, authz.ActionTaskApprove, *req)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	mayRead, err := rt.mayDecide(r, principal, authz.ActionTaskRead, *req)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if !mayRead {
		rt.respondError(w, types.NotFound(NotFoundApproval))
		return
	}

	var visibleMeta *result.QueryResultMeta
	if rt.results != nil {
		meta, err := rt.results.Meta(r.Context(), *id)
		if err != nil {
			httpapi.RespondFallback(w, r, rt.log, err)
			return
		}
		if meta != nil {
			mayAssume, err := rt.mayReadResult(r, principal, *req)
			if err != nil {
				httpapi.RespondFallback(w, r, rt.log, err)
				return
			}
			redacted := *meta
			if !mayAssume { // INV-A7-23
				redacted.RowCount = nil
				redacted.Columns = []string{}
			}
			visibleMeta = &redacted
		}
	}

	// Mirrors /execute's gates exactly, so a merely-eligible approver who did not approve THIS task
	// gets no Run affordance that would just 403.
	canExecute := rt.results != nil && isApprover && req.Status == "APPROVED" &&
		req.DecidedBy != nil && *req.DecidedBy == principal
	canCancel := false
	if req.Status == "EXECUTING" {
		if canCancel, err = rt.mayDecide(r, principal, authz.ActionTaskCancel, *req); err != nil {
			httpapi.RespondFallback(w, r, rt.log, err)
			return
		}
	}
	rt.respond(w, r, http.StatusOK, ApprovalDetail{
		Request:    *req,
		CanDecide:  req.Status == "PENDING" && isApprover,
		Result:     visibleMeta,
		CanExecute: canExecute,
		CanCancel:  canCancel,
	})
}

// ---------------------------------------------------------------------------------------------
// POST /{id}/approve and POST /{id}/reject — Approvals.kt:576-626
// ---------------------------------------------------------------------------------------------

// approve decides a pending request in the requester's favour. Approval authorizes EXECUTION; it does
// not run the statement — an approved QUERY request is run under R by the approver, and there is no
// requester-side re-run mode.
func (rt *Routes) approve(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	id := httpapi.IDParam(r)
	if id == nil {
		rt.respondError(w, types.BadID())
		return
	}
	principal, ok := rt.principal(w, r)
	if !ok {
		return
	}
	rt.decideRequest(w, r, *id, principal, true, nil)
}

// reject refuses it.
//
// ⚠️ THE BLANK-REASON 400 ANSWERS BEFORE THE REQUEST LOOKUP (Approvals.kt:606-609), so a reject with
// no reason on a NON-EXISTENT id is a 400, not a 404. Asymmetric with approve — which has no body to
// validate — and reproduced, including the ORDER: requireApi, then the id parse, then the body, then
// the blank check, and only then the lookup.
func (rt *Routes) reject(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	id := httpapi.IDParam(r)
	if id == nil {
		rt.respondError(w, types.BadID())
		return
	}
	principal, ok := rt.principal(w, r)
	if !ok {
		return
	}
	var body access.RejectInput
	// ⚠️ Unlike A6's `/api/access-requests/{id}/approve`, this uses a PLAIN receive, so a missing or
	// malformed body is an error rather than a tolerated default. Asymmetric but intentional: the
	// reason is mandatory and the duration is not.
	if err := httpapi.Receive(r, &body); err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if engine.IsBlank(body.Reason) {
		rt.respondError(w, types.FieldRequired("reason"))
		return
	}
	reason := trim(body.Reason)
	rt.decideRequest(w, r, *id, principal, false, &reason)
}

// decideRequest is the shared tail of approve and reject.
//
// 🔒 INV-A7-24 — BOTH ask `task.approve`. There is no separate reject action, so one role-scoped
// approval policy governs both directions.
func (rt *Routes) decideRequest(
	w http.ResponseWriter, r *http.Request, id int64, principal string, approved bool, rejectionReason *string,
) {
	req, ok := rt.workflowRequest(w, r, id)
	if !ok {
		return
	}
	if req.Status != "PENDING" {
		rt.respondCode(w, http.StatusConflict, "approval.already_decided", nil)
		return
	}
	allowed, err := rt.mayDecide(r, principal, authz.ActionTaskApprove, *req)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if !allowed {
		rt.respondCode(w, http.StatusForbidden, "approval.not_approver", nil)
		return
	}
	// The guarded conditional UPDATE is the real concurrency control (INV-A6-18); the status check
	// above is only a fast path, and a lost race answers the SAME 409.
	updated, err := rt.access.DecideQueryRequest(r.Context(), id, approved, rejectionReason, principal)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if updated == nil {
		rt.respondCode(w, http.StatusConflict, "approval.already_decided", nil)
		return
	}
	verb := "approved"
	if !approved {
		verb = "rejected"
	}
	rt.log.Info("query approval "+verb, "request", id, "requester", req.Principal,
		"decider", principal, "sourceDecisionId", req.SourceDecisionID)
	rt.respond(w, r, http.StatusOK, *updated)
}

// ---------------------------------------------------------------------------------------------
// POST /{id}/cancel — Approvals.kt:628-663
// ---------------------------------------------------------------------------------------------

// cancel terminalizes an in-flight run.
//
// The status switch is deliberately three-way: already-terminal is an IDEMPOTENT 200 with the
// request, the pre-execution states are 409 `approval.not_cancelable`, and only EXECUTING proceeds.
//
// 🔒 INV-A7-25 — the CANCELLED push happens HERE, immediately, rather than waiting for the run
// goroutine, which may not unwind for a long time on a stuck run. It is best-effort; the coroutine's
// own terminal push and the console's poll both still cover it.
func (rt *Routes) cancel(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	id := httpapi.IDParam(r)
	if id == nil {
		rt.respondError(w, types.BadID())
		return
	}
	principal, ok := rt.principal(w, r)
	if !ok {
		return
	}
	req, ok := rt.workflowRequest(w, r, *id)
	if !ok {
		return
	}
	allowed, err := rt.mayDecide(r, principal, authz.ActionTaskCancel, *req)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if !allowed {
		rt.respondCode(w, http.StatusForbidden, "approval.cancel_forbidden", nil)
		return
	}
	switch req.Status {
	case "EXECUTED", "FAILED", "CANCELLED":
		rt.respond(w, r, http.StatusOK, *req) // idempotent
		return
	case "EXECUTING": // proceed
	default:
		// DRAFT / PENDING / APPROVED / REJECTED and anything unrecognised.
		rt.respondCode(w, http.StatusConflict, "approval.not_cancelable", nil)
		return
	}
	if rt.results == nil {
		rt.respondCode(w, http.StatusServiceUnavailable, "approval.result_storage_not_configured", nil)
		return
	}

	ctx := r.Context()
	cancelled, err := rt.results.CancelRun(ctx, *id, func(hookCtx context.Context, c store.Queryer, _ result.QueryResultMeta) error {
		won, err := rt.access.MarkCancelledOn(hookCtx, c, *id)
		if err != nil {
			return err
		}
		if !won {
			// Kotlin throws IllegalStateException, which rolls the child transition back with it.
			return errors.New("task " + itoa(*id) + " left EXECUTING before cancellation")
		}
		_, err = rt.audit.InsertOn(hookCtx, c, rt.e3Record(hookCtx, principal, *req, "result-canceled", channelPtr(query.ChannelWorkflowExecutor)))
		return err
	})
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if cancelled != nil {
		rt.runExec.CancelActiveRun(ctx, *id)
		if rt.hub != nil {
			parties := []string{req.Principal}
			if req.DecidedBy != nil {
				parties = append(parties, *req.DecidedBy)
			}
			rt.hub.PublishTo(parties, TaskEvent{TaskID: *id, Status: "CANCELLED"})
		}
	}
	updated, err := rt.access.GetRequest(ctx, *id)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if updated == nil {
		rt.respondError(w, types.NotFound(NotFoundApproval))
		return
	}
	rt.respond(w, r, http.StatusOK, *updated)
}

// ---------------------------------------------------------------------------------------------
// POST /{id}/execute — Approvals.kt:667-787
// ---------------------------------------------------------------------------------------------

// execute runs the approved statement under R, on the proxy.
//
// # The gate ORDER is the security contract
//
//  1. isWorkflowApproval          ⇒ 404
//  2. 🔒 task.approve             ⇒ 403 BEFORE any status disclosure
//  3. terminal/in-flight status   ⇒ 409 approval.already_executed
//  4. status != APPROVED          ⇒ 409 approval.not_approved
//  5. 🔒 decidedBy != executor    ⇒ 403 approval.not_the_approver, NO authDebug bypass
//  6. no result store ⇒ 503; no datasource ⇒ 409; no sql ⇒ 409
//  7. empty {R}                   ⇒ 409 approval.no_execute_role
//  8. claimAndStartRun lost       ⇒ 409 approval.already_executed
//  9. launch, respond 202
//
// 🔒 STEP 2 BEFORE STEPS 3-4 is the whole point: a caller who cannot approve this task gets a uniform
// 403 regardless of its status, so the `already_executed` / `not_approved` distinction is never a
// state oracle for a non-approver.
//
// 🔒 INV-A7-26 — step 5 pins `executedBy = decided_by = the approver`, so the run's identity always
// falls inside the `task.assume` permit (requester OR approver) and the saved result stays readable
// by its parties WITHOUT adding `executedBy` to the permit. An eligible approver who did not approve
// THIS task cannot run it, and there is no authDebug bypass because it is an identity invariant, not
// an authorization.
//
// 🔒 INV-A7-2 — step 7 is what stops a task with no R falling through to the proxy Decide under the
// REQUESTER's own roles, silently reinterpreting the authorization.
func (rt *Routes) execute(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	id := httpapi.IDParam(r)
	if id == nil {
		rt.respondError(w, types.BadID())
		return
	}
	executor, ok := rt.principal(w, r)
	if !ok {
		return
	}
	req, ok := rt.workflowRequest(w, r, *id) // STEP 1
	if !ok {
		return
	}
	// STEP 2 — before any status disclosure.
	allowed, err := rt.mayDecide(r, executor, authz.ActionTaskApprove, *req)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if !allowed {
		rt.respondCode(w, http.StatusForbidden, "approval.not_approver", nil)
		return
	}
	switch req.Status { // STEP 3
	case "EXECUTING", "EXECUTED", "FAILED", "CANCELLED":
		rt.respondCode(w, http.StatusConflict, "approval.already_executed", nil)
		return
	}
	if req.Status != "APPROVED" { // STEP 4
		rt.respondCode(w, http.StatusConflict, "approval.not_approved", nil)
		return
	}
	// STEP 5 — INV-A7-26. No authDebug bypass.
	if req.DecidedBy == nil || *req.DecidedBy != executor {
		rt.respondCode(w, http.StatusForbidden, "approval.not_the_approver", nil)
		return
	}
	// STEP 6.
	if rt.results == nil {
		rt.respondCode(w, http.StatusServiceUnavailable, "approval.result_storage_not_configured", nil)
		return
	}
	ctx := r.Context()
	if req.DatasourceID == nil {
		rt.respondCode(w, http.StatusConflict, "common.not_found", map[string]string{"resource": "datasource"})
		return
	}
	ds, found, err := rt.Decider.Datasources.Get(ctx, *req.DatasourceID)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if !found {
		rt.respondCode(w, http.StatusConflict, "common.not_found", map[string]string{"resource": "datasource"})
		return
	}
	if req.SQL == nil {
		rt.respondCode(w, http.StatusConflict, "approval.no_sql", nil)
		return
	}
	sql := *req.SQL
	requesterIP := rt.requesterIP(r)
	executeAs := req.ExecuteAs
	if len(executeAs) == 0 { // STEP 7 — INV-A7-2
		rt.respondCode(w, http.StatusConflict, "approval.no_execute_role", nil)
		return
	}

	// STEP 8 — 🔒 INV-A7-7: the parent's APPROVED→EXECUTING and the child's NULL→RUNNING commit in
	// ONE transaction, so a cancel can never land in a gap where the parent is EXECUTING with no
	// RUNNING child (which would no-op the cancel and let the query run anyway).
	claimed, err := rt.results.ClaimAndStartRun(ctx, *id, executor, func(txCtx context.Context, c store.Queryer) (bool, error) {
		return rt.access.ClaimExecutionOn(txCtx, c, *id)
	})
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if claimed == nil {
		rt.respondCode(w, http.StatusConflict, "approval.already_executed", nil)
		return
	}

	// STEP 9. The body outlives the request, exactly as `appScope.launch` outlives the call, so it
	// takes a context detached from the request's cancellation.
	async := context.WithoutCancel(ctx)
	taskID := *id
	snapshot := *req
	rt.scope(func() {
		rt.runApproved(async, taskID, executor, snapshot, ds, sql, executeAs, requesterIP)
	})
	rt.respond(w, r, http.StatusAccepted, ExecuteApprovalResponse{Decision: "EXECUTING"})
}

// runApproved is `appScope.launch { … }`'s body (Approvals.kt:718-785).
//
// 🔒 INV-A7-27 — on success, the child's DONE, the parent's EXECUTED and the execution audit row all
// commit in ONE transaction. If the parent has LEFT EXECUTING (a restart already reconciled it to
// FAILED), MarkExecutedOn matches nothing, the hook errors, and the WHOLE commit aborts — the child
// stays RUNNING and the failure path below transitions both consistently. Do not soften that error
// into a log line.
func (rt *Routes) runApproved(
	ctx context.Context,
	taskID int64,
	executor string,
	req access.AccessRequest,
	ds datasource.Datasource,
	sql string,
	executeAs []string,
	requesterIP *string,
) {
	failureCode := rt.executeRun(ctx, taskID, executor, req, ds, sql, executeAs, requesterIP)
	if failureCode != nil {
		// Child FAILED + parent FAILED in ONE transaction, mirroring the success path.
		if _, err := rt.results.FailRun(ctx, taskID, *failureCode, func(hookCtx context.Context, c store.Queryer, _ result.QueryResultMeta) error {
			_, err := rt.access.MarkFailedOn(hookCtx, c, taskID)
			return err
		}); err != nil {
			rt.log.Error("task failure transition failed", "request", taskID, "err", err)
		}
	}
	// Push the ACTUAL terminal state — EXECUTED, FAILED, or CANCELLED if a cancel raced.
	if rt.hub != nil {
		if updated, err := rt.access.GetRequest(ctx, taskID); err == nil && updated != nil {
			rt.hub.PublishTo([]string{req.Principal, executor}, TaskEvent{TaskID: taskID, Status: updated.Status})
		}
	}
}

// executeRun is the try/catch half, returning the Kotlin's `failureCode` (nil = no failure).
//
// ⚠️ THE EXCEPTION ARMS ARE NOT THE SAME SET THE EDITOR SUBMIT USES, and that asymmetry is real:
// there is NO `ProxyStreamWedgedException` arm here, so a wedged stream falls to the generic
// `catch (t: Throwable)` and is logged + reported as `approval.query_failed`, where the editor
// reports `query.proxy_stream_wedged`. REPRODUCE — see 00-INDEX.md's inconsistency rule.
func (rt *Routes) executeRun(
	ctx context.Context,
	taskID int64,
	executor string,
	req access.AccessRequest,
	ds datasource.Datasource,
	sql string,
	executeAs []string,
	requesterIP *string,
) *string {
	response, err := rt.runExec.Run(ctx, RunInput{
		Principal:  executor,
		Datasource: ds,
		SQL:        sql,
		MaxRows:    ExecuteMaxRows,
		// The approver executes: the ephemeral token, the connection binding and the execution audit
		// all carry the approver's identity. Execute-as R is enforced separately via AssumeRoles — the
		// role the decision runs AS, not who runs it.
		ApproverExec: true,
		AssumeRoles:  executeAs, // 🔒 INV-A7-1 — R alone.
		RequesterIP:  requesterIP,
		TaskID:       &taskID,
		Preflight: func() bool {
			meta, err := rt.results.Meta(ctx, taskID)
			return err == nil && meta != nil && meta.Status != nil && *meta.Status == "RUNNING"
		},
		ExchangeTimeoutMs: rt.exchangeMs,
	})
	switch {
	case err == nil:
	case errors.Is(err, ErrRunCanceledBeforeStart):
		return nil // not a failure
	case errors.Is(err, ErrNoProxyAttached):
		return strptr("query.no_proxy_attached")
	case errors.Is(err, ErrProxyRunTimeout):
		return strptr("query.proxy_timeout")
	default:
		var pre *ProxyRunError
		if errors.As(err, &pre) {
			return strptr("approval.query_failed")
		}
		// Includes ErrProxyStreamWedged — see the asymmetry note above.
		rt.log.Error("query approval execution failed", "request", taskID, "err", err)
		return strptr("approval.query_failed")
	}

	if pb.EnfAction(response.Decision) == pb.EnfAction_DENY {
		return strptr("approval.execute_denied")
	}
	res := result.DecryptedResult{Columns: response.Columns, Rows: response.Rows}
	completed, err := rt.results.CompleteRun(ctx, taskID, res, result.RetentionSec,
		func(hookCtx context.Context, c store.Queryer, _ result.QueryResultMeta) error {
			won, err := rt.access.MarkExecutedOn(hookCtx, c, taskID)
			if err != nil {
				return err
			}
			if !won { // INV-A7-27
				return errors.New("task " + itoa(taskID) + " left EXECUTING before completion")
			}
			_, err = rt.audit.InsertOn(hookCtx, c,
				rt.e3Record(hookCtx, executor, req, "result-executed", channelPtr(query.ChannelWorkflowExecutor)))
			return err
		})
	if err != nil {
		rt.log.Error("query approval execution failed", "request", taskID, "err", err)
		return strptr("approval.query_failed")
	}
	if completed == nil {
		return strptr("approval.query_failed")
	}
	rt.log.Info("query approval executed", "request", taskID, "requester", req.Principal,
		"executor", executor, "rows", len(res.Rows))
	return nil
}

// ---------------------------------------------------------------------------------------------
// GET /{id}/result — Approvals.kt:792-886
// ---------------------------------------------------------------------------------------------

// resultView releases the decrypted rows.
//
//  1. isWorkflowApproval        ⇒ 404
//  2. 🔒 deactivated viewer     ⇒ 404 (no result-existence oracle for a deprovisioned principal;
//     the live decideQuery repeats this gate as defence in depth)
//  3. no result child           ⇒ 404
//  4. 🔒 mayReadResult          ⇒ 404, NOT 403 — no existence oracle, and no authDebug bypass
//  5. status != DONE            ⇒ 409 approval.result_not_ready
//  6. payload purged/expired    ⇒ 410 approval.result_expired
//  7. decideResultView on WORKFLOW_VIEWER
//  8. Denied ⇒ audit `result-view-denied`, then 403 approval.result_view_denied
//  9. Allowed ⇒ classify, AUDIT, then respond
//
// 🔒 INV-A7-28 — STEP 9 AUDITS BEFORE THE ROWS ARE RETURNED, and a failed audit insert PROPAGATES as
// a 500 so PII is never returned without a durable record. A port that wrote the response first and
// audited after would break it silently, because the happy path looks identical.
//
// 🔒 INV-A7-29 — the view event is classified by the viewer's RELATIONSHIP, not requester-vs-everyone:
// `req.principal` ⇒ result-viewed-by-requester, `req.decidedBy` ⇒ result-viewed-by-approver, else ⇒
// result-viewed-by-assumer. A `system:auditor` (or any operator-defined `task.assume` principal) is
// neither party and must not be miscredited to the approver.
func (rt *Routes) resultView(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	id := httpapi.IDParam(r)
	if id == nil {
		rt.respondError(w, types.BadID())
		return
	}
	principal, ok := rt.principal(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	req, ok := rt.workflowRequest(w, r, *id) // STEP 1
	if !ok {
		return
	}
	// STEP 2.
	deactivated, err := rt.Decider.UserGroups.IsDeactivated(ctx, principal)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if deactivated {
		rt.respondError(w, types.NotFound(NotFoundApproval))
		return
	}
	// STEP 3 — 🔒 INV-A7-9: ONE read captures meta + the child's own SQL + the ciphertext, and the
	// decrypt is LAZY, so an unauthorized caller never triggers one and a concurrent re-execute
	// cannot swap the row between the check and the decrypt.
	if rt.results == nil {
		rt.respondError(w, types.NotFound(NotFoundApproval))
		return
	}
	access0, err := rt.results.AccessFor(ctx, *id)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if access0 == nil {
		rt.respondError(w, types.NotFound(NotFoundApproval))
		return
	}
	meta := access0.Meta
	// STEP 4.
	mayRead, err := rt.mayReadResult(r, principal, *req)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if !mayRead {
		rt.respondError(w, types.NotFound(NotFoundApproval))
		return
	}
	// STEP 5.
	if meta.Status == nil || *meta.Status != "DONE" {
		rt.respondCode(w, http.StatusConflict, "approval.result_not_ready", nil)
		return
	}
	// STEP 6.
	decrypted, err := access0.Decrypted()
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if decrypted == nil {
		rt.respondCode(w, http.StatusGone, "approval.result_expired", nil)
		return
	}

	// STEP 7.
	viewDecision, err := rt.viewDecisionFor(ctx, principal, *req, access0.SQL, *decrypted,
		rt.authzContext(r), query.ChannelWorkflowViewer,
		"approval request has no datasource", "approval request datasource no longer exists")
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}

	if viewDecision.IsDenied() { // STEP 8
		rt.log.Warn("query approval result view denied", "request", *id, "viewer", principal,
			"reason", *viewDecision.DeniedReason)
		if _, err := rt.audit.Insert(ctx, rt.e3Record(ctx, principal, *req, "result-view-denied", channelPtr(query.ChannelWorkflowViewer))); err != nil {
			httpapi.RespondFallback(w, r, rt.log, err)
			return
		}
		rt.respondCode(w, http.StatusForbidden, "approval.result_view_denied", nil)
		return
	}

	// STEP 9 — INV-A7-29 then INV-A7-28.
	viewEvent := "result-viewed-by-assumer"
	switch {
	case principal == req.Principal:
		viewEvent = "result-viewed-by-requester"
	case req.DecidedBy != nil && principal == *req.DecidedBy:
		viewEvent = "result-viewed-by-approver"
	}
	if _, err := rt.audit.Insert(ctx, rt.e3Record(ctx, principal, *req, viewEvent, channelPtr(query.ChannelWorkflowViewer))); err != nil {
		// 🔒 INV-A7-28 — propagate. The rows are NOT written.
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	rt.respond(w, r, http.StatusOK, QueryResultView{
		Meta:          meta,
		Columns:       viewDecision.Columns,
		Rows:          viewDecision.Rows,
		Decision:      viewDecisionLabel(viewDecision),
		MaskedColumns: viewDecision.MaskedColumns,
	})
}

// viewDecisionFor is the `when` that guards [Decider.DecideResultView] with the two pre-checks both
// result routes make — no datasource id, and a datasource row that has since been deleted. The two
// reason strings differ per route, which is why they are parameters.
func (rt *Routes) viewDecisionFor(
	ctx context.Context,
	viewer string,
	req access.AccessRequest,
	childSQL *string,
	decrypted result.DecryptedResult,
	callerContext authz.AuthzContext,
	channel query.Channel,
	noDatasourceReason, datasourceGoneReason string,
) (ResultViewDecision, error) {
	if req.DatasourceID == nil {
		return viewDenied(noDatasourceReason), nil
	}
	if childSQL == nil {
		return viewDenied(denyNoChildSQL), nil
	}
	ds, found, err := rt.Decider.Datasources.Get(ctx, *req.DatasourceID)
	if err != nil {
		return ResultViewDecision{}, err
	}
	if !found {
		return viewDenied(datasourceGoneReason), nil
	}
	return rt.Decider.DecideResultView(ctx, ResultViewInput{
		Viewer: viewer, Req: req, ChildSQL: childSQL, DS: ds, Decrypted: decrypted,
		CallerContext: callerContext, Channel: channel,
	})
}

// viewDecisionLabel is 🔒 INV-A6-27 / INV-A7-4: the response's `decision` is derived SERVER-SIDE from
// whether the view actually masked anything. Deriving it client-side from "are there rows" is what
// previously let a masked result display as a clean ALLOW.
func viewDecisionLabel(d ResultViewDecision) types.Decision {
	if len(d.MaskedColumns) == 0 {
		return types.DecisionAllow
	}
	return types.DecisionMask
}

// ---------------------------------------------------------------------------------------------
// Shared plumbing
// ---------------------------------------------------------------------------------------------

// workflowRequest loads a task and enforces 🔒 INV-A7-5 in ONE place: an absent row and a
// non-WORKFLOW row answer the SAME 404, so the seven id-addressed routes cannot drift on the guard
// and none of them is an existence oracle for an editor or wire task.
func (rt *Routes) workflowRequest(w http.ResponseWriter, r *http.Request, id int64) (*access.AccessRequest, bool) {
	req, err := rt.access.GetRequest(r.Context(), id)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return nil, false
	}
	if req == nil || !IsWorkflowApproval(*req) {
		rt.respondError(w, types.NotFound(NotFoundApproval))
		return nil, false
	}
	return req, true
}

// principal is `call.userSession()?.principal ?: "debug-user"`.
//
// The bool is false only when the session store itself failed, which requireApi's postcondition makes
// unreachable on a non-debug request; it answers the StatusPages fallback rather than acting as
// "debug-user" on a database error.
func (rt *Routes) principal(w http.ResponseWriter, r *http.Request) (string, bool) {
	sess, err := rt.gates.Sessions.UserSession(r)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return "", false
	}
	if sess == nil {
		return DebugPrincipal, true
	}
	return sess.Principal, true
}

// authzContext is `call.httpAuthzContext(config)`.
//
// 🔴 IT IS EMPTY UNTIL A12 LANDS. For this package that is a REAL divergence in three places — the
// compose preview (INV-A7-22), discovery's one-shot context (INV-A7-13) and every view re-decision —
// because all three are specified as carrying the server-attested `requester_ip`. Absence is
// FAIL-CLOSED (A2 INV-A2-8: a policy conditioning on an absent optional attribute does not fire), so
// nothing is widened; an ip-conditioned deployment simply sees narrower previews and views here than
// the Kotlin gives.
//
// It reads through httpapi.Gates.Context so the day A12 wires the real context in ONE place, the
// gates and these routes get it together.
//
//	TODO(A12): 12-request-context.md §2.
func (rt *Routes) authzContext(r *http.Request) authz.AuthzContext {
	return rt.gates.AuthzContext(r)
}

// requesterIP is `call.httpRequesterIp(config)`, read off the SAME seam as [Routes.authzContext] so
// the two can never disagree about one request. Nil until A12 lands.
func (rt *Routes) requesterIP(r *http.Request) *string {
	return rt.authzContext(r).RequesterIP
}

func (rt *Routes) respond(w http.ResponseWriter, r *http.Request, status int, body any) {
	if err := httpapi.RespondJSON(w, status, body); err != nil {
		rt.log.Error("failed to write response", "path", r.URL.Path, "status", status, "err", err)
	}
}

func (rt *Routes) respondError(w http.ResponseWriter, e types.ErrorResponse) {
	if err := httpapi.RespondAPIError(w, e); err != nil {
		rt.log.Error("failed to write error response", "code", e.Body.Code, "err", err)
	}
}

// respondCode is `call.respond(status, ApiError(code, params))` for the ~15 route-specific
// `approval.*` codes that have no shared helper in internal/types.
func (rt *Routes) respondCode(w http.ResponseWriter, status int, code string, params map[string]string) {
	rt.respondError(w, types.ErrorResponse{Status: status, Body: types.ApiError{Code: code, Params: params}})
}

// readBody reads the whole body under the same cap httpapi.Receive applies, for the one route that
// must decode through a defaults-applying helper rather than straight into a struct.
func readBody(r *http.Request) ([]byte, error) {
	var raw json.RawMessage
	if err := httpapi.Receive(r, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// trim is Kotlin's `String.trim()`, expressed over [engine.IsBlank] so the port keeps ONE definition
// of whitespace. strings.TrimSpace would silently disagree on U+001C..U+001F, which Kotlin trims and
// unicode.IsSpace does not.
func trim(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return engine.IsBlank(string(r)) })
}

// trimmedTitle is `input?.trim()?.takeIf { it.isNotEmpty() }` (Approvals.kt:376) — note it tests
// isNotEmpty on the ALREADY-TRIMMED value, so a whitespace-only title becomes nil rather than "".
func trimmedTitle(input *string) *string {
	if input == nil {
		return nil
	}
	t := trim(*input)
	if t == "" {
		return nil
	}
	return &t
}

func channelPtr(c query.Channel) *query.Channel { return &c }

func strptr(s string) *string { return &s }

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

// emptyIfNil keeps a list response `[]` rather than `null` (INV-A1-4). The stores already return an
// empty slice, so this is a belt-and-braces normalisation at the wire boundary.
func emptyIfNil(v []access.AccessRequest) []access.AccessRequest {
	if v == nil {
		return []access.AccessRequest{}
	}
	return v
}
