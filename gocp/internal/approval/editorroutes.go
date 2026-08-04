package approval

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/engine"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/result"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// NotFoundEditorTask is the `resource` param on every editor-task 404. Like [NotFoundApproval] it is
// ONE string for five distinct failures — absent, wrong kind, wrong creator kind, not the owner, and
// a Cedar denial — so none of them is an existence oracle.
const NotFoundEditorTask = "editor task"

// NotFoundEditorSession is `notFound("editor session")` on the owner-scoped session lookup.
const NotFoundEditorSession = "editor session"

// EditorRoutes is `Route.editorSessionRoutes(...)` (Query.kt:904-1180) — seven routes, all
// `requireApi`, all falling back to "debug-user" when there is no session.
//
// A6 owns them; they live in this package because they are built out of A7's parts — the same
// [Decider], the same [RunExec], [DecideResultView] and [TaskCompletionHub]. See doc.go.
//
// # The gate layering on the read paths, stated precisely
//
//	route                            owner guard            Cedar gate            authDebug bypasses Cedar?
//	GET  /api/editor/tasks/{id}      kind+creator+owner→404  TASK_READ   → 404      yes
//	POST /api/editor/tasks/{id}/…    same             →404   TASK_CANCEL → 403      yes
//	GET  /api/editor/tasks/{id}/…    same             →404   TASK_ASSUME → 404      **NO**
//
// 🔒 INV-A6-25 — the RESULT route has no authDebug bypass. Metadata gates bypass; the ROW gate does
// not. Same rule as A7 INV-A7-18.
//
// 🔒 INV-A6-26 — the owner guard is NOT a substitute for Cedar and Cedar is NOT a substitute for the
// owner guard. A Cedar forbid (task.read denied from an untrusted zone) must still override the
// self-read permit — hence both. Conversely the result route's owner check is load-bearing because a
// `task.assume` grantee (system:auditor via V40) could otherwise read ANOTHER user's editor rows,
// which the frozen contract forbids.
type EditorRoutes struct {
	*Decider
	gates       *httpapi.Gates
	access      AccessStore
	results     ResultStore
	runExec     RunExec
	selfApprove SelfApprover
	hub         *TaskCompletionHub
	scope       func(func())
	exchangeMs  int64
	log         *slog.Logger
}

// NewEditorRoutes builds the group from the SAME [Deps] the approval group takes, so a wiring site
// cannot hand the two different Deciders or different result stores.
func NewEditorRoutes(d Deps) *EditorRoutes {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	scope := d.Scope
	if scope == nil {
		scope = func(f func()) { go f() }
	}
	return &EditorRoutes{
		Decider: d.Decider, gates: d.Gates, access: d.Access, results: d.Results, runExec: d.RunExec,
		selfApprove: d.SelfApprove, hub: d.Hub, scope: scope, exchangeMs: d.ExchangeTimeoutMs, log: log,
	}
}

var _ httpapi.RouteGroup = (*EditorRoutes)(nil)

// Register mounts the seven editor patterns.
func (rt *EditorRoutes) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/editor/sessions", rt.openSession)
	mux.HandleFunc("POST /api/editor/sessions/{sessionId}/query", rt.submit)
	mux.HandleFunc("DELETE /api/editor/sessions/{sessionId}", rt.closeSession)
	mux.HandleFunc("GET /api/editor/tasks/{taskId}", rt.taskStatus)
	mux.HandleFunc("POST /api/editor/tasks/{taskId}/cancel", rt.cancelTask)
	mux.HandleFunc("GET /api/editor/tasks/{taskId}/result", rt.taskResult)
	mux.HandleFunc("DELETE /api/editor/tasks/{taskId}", rt.deleteTask)
}

// ---------------------------------------------------------------------------------------------
// POST /api/editor/sessions — Query.kt:920-937
// ---------------------------------------------------------------------------------------------

// openSession dials ONE proxy stream = one backend connection for the tab.
func (rt *EditorRoutes) openSession(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	var input OpenEditorSessionInput
	if err := httpapi.Receive(r, &input); err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	ds, found, err := rt.Decider.Datasources.Get(r.Context(), input.DatasourceID)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if !found {
		rt.respondError(w, types.NotFound("datasource"))
		return
	}
	principal, ok := rt.principal(w, r)
	if !ok {
		return
	}
	sessionID, err := rt.runExec.OpenSession(r.Context(), principal, ds, rt.requesterIP(r))
	if err != nil {
		rt.respondRunExecError(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, EditorSessionOpened{SessionID: sessionID})
}

// respondRunExecError is the transport exception → status mapping shared by openSession and A6's
// `queryRoutes` (06-query-decision.md §6):
//
//	NoProxyAttached    ⇒ 503 query.no_proxy_attached
//	ProxyStreamWedged  ⇒ 503 query.proxy_stream_wedged   🔒 INV-A7-34 — distinct from the above
//	ProxyRunTimeout    ⇒ 504 query.proxy_timeout
//	ProxyRunError      ⇒ 502 query.failed{detail}
//
// ⚠️ `detail` is the exception's own English MESSAGE on the wire (`e.message ?: ""`), which sits
// uneasily with INV-A1-13. REPRODUCE — same disposition as F13's denyReason.
func (rt *EditorRoutes) respondRunExecError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNoProxyAttached):
		rt.respondCode(w, http.StatusServiceUnavailable, "query.no_proxy_attached", nil)
	case errors.Is(err, ErrProxyStreamWedged):
		rt.respondCode(w, http.StatusServiceUnavailable, "query.proxy_stream_wedged", nil)
	case errors.Is(err, ErrProxyRunTimeout):
		rt.respondCode(w, http.StatusGatewayTimeout, "query.proxy_timeout", nil)
	default:
		var pre *ProxyRunError
		if errors.As(err, &pre) {
			rt.respondCode(w, http.StatusBadGateway, "query.failed", map[string]string{"detail": pre.Message})
			return
		}
		// Not a RunExecException at all — a bug or a store failure. The Kotlin lets it reach
		// StatusPages, and so does this.
		httpapi.RespondFallback(w, r, rt.log, err)
	}
}

// ---------------------------------------------------------------------------------------------
// POST /api/editor/sessions/{sessionId}/query — Query.kt:941-1032
// ---------------------------------------------------------------------------------------------

// submit launches the run as an auto-approved EDITOR task and ACKs 202 — no rows inline.
//
// The order is the contract (06-query-decision.md §6):
//
//  1. blank sql        ⇒ 400 common.field_required{fields: "sql"}
//  2. own roles EMPTY  ⇒ 403 common.forbidden
//  3. session lookup   ⇒ 404 "editor session"   🔒 OWNER-SCOPED — a leaked session id cannot target
//     another principal's connection
//  4. datasource       ⇒ 404
//  5. no result store  ⇒ 503 approval.result_storage_not_configured
//  6. unless authDebug: autoApproveTask ⇒ 403   🔒 INV-A7-17 — BOTH task.request and task.approve
//  7. createEditorTask + editorChildId
//  8. claimAndStartRun ⇒ 409 approval.already_executed   🔒 INV-A6-23 — atomic across parent + child
//  9. launch, respond 202
//
// 🔒 INV-A6-22 — `executeAs` is the caller's OWN roles, freshly resolved AT THIS SUBMIT: never an
// elevation, never frozen across submits, so a revoked role fails closed on the next one.
func (rt *EditorRoutes) submit(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	sessionID := r.PathValue("sessionId")
	if sessionID == "" {
		rt.respondError(w, types.BadID())
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
	req, err := query.DecodeQueryRequest(body)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	ctx := r.Context()

	if engine.IsBlank(req.SQL) { // STEP 1
		rt.respondError(w, types.FieldRequired("sql"))
		return
	}
	ownRoles, err := rt.Decider.Roles.Resolve(ctx, principal) // STEP 2 — INV-A6-22
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if len(ownRoles) == 0 {
		rt.respondError(w, types.Forbidden(nil))
		return
	}
	dsName, owns := rt.runExec.SessionDatasourceName(sessionID, principal) // STEP 3
	if !owns {
		rt.respondError(w, types.NotFound(NotFoundEditorSession))
		return
	}
	ds, found, err := rt.Decider.Datasources.GetByName(ctx, dsName) // STEP 4
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if !found {
		rt.respondError(w, types.NotFound("datasource"))
		return
	}
	if rt.results == nil { // STEP 5
		rt.respondCode(w, http.StatusServiceUnavailable, "approval.result_storage_not_configured", nil)
		return
	}
	// STEP 6 — 🔒 INV-A7-17. Note the authDebug short-circuit is on the CALLER side, exactly as the
	// Kotlin writes it (`!config.authDebug && !autoApproveTask(...)`), so under authDebug Cedar is
	// never reached rather than being asked and ignored (INV-A2-16's distinction).
	if !rt.gates.Config.AuthDebug &&
		!rt.selfApprove.AutoApproveTask(principal, ownRoles, ds, rt.authzContext(r), query.ChannelEditor) {
		rt.respondError(w, types.Forbidden(nil))
		return
	}

	task, err := rt.access.CreateEditorTask(ctx, principal, ds.ID, req.SQL, ownRoles, principal) // STEP 7
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	childID := int64(-1) // `?: -1L`
	if id, err := rt.access.EditorChildID(ctx, task.ID); err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	} else if id != nil {
		childID = *id
	}
	// STEP 8 — INV-A6-23 / INV-A7-7.
	claimed, err := rt.results.ClaimAndStartRun(ctx, task.ID, principal, func(txCtx context.Context, c store.Queryer) (bool, error) {
		return rt.access.ClaimExecutionOn(txCtx, c, task.ID)
	})
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if claimed == nil {
		rt.respondCode(w, http.StatusConflict, "approval.already_executed", nil)
		return
	}

	// STEP 9.
	async := context.WithoutCancel(ctx)
	taskID := task.ID
	requesterIP := rt.requesterIP(r)
	maxRows := req.MaxRows
	sql := req.SQL
	rt.scope(func() { rt.runEditorTask(async, sessionID, principal, taskID, sql, maxRows, requesterIP) })
	rt.respond(w, r, http.StatusAccepted, EditorSubmitResponse{TaskID: taskID, ChildID: childID})
}

// runEditorTask is `appScope.launch { … }`'s body (Query.kt:1000-1030).
//
// 🔒 INV-A6-24 — NO task-level audit row is written on the success path. The run's per-statement
// Decide round-trip already wrote the real audit decision with its decisionId; adding one here would
// duplicate it as a FALSE ALLOW. That is the one structural difference from the approval execute
// path, whose e3Record is a lifecycle row, not a decision.
func (rt *EditorRoutes) runEditorTask(
	ctx context.Context, sessionID, principal string, taskID int64, sql string, maxRows int, requesterIP *string,
) {
	failureCode := rt.editorRun(ctx, sessionID, principal, taskID, sql, maxRows, requesterIP)
	if failureCode != nil {
		if _, err := rt.results.FailRun(ctx, taskID, *failureCode, func(hookCtx context.Context, c store.Queryer, _ result.QueryResultMeta) error {
			_, err := rt.access.MarkFailedOn(hookCtx, c, taskID)
			return err
		}); err != nil {
			rt.log.Error("editor task failure transition failed", "task", taskID, "err", err)
		}
	}
	if rt.hub != nil {
		if updated, err := rt.access.GetRequest(ctx, taskID); err == nil && updated != nil {
			rt.hub.Publish(principal, TaskEvent{TaskID: taskID, Status: updated.Status})
		}
	}
}

// editorRun is the try/catch half.
//
// ⚠️ Unlike the approval execute path, this one DOES have a ProxyStreamWedged arm
// (`query.proxy_stream_wedged`). The asymmetry is in the Kotlin and is reproduced on both sides.
func (rt *EditorRoutes) editorRun(
	ctx context.Context, sessionID, principal string, taskID int64, sql string, maxRows int, requesterIP *string,
) *string {
	response, err := rt.runExec.RunOnSession(ctx, SessionRunInput{
		SessionID:   sessionID,
		Principal:   principal,
		SQL:         sql,
		MaxRows:     maxRows,
		RequesterIP: requesterIP,
		TaskID:      &taskID,
		Preflight: func() bool {
			meta, err := rt.results.Meta(ctx, taskID)
			return err == nil && meta != nil && meta.Status != nil && *meta.Status == "RUNNING"
		},
		ExchangeTimeoutMs: rt.exchangeMs,
	})
	switch {
	case err == nil:
	case errors.Is(err, ErrRunCanceledBeforeStart):
		return nil
	case errors.Is(err, ErrNoProxyAttached):
		return strptr("query.no_proxy_attached")
	case errors.Is(err, ErrProxyStreamWedged):
		return strptr("query.proxy_stream_wedged")
	case errors.Is(err, ErrProxyRunTimeout):
		return strptr("query.proxy_timeout")
	default:
		var pre *ProxyRunError
		if errors.As(err, &pre) {
			return strptr("approval.query_failed")
		}
		rt.log.Error("editor task execution failed", "task", taskID, "err", err)
		return strptr("approval.query_failed")
	}

	if pb.EnfAction(response.Decision) == pb.EnfAction_DENY {
		// The already-translated approval.* codes are reused deliberately: the messages
		// ("denied at execution time") are channel-agnostic, so the web needs no editor-specific
		// catalog entries.
		return strptr("approval.execute_denied")
	}
	res := result.DecryptedResult{Columns: response.Columns, Rows: response.Rows}
	completed, err := rt.results.CompleteRun(ctx, taskID, res, result.RetentionSec,
		func(hookCtx context.Context, c store.Queryer, _ result.QueryResultMeta) error {
			won, err := rt.access.MarkExecutedOn(hookCtx, c, taskID)
			if err != nil {
				return err
			}
			if !won {
				return errors.New("editor task " + itoa(taskID) + " left EXECUTING before completion")
			}
			return nil // INV-A6-24 — no audit row here.
		})
	if err != nil {
		rt.log.Error("editor task execution failed", "task", taskID, "err", err)
		return strptr("approval.query_failed")
	}
	if completed == nil {
		return strptr("approval.query_failed")
	}
	return nil
}

// ---------------------------------------------------------------------------------------------
// GET /api/editor/tasks/{taskId} — Query.kt:1036-1069
// ---------------------------------------------------------------------------------------------

// taskStatus polls the parent status plus the child metadata. Rows stay behind /result.
func (rt *EditorRoutes) taskStatus(w http.ResponseWriter, r *http.Request) {
	task, principal, ok := rt.ownedEditorTask(w, r)
	if !ok {
		return
	}
	// 🔒 INV-A6-26 — the owner guard above is NOT a substitute for this. authDebug bypasses.
	allowed, err := rt.mayEditor(r, principal, authz.ActionTaskRead, *task)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if !allowed {
		rt.respondError(w, types.NotFound(NotFoundEditorTask))
		return
	}
	meta, err := rt.meta(r.Context(), task.ID)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	rt.respond(w, r, http.StatusOK, EditorTaskStatus{TaskID: task.ID, Status: task.Status, Result: meta})
}

// ---------------------------------------------------------------------------------------------
// POST /api/editor/tasks/{taskId}/cancel — Query.kt:1071-1110
// ---------------------------------------------------------------------------------------------

// cancelTask terminalizes an in-flight editor run.
//
// ⚠️ A non-EXECUTING task is answered 200 with its CURRENT status, not a 409 — the opposite of the
// approval cancel's `not_cancelable`. The editor tab closes and re-polls, so an idempotent read is
// the right answer there; reproduced as the asymmetry it is.
func (rt *EditorRoutes) cancelTask(w http.ResponseWriter, r *http.Request) {
	task, principal, ok := rt.ownedEditorTask(w, r)
	if !ok {
		return
	}
	allowed, err := rt.mayEditor(r, principal, authz.ActionTaskCancel, *task)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if !allowed {
		rt.respondCode(w, http.StatusForbidden, "approval.cancel_forbidden", nil)
		return
	}
	ctx := r.Context()
	if task.Status != "EXECUTING" {
		meta, err := rt.meta(ctx, task.ID)
		if err != nil {
			httpapi.RespondFallback(w, r, rt.log, err)
			return
		}
		rt.respond(w, r, http.StatusOK, EditorTaskStatus{TaskID: task.ID, Status: task.Status, Result: meta})
		return
	}
	if rt.results == nil {
		rt.respondCode(w, http.StatusServiceUnavailable, "approval.result_storage_not_configured", nil)
		return
	}
	cancelled, err := rt.results.CancelRun(ctx, task.ID, func(hookCtx context.Context, c store.Queryer, _ result.QueryResultMeta) error {
		won, err := rt.access.MarkCancelledOn(hookCtx, c, task.ID)
		if err != nil {
			return err
		}
		if !won {
			return errors.New("editor task " + itoa(task.ID) + " left EXECUTING before cancellation")
		}
		return nil
	})
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if cancelled != nil {
		rt.runExec.CancelActiveRun(ctx, task.ID)
		// INV-A7-25's editor twin: a cancel can win the CAS long before the run goroutine unwinds.
		if rt.hub != nil {
			rt.hub.Publish(principal, TaskEvent{TaskID: task.ID, Status: "CANCELLED"})
		}
	}
	updated, err := rt.access.GetRequest(ctx, task.ID)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if updated == nil {
		rt.respondError(w, types.NotFound(NotFoundEditorTask))
		return
	}
	meta, err := rt.results.Meta(ctx, task.ID)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	rt.respond(w, r, http.StatusOK, EditorTaskStatus{TaskID: updated.ID, Status: updated.Status, Result: meta})
}

// ---------------------------------------------------------------------------------------------
// GET /api/editor/tasks/{taskId}/result — Query.kt:1114-1173
// ---------------------------------------------------------------------------------------------

// taskResult releases the tab's decrypted rows.
//
// 🔒 INV-A6-25 — NO authDebug bypass on the `task.assume` gate below. Metadata gates bypass; the row
// gate does not.
//
// 🔒 INV-A6-26 — the owner guard is load-bearing in BOTH directions here: without the Cedar gate a
// forbid could not override the self-read permit, and without the owner guard a `task.assume`
// grantee (system:auditor via V40) could read another user's editor rows.
func (rt *EditorRoutes) taskResult(w http.ResponseWriter, r *http.Request) {
	task, principal, ok := rt.ownedEditorTask(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	// Deprovisioning gate before the result lookup; the live decide repeats it as defence in depth.
	deactivated, err := rt.Decider.UserGroups.IsDeactivated(ctx, principal)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if deactivated {
		rt.respondError(w, types.NotFound(NotFoundEditorTask))
		return
	}
	if rt.results == nil {
		rt.respondError(w, types.NotFound(NotFoundEditorTask))
		return
	}
	// 🔒 INV-A7-9 — one read, lazy decrypt. The AccessFor call precedes the assume gate exactly as
	// the Kotlin orders it, and that is safe BECAUSE the decrypt is lazy: nothing is decrypted until
	// after the gate passes.
	access0, err := rt.results.AccessFor(ctx, task.ID)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if access0 == nil {
		rt.respondError(w, types.NotFound(NotFoundEditorTask))
		return
	}
	tags, err := rt.editorDatasourceTags(ctx, task.DatasourceID)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	// 🔒 INV-A6-25 — no `if !authDebug` guard around this one, deliberately.
	if !rt.Decider.Authz.AuthorizeWithContext(
		principal, authz.ActionTaskAssume, requestResource(*task), rt.authzContext(r), task.DatasourceName, tags,
	).Allowed {
		rt.respondError(w, types.NotFound(NotFoundEditorTask))
		return
	}
	meta := access0.Meta
	if meta.Status == nil || *meta.Status != "DONE" {
		rt.respondCode(w, http.StatusConflict, "approval.result_not_ready", nil)
		return
	}
	decrypted, err := access0.Decrypted()
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if decrypted == nil {
		rt.respondCode(w, http.StatusGone, "approval.result_expired", nil)
		return
	}

	viewDecision, err := rt.viewDecisionFor(ctx, principal, *task, access0.SQL, *decrypted,
		rt.authzContext(r), query.ChannelEditor,
		"editor task has no datasource", "editor task datasource no longer exists")
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if viewDecision.IsDenied() {
		// ⚠️ NO AUDIT ROW on the editor view, denied or allowed — unlike the approval view's
		// INV-A7-28. An editor tab's rows are the caller's own output and the run already wrote its
		// real decision row (INV-A6-24). Reproduced as the asymmetry it is.
		rt.log.Warn("editor result view denied", "task", task.ID, "viewer", principal,
			"reason", *viewDecision.DeniedReason)
		rt.respondCode(w, http.StatusForbidden, "approval.result_view_denied", nil)
		return
	}
	rt.respond(w, r, http.StatusOK, QueryResultView{
		Meta:    meta,
		Columns: viewDecision.Columns,
		Rows:    viewDecision.Rows,
		// 🔒 INV-A6-27 — derived SERVER-SIDE from whether this view actually masked anything.
		Decision:      viewDecisionLabel(viewDecision),
		MaskedColumns: viewDecision.MaskedColumns,
	})
}

// ---------------------------------------------------------------------------------------------
// The two DELETEs — Query.kt:1177-1198
// ---------------------------------------------------------------------------------------------

// deleteTask is delete-on-close: drop the tab's saved rows and its task row (CASCADE).
//
// 🔒 Owner-scoped and EDITOR-only, and IDEMPOTENT 204 regardless — a non-owner or unknown id is a
// silent no-op, so the route is not an existence oracle for another principal's task.
func (rt *EditorRoutes) deleteTask(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	taskID := httpapi.NamedIDParam(r, "taskId")
	if taskID == nil {
		rt.respondError(w, types.BadID())
		return
	}
	principal, ok := rt.principal(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	task, err := rt.access.GetRequest(ctx, *taskID)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if isOwnedEditorTask(task, principal) {
		if task.Status == "EXECUTING" {
			rt.runExec.CancelActiveRun(ctx, *taskID)
		}
		if rt.results != nil {
			if _, err := rt.results.DeleteResultsForTask(ctx, *taskID); err != nil {
				httpapi.RespondFallback(w, r, rt.log, err)
				return
			}
		}
		if _, err := rt.access.DeleteEditorTask(ctx, *taskID, principal); err != nil {
			httpapi.RespondFallback(w, r, rt.log, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// closeSession tears down the held connection.
//
// 🔒 Owner-scoped through [RunExec.CloseSessionOwnedBy] — a principal who learns another user's
// sessionId cannot tear down that connection or revoke its token — and an idempotent 204 either way,
// so it reveals nothing about whether the id exists.
func (rt *EditorRoutes) closeSession(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	sessionID := r.PathValue("sessionId")
	if sessionID == "" {
		rt.respondError(w, types.BadID())
		return
	}
	principal, ok := rt.principal(w, r)
	if !ok {
		return
	}
	rt.runExec.CloseSessionOwnedBy(sessionID, principal)
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------------------------
// Shared plumbing
// ---------------------------------------------------------------------------------------------

// isOwnedEditorTask is the owner guard, in one place so the four id-addressed editor routes cannot
// drift: `kind == "QUERY" && creatorKind == "EDITOR" && principal == owner`.
func isOwnedEditorTask(task *access.AccessRequest, principal string) bool {
	return task != nil && task.Kind == "QUERY" &&
		task.CreatorKind != nil && *task.CreatorKind == "EDITOR" &&
		task.Principal == principal
}

// ownedEditorTask runs requireApi, the id parse, the principal fallback and the owner guard — the
// prelude the three non-DELETE id-addressed routes share, all answering the same opaque 404.
func (rt *EditorRoutes) ownedEditorTask(w http.ResponseWriter, r *http.Request) (*access.AccessRequest, string, bool) {
	if !rt.gates.RequireAPI(w, r) {
		return nil, "", false
	}
	taskID := httpapi.NamedIDParam(r, "taskId")
	if taskID == nil {
		rt.respondError(w, types.BadID())
		return nil, "", false
	}
	principal, ok := rt.principal(w, r)
	if !ok {
		return nil, "", false
	}
	task, err := rt.access.GetRequest(r.Context(), *taskID)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return nil, "", false
	}
	if !isOwnedEditorTask(task, principal) {
		rt.respondError(w, types.NotFound(NotFoundEditorTask))
		return nil, "", false
	}
	return task, principal, true
}

// mayEditor is the metadata Cedar gate for the poll and cancel routes. authDebug BYPASSES.
func (rt *EditorRoutes) mayEditor(r *http.Request, principal string, action authz.AuthzAction, task access.AccessRequest) (bool, error) {
	if rt.gates.Config.AuthDebug {
		return true, nil
	}
	tags, err := rt.editorDatasourceTags(r.Context(), task.DatasourceID)
	if err != nil {
		return false, err
	}
	return rt.Decider.Authz.AuthorizeWithContext(
		principal, action, requestResource(task), rt.authzContext(r), task.DatasourceName, tags,
	).Allowed, nil
}

func (rt *EditorRoutes) editorDatasourceTags(ctx context.Context, datasourceID *int64) ([]string, error) {
	if datasourceID == nil {
		return nil, nil
	}
	ds, found, err := rt.Decider.Datasources.Get(ctx, *datasourceID)
	if err != nil || !found {
		return nil, err
	}
	return ds.Tags, nil
}

// meta is `queryResultStore?.meta(taskId)` — nil store means nil metadata, not an error.
func (rt *EditorRoutes) meta(ctx context.Context, taskID int64) (*result.QueryResultMeta, error) {
	if rt.results == nil {
		return nil, nil
	}
	return rt.results.Meta(ctx, taskID)
}

// viewDecisionFor mirrors [Routes.viewDecisionFor]; the two are separate methods only because the
// receivers differ, and they must stay behaviourally identical.
func (rt *EditorRoutes) viewDecisionFor(
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

func (rt *EditorRoutes) principal(w http.ResponseWriter, r *http.Request) (string, bool) {
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

func (rt *EditorRoutes) authzContext(r *http.Request) authz.AuthzContext {
	return rt.gates.AuthzContext(r)
}

func (rt *EditorRoutes) requesterIP(r *http.Request) *string { return rt.authzContext(r).RequesterIP }

func (rt *EditorRoutes) respond(w http.ResponseWriter, r *http.Request, status int, body any) {
	if err := httpapi.RespondJSON(w, status, body); err != nil {
		rt.log.Error("failed to write response", "path", r.URL.Path, "status", status, "err", err)
	}
}

func (rt *EditorRoutes) respondError(w http.ResponseWriter, e types.ErrorResponse) {
	if err := httpapi.RespondAPIError(w, e); err != nil {
		rt.log.Error("failed to write error response", "code", e.Body.Code, "err", err)
	}
}

func (rt *EditorRoutes) respondCode(w http.ResponseWriter, status int, code string, params map[string]string) {
	rt.respondError(w, types.ErrorResponse{Status: status, Body: types.ApiError{Code: code, Params: params}})
}
