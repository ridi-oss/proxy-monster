package approval

import (
	"context"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/result"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// The store seams are declared HERE, structurally, rather than as concrete types, for the reason
// internal/query's doc.go states: every one of them is satisfied by the production type without that
// type knowing this package exists, and none of them drags an import that would cycle back through
// internal/dbtest into this package's own DB suites.
//
// They are also narrow on purpose. [AccessStore] exposes eleven of internal/access's thirty-odd
// methods and none of the ROLE-elevation path: an approval route that could reach `Approve` could
// mint a JIT grant, which is A6's surface and not this one.

// AccessStore is the slice of A6's task lifecycle store these routes use.
// *access.Store satisfies it.
type AccessStore interface {
	GetRequest(ctx context.Context, id int64) (*access.AccessRequest, error)
	// ListQueryRequests already filters `creator_kind = 'WORKFLOW'` (INV-A6-17), which is what keeps
	// editor tabs and wire authorizations off the human approval queue.
	ListQueryRequests(ctx context.Context, status, principal *string) ([]access.AccessRequest, error)
	PendingQueryRequestExists(ctx context.Context, sourceDecisionID int64) (bool, error)
	CreateQueryRequest(ctx context.Context, in access.CreateQueryRequestInput) (*access.AccessRequest, error)
	DecideQueryRequest(ctx context.Context, id int64, approved bool, rejectionReason *string, decidedBy string) (*access.AccessRequest, error)
	CreateEditorTask(ctx context.Context, principal string, datasourceID int64, sql string, executeAs []string, approver string) (*access.AccessRequest, error)
	EditorChildID(ctx context.Context, taskID int64) (*int64, error)
	DeleteEditorTask(ctx context.Context, taskID int64, principal string) (bool, error)
	// The three "On" forms take the caller's transaction so the parent's flip commits with the
	// child's (INV-A6-19, INV-A7-7). There is no non-transactional form here on purpose.
	ClaimExecutionOn(ctx context.Context, c store.Queryer, id int64) (bool, error)
	MarkExecutedOn(ctx context.Context, c store.Queryer, id int64) (bool, error)
	MarkFailedOn(ctx context.Context, c store.Queryer, id int64) (bool, error)
	MarkCancelledOn(ctx context.Context, c store.Queryer, id int64) (bool, error)
}

// Datasources is the slice of A5's DatasourceStore these routes use.
// *datasource.DatasourceStore satisfies it.
type Datasources interface {
	Get(ctx context.Context, id int64) (datasource.Datasource, bool, error)
	GetByName(ctx context.Context, name string) (datasource.Datasource, bool, error)
	List(ctx context.Context) ([]datasource.Datasource, error)
	Catalog(ctx context.Context, id int64) ([]datasource.CatalogColumn, error)
}

// AuditStore is the slice of A8's store these routes use. *audit.Store satisfies it.
//
// InsertOn is not optional plumbing: 🔒 INV-A7-28 and the execute path's single-commit rule both
// depend on the audit row joining the CALLER's transaction.
type AuditStore interface {
	Get(ctx context.Context, id int64) (*types.AuditEvent, error)
	Insert(ctx context.Context, rec types.AuditEvent) (int64, error)
	InsertOn(ctx context.Context, c store.Queryer, rec types.AuditEvent) (int64, error)
}

// ResultStore is the slice of A7's child state machine these routes use. *result.Store satisfies it.
//
// A NIL ResultStore is a legal, meaningful state: PM_RESULT_KEY unset ⇒ no crypto ⇒ no result
// storage, and approver-exec / editor submit are refused fail-closed with 503
// `approval.result_storage_not_configured` rather than persisting plaintext PII.
type ResultStore interface {
	Meta(ctx context.Context, taskID int64) (*result.QueryResultMeta, error)
	AccessFor(ctx context.Context, taskID int64) (*result.ResultAccess, error)
	ClaimAndStartRun(ctx context.Context, taskID int64, executedBy string, claimParent result.ClaimParent) (*result.QueryResultMeta, error)
	CompleteRun(ctx context.Context, taskID int64, res result.DecryptedResult, retentionSec int64, audit result.Hook) (*result.QueryResultMeta, error)
	FailRun(ctx context.Context, taskID int64, errorCode string, onFailed result.Hook) (*result.QueryResultMeta, error)
	CancelRun(ctx context.Context, taskID int64, onCancelled result.Hook) (*result.QueryResultMeta, error)
	DeleteResultsForTask(ctx context.Context, taskID int64) (int64, error)
}

// SelfApprover is A7's `autoApproveTask` as the editor submit consumes it.
// *core.ControlPlaneCore satisfies it — the function already lives there (core/decideconnection.go)
// because the WIRE path needs it too, and a second copy here would be a second self-approve gate.
//
// 🔒 INV-A7-17 — a self-approved task must clear BOTH `task.request` on the datasource AND
// `task.approve` against a self-requested Request. Either Deny fails the task closed.
type SelfApprover interface {
	AutoApproveTask(principal string, ownRoles []string, ds datasource.Datasource, raw authz.AuthzContext, channel query.Channel) bool
}

// SelfApproverFunc adapts a plain function to [SelfApprover].
type SelfApproverFunc func(principal string, ownRoles []string, ds datasource.Datasource, raw authz.AuthzContext, channel query.Channel) bool

// AutoApproveTask implements SelfApprover.
func (f SelfApproverFunc) AutoApproveTask(
	principal string, ownRoles []string, ds datasource.Datasource, raw authz.AuthzContext, channel query.Channel,
) bool {
	return f(principal, ownRoles, ds, raw, channel)
}

// DecideFn is the A6 pipeline. Production binds [query.DecideQuery]; a suite that must drive a branch
// the real analyzer cannot emit substitutes here rather than reaching for FactsOverride at every call
// site.
type DecideFn func(ctx context.Context, in query.DecideQueryInput) (query.DecisionContext, error)

// Decider is the bundle of seams every live re-decision needs — the Kotlin threads these as eight
// positional parameters through `decideResultView`, the compose preview and role discovery, and a Go
// port that did the same would put an eight-argument call in five places.
//
// It is a distinct type from [Routes] because the EDITOR routes and the APPROVAL routes share exactly
// this and nothing else.
type Decider struct {
	Datasources Datasources
	// Decide defaults to query.DecideQuery — see [Decider.decide].
	Decide DecideFn
	// MaskFns / UserGroups / Roles are internal/query's three store seams, verbatim.
	MaskFns    query.MaskFnLister
	UserGroups query.UserGroupStore
	Roles      query.RoleResolver
	// Authz is the SHARED Cedar graph (INV-A1-1).
	Authz *authz.Authz
	// SystemClassification keeps a view/preview classifying system tables the same way execution
	// does. Nil keeps system schemas deny-by-default (INV-A5-60).
	//
	// ⚠️ Pass a genuinely nil interface, never a typed nil pointer — internal/query calls it without
	// a nil-pointer guard.
	SystemClassification query.SystemClassifier
}

// decide runs the pipeline through the injected [Decider.Decide], defaulting to the production one.
func (d *Decider) decide(ctx context.Context, in query.DecideQueryInput) (query.DecisionContext, error) {
	if d.Decide != nil {
		return d.Decide(ctx, in)
	}
	return query.DecideQuery(ctx, in)
}
