// Package core is `ControlPlaneCore.kt` — THE shared enforcement dependency graph, constructed once
// and used by BOTH the HTTP surface and the gRPC surface.
//
// Area doc: plans/proxy-monster-go-port/01-bootstrap.md §2. It also hosts A5's `ConnectionDecide.kt`
// (decideconnection.go), because that function's first parameter IS the core and it reaches both
// internal/query and internal/datasource — putting it in internal/datasource would be an import
// cycle (internal/query already imports internal/datasource).
//
// # INV-A1-1 — sharing is MANDATORY, not an optimisation
//
// [authz.CedarEngine] caches its compiled PolicySet and rebuilds only when the policy store's
// StateVersion moves; that version is an in-memory counter bumped on the SAME instance that commits a
// policy mutation. Two graphs ⇒ two counters ⇒ a policy edited over HTTP never invalidates the
// gRPC-side engine, whose decisions go silently and PERMANENTLY stale. One graph → one cache → one
// counter. Never construct a second [ControlPlaneCore] in a process.
//
// # What is wired, and what is a stub with a name
//
// Wired against the database: AuditStore, DatasourceStore, PolicyStore, AccessStore, UserGroupStore,
// TokenStore, RoleResolver, CedarPolicyStore, CedarEngine, Authz, SystemClassification.
// In-memory and complete: ConnectionCatalog, RunRequesterIPs, ProxyEventsHub, RunChannels — whose
// producer side is internal/runexec's RunExecService.
// In-memory and REGISTRY-ONLY (its producer service is a later increment): TableDetailChannels — see
// registries.go.
//
//	TODO(A11): McpTokenStore, the 17th member, has no Go counterpart yet.
package core

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/audit"
	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
	"github.com/ridi-oss/proxy-monster/gocp/internal/policy"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/token"
)

// ControlPlaneCore is `class ControlPlaneCore(val dataSource: DataSource)`.
type ControlPlaneCore struct {
	// DB is the shared pool. Kotlin's `dataSource` — the handle `inTx` composes over.
	DB *store.Db

	AuditStore      *audit.Store
	DatasourceStore *datasource.DatasourceStore
	PolicyStore     *policy.PolicyStore
	AccessStore     *access.Store
	UserGroupStore  *identity.UserGroupStore
	TokenStore      *token.Store
	RoleResolver    *identity.RoleResolver

	// CedarPolicyStore and CedarEngine are the pair INV-A1-1 is about. The engine holds a reference
	// to the store's StateVersion; nothing else may hold a different store.
	CedarPolicyStore *policy.CedarPolicyStore
	CedarEngine      *authz.CedarEngine
	Authz            *authz.Authz

	// SystemClassification loads and validates the bundled manifests AT CONSTRUCTION.
	// 🔒 INV-A5-55 — a malformed manifest ABORTS STARTUP, like a failed migration. Booting past it
	// would leave system schemas unclassified, and A6's utility path hard-denies unclassified
	// utilities while its function path treats an unclassified function as SAFE — a silent loss of
	// the dangerous-function floor.
	SystemClassification *datasource.SystemClassificationService

	ProxyEventsHub    *ProxyEventsHub
	ConnectionCatalog *datasource.ConnectionCatalogRegistry

	// RunChannels and RunRequesterIPs live HERE rather than in the HTTP module specifically because
	// ControlPlaneGrpcService is constructed in main() BEFORE the HTTP module's RunExecService
	// exists (01-bootstrap.md §2).
	RunChannels         *RunChannelRegistry
	TableDetailChannels *TableDetailChannelRegistry
	RunRequesterIPs     *RequesterIPRegistry

	// MaskFns is A6's step-19 seam, bound to the production PolicyStore. It is a field rather than a
	// method so a test can substitute it without a second policy store.
	MaskFns query.MaskFnLister

	// Log is the core's logger. Handlers log through it so a test can capture boot/handler output.
	Log *slog.Logger
}

// Options are the construction knobs Kotlin expresses as default arguments.
type Options struct {
	// AllowSystemClassificationFallback is `SystemClassificationService(allowFallback = …)`.
	// 🔒 INV-A13-27 — it must default to FALSE: the operator opt-in is a WIDENING. With fallback off
	// an uncertified major resolves to no manifest and that datasource's system schemas stay closed.
	AllowSystemClassificationFallback bool
	// Log defaults to slog.Default().
	Log *slog.Logger
}

// New is `ControlPlaneCore(dataSource)`.
//
// Construction ORDER matters only where one member is another's argument, but the failure modes do:
// the system-classification load is the one step that can abort a boot, and it must stay an error
// return rather than a logged warning (INV-A5-55).
func New(db *store.Db, opts Options) (*ControlPlaneCore, error) {
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}

	auditStore := audit.New(db.Pool)
	datasourceStore := datasource.NewDatasourceStore(db)
	policyStore := policy.NewPolicyStore(db.Pool)
	accessStore := access.NewStore(db.Pool)
	userGroupStore := identity.NewUserGroupStore(db.Pool)
	tokenStore := token.NewStore(db.Pool)
	roleResolver := identity.NewRoleResolver(db.Pool, userGroupStore, grantRolesAdapter{accessStore})

	cedarPolicyStore := policy.NewCedarPolicyStore(db.Pool)
	cedarEngine, err := authz.NewCedarEngine(cedarPolicyStore)
	if err != nil {
		return nil, fmt.Errorf("cedar engine: %w", err)
	}

	// Authz NEVER resolves roles itself; it takes a RoleSource port. Kotlin binds
	// `roleResolver::resolve` directly, so a store failure THROWS out of the authorization call. Go's
	// RoleSource returns no error, so a failure is logged and reported as the EMPTY role set —
	// fail-closed (fewer roles ⇒ fewer grants ⇒ deny), never a silently retained previous set.
	roleSource := authz.RoleSourceFunc(func(principal string) []string {
		roles, err := roleResolver.Resolve(context.Background(), principal)
		if err != nil {
			log.Error("role resolution failed; deciding with no roles", "principal", principal, "err", err)
			return nil
		}
		return roles
	})
	az := authz.New(cedarEngine, cedarPolicyStore, roleSource)

	systemClassification, err := datasource.NewBundledSystemClassificationService(opts.AllowSystemClassificationFallback)
	if err != nil {
		// INV-A5-55: propagate. Main turns this into a failed boot.
		return nil, err
	}

	return &ControlPlaneCore{
		DB:                   db,
		AuditStore:           auditStore,
		DatasourceStore:      datasourceStore,
		PolicyStore:          policyStore,
		AccessStore:          accessStore,
		UserGroupStore:       userGroupStore,
		TokenStore:           tokenStore,
		RoleResolver:         roleResolver,
		CedarPolicyStore:     cedarPolicyStore,
		CedarEngine:          cedarEngine,
		Authz:                az,
		SystemClassification: systemClassification,
		ProxyEventsHub:       newProxyEventsHubWithLog(log),
		ConnectionCatalog:    datasource.NewConnectionCatalogRegistry(),
		RunChannels:          NewRunChannelRegistry(),
		TableDetailChannels:  NewTableDetailChannelRegistry(),
		RunRequesterIPs:      NewRequesterIPRegistry(),
		MaskFns:              maskFnLister(policyStore),
		Log:                  log,
	}, nil
}

// grantRolesAdapter is the one-line adapter identity.AccessGrants' TODO(A6) asks for: it keeps the
// `.map { roleName }` on the caller's side rather than growing a second method on AccessStore.
type grantRolesAdapter struct{ store *access.Store }

func (a grantRolesAdapter) ListGrantRoles(ctx context.Context, principal string, activeOnly bool) ([]string, error) {
	grants, err := a.store.ListGrants(ctx, &principal, activeOnly)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(grants))
	for _, g := range grants {
		out = append(out, g.RoleName)
	}
	return out, nil
}

// maskFnLister binds A6's step-19 seam to the production PolicyStore. The three-line conversion is
// what internal/query's doc.go describes: Go cannot convert []policy.MaskFn to []query.MaskFn
// implicitly, and naming policy.MaskFn inside internal/query would be an import cycle.
func maskFnLister(ps *policy.PolicyStore) query.MaskFnLister {
	return func(ctx context.Context) ([]query.MaskFn, error) {
		rows, err := ps.ListMaskFns(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]query.MaskFn, 0, len(rows))
		for _, r := range rows {
			out = append(out, query.MaskFn{Name: r.Name, Kind: r.Kind})
		}
		return out, nil
	}
}
