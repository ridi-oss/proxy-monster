package authz

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

// Engine decides Cedar authorization from the enabled policies in the store.
type Engine struct {
	pool *pgxpool.Pool

	mu          sync.Mutex
	fingerprint string
	policies    *cedar.PolicySet
	vocabulary  []string
}

func New(pool *pgxpool.Pool) *Engine { return &Engine{pool: pool} }

// load returns the current policy set, reloading it when the enabled policies changed. The fingerprint
// query is how a change Kotlin makes (an MCP policy tool) reaches this engine without a signal.
func (e *Engine) load(ctx context.Context) (*cedar.PolicySet, []string, error) {
	q := db.New(e.pool)
	fp, err := q.PolicyFingerprint(ctx)
	if err != nil {
		return nil, nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.policies != nil && fp == e.fingerprint {
		return e.policies, e.vocabulary, nil
	}
	rows, err := q.EnabledPolicies(ctx)
	if err != nil {
		return nil, nil, err
	}
	set := cedar.NewPolicySet()
	var vocab []string
	for _, row := range rows {
		id, src := row.ID, row.CedarSrc
		list, err := cedar.NewPolicyListFromBytes("policy-"+strconv.FormatInt(id, 10), []byte(src))
		if err != nil {
			return nil, nil, fmt.Errorf("authz: policy %d: %w", id, err)
		}
		for i, p := range list {
			pid := "policy-" + strconv.FormatInt(id, 10)
			if i > 0 {
				pid += "-" + strconv.Itoa(i)
			}
			set.Add(cedar.PolicyID(pid), p)
		}
		for _, t := range contextTagNames(src) {
			if !slices.Contains(vocab, t) {
				vocab = append(vocab, t)
			}
		}
	}
	slices.Sort(vocab)
	e.policies, e.vocabulary, e.fingerprint = set, vocab, fp
	return set, vocab, nil
}

// Roles is RoleResolver.resolve: direct assignments, live JIT grants and group roles; none for a
// deactivated principal.
func (e *Engine) Roles(ctx context.Context, principal string) ([]string, error) {
	roles, err := db.New(e.pool).PrincipalRoles(ctx, principal)
	if err != nil {
		return nil, err
	}
	deactivated, err := e.deactivated(ctx, principal)
	if err != nil || deactivated {
		return nil, err
	}
	slices.Sort(roles)
	return roles, nil
}

func (e *Engine) deactivated(ctx context.Context, principal string) (bool, error) {
	return db.New(e.pool).IsDeactivated(ctx, principal)
}

func uid(typ, id string) types.EntityUID {
	return types.NewEntityUID(types.EntityType(typ), types.String(id))
}

// graph is the entity set one decision evaluates: the principal with its roles as parents, the roles, and
// whatever the resource resolves against.
type graph struct {
	principal types.EntityUID
	entities  types.EntityMap
}

func newGraph(principal string, roles []string) graph {
	g := graph{principal: uid("User", principal), entities: types.EntityMap{}}
	var parents []types.EntityUID
	for _, r := range roles {
		ru := uid("Role", r)
		parents = append(parents, ru)
		g.add(types.Entity{UID: ru})
	}
	g.entities[g.principal] = types.Entity{UID: g.principal, Parents: types.NewEntityUIDSet(parents...)}
	return g
}

// add keeps the first entity for a UID, as Kotlin's dedupeByEuid does.
func (g graph) add(e types.Entity) {
	if _, ok := g.entities[e.UID]; !ok {
		g.entities[e.UID] = e
	}
}

// datasource adds the Datasource entity, its tags as Tag parents, and the tag entities.
func (g graph) datasource(name string, tags []string) types.EntityUID {
	ds := uid("Datasource", name)
	var parents []types.EntityUID
	for _, t := range tags {
		tu := uid("Tag", t)
		parents = append(parents, tu)
		g.add(types.Entity{UID: tu})
	}
	g.add(types.Entity{UID: ds, Parents: types.NewEntityUIDSet(parents...),
		Attributes: types.NewRecord(types.RecordMap{"name": types.String(name)})})
	return ds
}

// Context is the Kotlin AuthzContext.
type Context struct {
	RequesterIP     string
	Channel         string
	Tags            []string
	StmtKind        string
	Masked          *bool
	NativeOperation string
}

func (c Context) record(includeTags bool) types.Record {
	m := types.RecordMap{"network_zones": types.NewSet()}
	if includeTags {
		var tags []types.Value
		for _, t := range c.Tags {
			tags = append(tags, types.String(t))
		}
		m["tags"] = types.NewSet(tags...)
	}
	if c.Channel != "" {
		m["channel"] = types.String(c.Channel)
	}
	if c.StmtKind != "" {
		m["stmt_kind"] = types.String(c.StmtKind)
	}
	if c.Masked != nil {
		m["masked"] = types.Boolean(*c.Masked)
	}
	if c.NativeOperation != "" {
		m["native_operation"] = types.String(c.NativeOperation)
	}
	// An address Cedar cannot parse is dropped, so a policy conditioning on it denies rather than errors.
	if c.RequesterIP != "" {
		if ip, err := types.ParseIPAddr(c.RequesterIP); err == nil {
			m["requester_ip"] = ip
		}
	}
	return types.NewRecord(m)
}

// resource adds r's focal entity (and anything it resolves against) to g and returns its UID.
func (g graph) resource(r bridge.Resource) (types.EntityUID, error) {
	addScopedParents := func(datasource, role *string) []types.EntityUID {
		var parents []types.EntityUID
		if datasource != nil {
			ds := uid("Datasource", *datasource)
			parents = append(parents, ds)
			g.add(types.Entity{UID: ds})
		}
		if role != nil {
			ru := uid("Role", *role)
			parents = append(parents, ru)
			g.add(types.Entity{UID: ru})
		}
		return parents
	}
	var e types.Entity
	switch r.Type {
	case "System":
		e = types.Entity{UID: uid("System", "system")}
	case "AuditLog":
		e = types.Entity{UID: uid("AuditLog", "all")}
	case "AuditRecord":
		e = types.Entity{UID: uid("AuditRecord", r.Principal),
			Attributes: types.NewRecord(types.RecordMap{"principal": uid("User", r.Principal)})}
	case "ApprovalRequest":
		attrs := types.RecordMap{"requester": uid("User", r.Principal)}
		if r.Approver != nil {
			attrs["approver"] = uid("User", *r.Approver)
		}
		if r.ExecutedBy != nil {
			attrs["executedBy"] = uid("User", *r.ExecutedBy)
		}
		ds := "-"
		if r.DatasourceName != nil {
			ds = *r.DatasourceName
		}
		e = types.Entity{UID: uid("Request", r.Principal+"#"+ds), Attributes: types.NewRecord(attrs),
			Parents: types.NewEntityUIDSet(addScopedParents(r.DatasourceName, r.RoleName)...)}
	case "AccessGrant":
		e = types.Entity{UID: uid("AccessGrant", r.Principal+"#"+strconv.FormatInt(r.ID, 10)),
			Attributes: types.NewRecord(types.RecordMap{"owner": uid("User", r.Principal)}),
			Parents:    types.NewEntityUIDSet(addScopedParents(r.DatasourceName, r.RoleName)...)}
	case "Token":
		attrs := types.RecordMap{"owner": uid("User", r.Principal)}
		kind := "-"
		if r.Kind != "" {
			kind = r.Kind
			attrs["kind"] = types.String(r.Kind)
		}
		e = types.Entity{UID: uid("Token", r.Principal+"#"+kind), Attributes: types.NewRecord(attrs)}
	case "NativeResource":
		if r.DatasourceName == nil {
			return types.EntityUID{}, errors.New("authz: native resource without a datasource")
		}
		ds := g.datasource(*r.DatasourceName, r.DatasourceTags)
		attrs := types.RecordMap{"kind": types.String(r.NativeKind), "id": types.String(r.NativeID)}
		if r.Owner != nil {
			attrs["owner"] = uid("User", *r.Owner)
		}
		id := strings.Join([]string{formEncode(*r.DatasourceName), formEncode(r.NativeKind), formEncode(r.NativeID)}, "/")
		e = types.Entity{UID: uid("NativeResource", id), Attributes: types.NewRecord(attrs), Parents: types.NewEntityUIDSet(ds)}
	default:
		return types.EntityUID{}, fmt.Errorf("authz: unknown resource type %q", r.Type)
	}
	g.entities[e.UID] = e
	return e.UID, nil
}

// Decision is an allow, or a deny with Kotlin's reason text.
type Decision struct {
	Allow  bool
	Reason string
}

func decide(policies *cedar.PolicySet, g graph, action string, resource types.EntityUID, ctx types.Record) Decision {
	ok, diag := cedar.Authorize(policies, g.entities, cedar.Request{
		Principal: g.principal, Action: uid("Action", action), Resource: resource, Context: ctx,
	})
	// An erroring policy is skipped by Cedar, so an erroring forbid could let a permit through: any
	// evaluation error denies, as in Kotlin.
	if len(diag.Errors) > 0 {
		var msgs []string
		for _, e := range diag.Errors {
			msgs = append(msgs, e.String())
		}
		slices.Sort(msgs)
		return Decision{Reason: "policy evaluation error: " + strings.Join(msgs, "; ")}
	}
	if ok == cedar.Allow {
		return Decision{Allow: true}
	}
	if len(diag.Reasons) == 0 {
		return Decision{Reason: "no policy permits this action"}
	}
	var ids []string
	for _, r := range diag.Reasons {
		ids = append(ids, string(r.PolicyID))
	}
	slices.Sort(ids)
	return Decision{Reason: "denied by policy: " + strings.Join(ids, ", ")}
}

// AuthorizeAs is Kotlin's authorizeAs: one decision with an already-resolved role set.
func (e *Engine) AuthorizeAs(ctx context.Context, principal string, roles []string, action string, r bridge.Resource, c Context) (Decision, error) {
	if r.Type == "NativeResource" && (r.DatasourceName == nil || *r.DatasourceName == "" || r.NativeKind == "" ||
		r.NativeID == "" || (r.Owner != nil && *r.Owner == "") || c.NativeOperation == "") {
		return Decision{Reason: "invalid native resource or operation"}, nil
	}
	policies, _, err := e.load(ctx)
	if err != nil {
		return Decision{}, err
	}
	g := newGraph(principal, roles)
	res, err := g.resource(r)
	if err != nil {
		return Decision{}, err
	}
	return decide(policies, g, action, res, c.record(true)), nil
}

// DatasourceAction is authorizeDatasourceActionId: an action on the name-keyed Datasource itself, with the
// action's group ancestry as entities so a category permit reaches it.
func (e *Engine) DatasourceAction(ctx context.Context, principal string, roles []string, action, datasource string, tags []string, c Context) (Decision, error) {
	policies, _, err := e.load(ctx)
	if err != nil {
		return Decision{}, err
	}
	g := newGraph(principal, roles)
	ds := g.datasource(datasource, tags)
	for a, parents := range actionAncestry(action) {
		var ps []types.EntityUID
		for _, p := range parents {
			ps = append(ps, uid("Action", p))
		}
		g.add(types.Entity{UID: uid("Action", a), Parents: types.NewEntityUIDSet(ps...)})
	}
	return decide(policies, g, action, ds, c.record(true)), nil
}

// ContextTags is resolveContextTags: the tags whose rules permit this principal on the datasource, from the
// raw context alone.
func (e *Engine) ContextTags(ctx context.Context, principal string, roles []string, datasource string, tags []string, raw Context) ([]string, error) {
	policies, vocab, err := e.load(ctx)
	if err != nil || len(vocab) == 0 {
		return nil, err
	}
	g := newGraph(principal, roles)
	ds := g.datasource(datasource, tags)
	rec := raw.record(false)
	var out []string
	for _, t := range vocab {
		// Kotlin's tag pass reads Cedar's allow alone, evaluation errors included.
		ok, _ := cedar.Authorize(policies, g.entities, cedar.Request{
			Principal: g.principal, Action: uid("Action", "context.tag::"+t), Resource: ds, Context: rec,
		})
		if ok == cedar.Allow {
			out = append(out, t)
		}
	}
	return out, nil
}

// AuthorizeWithContext is authorizeWithContext: one role snapshot for both passes, context tags derived only
// when the decision has a datasource in scope.
func (e *Engine) AuthorizeWithContext(ctx context.Context, principal, action string, r bridge.Resource, raw Context, datasource *string, tags []string) (Decision, error) {
	roles, err := e.Roles(ctx, principal)
	if err != nil {
		return Decision{}, err
	}
	c := raw
	if datasource != nil {
		if c.Tags, err = e.ContextTags(ctx, principal, roles, *datasource, tags, raw); err != nil {
			return Decision{}, err
		}
	}
	return e.AuthorizeAs(ctx, principal, roles, action, r, c)
}

// formEncode is java.net.URLEncoder.encode, which Kotlin's native resource UIDs use: it keeps '*' and escapes '~',
// the reverse of url.QueryEscape.
func formEncode(s string) string {
	return strings.NewReplacer("%2A", "*", "~", "%7E").Replace(url.QueryEscape(s))
}
