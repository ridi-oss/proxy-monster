package authz

import (
	"cmp"
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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

// Decider decides Cedar authorization from the enabled policies in the store.
type Decider struct {
	pool   *pgxpool.Pool
	schema *Schema

	mu          sync.Mutex
	fingerprint string
	policies    *cedar.PolicySet
	vocabulary  []string
}

func NewDecider(pool *pgxpool.Pool, schema *Schema) *Decider {
	return &Decider{pool: pool, schema: schema}
}

// load returns the current policy set, reloading it when the enabled policies changed. The fingerprint
// query is how a change Kotlin makes (an MCP policy tool) reaches this decider without a signal.
func (d *Decider) load(ctx context.Context) (*cedar.PolicySet, []string, error) {
	q := db.New(d.pool)
	fp, err := q.PolicyFingerprint(ctx)
	if err != nil {
		return nil, nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.policies != nil && fp == d.fingerprint {
		return d.policies, d.vocabulary, nil
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
	d.policies, d.vocabulary, d.fingerprint = set, vocab, fp
	return set, vocab, nil
}

// Roles is RoleResolver.resolve: direct assignments, live JIT grants and group roles; none for a
// deactivated principal.
func (d *Decider) Roles(ctx context.Context, principal string) ([]string, error) {
	return Roles(ctx, d.pool, principal)
}

// Roles is Decider.Roles for a caller that holds only a connection.
func Roles(ctx context.Context, conn db.DBTX, principal string) ([]string, error) {
	q := db.New(conn)
	roles, err := q.PrincipalRoles(ctx, principal)
	if err != nil {
		return nil, err
	}
	deactivated, err := q.IsDeactivated(ctx, principal)
	if err != nil || deactivated {
		return nil, err
	}
	slices.Sort(roles)
	return roles, nil
}

// Parents is a principal's Cedar parents (its roles and the local groups it belongs to) and its stored
// user attributes.
type Parents struct {
	Roles, Groups []string
	Attributes    []byte
}

// Parents is RoleResolver.resolveParents: Roles' role set plus the active user's non-deleted groups and
// attributes.
func (d *Decider) Parents(ctx context.Context, principal string) (Parents, error) {
	roles, err := d.Roles(ctx, principal)
	if err != nil || roles == nil {
		return Parents{Roles: roles}, err
	}
	q := db.New(d.pool)
	groups, err := q.PrincipalGroups(ctx, principal)
	if err != nil {
		return Parents{}, err
	}
	attrs, err := q.PrincipalAttributes(ctx, principal)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	return Parents{Roles: roles, Groups: groups, Attributes: attrs}, err
}

func (d *Decider) deactivated(ctx context.Context, principal string) (bool, error) {
	return db.New(d.pool).IsDeactivated(ctx, principal)
}

func uid(typ, id string) types.EntityUID {
	return types.NewEntityUID(types.EntityType(typ), types.String(id))
}

// graph is the entity set one decision evaluates: the principal with its roles and groups as parents, those
// roles and groups, and whatever the resource resolves against.
type graph struct {
	principal types.EntityUID
	entities  types.EntityMap
	schema    *Schema
	// parentsOf resolves another user the resource names, seeded with the principal's own snapshot.
	parentsOf func(user string) (Parents, error)
}

func (d *Decider) newGraph(ctx context.Context, principal string, p Parents) (graph, error) {
	known := map[string]Parents{principal: p}
	g := graph{principal: uid("User", principal), entities: types.EntityMap{}, schema: d.schema, parentsOf: func(user string) (Parents, error) {
		if p, ok := known[user]; ok {
			return p, nil
		}
		p, err := d.Parents(ctx, user)
		known[user] = p
		return p, err
	}}
	_, err := g.user(principal, p)
	return g, err
}

// user adds a User entity whose parents are its roles and groups and whose attributes are its declared
// ones, and those role and group entities.
func (g graph) user(name string, p Parents) (types.EntityUID, error) {
	var parents []types.EntityUID
	for _, r := range p.Roles {
		parents = append(parents, uid("Role", r))
	}
	for _, gr := range p.Groups {
		parents = append(parents, uid("Group", gr))
	}
	attrs, err := g.schema.userRecord(p.Attributes)
	if err != nil {
		return types.EntityUID{}, err
	}
	u := uid("User", name)
	g.add(types.Entity{UID: u, Parents: types.NewEntityUIDSet(parents...), Attributes: attrs})
	for _, pu := range parents {
		g.add(types.Entity{UID: pu})
	}
	return u, nil
}

// namedUser adds a user the resource names, with its own roles and groups.
func (g graph) namedUser(name string) (types.EntityUID, error) {
	p, err := g.parentsOf(name)
	if err != nil {
		return types.EntityUID{}, err
	}
	return g.user(name, p)
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
		attrs := types.RecordMap{}
		for key, name := range map[string]*string{"requester": &r.Principal, "approver": r.Approver, "executedBy": r.ExecutedBy} {
			if name == nil {
				continue
			}
			u, err := g.namedUser(*name)
			if err != nil {
				return types.EntityUID{}, err
			}
			attrs[types.String(key)] = u
		}
		attrs["source"] = types.String(cmp.Or(r.Source, "console"))
		if len(r.CCs) > 0 {
			ccs := make([]types.Value, 0, len(r.CCs))
			// Kotlin passes CCs as bare ids: their roles, groups and attributes are not in the graph.
			for _, name := range r.CCs {
				ccs = append(ccs, uid("User", name))
			}
			attrs["ccs"] = types.NewSet(ccs...)
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
func (d *Decider) AuthorizeAs(ctx context.Context, principal string, p Parents, action string, r bridge.Resource, c Context) (Decision, error) {
	if r.Type == "NativeResource" && (r.DatasourceName == nil || *r.DatasourceName == "" || r.NativeKind == "" ||
		r.NativeID == "" || (r.Owner != nil && *r.Owner == "") || c.NativeOperation == "") {
		return Decision{Reason: "invalid native resource or operation"}, nil
	}
	policies, _, err := d.load(ctx)
	if err != nil {
		return Decision{}, err
	}
	g, err := d.newGraph(ctx, principal, p)
	if err != nil {
		return Decision{}, err
	}
	res, err := g.resource(r)
	if err != nil {
		return Decision{}, err
	}
	return decide(policies, g, action, res, c.record(true)), nil
}

// DatasourceAction is authorizeDatasourceActionId: an action on the name-keyed Datasource itself, with the
// action's group ancestry as entities so a category permit reaches it.
func (d *Decider) DatasourceAction(ctx context.Context, principal string, p Parents, action, datasource string, tags []string, c Context) (Decision, error) {
	policies, _, err := d.load(ctx)
	if err != nil {
		return Decision{}, err
	}
	g, err := d.newGraph(ctx, principal, p)
	if err != nil {
		return Decision{}, err
	}
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
func (d *Decider) ContextTags(ctx context.Context, principal string, p Parents, datasource string, tags []string, raw Context) ([]string, error) {
	policies, vocab, err := d.load(ctx)
	if err != nil || len(vocab) == 0 {
		return nil, err
	}
	g, err := d.newGraph(ctx, principal, p)
	if err != nil {
		return nil, err
	}
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
func (d *Decider) AuthorizeWithContext(ctx context.Context, principal, action string, r bridge.Resource, raw Context, datasource *string, tags []string) (Decision, error) {
	p, err := d.Parents(ctx, principal)
	if err != nil {
		return Decision{}, err
	}
	c := raw
	if datasource != nil {
		if c.Tags, err = d.ContextTags(ctx, principal, p, *datasource, tags, raw); err != nil {
			return Decision{}, err
		}
	}
	return d.AuthorizeAs(ctx, principal, p, action, r, c)
}

// formEncode is java.net.URLEncoder.encode, which Kotlin's native resource UIDs use: it keeps '*' and escapes '~',
// the reverse of url.QueryEscape.
func formEncode(s string) string {
	return strings.NewReplacer("%2A", "*", "~", "%7E").Replace(url.QueryEscape(s))
}
