package grpcsvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/cpgo/authz"
	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
	pb "github.com/ridi-oss/proxy-monster/cpgo/grpcsvc/pb"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

const (
	nativeNotAuthorized      = "native.not_authorized"
	nativeInvalidDescriptor  = "native.invalid_descriptor"
	nativeScopeViolation     = "native.scope_violation"
	nativeContextUnavailable = "native.context_unavailable"
)

// requestDatasource is the datasource an AuthorizeRequest names.
type requestDatasource struct {
	name, catalog string
	tags          []string
	engine        *engines.Engine
}

// caller is who a request authorizes as: the token's principal with the roles it resolves to now.
type caller struct {
	principal string
	parents   authz.Parents
	context   authz.Context
}

// nativeResource is one resource a native call touches, e.g. kind workgroup, id primary; owner when the target
// reports one.
type nativeResource struct {
	kind, id string
	owner    *string
}

// access is what a request without SQL touches, as its engine reads it: a deny code, a metadata read (only the
// connect gate applies), or a native call whose resources each need native.invoke as operation.
type access struct {
	deny      string
	native    bool
	operation string
	resources []nativeResource
	athena    *analyzerpb.AthenaNativeInstructions
}

// readRequest is how an engine reads a request; it never asks Cedar.
type readRequest func(r *pb.RequestAuthorization, ds requestDatasource, principal string, now time.Time) access

var requestReaders = map[*engines.Engine]readRequest{
	engines.MySQL:    metadataAccess,
	engines.Postgres: metadataAccess,
	engines.Athena:   athenaAccess,
}

// admission is the verdict on one request: a deny code, or an allow with the native instructions.
type admission struct {
	deny   string
	athena *analyzerpb.AthenaNativeInstructions
}

// AuthorizeRequest decides an operation that runs no SQL, such as a forwarding proxy's metadata or Athena API
// call. Deny by default: the named datasource's engine admits it or the result carries a stable deny code.
func (s *service) AuthorizeRequest(ctx context.Context, r *pb.RequestAuthorization) (*pb.RequestAuthorizationResult, error) {
	q := db.New(s.pool)
	sum := sha256.Sum256([]byte(r.GetToken()))
	tok, err := q.RequestCaller(ctx, hex.EncodeToString(sum[:]))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, status.Error(codes.Unauthenticated, "invalid, expired, revoked, or deactivated credential")
	}
	if err != nil {
		return nil, err
	}
	if deactivated, err := q.IsDeactivated(ctx, tok.Principal); err != nil {
		return nil, err
	} else if deactivated {
		return nil, status.Error(codes.Unauthenticated, "invalid, expired, revoked, or deactivated credential")
	}
	if tok.Kind != "SESSION" && tok.Kind != "USER" {
		return nil, status.Error(codes.Unauthenticated, "request authorization requires a wire credential")
	}
	row, err := q.RequestDatasource(ctx, r.GetDatasourceName())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, status.Error(codes.NotFound, "unknown datasource")
	}
	if err != nil {
		return nil, err
	}
	engine, err := engines.Parse(row.Engine)
	if err != nil {
		return nil, status.Error(codes.Internal, "unregistered engine")
	}
	ds := requestDatasource{name: row.Name, tags: row.Tags, engine: engine, catalog: engine.CatalogName(row.DbName).String()}
	if row.CurrentCatalogName != nil {
		ds.catalog = *row.CurrentCatalogName
	}
	parents, err := s.authz.Parents(ctx, tok.Principal)
	if err != nil {
		return nil, err
	}
	c := caller{principal: tok.Principal, parents: parents, context: authz.Context{Channel: "wire", RequesterIP: requesterIP(r.GetClientAddr())}}
	a, err := s.authorizeRequest(ctx, r, ds, c, time.Now())
	if err != nil {
		return nil, err
	}
	out := &pb.RequestAuthorizationResult{Allowed: a.deny == "", DenyReason: a.deny, EffectiveRoles: parents.Roles}
	if a.deny == "" {
		out.Principal = tok.Principal
		if a.athena != nil {
			out.Instructions = &pb.RequestAuthorizationResult_Athena{Athena: a.athena}
		}
	}
	return out, nil
}

func isNative(r *pb.RequestAuthorization) bool {
	return r.GetReadCatalog() == nil && r.GetReadTableMetadata() == nil
}

func denied(r *pb.RequestAuthorization) admission {
	if isNative(r) {
		return admission{deny: nativeNotAuthorized}
	}
	return admission{deny: "datasource.not_connectable"}
}

// authorizeRequest reads what the request touches through its engine, then asks Cedar the connect gate and
// native.invoke on each resource. A request naming another datasource or no operation is refused first.
func (s *service) authorizeRequest(ctx context.Context, r *pb.RequestAuthorization, ds requestDatasource, c caller, now time.Time) (admission, error) {
	if blank(r.GetDatasourceName()) || r.GetDatasourceName() != ds.name || r.GetOperation() == nil {
		return denied(r), nil
	}
	read := requestReaders[ds.engine]
	if s.read != nil && testing.Testing() {
		read = s.read
	}
	a := read(r, ds, c.principal, now)
	if a.deny != "" {
		return admission{deny: a.deny}, nil
	}
	if a.native != isNative(r) {
		return denied(r), nil
	}
	c.context = authz.Context{Channel: c.context.Channel, RequesterIP: c.context.RequesterIP, Masked: c.context.Masked}
	if ok, err := s.mayConnect(ctx, ds, c); err != nil || !ok {
		return denied(r), err
	}
	if ok, err := s.mayInvoke(ctx, ds, c, a.operation, a.resources...); err != nil || !ok {
		return denied(r), err
	}
	return admission{athena: a.athena}, nil
}

// metadataAccess is a MySQL or PostgreSQL catalog or table-metadata read whose selector names the datasource's
// catalog; anything else is denied.
func metadataAccess(r *pb.RequestAuthorization, ds requestDatasource, _ string, _ time.Time) access {
	no := access{deny: denied(r).deny}
	var catalog string
	switch {
	case r.GetReadCatalog() != nil:
		ns := r.GetReadCatalog().GetNamespace()
		if blank(ns.GetCatalog()) || blank(ns.GetSchema()) {
			return no
		}
		catalog = ns.GetCatalog()
	case r.GetReadTableMetadata() != nil:
		t := r.GetReadTableMetadata().GetTable()
		if blank(t.GetCatalog()) || blank(t.GetSchema()) || blank(t.GetTable()) {
			return no
		}
		catalog = t.GetCatalog()
	default:
		return no
	}
	if catalog != ds.catalog {
		return no
	}
	return access{}
}

// mayConnect is the datasource.connect gate the HTTP metadata routes use, with context tags derived first.
func (s *service) mayConnect(ctx context.Context, ds requestDatasource, c caller) (bool, error) {
	raw := c.context
	tags, err := s.authz.ContextTags(ctx, c.principal, c.parents, ds.name, ds.tags, raw)
	if err != nil {
		return false, err
	}
	raw.Tags = tags
	d, err := s.authz.DatasourceAction(ctx, c.principal, c.parents, "datasource.connect", ds.name, ds.tags, raw)
	return d.Allow, err
}

// mayInvoke is native.invoke as operation on every resource; supplied tags, statement kind and operation are
// replaced, and the datasource's context tags are derived once for all of them.
func (s *service) mayInvoke(ctx context.Context, ds requestDatasource, c caller, operation string, resources ...nativeResource) (bool, error) {
	raw := authz.Context{Channel: c.context.Channel, RequesterIP: c.context.RequesterIP, Masked: c.context.Masked, NativeOperation: operation}
	tags, err := s.authz.ContextTags(ctx, c.principal, c.parents, ds.name, ds.tags, raw)
	if err != nil {
		return false, err
	}
	raw.Tags = tags
	for _, res := range resources {
		d, err := s.authz.AuthorizeAs(ctx, c.principal, c.parents, "native.invoke", bridge.Resource{
			Type: "NativeResource", DatasourceName: &ds.name, NativeKind: res.kind, NativeID: res.id, Owner: res.owner, DatasourceTags: ds.tags,
		}, raw)
		if err != nil || !d.Allow {
			return false, err
		}
	}
	return true, nil
}

// requesterIP is parseRequesterIp: the proxy's client address without its port, or "" when there is none.
func requesterIP(clientAddr string) string {
	a := strings.TrimPrefix(strings.TrimSpace(clientAddr), "/")
	switch {
	case a == "":
		return ""
	case strings.HasPrefix(a, "["):
		a, _, _ = strings.Cut(strings.TrimPrefix(a, "["), "]")
	case strings.Count(a, ":") == 1:
		a, _, _ = strings.Cut(a, ":")
	}
	return a
}
