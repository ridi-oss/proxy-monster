package grpcsvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	athenapb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ridi-oss/proxy-monster/cpgo/authz"
	"github.com/ridi-oss/proxy-monster/cpgo/engine"
	pb "github.com/ridi-oss/proxy-monster/cpgo/internal/pb"
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
	def           *engine.Definition
}

// caller is who a request authorizes as: the token's principal with the roles it resolves to now.
type caller struct {
	principal string
	roles     []string
	context   authz.Context
}

// admission is an engine's verdict on one request: a deny code, or an allow with the native instructions.
type admission struct {
	deny   string
	athena *athenapb.AthenaNativeInstructions
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
	def, ok := engine.ByWireName(row.Engine)
	if !ok {
		return nil, status.Error(codes.Internal, "unregistered engine")
	}
	ds := requestDatasource{name: row.Name, tags: row.Tags, def: def, catalog: def.CatalogName(row.DbName)}
	if row.CurrentCatalogName != nil {
		ds.catalog = *row.CurrentCatalogName
	}
	roles, err := s.authz.Roles(ctx, tok.Principal)
	if err != nil {
		return nil, err
	}
	c := caller{principal: tok.Principal, roles: roles, context: authz.Context{Channel: "wire", RequesterIP: requesterIP(r.GetClientAddr())}}
	a, err := s.authorizeBounded(ctx, r, ds, c)
	if err != nil {
		return nil, err
	}
	out := &pb.RequestAuthorizationResult{Allowed: a.deny == "", DenyReason: a.deny, EffectiveRoles: roles}
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

// authorizeBounded refuses a request naming another datasource or no operation before the engine runs, and an
// allow whose instructions do not match its kind: a native call needs them, a metadata read never has them.
func (s *service) authorizeBounded(ctx context.Context, r *pb.RequestAuthorization, ds requestDatasource, c caller) (admission, error) {
	if blank(r.GetDatasourceName()) || r.GetDatasourceName() != ds.name || r.GetOperation() == nil {
		return denied(r), nil
	}
	c.context = authz.Context{Channel: c.context.Channel, RequesterIP: c.context.RequesterIP, Masked: c.context.Masked}
	var (
		a   admission
		err error
	)
	switch ds.def.Requests {
	case engine.AthenaRequests:
		a, err = s.authorizeAthena(ctx, r, ds, c)
	default:
		a, err = s.authorizeMetadata(ctx, r, ds, c)
	}
	if err != nil || a.deny != "" {
		return a, err
	}
	if isNative(r) != (a.athena != nil) {
		return denied(r), nil
	}
	return a, nil
}

// authorizeMetadata admits a catalog or table-metadata read of this datasource's own catalog under datasource.connect.
func (s *service) authorizeMetadata(ctx context.Context, r *pb.RequestAuthorization, ds requestDatasource, c caller) (admission, error) {
	var catalog string
	switch {
	case r.GetReadCatalog() != nil:
		ns := r.GetReadCatalog().GetNamespace()
		if blank(ns.GetCatalog()) || blank(ns.GetSchema()) {
			return denied(r), nil
		}
		catalog = ns.GetCatalog()
	case r.GetReadTableMetadata() != nil:
		t := r.GetReadTableMetadata().GetTable()
		if blank(t.GetCatalog()) || blank(t.GetSchema()) || blank(t.GetTable()) {
			return denied(r), nil
		}
		catalog = t.GetCatalog()
	default:
		return denied(r), nil
	}
	if catalog != ds.catalog {
		return denied(r), nil
	}
	ok, err := s.mayConnect(ctx, ds, c)
	if err != nil || !ok {
		return denied(r), err
	}
	return admission{}, nil
}

// mayConnect is the datasource.connect gate the HTTP metadata routes use, with context tags derived first.
func (s *service) mayConnect(ctx context.Context, ds requestDatasource, c caller) (bool, error) {
	raw := c.context
	tags, err := s.authz.ContextTags(ctx, c.principal, c.roles, ds.name, ds.tags, raw)
	if err != nil {
		return false, err
	}
	raw.Tags = tags
	d, err := s.authz.DatasourceAction(ctx, c.principal, c.roles, "datasource.connect", ds.name, ds.tags, raw)
	return d.Allow, err
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
