package grpcsvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	apb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/ridi-oss/proxy-monster/cpgo/authz"
	"github.com/ridi-oss/proxy-monster/cpgo/engine"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/cpgo/internal/pb"
)

const (
	connectAll        = `permit(principal, action == Action::"datasource.connect", resource);`
	invokeAll         = `permit(principal, action == Action::"native.invoke", resource);`
	notConnectable    = "datasource.not_connectable"
	badCredential     = "invalid, expired, revoked, or deactivated credential"
	wireOnly          = "request authorization requires a wire credential"
	trustedNetworkTag = `permit(principal, action == Action::"context.tag::trusted-network", resource)
		when { context has requester_ip && context.requester_ip.isInRange(ip("10.0.0.0/8")) };`
)

type fixture struct {
	t  *testing.T
	st dbtest.Store
	c  pb.ControlPlaneClient
	s  *service
	n  int
}

// newFixture disables the shipped policies so each case decides under exactly the policies it sets.
func newFixture(t *testing.T) *fixture {
	st, c := setup(t, "")
	f := &fixture{t: t, st: st, c: c, s: &service{pool: st.Pool, authz: authz.New(st.Pool)}}
	f.policies()
	return f
}

func (f *fixture) next() int { f.n++; return f.n }

func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.st.Pool.Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) policies(srcs ...string) {
	f.t.Helper()
	f.exec(`UPDATE policy SET enabled = false WHERE enabled`)
	for _, src := range srcs {
		f.exec(`INSERT INTO policy (name, cedar_src, enabled, origin) VALUES ($1, $2, true, 'USER')`, fmt.Sprintf("test-%d", f.next()), src)
	}
}

func (f *fixture) datasource(name, eng, dbName string, tags ...string) {
	f.t.Helper()
	if tags == nil {
		tags = []string{}
	}
	j, _ := json.Marshal(tags)
	f.exec(`INSERT INTO datasource (name, engine, host, port, db_name, tags) VALUES ($1, $2, 'h', 1, $3, $4::jsonb)`, name, eng, dbName, string(j))
}

func (f *fixture) grant(principal, role string) {
	f.t.Helper()
	f.exec(`INSERT INTO app_role (name) SELECT $1::text WHERE NOT EXISTS (SELECT 1 FROM app_role WHERE name = $1 AND deleted_at IS NULL)`, role)
	f.exec(`INSERT INTO principal_role (principal, role_id) SELECT $1, id FROM app_role WHERE name = $2 AND deleted_at IS NULL`, principal, role)
}

func (f *fixture) deleteRole(role string) {
	f.t.Helper()
	f.exec(`UPDATE app_role SET deleted_at = now() WHERE name = $1 AND deleted_at IS NULL`, role)
}

func tokenHash(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// token mints a live proxy_token whose roles column is the issuance snapshot.
func (f *fixture) token(kind, principal string, roles ...string) string {
	f.t.Helper()
	if roles == nil {
		roles = []string{}
	}
	j, _ := json.Marshal(roles)
	tok := fmt.Sprintf("tok-%d-%s", f.next(), kind)
	f.exec(`INSERT INTO proxy_token (token_hash, kind, principal, roles, expires_at) VALUES ($1, $2, $3, $4::jsonb, now() + interval '1 hour')`,
		tokenHash(tok), kind, principal, string(j))
	return tok
}

func (f *fixture) authorize(r *pb.RequestAuthorization) (*pb.RequestAuthorizationResult, error) {
	return f.c.AuthorizeRequest(context.Background(), r)
}

// want asserts an allow (deny == "") or a deny with that code.
func (f *fixture) want(name string, r *pb.RequestAuthorization, deny string) *pb.RequestAuthorizationResult {
	f.t.Helper()
	res, err := f.authorize(r)
	if err != nil {
		f.t.Fatalf("%s: %v", name, err)
	}
	if res.GetAllowed() != (deny == "") || res.GetDenyReason() != deny {
		f.t.Errorf("%s: allowed=%v deny=%q, want deny=%q", name, res.GetAllowed(), res.GetDenyReason(), deny)
	}
	return res
}

func wantStatus(t *testing.T, name string, err error, code codes.Code, msg string) {
	t.Helper()
	if s := status.Convert(err); err == nil || s.Code() != code || s.Message() != msg {
		t.Errorf("%s: %v, want %v %q", name, err, code, msg)
	}
}

func ref(catalog, schema, table string) *apb.ObjectRef {
	return &apb.ObjectRef{Catalog: catalog, Schema: schema, Table: table}
}

func catalogOp(ns *apb.ObjectRef) *pb.RequestAuthorization {
	return &pb.RequestAuthorization{Operation: &pb.RequestAuthorization_ReadCatalog{ReadCatalog: &pb.ReadCatalog{Namespace: ns}}}
}

func tableOp(t *apb.ObjectRef) *pb.RequestAuthorization {
	return &pb.RequestAuthorization{Operation: &pb.RequestAuthorization_ReadTableMetadata{ReadTableMetadata: &pb.ReadTableMetadata{Table: t}}}
}

func athenaOp(d *apb.AthenaNativeDescriptor) *pb.RequestAuthorization {
	return &pb.RequestAuthorization{Operation: &pb.RequestAuthorization_Athena{Athena: d}}
}

func on(r *pb.RequestAuthorization, token, ds, addr string) *pb.RequestAuthorization {
	c := proto.Clone(r).(*pb.RequestAuthorization)
	c.Token, c.DatasourceName, c.ClientAddr = token, ds, addr
	return c
}

func withUnknownField(r *pb.RequestAuthorization) *pb.RequestAuthorization {
	b := protowire.AppendTag(nil, 99, protowire.BytesType)
	r.ProtoReflect().SetUnknown(protowire.AppendBytes(b, nil))
	return r
}

func reqDS(name, wire, dbName string, tags ...string) requestDatasource {
	def, _ := engine.ByWireName(wire)
	return requestDatasource{name: name, catalog: def.CatalogName(dbName), tags: tags, def: def}
}

func (f *fixture) bounded(r *pb.RequestAuthorization, ds requestDatasource, roles []string, c authz.Context) admission {
	f.t.Helper()
	r = proto.Clone(r).(*pb.RequestAuthorization)
	if r.DatasourceName == "" {
		r.DatasourceName = ds.name
	}
	a, err := f.s.authorizeBounded(context.Background(), r, ds, caller{principal: "alice", roles: roles, context: c})
	if err != nil {
		f.t.Fatal(err)
	}
	return a
}

// MySQL and PostgreSQL metadata use the same datasource connect gate as HTTP.
func TestMetadataUsesConnectGate(t *testing.T) {
	f := newFixture(t)
	f.datasource("reports", "mysql", "app", "production")
	f.datasource("reports-pg", "postgres", "app", "production")
	f.grant("alice", "reader")
	alice := f.token("USER", "alice")
	for _, ds := range []struct{ name, catalog string }{{"reports", "def"}, {"reports-pg", "app"}} {
		for _, r := range []*pb.RequestAuthorization{catalogOp(ref(ds.catalog, "app", "")), tableOp(ref(ds.catalog, "app", "users"))} {
			f.policies(connectAll)
			if res := f.want(ds.name+" permitted", on(r, alice, ds.name, ""), ""); res.GetPrincipal() != "alice" || res.GetInstructions() != nil {
				t.Errorf("%s: principal %q instructions %v", ds.name, res.GetPrincipal(), res.GetInstructions())
			}
			f.policies()
			f.want(ds.name+" no permit", on(r, alice, ds.name, ""), notConnectable)
		}
	}
}

// Metadata gate preserves datasource name, tags, role and requester IP restrictions.
func TestMetadataGateRestrictions(t *testing.T) {
	f := newFixture(t)
	f.datasource("reports", "mysql", "app", "production")
	f.grant("alice", "reader")
	alice, carol := f.token("USER", "alice"), f.token("USER", "carol")
	f.policies(`permit(principal in Role::"reader", action == Action::"datasource.connect", resource in Tag::"production")
		when { resource has name && resource.name == "reports" && context has requester_ip && context.requester_ip.isInRange(ip("10.0.0.0/8")) };`)
	r := catalogOp(ref("def", "app", ""))
	for _, tc := range []struct {
		name, token, addr string
		untagged          bool
		deny              string
	}{
		{"reader in range", alice, "10.2.3.4:49152", false, ""},
		{"no roles", carol, "10.2.3.4:49152", false, notConnectable},
		{"untagged datasource", alice, "10.2.3.4:49152", true, notConnectable},
		{"out of range", alice, "198.51.100.7:49152", false, notConnectable},
		{"no address", alice, "", false, notConnectable},
	} {
		tags := `["production"]`
		if tc.untagged {
			tags = `[]`
		}
		f.exec(`UPDATE datasource SET tags = $1::jsonb WHERE name = 'reports'`, tags)
		f.want(tc.name, on(r, tc.token, "reports", tc.addr), tc.deny)
	}
}

// HTTP metadata retains absent channel while wire requests carry their channel.
func TestMetadataChannel(t *testing.T) {
	f := newFixture(t)
	f.datasource("reports", "mysql", "app", "production")
	f.grant("alice", "reader")
	f.policies(`permit(principal, action == Action::"datasource.connect", resource) when { context has channel && context.channel == "wire" };`)
	f.want("wire", on(catalogOp(ref("def", "app", "")), f.token("USER", "alice"), "reports", ""), "")
	ds := reqDS("reports", "mysql", "app", "production")
	for _, tc := range []struct {
		name string
		ctx  authz.Context
		want bool
	}{
		{"absent channel", authz.Context{}, false},
		{"editor channel", authz.Context{Channel: "editor"}, false},
		{"wire channel", authz.Context{Channel: "wire"}, true},
	} {
		ok, err := f.s.mayConnect(context.Background(), ds, caller{principal: "alice", roles: []string{"reader"}, context: tc.ctx})
		if err != nil || ok != tc.want {
			t.Errorf("%s: %v %v, want %v", tc.name, ok, err, tc.want)
		}
	}
}

// Metadata derives context tags and ignores supplied tags and statement kind.
func TestMetadataDerivesContextTags(t *testing.T) {
	f := newFixture(t)
	f.datasource("reports", "mysql", "app", "production")
	f.grant("alice", "reader")
	f.policies(trustedNetworkTag, `permit(principal, action == Action::"datasource.connect", resource)
		when { context has tags && context.tags.contains("trusted-network") && !(context has stmt_kind) };`)
	alice := f.token("USER", "alice")
	r := catalogOp(ref("def", "app", ""))
	f.want("trusted address", on(r, alice, "reports", "10.2.3.4:49152"), "")
	f.want("untrusted address", on(r, alice, "reports", "198.51.100.7:49152"), notConnectable)
	ds := reqDS("reports", "mysql", "app", "production")
	for _, tc := range []struct {
		name string
		ctx  authz.Context
		deny string
	}{
		{"statement kind is scrubbed", authz.Context{Channel: "wire", RequesterIP: "10.2.3.4", StmtKind: "select"}, ""},
		{"supplied tags are ignored", authz.Context{Channel: "wire", Tags: []string{"trusted-network"}}, notConnectable},
	} {
		if a := f.bounded(r, ds, []string{"reader"}, tc.ctx); a.deny != tc.deny {
			t.Errorf("%s: deny %q, want %q", tc.name, a.deny, tc.deny)
		}
	}
}

// Unknown and missing operations deny even with a broad connect permit.
func TestUnknownAndMissingOperationsDeny(t *testing.T) {
	f := newFixture(t)
	f.datasource("reports", "mysql", "app", "production")
	f.grant("alice", "reader")
	f.policies(connectAll)
	alice := f.token("USER", "alice")
	f.want("missing operation", &pb.RequestAuthorization{Token: alice, DatasourceName: "reports"}, nativeNotAuthorized)
	f.want("unknown operation", withUnknownField(&pb.RequestAuthorization{Token: alice, DatasourceName: "reports"}), nativeNotAuthorized)
}

// Catalog and table selectors must be present, nonblank, and bound to the datasource.
func TestMetadataSelectors(t *testing.T) {
	f := newFixture(t)
	f.datasource("reports", "mysql", "app", "production")
	f.grant("alice", "reader")
	f.policies(connectAll)
	alice := f.token("USER", "alice")
	for _, tc := range []struct {
		name string
		r    *pb.RequestAuthorization
		deny string
	}{
		{"no catalog operation", &pb.RequestAuthorization{}, nativeNotAuthorized},
		{"empty namespace", catalogOp(nil), notConnectable},
		{"namespace without schema", catalogOp(ref("def", "", "")), notConnectable},
		{"namespace without catalog", catalogOp(ref("", "app", "")), notConnectable},
		{"blank schema", catalogOp(ref("def", " ", "")), notConnectable},
		{"another catalog", catalogOp(ref("other", "app", "")), notConnectable},
		{"empty table ref", tableOp(nil), notConnectable},
		{"table without name", tableOp(ref("def", "app", "")), notConnectable},
		{"table without schema", tableOp(ref("def", "", "users")), notConnectable},
		{"table without catalog", tableOp(ref("", "app", "users")), notConnectable},
		{"blank table", tableOp(ref("def", "app", " ")), notConnectable},
		{"table in another catalog", tableOp(ref("other", "app", "users")), notConnectable},
	} {
		f.want(tc.name, on(tc.r, alice, "reports", ""), tc.deny)
	}
	ds := reqDS("reports", "mysql", "app", "production")
	for _, tc := range []struct {
		name string
		r    *pb.RequestAuthorization
	}{
		{"another datasource", on(catalogOp(ref("def", "app", "")), "", "other", "")},
		{"blank datasource", on(tableOp(ref("def", "app", "users")), "", " ", "")},
	} {
		if a := f.bounded(tc.r, ds, []string{"reader"}, authz.Context{Channel: "wire"}); a.deny != notConnectable {
			t.Errorf("%s: deny %q", tc.name, a.deny)
		}
	}
	if a, _ := f.s.authorizeBounded(context.Background(), tableOp(ref("def", "app", "users")), ds, caller{principal: "alice", roles: []string{"reader"}}); a.deny != notConnectable {
		t.Errorf("empty datasource name: deny %q", a.deny)
	}
	if _, err := f.authorize(on(catalogOp(ref("def", "app", "")), alice, "other", "")); status.Code(err) != codes.NotFound {
		t.Errorf("another datasource over RPC: %v", err)
	}
}

// PostgreSQL selectors cannot cross databases.
func TestPostgresSelectorsStayInDatabase(t *testing.T) {
	f := newFixture(t)
	f.datasource("reports", "postgres", "app", "production")
	f.grant("alice", "reader")
	f.policies(connectAll)
	alice := f.token("USER", "alice")
	f.want("own database", on(catalogOp(ref("app", "public", "")), alice, "reports", ""), "")
	f.want("catalog in another database", on(catalogOp(ref("other", "public", "")), alice, "reports", ""), notConnectable)
	f.want("table in another database", on(tableOp(ref("other", "public", "users")), alice, "reports", ""), notConnectable)
}

// MySQL and PostgreSQL reject native envelopes even with broad metadata access.
func TestRelationalEnginesRejectNativeEnvelopes(t *testing.T) {
	f := newFixture(t)
	f.datasource("reports", "mysql", "app", "production")
	f.datasource("reports-pg", "postgres", "app", "production")
	f.grant("alice", "reader")
	f.policies(connectAll, invokeAll)
	alice := f.token("USER", "alice")
	for _, ds := range []string{"reports", "reports-pg"} {
		f.want(ds, on(athenaOp(descriptor("ListWorkGroups", "{}", requestPhase)), alice, ds, ""), nativeNotAuthorized)
	}
}

// Common native dispatch refuses a request naming another datasource or no operation, and scrubs the context.
func TestNativeDispatchBounds(t *testing.T) {
	f := newFixture(t)
	f.datasource("lake", "athena", "analytics", "production")
	f.grant("alice", "reader")
	f.policies(
		`permit(principal, action == Action::"datasource.connect", resource)
			when { context has channel && context.channel == "workflow-executor" && context has requester_ip && context.requester_ip == ip("10.2.3.4")
				&& !context.tags.contains("forged") && !(context has stmt_kind) && !(context has native_operation) };`,
		`permit(principal in Role::"reader", action == Action::"native.invoke", resource)
			when { context has channel && context.channel == "workflow-executor" && context has requester_ip && context.requester_ip == ip("10.2.3.4")
				&& !context.tags.contains("forged") && !(context has stmt_kind) && context has native_operation && context.native_operation == "athena:ListWorkGroups" };`,
	)
	ds := reqDS("lake", "athena", "analytics", "production")
	forged := authz.Context{Channel: "workflow-executor", RequesterIP: "10.2.3.4", Tags: []string{"forged"}, StmtKind: "select", NativeOperation: "forged"}
	r := athenaOp(descriptor("ListWorkGroups", "{}", requestPhase))
	for _, tc := range []struct {
		name string
		r    *pb.RequestAuthorization
		deny string
	}{
		{"forged context is scrubbed", r, ""},
		{"no operation", &pb.RequestAuthorization{}, nativeNotAuthorized},
		{"another datasource", on(r, "", "other", ""), nativeNotAuthorized},
	} {
		if a := f.bounded(tc.r, ds, []string{"reader"}, forged); a.deny != tc.deny {
			t.Errorf("%s: deny %q, want %q", tc.name, a.deny, tc.deny)
		}
	}
	f.policies(connectAll, invokeAll)
	f.want("no operation over RPC", &pb.RequestAuthorization{Token: f.token("USER", "alice"), DatasourceName: "lake"}, nativeNotAuthorized)
}

// Native admission carries instructions, metadata admission never does, and an engine's deny code passes through.
func TestAdmissionInstructions(t *testing.T) {
	f := newFixture(t)
	f.datasource("lake", "athena", "analytics", "production")
	f.datasource("reports", "mysql", "app", "production")
	f.grant("alice", "reader")
	f.policies(connectAll, invokeAll)
	alice := f.token("USER", "alice")
	if res := f.want("native", on(athenaOp(descriptor("ListWorkGroups", "{}", requestPhase)), alice, "lake", ""), ""); res.GetAthena() == nil {
		t.Error("native allow without instructions")
	}
	if res := f.want("metadata", on(catalogOp(ref("def", "app", "")), alice, "reports", ""), ""); res.GetInstructions() != nil {
		t.Errorf("metadata allow with instructions %v", res.GetInstructions())
	}
	scope := descriptor("StartQueryExecution", `{"QueryString":"select 1","WorkGroup":"other"}`, requestPhase)
	if res := f.want("engine deny code", on(athenaOp(scope), alice, "lake", ""), nativeScopeViolation); res.GetInstructions() != nil || res.GetPrincipal() != "" {
		t.Errorf("denied result carries %v %q", res.GetInstructions(), res.GetPrincipal())
	}
}

// Missing, invalid, expired, revoked, and deprovisioned tokens are unauthenticated; task tokens are not wire credentials.
func TestAuthorizeRequestCredentials(t *testing.T) {
	f := newFixture(t)
	f.datasource("reports", "mysql", "app")
	expired, revoked, retired := f.token("USER", "alice"), f.token("SESSION", "alice"), f.token("SESSION", "alice")
	f.exec(`UPDATE proxy_token SET expires_at = now() - interval '1 second' WHERE token_hash = $1`, tokenHash(expired))
	f.exec(`UPDATE proxy_token SET revoked_at = now() WHERE token_hash = $1`, tokenHash(revoked))
	f.exec(`UPDATE proxy_token SET retired_at = now() WHERE token_hash = $1`, tokenHash(retired))
	f.exec(`INSERT INTO app_user (principal, active) VALUES ('gone', true)`)
	gone := f.token("USER", "gone")
	f.exec(`UPDATE app_user SET active = false WHERE principal = 'gone'`)
	for _, tc := range []struct {
		name, token, msg string
	}{
		{"missing", "", badCredential},
		{"invalid", "invalid", badCredential},
		{"expired", expired, badCredential},
		{"revoked", revoked, badCredential},
		{"deactivated principal", gone, badCredential},
		{"editor token", f.token("EDITOR", "alice", "reader"), wireOnly},
		{"approver token", f.token("APPROVER_EXEC", "alice", "reader"), wireOnly},
		{"editor token without roles", f.token("EDITOR", "alice"), wireOnly},
	} {
		_, err := f.authorize(on(catalogOp(ref("def", "app", "")), tc.token, "reports", ""))
		wantStatus(t, tc.name, err, codes.Unauthenticated, tc.msg)
	}
	if _, err := f.authorize(on(catalogOp(ref("def", "app", "")), retired, "reports", "")); err != nil {
		t.Errorf("a retired session token still authorizes: %v", err)
	}
	_, err := f.authorize(on(catalogOp(ref("def", "app", "")), f.token("USER", "alice"), "nope", ""))
	wantStatus(t, "unknown datasource", err, codes.NotFound, "unknown datasource")
}

// Native credentials use live roles rather than token roles, and ordinary roles are refreshed after deletion.
func TestAuthorizeRequestLiveRoles(t *testing.T) {
	f := newFixture(t)
	f.datasource("reports", "mysql", "app")
	f.grant("alice", "live")
	f.policies(`permit(principal in Role::"live", action == Action::"datasource.connect", resource)
		when { context has channel && context.channel == "wire" && context has requester_ip && context.requester_ip == ip("198.51.100.7") };`)
	r := catalogOp(ref("def", "app", ""))
	for _, kind := range []string{"USER", "SESSION"} {
		tok := f.token(kind, "alice", "system:admin")
		res := f.want(kind, on(r, tok, "reports", "198.51.100.7:45100"), "")
		if !slices.Equal(res.GetEffectiveRoles(), []string{"live"}) {
			t.Errorf("%s: effective roles %v", kind, res.GetEffectiveRoles())
		}
	}
	tok := f.token("USER", "alice")
	f.deleteRole("live")
	res := f.want("role deleted", on(r, tok, "reports", "198.51.100.7:45100"), notConnectable)
	if len(res.GetEffectiveRoles()) != 0 {
		t.Errorf("effective roles after deletion %v", res.GetEffectiveRoles())
	}
}

// AuthorizeRequest enforces live roles and wire IP.
func TestAuthorizeRequestEnforcesLiveRolesAndWireIP(t *testing.T) {
	f := newFixture(t)
	f.datasource("request-ds", "mysql", "app")
	f.grant("request@example.com", "request-role")
	f.policies(`permit(principal in Role::"request-role", action == Action::"datasource.connect", resource == Datasource::"request-ds")
		when { context has channel && context.channel == "wire" && context has requester_ip && context.requester_ip.isInRange(ip("10.0.0.0/8")) };`)
	tok := f.token("USER", "request@example.com", "system:admin")
	r := on(catalogOp(ref("def", "app", "")), tok, "request-ds", "10.2.3.4:49152")
	res := f.want("catalog", r, "")
	if res.GetPrincipal() != "request@example.com" || !slices.Equal(res.GetEffectiveRoles(), []string{"request-role"}) {
		t.Errorf("principal %q roles %v", res.GetPrincipal(), res.GetEffectiveRoles())
	}
	f.want("table", on(tableOp(ref("def", "app", "users")), tok, "request-ds", "10.2.3.4:49152"), "")
	if res := f.want("outside range", on(r, tok, "request-ds", "198.51.100.7:49152"), notConnectable); res.GetPrincipal() != "" {
		t.Errorf("denied principal %q", res.GetPrincipal())
	}
	f.want("unknown operation", withUnknownField(&pb.RequestAuthorization{Token: tok, DatasourceName: "request-ds", ClientAddr: "10.2.3.4:49152"}), nativeNotAuthorized)
	f.deleteRole("request-role")
	f.want("role deleted", r, notConnectable)
}

// The native RPC refuses task tokens and relational engines refuse its descriptor.
func TestNativeRequestRefusesTaskTokens(t *testing.T) {
	f := newFixture(t)
	f.datasource("native-ds", "mysql", "app")
	f.grant("native@example.com", "own")
	f.policies(connectAll, invokeAll)
	r := athenaOp(descriptor("ListWorkGroups", "{}", requestPhase))
	for _, kind := range []string{"EDITOR", "APPROVER_EXEC"} {
		_, err := f.authorize(on(r, f.token(kind, "native@example.com", "assumed"), "native-ds", ""))
		wantStatus(t, kind, err, codes.Unauthenticated, wireOnly)
	}
	tok := f.token("USER", "native@example.com", "system:admin")
	res := f.want("user token", on(r, tok, "native-ds", ""), nativeNotAuthorized)
	if !slices.Equal(res.GetEffectiveRoles(), []string{"own"}) {
		t.Errorf("effective roles %v", res.GetEffectiveRoles())
	}
	f.exec(`INSERT INTO app_user (principal, active) VALUES ('native@example.com', false)`)
	_, err := f.authorize(on(r, tok, "native-ds", ""))
	wantStatus(t, "deactivated", err, codes.Unauthenticated, badCredential)
}

func TestRequesterIP(t *testing.T) {
	for in, want := range map[string]string{
		"/1.2.3.4:5432":      "1.2.3.4",
		"/[::1]:5432":        "::1",
		"/[2001:db8::1]:443": "2001:db8::1",
		"10.0.0.1:5432":      "10.0.0.1",
		"192.168.1.1":        "192.168.1.1",
		"/100.100.5.5:0":     "100.100.5.5",
		"":                   "",
		"   ":                "",
		"/":                  "",
	} {
		if got := requesterIP(in); got != want {
			t.Errorf("requesterIP(%q) = %q, want %q", in, got, want)
		}
	}
}
