//go:build goproxywire

package app_test

// THE MISSING INTEGRATION: the REAL goproxy client against the REAL Go control plane.
//
// This file closes F28 — 10-grpc.md:1456, "🔒 No test anywhere runs real goproxy against a real
// control-plane… Highest-value test the port should add." Today every goproxy-side test binds one of SIX
// hand-written fakes embedding pb.UnimplementedControlPlaneServer —
//
//	goproxy/cp/client_test.go:194, goproxy/cp/client_test.go:567,
//	goproxy/mysqlproxy/proxy_test.go:46, goproxy/pgproxy/proxy_test.go:39,
//	goproxy/run/runner_test.go:45, goproxy/run/table_detail_test.go:35
//
// — while every control-plane-side test (boot_e2e_db_test.go included) drives the CONTROL PLANE's own
// generated stub. Both sides are green against their own copy of the contract, and nothing anywhere
// links the two GENERATED PACKAGES into one process. A field-number reuse, a status-code change, or a
// presence-semantics slip between the two checked-in copies of controlplane.pb.go is invisible.
//
// This file links them. `github.com/ridi-oss/proxy-monster/goproxy/cp` — the same *cp.Client the wire
// proxy runs in production, with its own generated stubs and its own wire mappers — talks to the app
// booted by [bootE2E], and every answer is cross-checked against what internal/query.DecideQuery
// returns for the same inputs in the same process.
//
// # 🔴 WHY THIS FILE IS BUILD-TAGGED, and how to run it
//
//	GOLANG_PROTOBUF_REGISTRATION_CONFLICT=warn \
//	  go test ./internal/app -tags goproxywire -v -timeout 600s
//
// goproxy/internal/pb and controlplane/internal/pb are two INDEPENDENT protoc-gen-go outputs of the
// SAME proto/src/main/proto/controlplane.proto. Both call protoregistry.GlobalFiles.RegisterFile
// under the path "controlplane.proto" in init(), and the protobuf runtime's default conflict policy
// is `panic`. Linking both — which is the whole point of this file — therefore aborts the test binary
// before TestMain runs:
//
//	panic: proto: file "controlplane.proto" is already registered
//	  previously from: "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
//	  currently from:  "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
//
// The env var is read lazily by protoregistry's ignoreConflict (registry.go:47-64), so it must be set
// by the PROCESS THAT LAUNCHES the binary — no init() here can set it in time, because both pb
// packages are dependencies of this one and are initialised first. That is why this is a build tag
// and an env var rather than a plain test: `go test ./internal/app` must keep working untouched.
//
// `warn` (not `ignore`) so the collision is still printed. Dropping the second registration is
// harmless for what this file asserts: gRPC marshals the CONCRETE generated types, whose descriptors
// live in their own package's msgTypes table, not in GlobalFiles. The two type sets stay genuinely
// independent, which is exactly what makes the cross-check meaningful.
//
// The permanent fix is one directory rename in goproxy — see the assessment in this increment's
// report. It is deliberately NOT applied here: the brief is to consume goproxy, not modify it.
//
// # WHAT THE MODULE GRAPH STILL WON'T LET THIS FILE DO
//
// Three of *cp.Client's methods take or return types from goproxy/internal/pb:
//
//	PushCatalog(*pb.CatalogRequest) error
//	PushSchemaFragment(*pb.SchemaFragmentPush) (uint64, error)
//	engine.DecideRequest.RunCommands func([]*pb.Refetch) error
//
// A package outside goproxy/… cannot NAME those types, so it cannot construct an argument for them.
// The two pushes below therefore go through the control plane's own stub as SETUP — flagged at each
// call site. Everything this file ASSERTS on (Register, ValidateToken, Decide, ReportCompletion,
// CloseConnection, Events, RunExec) crosses the wire through the real client.
//
// The RunCommands hole is the interesting one: it means an out-of-module consumer cannot satisfy a
// before_decide round at all. That is asserted as an observable fact in
// TestGoproxyClientCannotSatisfyBeforeDecideWithoutARunner rather than worked around.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/authz"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/datasource"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/query"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/token"
	"github.com/ridi-oss/proxy-monster/goproxy/cp"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// maskedSQL touches all three app_users columns. `rrn` is classified pii + last4 below, and the
// policy pair grants unmasked on the non-pii columns and MASKED on the pii ones — the worked example
// from docs/authz-model.md, reproduced here because MASK is the only verdict whose correctness
// depends on a number surviving the wire.
const maskedSQL = "select id, email, rrn from app_users"

// wireClientOf dials the booted control plane with the PRODUCTION proxy client.
func wireClientOf(t *testing.T, b *bootedApp, secret, dsName string) *cp.Client {
	t.Helper()
	c, err := cp.New(fmt.Sprintf("127.0.0.1:%d", b.app.Grpc.BoundPort()), secret, dsName)
	if err != nil {
		t.Fatalf("cp.New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// streamGateWindow bounds every streaming assertion below.
//
// ⚠️ IT IS LOAD-BEARING, and mutation testing is what proved it. *cp.Client.StreamEvents takes no
// context — it builds its own, bounded by the unexported eventsStreamMaxAge (4 minutes). So when the
// gate is REMOVED the call does not return an error, it BLOCKS: Events emits nothing while idle and
// holds the stream. A version of this test that simply called StreamEvents and inspected the returned
// error hung for four minutes per case on exactly the regression it exists to catch. Waiting on a
// channel makes "no answer" a first-class, fast FAILURE instead.
const streamGateWindow = 5 * time.Second

// eventsStreamErr runs StreamEvents on its own goroutine and reports its terminal error. The
// goroutine outlives a failed wait — it unblocks when the client is closed in t.Cleanup — so it never
// touches *testing.T.
func eventsStreamErr(client *cp.Client) <-chan error {
	done := make(chan error, 1)
	go func() {
		done <- client.StreamEvents(func() {}, func(spi.RunOpen) {}, func(_, _, _ string) {})
	}()
	return done
}

// schemasOf reads GetSchema() off a slice whose ELEMENT TYPE this package may not name
// (goproxy/internal/pb.Refetch). Type inference binds T without an import — the only way to observe
// spi.Identity.OnOpen and Decision.AfterStatement from outside goproxy/….
func schemasOf[T interface{ GetSchema() string }](commands []T) []string {
	out := make([]string, 0, len(commands))
	for _, c := range commands {
		out = append(out, c.GetSchema())
	}
	return out
}

// enfName is grpcsvc's verdict → goproxy's Action string, for the direct-vs-wire comparison. It is
// deliberately a SEPARATE spelling from engine.EnfActionName: using goproxy's own mapper on both
// sides would make the comparison tautological for exactly the enum whose numbers 10-grpc.md warns
// do not match the Kotlin ordinals (INV-A10-53).
func enfName(a pb.EnfAction) string {
	switch a {
	case pb.EnfAction_ALLOW:
		return "ALLOW"
	case pb.EnfAction_MASK:
		return "MASK"
	case pb.EnfAction_DENY:
		return "DENY"
	default:
		return fmt.Sprintf("EnfAction(%d)", int32(a))
	}
}

func indexOf(haystack []string, needle string) int {
	for i, v := range haystack {
		if v == needle {
			return i
		}
	}
	return -1
}

// ---- the wire session ---------------------------------------------------------------------------

// wireSession is one fully handshaken proxy session: the real client, the datasource row it
// registered, and the connection id ValidateToken minted.
type wireSession struct {
	client *cp.Client
	ds     datasource.Datasource
	connID []byte
	token  string
	name   string
}

// openWireSession runs the proxy's real boot handshake through *cp.Client and leaves the connection
// holding a fresh schema fragment, so the next Decide answers with a verdict rather than the
// freshness pre-gate.
func openWireSession(t *testing.T, b *bootedApp, secret, dsName string, seedPolicy func(ds datasource.Datasource)) wireSession {
	t.Helper()
	client := wireClientOf(t, b, secret, dsName)

	// 1. Register — THE REAL CLIENT. No posture tag, so the datasource sits on the production floor
	// via deny-by-default (see boot_e2e_db_test.go's note on why `system:development` would make the
	// deny assertions pass for the wrong reason).
	if err := client.Register(enginepb.Engine_POSTGRES, "127.0.0.1", 5432, b.dbName, nil, "", nil, false); err != nil {
		t.Fatalf("cp.Client.Register: %v", err)
	}

	// 2. PushCatalog — SETUP through the control plane's own stub. *cp.Client.PushCatalog takes a
	// *goproxy/internal/pb.CatalogRequest, a type this package cannot name (see the file header).
	if _, err := b.client.PushCatalog(b.authed, &pb.CatalogRequest{
		DatasourceName: dsName,
		DefaultSchemas: []string{e2eSchema},
		EngineVersion:  "PostgreSQL 17.2 on aarch64-unknown-linux-gnu",
		Columns:        e2eColumns(),
	}); err != nil {
		t.Fatalf("PushCatalog (setup): %v", err)
	}

	ds, found, err := b.app.Core.DatasourceStore.GetByName(context.Background(), dsName)
	if err != nil || !found {
		t.Fatalf("GetByName(%q) = found %v, err %v", dsName, found, err)
	}
	seedPolicy(ds)

	rawToken := issueE2EToken(t, b, token.KindUser)

	// 3. ValidateToken — THE REAL CLIENT, returning the proxy's own spi.Identity.
	identity, err := client.ValidateToken(rawToken)
	if err != nil {
		t.Fatalf("cp.Client.ValidateToken: %v", err)
	}
	assertIdentity(t, identity)

	// 4. PushSchemaFragment — SETUP through the control plane's stub, same reason as PushCatalog.
	if _, err := b.client.PushSchemaFragment(b.authed, &pb.SchemaFragmentPush{
		ConnectionId:      identity.ConnectionID,
		DatasourceName:    dsName,
		Schema:            e2eSchema,
		ContentHash:       []byte("goproxy-wire-content-hash-v1"),
		Columns:           e2eColumns(),
		BackendGeneration: 1,
	}); err != nil {
		t.Fatalf("PushSchemaFragment (setup): %v", err)
	}

	return wireSession{client: client, ds: ds, connID: identity.ConnectionID, token: rawToken, name: dsName}
}

// assertIdentity pins what the proxy's own mapper made of WireIdentity.
func assertIdentity(t *testing.T, identity spi.Identity) {
	t.Helper()
	if identity.Principal != e2ePrincipal {
		t.Errorf("spi.Identity.Principal = %q, want %q", identity.Principal, e2ePrincipal)
	}
	// 🔒 INV-A10-18 — 128 CSPRNG bits, enforced on BOTH sides. cp.identityFromWire refuses anything
	// else, so reaching here at all is half the assertion; the length check is the other half.
	if len(identity.ConnectionID) != 16 {
		t.Fatalf("spi.Identity.ConnectionID is %d bytes, want exactly 16", len(identity.ConnectionID))
	}
	if got := schemasOf(identity.OnOpen); indexOf(got, e2eSchema) < 0 {
		t.Fatalf("spi.Identity.OnOpen schemas = %v, want one for %q", got, e2eSchema)
	}
}

// seedMaskingPolicy is the pii pair: unmasked on everything NOT tagged pii, MASKED on what is.
// `ungranted_orders` deliberately gets nothing, so deny-by-default is provable in the same session.
func seedMaskingPolicy(t *testing.T, b *bootedApp, ds datasource.Datasource) {
	t.Helper()
	s := dbtest.NewSeed(t, b.app.Db)
	s.User(e2ePrincipal)
	roleID := s.Role(e2eRole)
	s.AssignRole(e2ePrincipal, roleID)

	maskFnID := s.MaskFn("last4", "LAST_N")
	s.Classify(ds.ID, e2eSchema, e2eTable, "rrn", []string{"pii"}, &maskFnID)

	table := fmt.Sprintf("%s/%s/%s/%s", ds.Name, b.dbName, e2eSchema, e2eTable)
	s.CedarPolicy("wire-connect-select", fmt.Sprintf(
		`permit(principal in Role::%q, action in [Action::"datasource.connect", Action::"sql.select"], resource in Datasource::%q);`,
		e2eRole, ds.Name))
	s.CedarPolicy("wire-users-unmasked", fmt.Sprintf(
		`permit(principal in Role::%q, action == Action::"result.read.unmasked", resource in Table::%q) unless { resource in Tag::"pii" };`,
		e2eRole, table))
	s.CedarPolicy("wire-users-masked-pii", fmt.Sprintf(
		`permit(principal in Role::%q, action == Action::"result.read.masked", resource in Table::%q) when { resource in Tag::"pii" };`,
		e2eRole, table))
}

// ---- the direct oracle --------------------------------------------------------------------------

// decideDirectly calls internal/query.DecideQuery IN PROCESS with the inputs
// core.decideOnConnection builds for the same request — the connection's HELD structural rows plus
// the datasource's live classifications (its STEP 4-5), and ChannelWire's requester-IP selection
// (its STEP 7).
//
// It is the oracle the wire answer is compared against. Reconstructing the input here rather than
// calling core.DecideConnection is deliberate: DecideConnection writes an audit row and a wire task,
// so using it as an oracle would double every side effect and make the audit-row counts meaningless.
// DecideQuery is pure.
func decideDirectly(t *testing.T, b *bootedApp, sess wireSession, sql, clientAddr string) query.DecisionContext {
	t.Helper()
	ctx := context.Background()
	ds := sess.ds

	conn := b.app.Core.ConnectionCatalog.Find(datasource.ConnectionID(sess.connID))
	if conn == nil {
		t.Fatalf("connection %x is not in the registry; the wire handshake did not leave one open", sess.connID)
	}
	catalogName, err := datasource.CatalogName(ds.Engine, ds.DBName)
	if err != nil {
		t.Fatalf("CatalogName: %v", err)
	}
	classifications, err := b.app.Core.DatasourceStore.ClassificationsFor(ctx, ds.ID)
	if err != nil {
		t.Fatalf("ClassificationsFor: %v", err)
	}

	rows := b.app.Core.ConnectionCatalog.StructuralRows(conn)
	catalog := make([]datasource.CatalogColumn, 0, len(rows))
	for _, r := range rows {
		col := datasource.CatalogColumn{
			Catalog:  catalogName,
			Schema:   r.Schema,
			Table:    r.Table,
			Column:   r.Column,
			DataType: r.DataType,
			SQLType:  datasource.SQLTypeFor(r.DataType),
			Ordinal:  r.Ordinal,
			Nullable: r.Nullable,
			// IsTemp is NEVER set here (INV-A5-1), matching core.decideOnConnection.
		}
		if cl, ok := classifications[datasource.ColumnKey{Schema: r.Schema, Table: r.Table, Column: r.Column}]; ok {
			found := cl
			col.Classification = &found
		}
		catalog = append(catalog, col)
	}

	addr := clientAddr
	searchPath := []string{e2eSchema}
	direct, err := query.DecideQuery(ctx, query.DecideQueryInput{
		Principal:            e2ePrincipal,
		Datasource:           ds,
		SQL:                  sql,
		Channel:              query.ChannelWire,
		Catalog:              catalog,
		MaskFns:              b.app.Core.MaskFns,
		UserGroups:           b.app.Core.UserGroupStore,
		Roles:                b.app.Core.RoleResolver,
		Authz:                b.app.Core.Authz,
		Context:              authz.AuthzContext{RequesterIP: query.ParseRequesterIp(&addr)},
		LiveSearchPath:       &searchPath,
		SystemClassification: b.app.Core.SystemClassification,
	})
	if err != nil {
		t.Fatalf("query.DecideQuery: %v", err)
	}
	return direct
}

// ---- 1. the round trip ---------------------------------------------------------------------------

// TestGoproxyClientDecidesAMaskedStatementOverTheWire is the integration this increment exists for.
//
// The REAL *cp.Client registers, validates and decides against the REAL control plane, and every
// answer is checked against internal/query.DecideQuery's own result for the same inputs. A mapping
// bug in EITHER direction — grpcsvc.toWireDecision on the way out, cp.decisionFromWire on the way
// back — fails it, and so does a divergence between the two generated packages.
func TestGoproxyClientDecidesAMaskedStatementOverTheWire(t *testing.T) {
	secret := e2eSecret
	b := bootE2E(t, &secret)
	const clientAddr = "10.1.2.3:54321"

	sess := openWireSession(t, b, secret, "goproxy-wire-mask", func(ds datasource.Datasource) {
		seedMaskingPolicy(t, b, ds)
	})

	// The wire self-approve gate (core.decideOnConnection STEP 11) can turn an ALLOW/MASK into a
	// synthesized DENY on the WIRE path only, which DecideQuery knows nothing about. Assert it is open
	// first, so a gate refusal reports itself instead of masquerading as a mapping mismatch.
	if !b.app.Core.AutoApproveTask(e2ePrincipal, []string{e2eRole}, sess.ds, authz.AuthzContext{}, query.ChannelWire) {
		t.Fatalf("the wire self-approve gate is CLOSED for %s; every verdict below would be a synthesized "+
			"DENY and the direct-vs-wire comparison would be meaningless", e2ePrincipal)
	}

	outcome := sess.client.Decide(engine.DecideRequest{
		Token:        sess.token,
		SQL:          maskedSQL,
		ClientAddr:   clientAddr,
		Namespace:    []string{e2eSchema},
		ConnectionID: sess.connID,
	})
	if outcome.IsErr() {
		t.Fatalf("cp.Client.Decide: %s", outcome.Err)
	}
	wire := outcome.Decision

	direct := decideDirectly(t, b, sess, maskedSQL, clientAddr)

	// --- the verdict itself.
	if direct.Action != pb.EnfAction_MASK {
		t.Fatalf("internal/query.DecideQuery decided %s for %q, want MASK — the fixture no longer "+
			"produces the case this test is about", enfName(direct.Action), maskedSQL)
	}
	if wire.Action != enfName(direct.Action) {
		t.Errorf("wire Action = %q, DecideQuery = %q", wire.Action, enfName(direct.Action))
	}

	// 🔒 THE ORDINALS. This is why the whole file exists: the proxy masks by POSITION in the result
	// stream, so an ordinal that shifts by one on the wire hands the client the cleartext column it
	// was supposed to hide. Compare the WHOLE mask list field for field against DecideQuery's.
	if len(wire.Masks) != len(direct.Masks) {
		t.Fatalf("wire returned %d masks, DecideQuery produced %d", len(wire.Masks), len(direct.Masks))
	}
	if len(direct.Masks) != 1 {
		t.Fatalf("DecideQuery produced %d masks, want exactly 1 (the pii column)", len(direct.Masks))
	}
	for i := range direct.Masks {
		want, got := direct.Masks[i], wire.Masks[i]
		if got.GetColumn() != want.GetColumn() {
			t.Errorf("mask[%d].column: wire %q, DecideQuery %q", i, got.GetColumn(), want.GetColumn())
		}
		if got.GetMaskFn() != want.GetMaskFn() {
			t.Errorf("mask[%d].mask_fn: wire %q, DecideQuery %q", i, got.GetMaskFn(), want.GetMaskFn())
		}
		if got.GetKind() != want.GetKind() {
			t.Errorf("mask[%d].kind: wire %q, DecideQuery %q", i, got.GetKind(), want.GetKind())
		}
		// 🔒 INV-A10-52 / controlplane.proto's `optional int32 ordinal` — EXPLICIT PRESENCE must
		// survive. A nil here would be bound to result column 0 by a mapper that normalised it,
		// masking `id` and leaking `rrn`. cp.decisionFromWire deliberately does NOT normalise it, and
		// this is the assertion that keeps it that way.
		if got.Ordinal == nil {
			t.Fatalf("mask[%d].ordinal arrived ABSENT over the wire; explicit presence was lost", i)
		}
		if want.Ordinal == nil {
			t.Fatalf("DecideQuery produced mask[%d] with no ordinal", i)
		}
		if *got.Ordinal != *want.Ordinal {
			t.Errorf("mask[%d].ordinal: wire %d, DecideQuery %d", i, *got.Ordinal, *want.Ordinal)
		}
	}

	// …and independently of the comparison, the surviving ordinal must actually point at `rrn` in the
	// analyzer's output column list. Two agreeing-but-wrong sides would pass the loop above.
	rrnAt := indexOf(direct.OutputColumns, "rrn")
	if rrnAt < 0 {
		t.Fatalf("output columns = %v, want one named rrn", direct.OutputColumns)
	}
	if rrnAt != 2 {
		t.Fatalf("rrn is output column %d for %q, want 2 — the fixture changed", rrnAt, maskedSQL)
	}
	if m := wire.Masks[0]; m.GetColumn() != "rrn" || *m.Ordinal != int32(rrnAt) {
		t.Fatalf("wire mask = column %q ordinal %d, want rrn at %d (a shifted ordinal masks the wrong "+
			"column and relays the pii one in cleartext)", m.GetColumn(), *m.Ordinal, rrnAt)
	}

	// --- the rest of the verdict, both directions.
	if len(wire.EffectiveRoles) != len(direct.EffectiveRoles) {
		t.Errorf("effective_roles: wire %v, DecideQuery %v", wire.EffectiveRoles, direct.EffectiveRoles)
	} else {
		for i := range direct.EffectiveRoles {
			if wire.EffectiveRoles[i] != direct.EffectiveRoles[i] {
				t.Errorf("effective_roles[%d]: wire %q, DecideQuery %q", i, wire.EffectiveRoles[i], direct.EffectiveRoles[i])
			}
		}
	}
	if indexOf(wire.EffectiveRoles, e2eRole) < 0 {
		t.Errorf("effective_roles = %v, want the SERVER-RESOLVED %q", wire.EffectiveRoles, e2eRole)
	}
	if wire.UnmaskablePermitted != direct.UnmaskablePermitted {
		t.Errorf("unmasked_permitted: wire %v, DecideQuery %v", wire.UnmaskablePermitted, direct.UnmaskablePermitted)
	}
	if wire.SanitizeDiagnostics != direct.SanitizeDiagnostics {
		t.Errorf("sanitize_diagnostics: wire %v, DecideQuery %v", wire.SanitizeDiagnostics, direct.SanitizeDiagnostics)
	}
	// 🔒 INV-A10-37 — rewritten_sql stays ABSENT when there is no `*` to expand. "" would make the
	// proxy send an empty query. Presence must agree on both sides.
	if (direct.RewrittenSQL == nil) != (wire.RewrittenSQL == nil) {
		t.Errorf("rewritten_sql presence: wire nil=%v, DecideQuery nil=%v", wire.RewrittenSQL == nil, direct.RewrittenSQL == nil)
	}
	if direct.RewrittenSQL != nil && wire.RewrittenSQL != nil && *direct.RewrittenSQL != *wire.RewrittenSQL {
		t.Errorf("rewritten_sql: wire %q, DecideQuery %q", *wire.RewrittenSQL, *direct.RewrittenSQL)
	}
	wireReason := ""
	if direct.DenyReason != nil {
		wireReason = *direct.DenyReason
	}
	if wire.DenyReason != wireReason {
		t.Errorf("deny_reason: wire %q, DecideQuery %q", wire.DenyReason, wireReason)
	}
	// decision_id is NOT a DecideQuery output — it is the audit row grpcsvc stamped on the way out.
	// Its presence is what lets the proxy report a completion at all.
	if wire.DecisionID == 0 {
		t.Error("decision_id = 0 on a verdict; the audit row must have been written and referenced")
	}

	// --- deny-by-default on the same session, through the same client.
	denied := sess.client.Decide(engine.DecideRequest{
		Token:        sess.token,
		SQL:          "select * from ungranted_orders",
		ClientAddr:   clientAddr,
		Namespace:    []string{e2eSchema},
		ConnectionID: sess.connID,
	})
	if denied.IsErr() {
		t.Fatalf("Decide (ungranted table): %s", denied.Err)
	}
	if denied.Decision.Action != "DENY" {
		t.Errorf("ungranted table decided %q via the real client, want DENY", denied.Decision.Action)
	}

	// --- ReportCompletion, through the real client. It never returns an error by contract (a lost
	// completion must not affect a client session), so the audit table is the assertion.
	sess.client.ReportCompletion(engine.CompletionReport{
		DecisionID: wire.DecisionID, RowsReturned: 2, BytesReturned: 96,
		Status: engine.StatusOK, DurationMs: 7,
	})
	var completions int
	if err := b.app.Db.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_event WHERE kind='completion'`).Scan(&completions); err != nil {
		t.Fatalf("read audit_event: %v", err)
	}
	if completions != 1 {
		t.Errorf("audit_event completion rows = %d, want 1 — the real client's ReportCompletion did not land", completions)
	}

	// --- CloseConnection, through the real client. Afterwards the id is gone from the registry.
	if err := sess.client.CloseConnection(sess.connID); err != nil {
		t.Fatalf("cp.Client.CloseConnection: %v", err)
	}
	if conn := b.app.Core.ConnectionCatalog.Find(datasource.ConnectionID(sess.connID)); conn != nil {
		t.Error("connection is still in the registry after the real client closed it")
	}
}

// ---- 2. the before_decide arm --------------------------------------------------------------------

// TestGoproxyClientCannotSatisfyBeforeDecideWithoutARunner drives the OTHER arm of the WireDecision
// oneof through the real client, before any fragment exists.
//
// It doubles as the executable record of the module-graph hole in this file's header:
// engine.DecideRequest.RunCommands is `func([]*goproxy/internal/pb.Refetch) error`, so a consumer
// outside goproxy/… cannot write one. The client's own fail-closed message for that state is the
// assertion — the before_decide DID cross the wire and cp.decisionFromWire DID recognise it, which is
// the contract half that matters here.
func TestGoproxyClientCannotSatisfyBeforeDecideWithoutARunner(t *testing.T) {
	secret := e2eSecret
	b := bootE2E(t, &secret)
	dsName := "goproxy-wire-before-decide"

	client := wireClientOf(t, b, secret, dsName)
	if err := client.Register(enginepb.Engine_POSTGRES, "127.0.0.1", 5432, b.dbName, nil, "", nil, false); err != nil {
		t.Fatalf("cp.Client.Register: %v", err)
	}
	if _, err := b.client.PushCatalog(b.authed, &pb.CatalogRequest{
		DatasourceName: dsName, DefaultSchemas: []string{e2eSchema}, Columns: e2eColumns(),
	}); err != nil {
		t.Fatalf("PushCatalog (setup): %v", err)
	}
	ds, found, err := b.app.Core.DatasourceStore.GetByName(context.Background(), dsName)
	if err != nil || !found {
		t.Fatalf("GetByName(%q) = found %v, err %v", dsName, found, err)
	}
	seedMaskingPolicy(t, b, ds)

	rawToken := issueE2EToken(t, b, token.KindUser)
	identity, err := client.ValidateToken(rawToken)
	if err != nil {
		t.Fatalf("cp.Client.ValidateToken: %v", err)
	}
	assertIdentity(t, identity)

	// 🔒 INV-A5-49 — no fragment yet, so the freshness pre-gate fires BEFORE any analysis and before
	// any audit row. The client maps that to the "no runner" error rather than to a verdict.
	outcome := client.Decide(engine.DecideRequest{
		Token: rawToken, SQL: maskedSQL, Namespace: []string{e2eSchema}, ConnectionID: identity.ConnectionID,
	})
	if !outcome.IsErr() {
		t.Fatalf("Decide before any fragment returned a decision %+v; the freshness pre-gate must fire first",
			outcome.Decision)
	}
	if outcome.Err != "control plane demanded pre-decision commands but no runner is configured" {
		t.Fatalf("Decide error = %q, want the client's no-runner message — anything else means the "+
			"before_decide arm did not survive the wire", outcome.Err)
	}

	// …and it wrote NO audit row, which is the security half of INV-A5-49.
	var decisions int
	if err := b.app.Db.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_event WHERE kind='decision'`).Scan(&decisions); err != nil {
		t.Fatalf("read audit_event: %v", err)
	}
	if decisions != 0 {
		t.Errorf("audit_event decision rows = %d after a before_decide, want 0", decisions)
	}
}

// ---- 3. the secret-token gate, through the real client -------------------------------------------

// TestGoproxyClientIsRejectedOnUnaryAndStreamingRPCs is the file's security assertion.
//
// 🔒 gRPC-Go registers UnaryInterceptor and StreamInterceptor SEPARATELY. Wiring only the unary one
// leaves Events, RunExec and TableDetailExec completely UNGATED — 10-grpc.md §3.4 calls it the single
// most dangerous mechanical mistake available in this area, and the Kotlin's GrpcServerTest exercises
// only a unary RPC. boot_e2e_db_test.go asserts it through the control plane's own stub; this asserts
// it through the client that actually attaches the header in production, so a client-side header bug
// and a server-side gate bug cannot cancel each other out.
func TestGoproxyClientIsRejectedOnUnaryAndStreamingRPCs(t *testing.T) {
	secret := e2eSecret
	b := bootE2E(t, &secret)

	// A registered datasource, so Events cannot fail for the unrelated NotFound reason.
	const dsName = "goproxy-wire-gate"
	good := wireClientOf(t, b, secret, dsName)
	if err := good.Register(enginepb.Engine_POSTGRES, "127.0.0.1", 5432, b.dbName, nil, "", nil, false); err != nil {
		t.Fatalf("Register with the correct secret: %v", err)
	}

	const gateMsg = "missing or invalid x-pm-secret-token"
	for _, tc := range []struct {
		name   string
		secret string
	}{
		{"no secret at all", ""},
		{"wrong secret", "not-the-secret"},
		// A prefix of the real secret: the comparison is constant-time over the WHOLE value, so a
		// length-truncated guess is no closer than any other wrong value.
		{"prefix of the secret", e2eSecret[:10]},
	} {
		bad := wireClientOf(t, b, tc.secret, dsName)

		t.Run("unary/Register/"+tc.name, func(t *testing.T) {
			err := bad.Register(enginepb.Engine_POSTGRES, "127.0.0.1", 5432, b.dbName, nil, "", nil, false)
			if err == nil || !strings.Contains(err.Error(), gateMsg) {
				t.Fatalf("Register → %v, want the gate's %q", err, gateMsg)
			}
		})
		t.Run("unary/ValidateToken/"+tc.name, func(t *testing.T) {
			_, err := bad.ValidateToken("anything")
			if err == nil || !strings.Contains(err.Error(), gateMsg) {
				t.Fatalf("ValidateToken → %v, want the gate's %q", err, gateMsg)
			}
		})
		t.Run("unary/Decide/"+tc.name, func(t *testing.T) {
			outcome := bad.Decide(engine.DecideRequest{
				Token: "anything", SQL: "select 1", ConnectionID: make([]byte, 16),
			})
			if !outcome.IsErr() || !strings.Contains(outcome.Err, gateMsg) {
				t.Fatalf("Decide → %+v / %q, want the gate's %q", outcome.Decision, outcome.Err, gateMsg)
			}
		})

		// 🔒 THE STREAMING HALF, through the production client. An UNGATED stream does not answer
		// wrongly — it answers not at all (Events holds an idle stream open, RunExec waits for a
		// message), so silence past the window is the failure, not a stall to wait out.
		t.Run("stream/Events/"+tc.name, func(t *testing.T) {
			select {
			case err := <-eventsStreamErr(bad):
				if err == nil || !strings.Contains(err.Error(), gateMsg) {
					t.Fatalf("StreamEvents → %v, want the gate's %q", err, gateMsg)
				}
			case <-time.After(streamGateWindow):
				t.Fatalf("StreamEvents with %s was ADMITTED and is holding the stream open; the STREAM "+
					"interceptor is not gating (registering only UnaryInterceptor leaves Events, RunExec "+
					"and TableDetailExec wide open)", tc.name)
			}
		})
		t.Run("stream/RunExec/"+tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), streamGateWindow)
			defer cancel()
			stream, err := bad.RunExec(ctx)
			if err == nil {
				_, err = stream.Recv()
			}
			if err == nil || !strings.Contains(err.Error(), gateMsg) {
				t.Fatalf("RunExec → %v, want the gate's %q (the STREAM interceptor must gate too; a "+
					"DeadlineExceeded here means the call was ADMITTED and is waiting for a message)", err, gateMsg)
			}
		})
	}

	// THE POSITIVE CONTROL. A gate that rejected everything would pass every case above, so the
	// correctly-secreted client must be able to hold a stream open. Events emits nothing of its own
	// while idle, so "no error within the window" IS the signal; the stream is torn down by the
	// client's Close in t.Cleanup.
	t.Run("stream/Events/correct secret is admitted", func(t *testing.T) {
		select {
		case err := <-eventsStreamErr(good):
			t.Fatalf("StreamEvents with the correct secret ended early: %v — the gate is a wall, not a gate", err)
		case <-time.After(2 * time.Second):
		}
	})
}
