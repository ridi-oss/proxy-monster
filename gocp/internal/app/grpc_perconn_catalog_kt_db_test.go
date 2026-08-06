package app_test

// GrpcPerConnectionCatalogDbTest.kt — 11 cases, over a real gRPC server and a migrated database.
//
// The subject is the PER-CONNECTION CATALOG's wire surface: ValidateToken mints a connection id and an
// on-open plan, PushSchemaFragment answers pending commands under a CAS, CloseConnection tears the
// entry down, and Decide is gated on all of it. internal/datasource/connectioncatalog_test.go covers the
// registry's own state machine in isolation; what only a wire test can show is the STATUS CODE each
// failure maps to, because those codes are the proxy's whole vocabulary for "retry", "re-handshake" and
// "tear the session down".
//
// TWO of the eleven cases are @Disabled in the Kotlin, each paired with a live case that pins the
// DEFECT instead — the port policy's "REPRODUCE + PIN". Both pairs are handled below the same way the
// Kotlin handles them: the live half asserts the buggy behaviour, and the disabled half's identity is
// carried by whichever Go test would have to change when the defect is fixed.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/core"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/grpcsvc"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/token"
)

// perConnFixture is the Kotlin's @BeforeAll: one datasource, one USER token, one running server.
type perConnFixture struct {
	t     *testing.T
	b     *bootedApp
	ds    string
	token string
}

func newPerConnFixture(t *testing.T) *perConnFixture {
	t.Helper()
	b := bootE2E(t, nil)
	const dsName = "pccat-ds"
	mustRegister(t, b, dsName)
	seedE2EPolicy(t, b, dsName)
	return &perConnFixture{t: t, b: b, ds: dsName, token: issueE2EToken(t, b, token.KindUser)}
}

func (f *perConnFixture) validate() *pb.WireIdentity {
	f.t.Helper()
	identity, err := f.b.client.ValidateToken(context.Background(), &pb.ValidateTokenRequest{
		Token: f.token, DatasourceName: f.ds,
	})
	if err != nil {
		f.t.Fatalf("ValidateToken: %v", err)
	}
	return identity
}

// push is the Kotlin's `push(...)` helper. No columns: an accepted push with an empty column list is a
// legitimate "this schema is empty", and every assertion here is about the CAS and the status code
// rather than about catalog content.
func (f *perConnFixture) push(connID []byte, schema, hash string, opts ...func(*pb.SchemaFragmentPush)) (*pb.SchemaFragmentAck, error) {
	req := &pb.SchemaFragmentPush{
		ConnectionId:      connID,
		DatasourceName:    f.ds,
		Schema:            schema,
		ContentHash:       []byte(hash),
		BackendGeneration: 1,
	}
	for _, o := range opts {
		o(req)
	}
	return f.b.client.PushSchemaFragment(context.Background(), req)
}

func withGeneration(g uint64) func(*pb.SchemaFragmentPush) {
	return func(r *pb.SchemaFragmentPush) { r.BackendGeneration = g }
}
func withUnchanged() func(*pb.SchemaFragmentPush) {
	return func(r *pb.SchemaFragmentPush) { r.Unchanged = true }
}
func withDatasource(name string) func(*pb.SchemaFragmentPush) {
	return func(r *pb.SchemaFragmentPush) { r.DatasourceName = name }
}

// satisfyOnOpen is the Kotlin's `satisfyOnOpen`: answer every on-open Refetch, each with its own
// backend generation, so the connection reaches the state where a LATER pending command can be tested.
func (f *perConnFixture) satisfyOnOpen(identity *pb.WireIdentity) {
	f.t.Helper()
	for i, cmd := range identity.GetOnOpen() {
		schema := cmd.GetRefetch().GetSchema()
		if _, err := f.push(identity.GetConnectionId(), schema, "open:"+schema, withGeneration(uint64(1+i))); err != nil {
			f.t.Fatalf("satisfy on-open for %s: %v", schema, err)
		}
	}
}

func (f *perConnFixture) close(connID []byte) {
	f.t.Helper()
	if _, err := f.b.client.CloseConnection(context.Background(), &pb.CloseConnectionRequest{
		ConnectionId: connID, DatasourceName: f.ds,
	}); err != nil {
		f.t.Fatalf("CloseConnection: %v", err)
	}
}

func (f *perConnFixture) decide(tok string, connID []byte) (*pb.WireDecision, error) {
	return f.b.client.Decide(context.Background(), &pb.DecisionRequest{
		Token: tok, DatasourceName: f.ds, ConnectionId: connID,
		Sql: "select 1", SearchPath: []string{e2eSchema},
	})
}

func (f *perConnFixture) auditCount() int64 {
	f.t.Helper()
	var n int64
	if err := f.b.app.Db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_event`).Scan(&n); err != nil {
		f.t.Fatalf("count audit_event: %v", err)
	}
	return n
}

// otherToken issues a USER token for a DIFFERENT principal on the same datasource.
func (f *perConnFixture) otherToken(principal string) string {
	f.t.Helper()
	issued, err := f.b.app.Core.TokenStore.Issue(
		context.Background(), f.b.app.Db.Pool, token.KindUser, principal, nil, nil, 3600)
	if err != nil {
		f.t.Fatalf("issue token for %s: %v", principal, err)
	}
	return issued.Token
}

func forgedID(fill byte) []byte { return bytes.Repeat([]byte{fill}, 16) }

// TestValidateMintsAConnectionIdAndSystemOnOpenCommands is case 1.
//
// 🔒 INV-A10-18 — the id is 16 bytes (128 CSPRNG bits). A shorter or guessable id would let a hostile
// proxy push a fragment into someone else's connection, which is a catalog-poisoning primitive.
//
// 🔒 The on-open plan includes THE SYSTEM SCHEMAS, not just the default one. A connection that skipped
// pg_catalog / information_schema would decide against an unmeasured system namespace, and A5's
// system-classification floor has nothing to classify — so the uncovered-scan gate is the only thing
// left and every system query denies.
//
// KT: GrpcPerConnectionCatalogDbTest.kt#validate mints connection id and system on-open commands
func TestValidateMintsAConnectionIdAndSystemOnOpenCommands(t *testing.T) {
	f := newPerConnFixture(t)
	identity := f.validate()

	if got := len(identity.GetConnectionId()); got != 16 {
		t.Errorf("connection_id is %d bytes, want exactly 16 (INV-A10-18)", got)
	}
	// The Kotlin compares the SET, not membership: `assertEquals(setOf("pg_catalog",
	// "information_schema"), identity.onOpenList.map { it.refetch.schema }.toSet())`. "And nothing else"
	// is part of the claim — this datasource has no default_schemas, so the on-open plan is exactly the
	// engine's two system namespaces, and a plan that also enumerated user schemas would make every
	// handshake pay for measurements the connection never asked for.
	schemas := map[string]bool{}
	for _, cmd := range identity.GetOnOpen() {
		schemas[cmd.GetRefetch().GetSchema()] = true
	}
	want := map[string]bool{"pg_catalog": true, "information_schema": true}
	for name := range want {
		if !schemas[name] {
			t.Errorf("on_open = %v, want a Refetch for the system schema %q", schemas, name)
		}
	}
	for name := range schemas {
		if !want[name] {
			t.Errorf("on_open carries an UNEXPECTED Refetch for %q; the plan is exactly %v for a "+
				"datasource with no default_schemas", name, want)
		}
	}
}

// TestForgedPushAndCloseAreNotFoundAndALiveDatasourceMismatchIsFailedPrecondition is case 2.
//
// 🔒 THE THREE CODES ARE NOT INTERCHANGEABLE, and that is the whole case:
//
//   - an id that was never minted ⇒ NOT_FOUND on both push and close. A proxy cannot discover which
//     random ids exist by watching for a different error;
//   - a LIVE id presented against the WRONG datasource ⇒ FAILED_PRECONDITION, not NOT_FOUND. The id
//     exists, so claiming otherwise would be a lie; and it is bound to one datasource, so honouring the
//     push would write another datasource's schema into this connection's catalog.
//
// KT: GrpcPerConnectionCatalogDbTest.kt#forged push and close reject not-found and live datasource mismatch rejects precondition
func TestForgedPushAndCloseAreNotFoundAndALiveDatasourceMismatchIsFailedPrecondition(t *testing.T) {
	f := newPerConnFixture(t)
	forged := forgedID(9)

	if _, err := f.push(forged, e2eSchema, "h"); status.Code(err) != codes.NotFound {
		t.Errorf("push on a forged id = %v, want NOT_FOUND", status.Code(err))
	}
	_, err := f.b.client.CloseConnection(context.Background(), &pb.CloseConnectionRequest{
		ConnectionId: forged, DatasourceName: f.ds,
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("close on a forged id = %v, want NOT_FOUND", status.Code(err))
	}

	identity := f.validate()
	schema := identity.GetOnOpen()[0].GetRefetch().GetSchema()
	// A second, really-registered datasource, so the mismatch is about the BINDING and not about the
	// name being unknown.
	if _, err := f.b.client.Register(context.Background(), &pb.RegisterRequest{
		Name: "other-datasource", Engine: enginepb.Engine_POSTGRES, DbName: f.b.dbName,
	}); err != nil {
		t.Fatalf("register the second datasource: %v", err)
	}
	_, err = f.push(identity.GetConnectionId(), schema, "h", withDatasource("other-datasource"))
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("push of a LIVE id against another datasource = %v, want FAILED_PRECONDITION — the id "+
			"exists, so NOT_FOUND would be a lie, and honouring it would poison this connection's catalog",
			status.Code(err))
	}
}

// TestPushRejectsAnOldBackendGenerationAndAnUnchangedHashMismatch is case 3 — the CAS, from both sides.
//
// 🔒 A push carries the generation of the backend connection it was measured on. An OLDER generation is
// a measurement from before a backend reconnect, i.e. it describes a database state that may no longer
// exist; accepting it would mark the connection FRESH against stale content and the freshness gate
// would then stop asking.
//
// 🔒 `unchanged=true` means "what you hold is still current", and its hash is the PROOF. A mismatched
// hash therefore cannot be a no-op: the proxy and the control plane disagree about what is held, and
// the only safe answer is to refuse and make the proxy send the content.
//
// KT: GrpcPerConnectionCatalogDbTest.kt#push rejects old backend generation and unchanged hash mismatch
func TestPushRejectsAnOldBackendGenerationAndAnUnchangedHashMismatch(t *testing.T) {
	f := newPerConnFixture(t)
	identity := f.validate()
	f.satisfyOnOpen(identity)
	schema := identity.GetOnOpen()[0].GetRefetch().GetSchema()

	// Open a pending after-statement refetch for that schema, so there is a command to satisfy.
	conn := f.b.app.Core.ConnectionCatalog.Find(datasource.ConnectionID(identity.GetConnectionId()))
	if conn == nil {
		t.Fatal("the minted connection is not in the registry")
	}
	f.b.app.Core.ConnectionCatalog.MarkAfterStatement(conn, []string{schema})

	if _, err := f.push(identity.GetConnectionId(), schema, "old", withGeneration(0)); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("push with backend_generation 0 = %v, want FAILED_PRECONDITION", status.Code(err))
	}
	if _, err := f.push(identity.GetConnectionId(), schema, "wrong", withGeneration(10), withUnchanged()); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("unchanged push with a MISMATCHED hash = %v, want FAILED_PRECONDITION", status.Code(err))
	}
}

// TestCurrentReplayBehaviorAcceptsAnOldFullPushForANewerPendingCommand is case 5, and it is a
// 🔴 CHARACTERIZATION TEST FOR A DOCUMENTED DEFECT, carried across per the port policy.
//
// ⚠️ IT ASSERTS THE BUGGY BEHAVIOUR ON PURPOSE. A full push replayed from an EARLIER measurement
// satisfies a NEWER pending refetch, because a Refetch command carries no nonce — nothing ties a push to
// the command it claims to answer, only to a schema and a generation. The Kotlin's paired
// `replayed full push cannot satisfy a newer pending refetch` is @Disabled and describes the DESIRED
// behaviour; making this test fail is the fix, and the disabled case's identity is carried here so the
// pair cannot be silently half-forgotten.
//
// KT: GrpcPerConnectionCatalogDbTest.kt#current replay behavior accepts an old full push for a newer pending command
// KT-DEFER: GrpcPerConnectionCatalogDbTest.kt#replayed full push cannot satisfy a newer pending refetch — the Kotlin marks it
//
//	@Disabled ("the command has no nonce"), so it asserts FAILED_PRECONDITION and never runs. This test asserts the
//	OPPOSITE — that the replay is ACCEPTED — so it cannot be a coverage claim for it: a marker whose case asserts the
//	negation of the test it sits on reads as coverage while proving nothing. Blocked on a Refetch command nonce tying a
//	push to the command it answers; when that lands, this test flips and the case becomes portable. Matches how the
//	suite's other @Disabled case is already accounted (perconnectioncatalog_adversarial_db_test.go:267).
func TestCurrentReplayBehaviorAcceptsAnOldFullPushForANewerPendingCommand(t *testing.T) {
	f := newPerConnFixture(t)
	identity := f.validate()
	f.satisfyOnOpen(identity)
	schema := identity.GetOnOpen()[0].GetRefetch().GetSchema()

	conn := f.b.app.Core.ConnectionCatalog.Find(datasource.ConnectionID(identity.GetConnectionId()))
	if conn == nil {
		t.Fatal("the minted connection is not in the registry")
	}
	f.b.app.Core.ConnectionCatalog.MarkAfterStatement(conn, []string{schema})

	// The REPLAY: the same content hash the on-open push used, against the newer pending command.
	ack, err := f.push(identity.GetConnectionId(), schema, "open:"+schema, withGeneration(10))
	if err != nil {
		t.Fatalf("the replayed push was REJECTED (%v). If a command nonce landed, that is the fix — "+
			"update this test and the Kotlin's @Disabled pair together", err)
	}
	if ack.GetGeneration() == 0 {
		t.Errorf("ack generation = 0, want an accepted push to advance the connection generation")
	}
}

// TestCrossPrincipalDecideOnALiveIdRejectsBindingMismatch is case 6.
//
// 🔒 THE CONNECTION ID IS NOT A BEARER TOKEN. It is bound to (datasource, principal, kind) at mint, and
// the token is re-resolved on EVERY Decide, so presenting someone else's live id with your own token is
// FAILED_PRECONDITION. Without this check a proxy that had ever seen another session's id could decide
// under that session's catalog — and the catalog is what determines which columns are masked.
//
// KT: GrpcPerConnectionCatalogDbTest.kt#cross-principal Decide on a live id rejects binding mismatch
func TestCrossPrincipalDecideOnALiveIdRejectsBindingMismatch(t *testing.T) {
	f := newPerConnFixture(t)
	identity := f.validate()

	other := f.otherToken("other@example.com")
	if _, err := f.decide(other, identity.GetConnectionId()); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("cross-principal Decide on a live id = %v, want FAILED_PRECONDITION", status.Code(err))
	}
}

// TestPostCloseLatePushRejectsNotFound is case 7: CloseConnection really does tear the entry down, so a
// push that arrives after it has nothing to write into.
//
// ⚠️ Note the asymmetry with the Decide path, which is case 9's defect: a late PUSH is refused, while a
// late DECIDE is recovered. The two answers differ because a push has no way to re-establish the
// binding and a Decide does (the token). It is still a defect, and keeping this case next to that one is
// what makes the inconsistency visible.
//
// KT: GrpcPerConnectionCatalogDbTest.kt#post-close late push rejects not-found
func TestPostCloseLatePushRejectsNotFound(t *testing.T) {
	f := newPerConnFixture(t)
	identity := f.validate()
	schema := identity.GetOnOpen()[0].GetRefetch().GetSchema()

	f.close(identity.GetConnectionId())

	if _, err := f.push(identity.GetConnectionId(), schema, "late"); status.Code(err) != codes.NotFound {
		t.Errorf("push after CloseConnection = %v, want NOT_FOUND", status.Code(err))
	}
}

// TestCurrentPostCloseDecideBehaviorRecoversTheClosedId is case 9, the other
// 🔴 CHARACTERIZATION TEST FOR A DOCUMENTED DEFECT (F29 / INV-A10-20).
//
// ⚠️ A CLOSED — or forged — connection id is RECOVERED by Decide rather than refused, because there is
// no tombstone and no mint evidence, which makes restart recovery and a replayed id indistinguishable.
// The recovery is deliberate (it is how a control-plane restart re-learns live proxy connections) and
// its blast radius is bounded, because recovery re-binds to (datasource, principal, kind) from the
// FRESHLY-RESOLVED token — case 6 above is what keeps that bound. But it is a defect, and this is its
// record. The desired behaviour is the Kotlin's @Disabled sibling, already carried by
// TestPostCloseDecideReuseIsRecovered in boot_e2e_db_test.go.
//
// KT: GrpcPerConnectionCatalogDbTest.kt#current post-close Decide behavior recovers the closed id
func TestCurrentPostCloseDecideBehaviorRecoversTheClosedId(t *testing.T) {
	f := newPerConnFixture(t)
	identity := f.validate()
	f.close(identity.GetConnectionId())

	recovered, err := f.decide(f.token, identity.GetConnectionId())
	if err != nil {
		t.Fatalf("Decide on a CLOSED id = %v; the DEFECT is that it succeeds, so an error here means the "+
			"behaviour changed and F29's record needs updating", err)
	}
	if recovered.GetBeforeDecide() == nil {
		t.Fatalf("Decide on a closed id = %v, want the recovery's before_decide", recovered)
	}
	if recovered.GetVerdict() != nil {
		t.Error("the recovery answered a VERDICT; the two outcome arms are structurally exclusive and a " +
			"recovered connection has measured nothing yet")
	}
	if len(recovered.GetBeforeDecide().GetCommands()) == 0 {
		t.Error("the recovery's before_decide carried NO commands, so the proxy has nothing to satisfy and " +
			"the connection can never become fresh")
	}
}

// TestUnknownConnectionDecideRecoversWithBeforeDecideOnlyAndNoAudit is case 11.
//
// 🔒 INV-A5-49 — A BEFORE_DECIDE IS NOT A DECISION, SO IT MUST NOT AUDIT. The audit trail is the record
// of what was decided about a statement; a refetch round-trip decided nothing. Auditing it would fill
// the chain with rows carrying no verdict and make "how many times was this statement denied"
// unanswerable — and every proxy reconnect would append noise to a hash chain an auditor walks.
//
// KT: GrpcPerConnectionCatalogDbTest.kt#unknown connection Decide recovers with before-decide only and no audit
func TestUnknownConnectionDecideRecoversWithBeforeDecideOnlyAndNoAudit(t *testing.T) {
	f := newPerConnFixture(t)
	unknown := forgedID(4)

	before := f.auditCount()
	got, err := f.decide(f.token, unknown)
	if err != nil {
		t.Fatalf("Decide on an unknown id: %v", err)
	}
	if got.GetBeforeDecide() == nil || got.GetVerdict() != nil {
		t.Fatalf("Decide on an unknown id = %v, want before_decide and NO verdict", got)
	}
	if len(got.GetBeforeDecide().GetCommands()) == 0 {
		t.Error("the recovery carried no commands")
	}
	if after := f.auditCount(); after != before {
		t.Errorf("audit rows %d → %d across a BEFORE_DECIDE; it decided nothing and must audit nothing "+
			"(INV-A5-49)", before, after)
	}
}

// TestRealRestartRecoversTheOriginalIdAndTokenThenAnchorsThePrincipal is case 10, and it is the case the
// recovery defect exists to serve — so it is the one that says the defect is not simply removable.
//
// The control plane is restarted for real: a NEW [core.New] over the SAME database, behind a NEW gRPC
// server. The connection catalog is in-memory, so the restart genuinely forgets every live connection
// while the proxy is still holding its backend connection and its id.
//
// Three claims, in order:
//
//  1. Decide on the forgotten id RECOVERS — before_decide with commands, and NO audit row, because a
//     recovery decided nothing (INV-A5-49);
//  2. once the proxy answers those commands the very next Decide produces a VERDICT, i.e. the recovered
//     connection is a fully working one and not a permanent refetch loop;
//  3. 🔒 the recovered connection is ANCHORED TO THE PRINCIPAL the token resolved to — a different
//     principal presenting the same id is FAILED_PRECONDITION. This is what bounds the blast radius of
//     the recovery: an attacker replaying an id gets a connection bound to THEIR OWN identity.
//
// KT: GrpcPerConnectionCatalogDbTest.kt#real restart recovers original id and token then anchors the principal
func TestRealRestartRecoversTheOriginalIdAndTokenThenAnchorsThePrincipal(t *testing.T) {
	f := newPerConnFixture(t)
	identity := f.validate()
	f.satisfyOnOpen(identity)
	connID := identity.GetConnectionId()

	// ---- the restart: a brand-new core (so a brand-new, EMPTY ConnectionCatalog) over the same pool,
	// behind a brand-new server. The Kotlin does exactly this: `core = ControlPlaneCore(dataSource)`.
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	fresh, err := core.New(f.b.app.Db, core.Options{Log: discard})
	if err != nil {
		t.Fatalf("rebuild the core: %v", err)
	}
	if fresh.ConnectionCatalog.Find(datasource.ConnectionID(connID)) != nil {
		t.Fatal("premise failed: the rebuilt core already knows the connection, so nothing is being recovered")
	}
	restarted := grpcsvc.NewServer(0, grpcsvc.NewService(fresh, 30*time.Second, discard), nil, discard)
	if err := restarted.Start(); err != nil {
		t.Fatalf("restart the gRPC server: %v", err)
	}
	defer restarted.Shutdown()

	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", restarted.BoundPort()),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial the restarted server: %v", err)
	}
	defer func() { _ = conn.Close() }()
	client := pb.NewControlPlaneClient(conn)

	decide := func(tok string) (*pb.WireDecision, error) {
		return client.Decide(context.Background(), &pb.DecisionRequest{
			Token: tok, DatasourceName: f.ds, ConnectionId: connID,
			Sql: "select 1", SearchPath: []string{e2eSchema},
		})
	}

	// ---- 1. the recovery, and no audit row for it.
	beforeAudit := f.auditCount()
	recovered, err := decide(f.token)
	if err != nil {
		t.Fatalf("Decide after the restart: %v", err)
	}
	if recovered.GetBeforeDecide() == nil || recovered.GetVerdict() != nil {
		t.Fatalf("Decide after the restart = %v, want before_decide and no verdict", recovered)
	}
	if len(recovered.GetBeforeDecide().GetCommands()) == 0 {
		t.Fatal("the recovery carried no commands, so the proxy cannot make the connection fresh")
	}
	if after := f.auditCount(); after != beforeAudit {
		t.Errorf("audit rows %d → %d across a recovery before_decide, want unchanged (INV-A5-49)", beforeAudit, after)
	}

	// ---- 2. answer them, and the next Decide is a verdict.
	for i, cmd := range recovered.GetBeforeDecide().GetCommands() {
		schema := cmd.GetRefetch().GetSchema()
		if _, err := client.PushSchemaFragment(context.Background(), &pb.SchemaFragmentPush{
			ConnectionId: connID, DatasourceName: f.ds, Schema: schema,
			ContentHash: []byte("restart:" + schema), BackendGeneration: uint64(100 + i),
		}); err != nil {
			t.Fatalf("push %s after the restart: %v", schema, err)
		}
	}
	verdict, err := decide(f.token)
	if err != nil {
		t.Fatalf("Decide after satisfying the recovery: %v", err)
	}
	if verdict.GetVerdict() == nil {
		t.Fatalf("Decide after satisfying the recovery = %v, want a VERDICT — a recovered connection must "+
			"become a working one, not a permanent refetch loop", verdict)
	}

	// ---- 3. and it is anchored to the principal.
	issued, err := fresh.TokenStore.Issue(
		context.Background(), f.b.app.Db.Pool, token.KindUser, "restart-other@example.com", nil, nil, 3600)
	if err != nil {
		t.Fatalf("issue the other principal's token: %v", err)
	}
	if _, err := decide(issued.Token); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("a DIFFERENT principal on the recovered id = %v, want FAILED_PRECONDITION — the recovery "+
			"binds to the freshly-resolved token, which is what bounds its blast radius", status.Code(err))
	}
}
