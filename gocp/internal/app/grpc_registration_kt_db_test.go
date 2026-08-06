package app_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
)

// ---------------------------------------------------------------------------------------------
// PORT of `GrpcRegistrationHandlerDbTest` — 22 cases over a real Postgres, a real ControlPlaneCore
// and a real gRPC server (docs/datasource-registration.md).
//
// THREE THEMES, and each one is a fail-closed rule rather than a convenience:
//
//  1. THE ENGINE IS IMMUTABLE. A datasource's engine decides how every statement is parsed and
//     classified, so flipping it under a live catalog would reinterpret stored columns against the
//     wrong dialect. Register REFUSES the change (FAILED_PRECONDITION) and — the part that is easy to
//     get wrong — must leave EVERY field and the catalog untouched, not just the engine.
//  2. THE ADVERTISED TLS POSTURE IS THE CP/pmon CONTRACT. `advertiseWireTls` is what makes pmon refuse
//     a plaintext downgrade, and `advertiseCertChain` is what clients verify against. A field present
//     in the row but absent from the response is a silent TLS downgrade for every brokered connection.
//  3. A CATALOG IS ONLY VALID FOR THE TARGET IT WAS READ FROM. Retargeting `db_name` INVALIDATES it;
//     re-registering the same target PRESERVES it. Keeping a stale catalog across a retarget would
//     authorize statements against columns that no longer exist.
// ---------------------------------------------------------------------------------------------

// selfSignedChain / caIssuedLeafAlone are the Kotlin's two PEM fixtures. The exact bytes do not matter
// to these cases — what matters is that one is a chain the control plane cannot vouch for, since
// storing rather than refusing it is the behaviour under test (case 5).
const selfSignedChain = `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKZ0Zm9ycmVnMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCXBt
LXByb3h5MB4XDTI2MDEwMTAwMDAwMFoXDTI3MDEwMTAwMDAwMFowFDESMBAGA1UE
AwwJcG0tcHJveHkwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAy2n0Ck1kZW1vLXNl
bGYtc2lnbmVkLWNlcnQtZm9yLXVuaXQtdGVzdHMtb25seS1ub3QtYS1yZWFsLWtl
eS0wMDABAgMBAAEwDQYJKoZIhvcNAQELBQADQQBmYWtlLXNpZ25hdHVyZS1mb3It
dGVzdHMtb25seS1kb2VzLW5vdC12ZXJpZnktYW5kLW5ldmVyLXNob3VsZC0wMDA=
-----END CERTIFICATE-----
`

const caIssuedLeafAlone = `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKZ0Y2FsZWFmMA0GCSqGSIb3DQEBCwUAMBoxGDAWBgNVBAMMD1Rl
c3QgUHJpdmF0ZSBDQTAeFw0yNjAxMDEwMDAwMDBaFw0yNzAxMDEwMDAwMDBaMBQx
EjAQBgNVBAMMCXBtLXByb3h5MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMtp9ApN
ZGVtby1jYS1pc3N1ZWQtbGVhZi1hbG9uZS1mb3ItdW5pdC10ZXN0cy1vbmx5LW5v
dC1yZWFsLTAwMDABAgMBAAEwDQYJKoZIhvcNAQELBQADQQBmYWtlLXNpZ25hdHVy
ZS1mb3ItdGVzdHMtb25seS1kb2VzLW5vdC12ZXJpZnktYW5kLW5ldmVyLXNob3Vs
ZC0wMDA=
-----END CERTIFICATE-----
`

type regFixture struct {
	t   *testing.T
	b   *bootedApp
	ctx context.Context
}

func newRegFixture(t *testing.T) *regFixture {
	t.Helper()
	return &regFixture{t: t, b: bootE2E(t, nil), ctx: context.Background()}
}

func (f *regFixture) register(req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	return f.b.client.Register(f.ctx, req)
}

func (f *regFixture) mustRegister(req *pb.RegisterRequest) *pb.RegisterResponse {
	f.t.Helper()
	resp, err := f.register(req)
	if err != nil {
		f.t.Fatalf("Register(%s): %v", req.GetName(), err)
	}
	return resp
}

func (f *regFixture) pushCatalog(req *pb.CatalogRequest) (*pb.CatalogResponse, error) {
	return f.b.client.PushCatalog(f.ctx, req)
}

func (f *regFixture) mustPush(req *pb.CatalogRequest) *pb.CatalogResponse {
	f.t.Helper()
	ack, err := f.pushCatalog(req)
	if err != nil {
		f.t.Fatalf("PushCatalog(%s): %v", req.GetDatasourceName(), err)
	}
	return ack
}

func (f *regFixture) byName(name string) datasource.Datasource {
	f.t.Helper()
	ds, found, err := f.b.app.Core.DatasourceStore.GetByName(f.ctx, name)
	if err != nil || !found {
		f.t.Fatalf("GetByName(%s) = found %v, err %v", name, found, err)
	}
	return ds
}

func (f *regFixture) absent(name string) bool {
	f.t.Helper()
	_, found, err := f.b.app.Core.DatasourceStore.GetByName(f.ctx, name)
	if err != nil {
		f.t.Fatalf("GetByName(%s): %v", name, err)
	}
	return !found
}

func (f *regFixture) catalog(id int64) []datasource.CatalogColumn {
	f.t.Helper()
	cols, err := f.b.app.Core.DatasourceStore.Catalog(f.ctx, id)
	if err != nil {
		f.t.Fatalf("Catalog(%d): %v", id, err)
	}
	return cols
}

func (f *regFixture) countNamed(name string) int {
	f.t.Helper()
	all, err := f.b.app.Core.DatasourceStore.List(f.ctx)
	if err != nil {
		f.t.Fatalf("List: %v", err)
	}
	n := 0
	for _, d := range all {
		if d.Name == name {
			n++
		}
	}
	return n
}

func col(schema, table, column, dataType string, ordinal int32, nullable bool) *pb.Column {
	return &pb.Column{
		Schema: schema, Table: table, Column: column,
		DataType: dataType, Ordinal: ordinal, Nullable: nullable,
	}
}

// --- 1-6: creation, the advertised posture, idempotence -------------------------------------------

// KT: GrpcRegistrationHandlerDbTest.kt#register self-creates a datasource by name with no service credential
func TestRegisterSelfCreatesADatasourceByName(t *testing.T) {
	f := newRegFixture(t)
	resp := f.mustRegister(&pb.RegisterRequest{
		Name: "reg-new", Engine: enginepb.Engine_POSTGRES,
		Host: "db.internal", Port: 5432, DbName: "app", Tags: []string{"system:development"},
	})
	if resp.GetName() != "reg-new" {
		t.Errorf("response name = %q, want reg-new", resp.GetName())
	}
	ds := f.byName("reg-new")
	if ds.Engine != datasource.EnginePostgres {
		t.Errorf("engine = %q, want postgres", ds.Engine)
	}
	if ds.Host != "db.internal" || ds.Port != 5432 || ds.DBName != "app" {
		t.Errorf("target = %s:%d/%s, want db.internal:5432/app", ds.Host, ds.Port, ds.DBName)
	}
	if len(ds.Tags) != 1 || ds.Tags[0] != "system:development" {
		t.Errorf("tags = %v, want [system:development]", ds.Tags)
	}
}

// KT: GrpcRegistrationHandlerDbTest.kt#register persists the advertised proxy address and cert chain and preserves them on a blank re-register
//
// 🔒 THE CHAIN MUST REACH THE DATASOURCE RESPONSE, not just the row — pmon reads it from there, so a
// field stored but not returned is a silent TLS downgrade for every brokered connection.
//
// 🔒 The blank re-register is the COALESCE upsert: a bare admin re-seed, or a transient read on the
// proxy, must not wipe what a proxy previously advertised.
func TestRegisterPersistsTheAdvertisedAddressAndChain(t *testing.T) {
	f := newRegFixture(t)
	f.mustRegister(&pb.RegisterRequest{
		Name: "reg-adv", Engine: enginepb.Engine_MYSQL, Host: "db.internal", Port: 3306, DbName: "app",
		AdvertiseAddr: "proxy.example.ts.net:6033", AdvertiseCertChain: strptr(selfSignedChain),
		AdvertiseWireTls: true,
	})
	ds := f.byName("reg-adv")
	if ds.AdvertiseAddr == nil || *ds.AdvertiseAddr != "proxy.example.ts.net:6033" {
		t.Errorf("advertiseAddr = %v, want proxy.example.ts.net:6033", ds.AdvertiseAddr)
	}
	if !ds.AdvertiseWireTls {
		t.Error("advertiseWireTls must persist; pmon refuses a plaintext downgrade on it")
	}
	if ds.AdvertiseCertChain == nil || *ds.AdvertiseCertChain != selfSignedChain {
		t.Error("advertiseCertChain must be on the datasource the API returns, not only in the row")
	}
	chain, err := f.b.app.Core.DatasourceStore.WireCertChain(f.ctx, ds.ID)
	if err != nil || chain == nil || *chain != selfSignedChain {
		t.Errorf("WireCertChain = %v (err %v), want the stored chain", chain, err)
	}

	f.mustRegister(&pb.RegisterRequest{
		Name: "reg-adv", Engine: enginepb.Engine_MYSQL, Host: "db2", Port: 3307, DbName: "app",
		AdvertiseWireTls: true,
	})
	ds2 := f.byName("reg-adv")
	if ds2.AdvertiseAddr == nil || *ds2.AdvertiseAddr != "proxy.example.ts.net:6033" {
		t.Errorf("a blank re-register wiped advertiseAddr: %v", ds2.AdvertiseAddr)
	}
	if ds2.AdvertiseCertChain == nil || *ds2.AdvertiseCertChain != selfSignedChain {
		t.Error("a blank re-register wiped advertiseCertChain; the COALESCE upsert must keep it")
	}
}

// KT: GrpcRegistrationHandlerDbTest.kt#turning wire TLS off clears a previously advertised chain
//
// 🔒 THE STATE TRANSITION AN OPERATOR ACTUALLY PERFORMS. If the stored chain survived TLS being turned
// off (or a rotation onto a publicly-trusted certificate), clients would keep verifying against dead
// roots and every connection would fail — and the console would keep offering a stale download.
func TestTurningWireTLSOffClearsThePreviouslyAdvertisedChain(t *testing.T) {
	f := newRegFixture(t)
	f.mustRegister(&pb.RegisterRequest{
		Name: "reg-tls-off", Engine: enginepb.Engine_MYSQL, Host: "h", Port: 3306, DbName: "d",
		AdvertiseCertChain: strptr(selfSignedChain), AdvertiseWireTls: true,
	})
	if ds := f.byName("reg-tls-off"); ds.AdvertiseCertChain == nil {
		t.Fatal("the chain was not stored, so the clearing assertion below would be vacuous")
	}

	f.mustRegister(&pb.RegisterRequest{
		Name: "reg-tls-off", Engine: enginepb.Engine_MYSQL, Host: "h", Port: 3306, DbName: "d",
		AdvertiseWireTls: false,
	})
	off := f.byName("reg-tls-off")
	if off.AdvertiseWireTls {
		t.Error("the proxy said TLS is off, so the row must say so")
	}
	if off.AdvertiseCertChain != nil {
		t.Error("a datasource with TLS off must not keep advertising a chain — clients would verify " +
			"against roots the proxy no longer serves")
	}
	chain, err := f.b.app.Core.DatasourceStore.WireCertChain(f.ctx, off.ID)
	if err != nil {
		t.Fatalf("WireCertChain: %v", err)
	}
	if chain != nil {
		t.Error("the download route must have nothing to serve")
	}
}

// KT: GrpcRegistrationHandlerDbTest.kt#a proxy serving TLS without publishing a chain still reports the TLS requirement
//
// 🔒 PM_TLS_NO_ADVERTISE: a publicly-trusted certificate publishes nothing, but the REQUIREMENT must
// still reach pmon or its plaintext-downgrade refusal goes dead for exactly this deployment — and an
// attacker answering the greeting without CLIENT_SSL collects a live session token.
func TestAProxyServingTLSWithoutAChainStillReportsTheRequirement(t *testing.T) {
	f := newRegFixture(t)
	f.mustRegister(&pb.RegisterRequest{
		Name: "reg-public-tls", Engine: enginepb.Engine_MYSQL, Host: "h", Port: 3306, DbName: "d",
		AdvertiseAddr: "proxy.example.com:6033", AdvertiseWireTls: true,
	})
	ds := f.byName("reg-public-tls")
	if ds.AdvertiseCertChain != nil {
		t.Error("nothing was published, so there is no chain to store")
	}
	if !ds.AdvertiseWireTls {
		t.Error("TLS is served; a client must learn that even with no chain — a chain-only response " +
			"would silently permit a plaintext downgrade")
	}
}

// KT: GrpcRegistrationHandlerDbTest.kt#register stores a questionable chain rather than refusing the datasource
//
// 🔒 STORE, DO NOT REFUSE. A chain the control plane cannot vouch for is still stored and served:
// refusing would mean the datasource is never created — no catalog, every decision failing closed —
// which is far worse than one client reporting its own TLS error. The client verifies; it is the only
// party that can.
func TestRegisterStoresAQuestionableChainRatherThanRefusing(t *testing.T) {
	f := newRegFixture(t)
	f.mustRegister(&pb.RegisterRequest{
		Name: "reg-odd-chain", Engine: enginepb.Engine_MYSQL, Host: "h", Port: 3306, DbName: "d",
		AdvertiseCertChain: strptr(caIssuedLeafAlone), AdvertiseWireTls: true,
	})
	ds := f.byName("reg-odd-chain")
	if ds.AdvertiseCertChain == nil || *ds.AdvertiseCertChain != caIssuedLeafAlone {
		t.Errorf("advertiseCertChain = %v, want the questionable chain stored verbatim", ds.AdvertiseCertChain)
	}
}

// KT: GrpcRegistrationHandlerDbTest.kt#register is idempotent by name and updates advisory fields
func TestRegisterIsIdempotentByNameAndUpdatesAdvisoryFields(t *testing.T) {
	f := newRegFixture(t)
	f.mustRegister(&pb.RegisterRequest{
		Name: "reg-idem", Engine: enginepb.Engine_POSTGRES, Host: "old", Port: 1, DbName: "d",
	})
	f.mustRegister(&pb.RegisterRequest{
		Name: "reg-idem", Engine: enginepb.Engine_POSTGRES, Host: "new", Port: 3306, DbName: "d2",
		Tags: []string{"system:production"},
	})
	ds := f.byName("reg-idem")
	if ds.Engine != datasource.EnginePostgres {
		t.Errorf("engine = %q; a same-engine re-register keeps it", ds.Engine)
	}
	if ds.Host != "new" || ds.Port != 3306 || ds.DBName != "d2" {
		t.Errorf("advisory fields = %s:%d/%s, want new:3306/d2", ds.Host, ds.Port, ds.DBName)
	}
	if len(ds.Tags) != 1 || ds.Tags[0] != "system:production" {
		t.Errorf("tags = %v, want [system:production]", ds.Tags)
	}
	if n := f.countNamed("reg-idem"); n != 1 {
		t.Errorf("rows named reg-idem = %d, want 1 — an upsert, never a second row", n)
	}
}

// --- 7-10: the engine guard -----------------------------------------------------------------------

// KT: GrpcRegistrationHandlerDbTest.kt#register refuses an engine change FAILED_PRECONDITION and leaves the row untouched
//
// 🔒 NO FIELD IS TOUCHED BY A REJECTED REGISTER, not just the engine, and the catalog survives. A
// handler that rejected the engine but had already written host/port/db_name would leave the row
// describing a target its catalog was never read from.
func TestRegisterRefusesAnEngineChangeAndLeavesTheRowUntouched(t *testing.T) {
	f := newRegFixture(t)
	f.mustRegister(&pb.RegisterRequest{
		Name: "reg-engine-lock", Engine: enginepb.Engine_POSTGRES, Host: "h", Port: 5432, DbName: "d",
	})
	f.mustPush(&pb.CatalogRequest{
		DatasourceName: "reg-engine-lock", DefaultSchemas: []string{"public"},
		Columns: []*pb.Column{col("public", "t", "c", "text", 1, true)},
	})
	before := f.byName("reg-engine-lock")
	if before.CatalogSyncedAt == nil {
		t.Fatal("catalog_synced_at was not stamped by the push")
	}

	_, err := f.register(&pb.RegisterRequest{
		Name: "reg-engine-lock", Engine: enginepb.Engine_MYSQL, Host: "h2", Port: 3306, DbName: "d2",
	})
	if got := codeOf(t, err); got != codes.FailedPrecondition {
		t.Errorf("code = %s, want FAILED_PRECONDITION", got)
	}

	after := f.byName("reg-engine-lock")
	if after.Engine != datasource.EnginePostgres {
		t.Errorf("engine = %q; a rejected engine change must not mutate the row", after.Engine)
	}
	if after.Host != "h" || after.Port != 5432 || after.DBName != "d" {
		t.Errorf("target = %s:%d/%s, want the untouched h:5432/d — no field is written by a rejected "+
			"register", after.Host, after.Port, after.DBName)
	}
	if len(f.catalog(before.ID)) == 0 {
		t.Error("a rejected engine change must not invalidate the catalog")
	}
	if after.CatalogSyncedAt == nil || *after.CatalogSyncedAt != *before.CatalogSyncedAt {
		t.Errorf("catalog_synced_at %v → %v; it is retained on a rejected register",
			before.CatalogSyncedAt, after.CatalogSyncedAt)
	}
}

// KT: GrpcRegistrationHandlerDbTest.kt#concurrent first registrations with different engines cannot bypass the engine guard
//
// 🔒 EXACTLY ONE WINNER. Two first-registrations racing with DIFFERENT engines: the guard is atomic in
// the upsert, so one wins and the other is REJECTED rather than silently upserting over it. A
// read-then-write guard would let both through and the last writer would flip the engine.
func TestConcurrentFirstRegistrationsCannotBypassTheEngineGuard(t *testing.T) {
	f := newRegFixture(t)
	const name = "reg-race"

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, eng := range []enginepb.Engine{enginepb.Engine_POSTGRES, enginepb.Engine_MYSQL} {
		wg.Add(1)
		go func(i int, eng enginepb.Engine) {
			defer wg.Done()
			_, errs[i] = f.register(&pb.RegisterRequest{
				Name: name, Engine: eng, Host: "h", Port: 1, DbName: "d",
			})
		}(i, eng)
	}
	wg.Wait()

	winners, rejected := 0, 0
	for _, err := range errs {
		if err == nil {
			winners++
			continue
		}
		rejected++
		if got := codeOf(t, err); got != codes.FailedPrecondition {
			t.Errorf("loser code = %s, want FAILED_PRECONDITION", got)
		}
	}
	if winners != 1 || rejected != 1 {
		t.Errorf("winners=%d rejected=%d, want exactly 1 and 1 — the losing engine must be rejected, "+
			"not silently upserted", winners, rejected)
	}
	if n := f.countNamed(name); n != 1 {
		t.Errorf("rows named %s = %d, want 1 — never a silent flip", name, n)
	}
	if eng := f.byName(name).Engine; eng != datasource.EnginePostgres && eng != datasource.EngineMySQL {
		t.Errorf("surviving engine = %q, want the winner's intact", eng)
	}
}

// KT: GrpcRegistrationHandlerDbTest.kt#a row racing into an in-flight register cannot bypass the engine guard (cross-writer)
//
// 🔒 THE CROSS-WRITER RACE, and the reason the guard must live INSIDE the upsert. A second writer
// stages a conflicting row and commits it while `Register`'s prior read has already returned "absent".
// A read-then-write guard would then insert over it and flip the engine; the atomic guard rejects.
//
// The interleaving is made deterministic by waiting until Register is PARKED on its upsert, blocked on
// the staged row's lock — proof its read already ran. The DB-level block, not the poll interval, is the
// barrier.
func TestARowRacingIntoAnInFlightRegisterCannotBypassTheEngineGuard(t *testing.T) {
	f := newRegFixture(t)
	const name = "reg-cross-writer-race"

	tx, err := f.b.app.Db.Pool.Begin(f.ctx)
	if err != nil {
		t.Fatalf("begin staging tx: %v", err)
	}
	defer func() { _ = tx.Rollback(f.ctx) }()
	if _, err := tx.Exec(f.ctx,
		`INSERT INTO datasource (name, engine, host, port, db_name, tags)
		     VALUES ($1, 'postgres', 'h', 5432, 'app', '[]'::jsonb)`, name); err != nil {
		t.Fatalf("stage conflicting row: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := f.b.app.Core.DatasourceStore.Register(context.Background(),
			name, datasource.EngineMySQL, "h2", 3306, "app", nil, "127.0.0.1:3306", nil, false)
		done <- err
	}()

	f.awaitRegisterParkedOnUpsert()
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatalf("commit the raced-in row: %v", err)
	}

	regErr := <-done
	if regErr == nil {
		t.Fatal("a raced-in row must not let register silently flip the engine")
	}
	var conflict *datasource.EngineConflictError
	if !errors.As(regErr, &conflict) {
		t.Errorf("error = %v, want an EngineConflictError — the cross-writer race must be rejected by "+
			"the ATOMIC engine guard", regErr)
	}
	if eng := f.byName(name).Engine; eng != datasource.EnginePostgres {
		t.Errorf("engine = %q, want postgres — the raced-in engine survives intact", eng)
	}
	if n := f.countNamed(name); n != 1 {
		t.Errorf("rows named %s = %d, want 1", name, n)
	}
}

// awaitRegisterParkedOnUpsert blocks until an in-flight Register is waiting on the staged row's lock
// inside its ON CONFLICT upsert.
func (f *regFixture) awaitRegisterParkedOnUpsert() {
	f.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var parked int
		if err := f.b.app.Db.Pool.QueryRow(f.ctx,
			`SELECT count(*) FROM pg_stat_activity
			     WHERE datname = current_database()
			       AND wait_event_type = 'Lock'
			       AND query ILIKE '%insert into datasource%on conflict%'`).Scan(&parked); err != nil {
			f.t.Fatalf("poll pg_stat_activity: %v", err)
		}
		if parked > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.t.Fatal("register never parked on its upsert INSERT — the deterministic interleaving barrier " +
		"was not reached")
}

// KT: GrpcRegistrationHandlerDbTest.kt#admin update refuses an engine change and invalidates the catalog on a db_name retarget
//
// The ADMIN path carries the same two rules as register: the engine is immutable, and a db_name
// retarget invalidates the catalog. A guard on only the gRPC path would leave the console able to do
// what the proxy cannot.
func TestAdminUpdateRefusesAnEngineChangeAndInvalidatesOnRetarget(t *testing.T) {
	f := newRegFixture(t)
	ds, err := f.b.app.Core.DatasourceStore.Create(f.ctx, datasource.DatasourceInput{
		Name: "upd-engine-lock", Engine: "postgres", Host: "h", Port: 5432, DBName: "app",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	f.mustPush(&pb.CatalogRequest{
		DatasourceName: "upd-engine-lock", DefaultSchemas: []string{"public"},
		Columns: []*pb.Column{col("public", "t", "c", "text", 1, true)},
	})

	_, _, err = f.b.app.Core.DatasourceStore.Update(f.ctx, ds.ID, datasource.DatasourceInput{
		Name: "upd-engine-lock", Engine: "mysql", Host: "h", Port: 5432, DBName: "app",
	})
	var conflict *datasource.EngineConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("Update to a different engine = %v, want an EngineConflictError", err)
	}
	afterReject := f.byName("upd-engine-lock")
	if afterReject.Engine != datasource.EnginePostgres {
		t.Errorf("engine = %q; a rejected admin engine change must not mutate the row", afterReject.Engine)
	}
	if len(f.catalog(ds.ID)) == 0 {
		t.Error("a rejected engine change must not touch the catalog")
	}

	edited, found, err := f.b.app.Core.DatasourceStore.Update(f.ctx, ds.ID, datasource.DatasourceInput{
		Name: "upd-engine-lock", Engine: "postgres", Host: "h2", Port: 5432, DBName: "app2",
	})
	if err != nil || !found {
		t.Fatalf("Update: found %v, err %v", found, err)
	}
	if edited.Host != "h2" || edited.DBName != "app2" {
		t.Errorf("edited target = %s/%s, want h2/app2", edited.Host, edited.DBName)
	}
	if n := len(f.catalog(ds.ID)); n != 0 {
		t.Errorf("catalog rows = %d, want 0 — a db_name retarget via admin PUT must invalidate the "+
			"stale catalog", n)
	}
	if edited.CatalogSyncedAt != nil {
		t.Errorf("catalogSyncedAt = %v, want nil on invalidation", edited.CatalogSyncedAt)
	}
}

// --- 11-14: tags and argument validation ----------------------------------------------------------

// KT: GrpcRegistrationHandlerDbTest.kt#re-register with empty tags preserves the existing tags
func TestReRegisterWithEmptyTagsPreservesTheExistingTags(t *testing.T) {
	f := newRegFixture(t)
	f.mustRegister(&pb.RegisterRequest{
		Name: "reg-tags", Engine: enginepb.Engine_POSTGRES, Host: "h", Port: 1, DbName: "d",
		Tags: []string{"system:development"},
	})
	f.mustRegister(&pb.RegisterRequest{
		Name: "reg-tags", Engine: enginepb.Engine_POSTGRES, Host: "h2", Port: 1, DbName: "d",
	})
	if tags := f.byName("reg-tags").Tags; len(tags) != 1 || tags[0] != "system:development" {
		t.Errorf("tags = %v, want [system:development] preserved across a tagless re-register", tags)
	}
}

// KT: GrpcRegistrationHandlerDbTest.kt#register accepts a free-form tag bag including both postures and custom tags
func TestRegisterAcceptsAFreeFormTagBag(t *testing.T) {
	f := newRegFixture(t)
	want := []string{"system:development", "system:production", "team-x"}
	f.mustRegister(&pb.RegisterRequest{
		Name: "reg-freeform", Engine: enginepb.Engine_POSTGRES, Host: "h", Port: 1, DbName: "d",
		Tags: want,
	})
	got := f.byName("reg-freeform").Tags
	if len(got) != len(want) {
		t.Fatalf("tags = %v, want %v stored verbatim", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tags = %v, want %v — a free-form bag is stored verbatim, both postures and "+
				"custom tags alike", got, want)
			break
		}
	}
}

// KT: GrpcRegistrationHandlerDbTest.kt#register rejects an unspecified engine INVALID_ARGUMENT
func TestRegisterRejectsAnUnspecifiedEngine(t *testing.T) {
	f := newRegFixture(t)
	_, err := f.register(&pb.RegisterRequest{Name: "reg-bad", Host: "h", Port: 1, DbName: "d"})
	if got := codeOf(t, err); got != codes.InvalidArgument {
		t.Errorf("code = %s, want INVALID_ARGUMENT", got)
	}
	if !f.absent("reg-bad") {
		t.Error("a rejected register must not create a row")
	}
}

// KT: GrpcRegistrationHandlerDbTest.kt#register rejects a blank name INVALID_ARGUMENT
func TestRegisterRejectsABlankName(t *testing.T) {
	f := newRegFixture(t)
	_, err := f.register(&pb.RegisterRequest{
		Name: "", Engine: enginepb.Engine_POSTGRES, Host: "h", Port: 1, DbName: "d",
	})
	if got := codeOf(t, err); got != codes.InvalidArgument {
		t.Errorf("code = %s, want INVALID_ARGUMENT", got)
	}
}

// --- 15-22: pushCatalog -------------------------------------------------------------------------

// KT: GrpcRegistrationHandlerDbTest.kt#pushCatalog for an unknown datasource is NOT_FOUND
func TestPushCatalogForAnUnknownDatasourceIsNotFound(t *testing.T) {
	f := newRegFixture(t)
	_, err := f.pushCatalog(&pb.CatalogRequest{DatasourceName: "never-registered"})
	if got := codeOf(t, err); got != codes.NotFound {
		t.Errorf("code = %s, want NOT_FOUND", got)
	}
}

// KT: GrpcRegistrationHandlerDbTest.kt#pushCatalog stores the proxy-pushed columns and default schemas
func TestPushCatalogStoresColumnsAndDefaultSchemas(t *testing.T) {
	f := newRegFixture(t)
	f.mustRegister(&pb.RegisterRequest{
		Name: "reg-cat", Engine: enginepb.Engine_POSTGRES, Host: "h", Port: 1, DbName: "d",
	})
	ack := f.mustPush(&pb.CatalogRequest{
		DatasourceName: "reg-cat", DefaultSchemas: []string{"pg_catalog", "public"},
		EngineVersion: "PostgreSQL 16.3 (aurora 16.3)",
		Columns: []*pb.Column{
			col("public", "users", "id", "integer", 1, false),
			col("public", "users", "rrn", "text", 2, true),
		},
	})
	if ack.GetColumns() != 2 {
		t.Errorf("ack columns = %d, want 2", ack.GetColumns())
	}
	ds := f.byName("reg-cat")
	if len(ds.DefaultSchemas) != 2 || ds.DefaultSchemas[0] != "pg_catalog" || ds.DefaultSchemas[1] != "public" {
		t.Errorf("defaultSchemas = %v, want [pg_catalog public]", ds.DefaultSchemas)
	}
	if ds.EngineVersion == nil || *ds.EngineVersion != "PostgreSQL 16.3 (aurora 16.3)" {
		t.Errorf("engineVersion = %v; the proxy-pushed version is stored for system-classification",
			ds.EngineVersion)
	}
	if ds.CatalogSyncedAt == nil {
		t.Error("catalog_synced_at is stamped on push")
	}
	var rrn *datasource.CatalogColumn
	for i := range f.catalog(ds.ID) {
		c := f.catalog(ds.ID)[i]
		if c.Table == "users" && c.Column == "rrn" {
			rrn = &c
			break
		}
	}
	if rrn == nil {
		t.Fatal("the pushed rrn column is not in the stored catalog")
	}
	if rrn.DataType != "text" {
		t.Errorf("dataType = %q, want text", rrn.DataType)
	}
	if rrn.SQLType != "VARCHAR" {
		t.Errorf("sqlType = %q, want VARCHAR — the control plane derives it from the raw data_type",
			rrn.SQLType)
	}
}

// KT: GrpcRegistrationHandlerDbTest.kt#re-register with the same target preserves the catalog and updates advisory fields
func TestReRegisterWithTheSameTargetPreservesTheCatalog(t *testing.T) {
	f := newRegFixture(t)
	ds, err := f.b.app.Core.DatasourceStore.Create(f.ctx, datasource.DatasourceInput{
		Name: "reg-preserve", Engine: "postgres", Host: "h", Port: 5432, DBName: "app",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	f.mustPush(&pb.CatalogRequest{
		DatasourceName: "reg-preserve", DefaultSchemas: []string{"public"},
		Columns: []*pb.Column{col("public", "keep", "c", "text", 1, true)},
	})
	f.mustRegister(&pb.RegisterRequest{
		Name: "reg-preserve", Engine: enginepb.Engine_POSTGRES, Host: "h2", Port: 5432, DbName: "app",
	})

	after := f.byName("reg-preserve")
	if after.Host != "h2" {
		t.Errorf("host = %q, want h2 — the advisory field is still updated", after.Host)
	}
	kept := false
	for _, c := range f.catalog(ds.ID) {
		if c.Table == "keep" {
			kept = true
		}
	}
	if !kept {
		t.Error("a same-target re-register must not wipe the catalog")
	}
	if after.CatalogSyncedAt == nil {
		t.Error("catalog_synced_at is retained on a same-target re-register")
	}
}

// KT: GrpcRegistrationHandlerDbTest.kt#re-register to a different schema invalidates the stale catalog (fail-closed)
//
// 🔒 FAIL-CLOSED. A catalog is only valid for the target it was read from; keeping it across a
// retarget would authorize statements against columns that no longer exist.
func TestReRegisterToADifferentSchemaInvalidatesTheStaleCatalog(t *testing.T) {
	f := newRegFixture(t)
	f.mustRegister(&pb.RegisterRequest{
		Name: "reg-retarget", Engine: enginepb.Engine_POSTGRES, Host: "h", Port: 5432, DbName: "db_a",
	})
	f.mustPush(&pb.CatalogRequest{
		DatasourceName: "reg-retarget", DefaultSchemas: []string{"public"},
		Columns: []*pb.Column{col("public", "old_table", "c", "text", 1, true)},
	})
	ds := f.byName("reg-retarget")
	if len(f.catalog(ds.ID)) == 0 {
		t.Fatal("the catalog was not stored, so the invalidation assertion would be vacuous")
	}

	f.mustRegister(&pb.RegisterRequest{
		Name: "reg-retarget", Engine: enginepb.Engine_POSTGRES, Host: "h", Port: 5432, DbName: "db_b",
	})
	after := f.byName("reg-retarget")
	if after.DBName != "db_b" {
		t.Errorf("dbName = %q, want db_b", after.DBName)
	}
	if n := len(f.catalog(ds.ID)); n != 0 {
		t.Errorf("catalog rows = %d, want 0 — a retarget must invalidate the stale catalog", n)
	}
	if after.CatalogSyncedAt != nil {
		t.Errorf("catalogSyncedAt = %v, want nil on invalidation", after.CatalogSyncedAt)
	}
	if len(after.DefaultSchemas) != 0 {
		t.Errorf("defaultSchemas = %v, want empty on invalidation", after.DefaultSchemas)
	}
}

// KT: GrpcRegistrationHandlerDbTest.kt#pushCatalog rolls back a mid-batch failure and keeps the prior catalog
//
// 🔒 ALL-OR-NOTHING. The push is delete-then-insert, so a mid-batch failure that was not rolled back
// would leave the datasource with a PARTIAL catalog — worse than either the old one or the new one,
// because A6 would then authorize against a subset it believes is complete.
func TestPushCatalogRollsBackAMidBatchFailure(t *testing.T) {
	f := newRegFixture(t)
	f.mustRegister(&pb.RegisterRequest{
		Name: "reg-rollback", Engine: enginepb.Engine_POSTGRES, Host: "h", Port: 1, DbName: "d",
	})
	f.mustPush(&pb.CatalogRequest{
		DatasourceName: "reg-rollback", DefaultSchemas: []string{"public"},
		Columns: []*pb.Column{col("public", "orig", "c", "text", 1, true)},
	})
	ds := f.byName("reg-rollback")

	// Two rows with the same (schema, table, column) identity violate the catalog's unique key.
	_, err := f.pushCatalog(&pb.CatalogRequest{
		DatasourceName: "reg-rollback", DefaultSchemas: []string{"public"},
		Columns: []*pb.Column{
			col("public", "dup", "x", "text", 1, true),
			col("public", "dup", "x", "text", 2, true),
		},
	})
	if err == nil {
		t.Fatal("a duplicate-column push must fail, not silently succeed")
	}

	cols := f.catalog(ds.ID)
	sawOrig, sawDup := false, false
	for _, c := range cols {
		if c.Table == "orig" {
			sawOrig = true
		}
		if c.Table == "dup" {
			sawDup = true
		}
	}
	if !sawOrig {
		t.Error("the prior catalog must survive a rolled-back push")
	}
	if sawDup {
		t.Error("no partial rows from the failed push may remain")
	}
}

// KT: GrpcRegistrationHandlerDbTest.kt#pushCatalog replaces the prior catalog (delete-then-insert)
func TestPushCatalogReplacesThePriorCatalog(t *testing.T) {
	f := newRegFixture(t)
	f.mustRegister(&pb.RegisterRequest{
		Name: "reg-replace", Engine: enginepb.Engine_POSTGRES, Host: "h", Port: 1, DbName: "d",
	})
	f.mustPush(&pb.CatalogRequest{
		DatasourceName: "reg-replace", DefaultSchemas: []string{"public"},
		Columns: []*pb.Column{
			col("public", "a", "x", "integer", 1, true),
			col("public", "b", "y", "integer", 1, true),
		},
	})
	ack := f.mustPush(&pb.CatalogRequest{
		DatasourceName: "reg-replace", DefaultSchemas: []string{"public"},
		Columns: []*pb.Column{col("public", "a", "x", "integer", 1, true)},
	})
	if ack.GetColumns() != 1 {
		t.Errorf("ack columns = %d, want 1", ack.GetColumns())
	}
	ds := f.byName("reg-replace")
	aCount, sawB := 0, false
	for _, c := range f.catalog(ds.ID) {
		if c.Table == "a" {
			aCount++
		}
		if c.Table == "b" {
			sawB = true
		}
	}
	if sawB {
		t.Error("the replaced catalog must not retain table b")
	}
	if aCount != 1 {
		t.Errorf("table a columns = %d, want 1", aCount)
	}
}

// KT: GrpcRegistrationHandlerDbTest.kt#pushCatalog replacement preserves classification for a surviving column identity
//
// 🔒 CLASSIFICATION SURVIVES A REPLACEMENT. Classifications are keyed on the column IDENTITY, not on
// the catalog row's id, so a delete-then-insert must not orphan them. If it did, every proxy catalog
// refresh would silently unclassify every PII column — masking would stop and nobody would be told.
func TestPushCatalogReplacementPreservesClassification(t *testing.T) {
	f := newRegFixture(t)
	f.mustRegister(&pb.RegisterRequest{
		Name: "reg-replace-classified", Engine: enginepb.Engine_POSTGRES, Host: "h", Port: 1, DbName: "d",
	})
	f.mustPush(&pb.CatalogRequest{
		DatasourceName: "reg-replace-classified", DefaultSchemas: []string{"public"},
		Columns: []*pb.Column{
			col("public", "users", "rrn", "text", 1, false),
			col("public", "users", "display_name", "text", 2, true),
		},
	})
	ds := f.byName("reg-replace-classified")
	if _, err := f.b.app.Db.Pool.Exec(f.ctx,
		`INSERT INTO column_classification (datasource_id, schema_name, table_name, column_name, tags)
		     VALUES ($1, 'public', 'users', 'rrn', '["pii","government-id"]'::jsonb)`, ds.ID); err != nil {
		t.Fatalf("classify rrn: %v", err)
	}

	// The replacement keeps rrn's identity, retypes display_name, and adds a column.
	f.mustPush(&pb.CatalogRequest{
		DatasourceName: "reg-replace-classified", DefaultSchemas: []string{"public"},
		Columns: []*pb.Column{
			col("public", "users", "rrn", "text", 1, false),
			col("public", "users", "display_name", "character varying", 2, false),
			col("public", "users", "created_at", "timestamp", 3, false),
		},
	})

	var rrn *datasource.CatalogColumn
	cols := f.catalog(ds.ID)
	for i := range cols {
		if cols[i].Schema == "public" && cols[i].Table == "users" && cols[i].Column == "rrn" {
			rrn = &cols[i]
		}
	}
	if rrn == nil {
		t.Fatal("rrn is missing from the replaced catalog")
	}
	if rrn.Classification == nil {
		t.Fatal("the surviving rrn identity lost its classification; every catalog refresh would " +
			"silently unclassify every PII column")
	}
	tags := rrn.Classification.Tags
	if len(tags) != 2 || tags[0] != "pii" || tags[1] != "government-id" {
		t.Errorf("classification tags = %v, want [pii government-id]", tags)
	}
}

func strptr(s string) *string { return &s }

// KT: GrpcRegistrationHandlerDbTest.kt#pushCatalog re-measures the enforcement catalog, not only the stored one
//
// 🔒 A PUSH MUST TOUCH BOTH CATALOGS. `pushCatalog` writes the STORED catalog, but enforcement reads a
// per-connection ENFORCEMENT catalog, and a push that updated only the former would leave live
// connections deciding against content the proxy has already replaced. Advancing the measured-at stamp
// is the observable proof the enforcement side was re-read.
//
// The adopter half is the consequence that matters operationally: because the ambient push refreshed
// the enforcement entry, a connection opening afterwards with adoptHeldContent has NOTHING to fetch —
// no round-trip, and it sees the pushed columns immediately.
func TestPushCatalogReMeasuresTheEnforcementCatalog(t *testing.T) {
	f := newRegFixture(t)
	f.mustRegister(&pb.RegisterRequest{
		Name: "reg-ambient", Engine: enginepb.Engine_MYSQL, Host: "h", Port: 1, DbName: "app",
	})
	ds := f.byName("reg-ambient")

	opened := f.b.app.Core.ConnectionCatalog.Open(datasource.Binding{
		DatasourceName: ds.Name, Principal: "p", TokenKind: "USER",
	}, []string{"app"}, false)

	applied := f.b.app.Core.ConnectionCatalog.ApplyPush(&pb.SchemaFragmentPush{
		ConnectionId:      []byte(opened.ConnectionID),
		DatasourceName:    ds.Name,
		Schema:            "app",
		ContentHash:       []byte("h1"),
		BackendGeneration: 1,
		Columns:           []*pb.Column{col("app", "users", "id", "bigint", 1, false)},
	}, ds)
	if _, ok := applied.(datasource.Applied); !ok {
		t.Fatalf("ApplyPush = %T, want Applied", applied)
	}
	before, ok := f.b.app.Core.ConnectionCatalog.MeasuredNanosFor(ds.Name, "app")
	if !ok {
		t.Fatal("no measured-at stamp after the fragment push")
	}

	f.mustPush(&pb.CatalogRequest{
		DatasourceName: ds.Name, DefaultSchemas: []string{"app"},
		Columns: []*pb.Column{col("app", "users", "id", "bigint", 1, false)},
	})

	after, ok := f.b.app.Core.ConnectionCatalog.MeasuredNanosFor(ds.Name, "app")
	if !ok {
		t.Fatal("the enforcement entry must SURVIVE the push, not be dropped")
	}
	if after <= before {
		t.Errorf("measured-at %d → %d; pushCatalog must record its read against the ENFORCEMENT "+
			"catalog, not only the stored one", before, after)
	}

	adopter := f.b.app.Core.ConnectionCatalog.Open(datasource.Binding{
		DatasourceName: ds.Name, Principal: "later", TokenKind: "USER",
	}, []string{"app"}, true)
	if len(adopter.OnOpen) != 0 {
		t.Errorf("adopter onOpen = %v, want empty — the ambient push must leave nothing to fetch",
			adopter.OnOpen)
	}
	conn := f.b.app.Core.ConnectionCatalog.Find(adopter.ConnectionID)
	if conn == nil {
		t.Fatal("the adopter connection vanished")
	}
	rows := f.b.app.Core.ConnectionCatalog.StructuralRows(conn)
	if len(rows) != 1 || rows[0].Column != "id" {
		cols := make([]string, len(rows))
		for i, r := range rows {
			cols[i] = r.Column
		}
		t.Errorf("adopted columns = %v, want [id]", cols)
	}
}
