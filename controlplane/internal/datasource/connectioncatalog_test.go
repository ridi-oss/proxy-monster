package datasource

import (
	"errors"
	"io"
	"sort"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
	"google.golang.org/grpc/codes"
)

// Port of PerConnectionCatalogStateTest.kt (402 LOC, 17 cases) — 05-datasources-catalog.md §9:
// "This is the porting critical path for A5. All 17 cases need only the registry, a fake clock and a
// fake RNG — no Docker, no Postgres, no analyzer. They cover 16 of the area's invariants directly."

func testDatasource(t *testing.T) Datasource {
	t.Helper()
	lower := int32(0)
	version := "8.4.0"
	return Datasource{
		ID: 1, Name: "ds", Engine: EngineMySQL, Host: "", Port: 0, DBName: "app",
		DefaultSchemas: []string{"app"}, MysqlLowerCaseTableNames: &lower, EngineVersion: &version,
	}
}

type pushOpt func(*pb.SchemaFragmentPush)

func withGeneration(g uint64) pushOpt { return func(p *pb.SchemaFragmentPush) { p.BackendGeneration = g } }
func withUnchanged() pushOpt {
	return func(p *pb.SchemaFragmentPush) { p.Unchanged = true; p.Columns = nil }
}
func withColumnName(name string) pushOpt {
	return func(p *pb.SchemaFragmentPush) {
		for _, c := range p.Columns {
			c.Column = name
		}
	}
}

// push mirrors the Kotlin fixture's `push(...)` helper, including its defaults (generation = 1, one
// `users.id bigint NOT NULL` column at ordinal 1).
func push(ds Datasource, opened OpenConnection, schema, hash string, opts ...pushOpt) *pb.SchemaFragmentPush {
	p := &pb.SchemaFragmentPush{
		ConnectionId:      opened.ConnectionID.Bytes(),
		DatasourceName:    ds.Name,
		Schema:            schema,
		ContentHash:       []byte(hash),
		BackendGeneration: 1,
		Columns: []*pb.Column{{
			Schema: schema, Table: "users", Column: "id", DataType: "bigint", Ordinal: 1, Nullable: false,
		}},
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

func mustApplied(t *testing.T, res CatalogMutationResult) Applied {
	t.Helper()
	applied, ok := res.(Applied)
	if !ok {
		t.Fatalf("expected Applied, got %#v", res)
	}
	return applied
}

func mustRejected(t *testing.T, res CatalogMutationResult) Rejected {
	t.Helper()
	rejected, ok := res.(Rejected)
	if !ok {
		t.Fatalf("expected Rejected, got %#v", res)
	}
	return rejected
}

func schemasOf(cmds []*pb.Refetch) []string {
	out := make([]string, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, c.GetSchema())
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// scriptedRandom replays a fixed list of 16-byte values, the Go form of the Kotlin case's stubbed
// SecureRandom.
type scriptedRandom struct{ values [][]byte }

func (s *scriptedRandom) Read(p []byte) (int, error) {
	if len(s.values) == 0 {
		return 0, errors.New("scriptedRandom exhausted")
	}
	next := s.values[0]
	s.values = s.values[1:]
	return copy(p, next), nil
}

var _ io.Reader = (*scriptedRandom)(nil)

// case 1 — 🔒 INV-A5-25
func TestMintedIdsAre16BytesAndCollisionsRetry(t *testing.T) {
	ones := make([]byte, 16)
	for i := range ones {
		ones[i] = 1
	}
	random := &scriptedRandom{values: [][]byte{make([]byte, 16), make([]byte, 16), ones}}
	registry := NewConnectionCatalogRegistry(WithRandom(random))
	first := registry.Open(Binding{"ds", "a", "USER"}, []string{"app"}, false)
	second := registry.Open(Binding{"ds", "b", "USER"}, []string{"app"}, false)
	if len(first.ConnectionID) != 16 || len(second.ConnectionID) != 16 {
		t.Fatalf("minted ids must be 16 bytes: %d, %d", len(first.ConnectionID), len(second.ConnectionID))
	}
	if first.ConnectionID == second.ConnectionID {
		t.Error("a collision must retry, not hand back the same id")
	}
}

// case 2 — 🔒 INV-A5-30
func TestPendingIsThePushCASAndReplayCannotRegressAuthoritative(t *testing.T) {
	ds := testDatasource(t)
	registry := NewConnectionCatalogRegistry()
	opened := registry.Open(Binding{ds.Name, "p", "USER"}, []string{"app"}, false)
	if got := mustApplied(t, registry.ApplyPush(push(ds, opened, "app", "z"), ds)).Generation; got != 1 {
		t.Errorf("first push generation = %d, want 1", got)
	}
	replay := mustRejected(t, registry.ApplyPush(push(ds, opened, "app", "a"), ds))
	if replay.Code != codes.FailedPrecondition {
		t.Errorf("replay code = %v", replay.Code)
	}
	auth, ok := registry.AuthoritativeFor(ds.Name, "app")
	if !ok || string(auth.Hash) != "z" {
		t.Errorf("authoritative = %q, %v; want z", auth.Hash, ok)
	}
}

// case 3 — rung 3
func TestBackendGenerationBindsAndOldPushesReject(t *testing.T) {
	ds := testDatasource(t)
	registry := NewConnectionCatalogRegistry()
	opened := registry.Open(Binding{ds.Name, "p", "USER"}, []string{"app"}, false)
	mustApplied(t, registry.ApplyPush(push(ds, opened, "app", "h1", withGeneration(5)), ds))
	connection := registry.Find(opened.ConnectionID)
	registry.MarkAfterStatement(connection, []string{"app"})
	rejected := mustRejected(t, registry.ApplyPush(push(ds, opened, "app", "h2", withGeneration(4)), ds))
	if rejected.Code != codes.FailedPrecondition {
		t.Errorf("stale generation code = %v", rejected.Code)
	}
	if got := string(connection.Held["app"].Hash); got != "h1" {
		t.Errorf("held hash = %q, want h1", got)
	}
}

// case 4 — INV-A5-34
func TestAuthoritativeOrderingFollowsAcceptedObservationOrderIncludingRevert(t *testing.T) {
	ds := testDatasource(t)
	registry := NewConnectionCatalogRegistry()
	one := registry.Open(Binding{ds.Name, "one", "USER"}, []string{"app"}, false)
	registry.ApplyPush(push(ds, one, "app", "z"), ds)
	auth1, _ := registry.AuthoritativeFor(ds.Name, "app")
	two := registry.Open(Binding{ds.Name, "two", "USER"}, []string{"app"}, false)
	registry.ApplyPush(push(ds, two, "app", "a"), ds)
	auth2, _ := registry.AuthoritativeFor(ds.Name, "app")
	three := registry.Open(Binding{ds.Name, "three", "USER"}, []string{"app"}, false)
	registry.ApplyPush(push(ds, three, "app", "z"), ds)
	final, _ := registry.AuthoritativeFor(ds.Name, "app")

	if auth2.Epoch <= auth1.Epoch {
		t.Errorf("epoch must advance: %d then %d", auth1.Epoch, auth2.Epoch)
	}
	if string(final.Hash) != "z" {
		t.Errorf("a revert to an older hash must win: got %q", final.Hash)
	}
	if final.Epoch <= auth2.Epoch {
		t.Errorf("epoch must advance on the revert too: %d then %d", auth2.Epoch, final.Epoch)
	}
}

// case 5 — 🔒 INV-A5-37 rule 3
func TestAHashMarkerQuietsOneAuthoritativeVersionAndRetriggersOnTheNext(t *testing.T) {
	ds := testDatasource(t)
	registry := NewConnectionCatalogRegistry()
	held := registry.Open(Binding{ds.Name, "held", "USER"}, []string{"app"}, false)
	registry.ApplyPush(push(ds, held, "app", "h1"), ds)
	sibling := registry.Open(Binding{ds.Name, "sibling", "USER"}, []string{"app"}, false)
	registry.ApplyPush(push(ds, sibling, "app", "h2", withColumnName("id")), ds)

	connection := registry.Find(held.ConnectionID)
	if got := registry.FreshnessGate(connection, []string{"app"}); !equalStrings(got, []string{"app"}) {
		t.Fatalf("a sibling's different content must gate: %v", got)
	}
	registry.MarkBeforeDecide(connection, []string{"app"})
	mustApplied(t, registry.ApplyPush(push(ds, held, "app", "h1", withUnchanged()), ds))
	if got := registry.FreshnessGate(connection, []string{"app"}); len(got) != 0 {
		t.Fatalf("one unchanged reply must quiet exactly that version: %v", got)
	}

	third := registry.Open(Binding{ds.Name, "third", "USER"}, []string{"app"}, false)
	registry.ApplyPush(push(ds, third, "app", "h3"), ds)
	if got := registry.FreshnessGate(connection, []string{"app"}); !equalStrings(got, []string{"app"}) {
		t.Errorf("the NEXT authoritative version must re-gate: %v", got)
	}
}

// case 6
func TestUnchangedAdoptionSharesPooledFragmentAndRefreshesStalenessClock(t *testing.T) {
	ds := testDatasource(t)
	var now int64
	registry := NewConnectionCatalogRegistry(
		WithClockNanos(func() int64 { return now }), WithStalenessNanos(10),
	)
	first := registry.Open(Binding{ds.Name, "first", "USER"}, []string{"app"}, false)
	registry.ApplyPush(push(ds, first, "app", "h1"), ds)
	key := registry.Find(first.ConnectionID).Held["app"].PooledRef
	second := registry.Open(Binding{ds.Name, "second", "USER"}, []string{"app"}, false)
	now = 20
	mustApplied(t, registry.ApplyPush(push(ds, second, "app", "h1", withUnchanged()), ds))
	pooled, _ := registry.PooledFor(key)
	if pooled.RefCount != 3 { // authoritative + two connections
		t.Errorf("refCount = %d, want 3", pooled.RefCount)
	}
	if got := registry.FreshnessGate(registry.Find(second.ConnectionID), []string{"app"}); len(got) != 0 {
		t.Errorf("just verified, must be fresh: %v", got)
	}
	now = 31
	if got := registry.FreshnessGate(registry.Find(second.ConnectionID), []string{"app"}); !equalStrings(got, []string{"app"}) {
		t.Errorf("past the ceiling, must gate: %v", got)
	}
}

// case 7 — INV-A5-28
func TestAdoptingHeldContentOpensWithNoFetchAndDecidesImmediately(t *testing.T) {
	ds := testDatasource(t)
	var now int64
	registry := NewConnectionCatalogRegistry(
		WithClockNanos(func() int64 { return now }), WithStalenessNanos(100),
	)
	first := registry.Open(Binding{ds.Name, "first", "USER"}, []string{"app"}, false)
	if got := schemasOf(first.OnOpen); !equalStrings(got, []string{"app"}) {
		t.Fatalf("nothing held yet: it must fetch, got %v", got)
	}
	registry.ApplyPush(push(ds, first, "app", "h1"), ds)

	now = 10
	second := registry.Open(Binding{ds.Name, "second", "USER"}, []string{"app"}, true)
	if len(second.OnOpen) != 0 {
		t.Fatalf("an adopting connection must not be sent a refetch: %v", schemasOf(second.OnOpen))
	}
	connection := registry.Find(second.ConnectionID)
	if got := string(connection.Held["app"].Hash); got != "h1" {
		t.Errorf("adopted hash = %q", got)
	}
	if len(connection.Pending) != 0 {
		t.Errorf("adopting leaves nothing pending, got %v", connection.Pending)
	}
	// The point of adopting: the first statement decides without waiting on the backend.
	if got := registry.FreshnessGate(connection, []string{"app"}); len(got) != 0 {
		t.Errorf("adopted content must decide immediately: %v", got)
	}
}

// case 8 — 🔒 INV-A5-27
func TestAdoptionInheritsTheOriginalMeasurementTimeSoStalenessStillFires(t *testing.T) {
	// Adopting must not restart the staleness clock. If it did, a stream of new connections would keep
	// content alive indefinitely without anyone re-reading the backend, and the bound could never fire.
	ds := testDatasource(t)
	var now int64
	registry := NewConnectionCatalogRegistry(
		WithClockNanos(func() int64 { return now }), WithStalenessNanos(10),
	)
	first := registry.Open(Binding{ds.Name, "first", "USER"}, []string{"app"}, false)
	registry.ApplyPush(push(ds, first, "app", "h1"), ds) // measured at now = 0

	now = 9
	second := registry.Open(Binding{ds.Name, "second", "USER"}, []string{"app"}, true)
	connection := registry.Find(second.ConnectionID)
	if got := registry.FreshnessGate(connection, []string{"app"}); len(got) != 0 {
		t.Fatalf("still inside the window: %v", got)
	}

	now = 11 // past staleness measured from the ORIGINAL read, not from adoption
	if got := registry.FreshnessGate(connection, []string{"app"}); !equalStrings(got, []string{"app"}) {
		t.Errorf("adopted content must go stale on the original measurement's clock: %v", got)
	}
}

// case 9 — INV-A5-44
func TestAnAmbientRefreshReMeasuresPooledContentSoAdoptersStayFresh(t *testing.T) {
	// The staleness ceiling sits above the ambient refresh interval on the premise that the refresh
	// itself keeps pooled content verified. Without that, content pooled once would age out no matter
	// how recently the backend was read, and every new session would refetch.
	ds := testDatasource(t)
	var now int64
	registry := NewConnectionCatalogRegistry(
		WithClockNanos(func() int64 { return now }), WithStalenessNanos(10),
	)
	first := registry.Open(Binding{ds.Name, "first", "USER"}, []string{"app"}, false)
	registry.ApplyPush(push(ds, first, "app", "h1"), ds)

	now = 8
	confirmed := registry.RecordAmbientMeasurement(ds.Name, map[string][]FragmentColumn{
		"app": {{Schema: "app", Table: "users", Column: "id", DataType: "bigint", Ordinal: 1, Nullable: false}},
	})
	if !equalStrings(confirmed, []string{"app"}) {
		t.Fatalf("confirmed = %v", confirmed)
	}

	now = 15 // past the original measurement, inside the window from the ambient one
	second := registry.Open(Binding{ds.Name, "second", "USER"}, []string{"app"}, true)
	if len(second.OnOpen) != 0 {
		t.Fatalf("must adopt: %v", schemasOf(second.OnOpen))
	}
	if got := registry.FreshnessGate(registry.Find(second.ConnectionID), []string{"app"}); len(got) != 0 {
		t.Errorf("the ambient re-measurement must reset the staleness clock for later adopters: %v", got)
	}
}

// case 10 — 🔒 INV-A5-41
func TestAnAmbientRefreshWhoseColumnsDifferNeverOverwritesPooledContent(t *testing.T) {
	// Confirmation only. Divergence belongs to the connection's own probe, which alone knows what that
	// connection's backend binds; installing a differing ambient read here would decide against a
	// catalog no connection measured.
	ds := testDatasource(t)
	var now int64
	registry := NewConnectionCatalogRegistry(
		WithClockNanos(func() int64 { return now }), WithStalenessNanos(10),
	)
	first := registry.Open(Binding{ds.Name, "first", "USER"}, []string{"app"}, false)
	registry.ApplyPush(push(ds, first, "app", "h1"), ds)

	now = 8
	confirmed := registry.RecordAmbientMeasurement(ds.Name, map[string][]FragmentColumn{
		"app": {{Schema: "app", Table: "users", Column: "DIFFERENT", DataType: "bigint", Ordinal: 1, Nullable: false}},
	})
	if len(confirmed) != 0 {
		t.Fatalf("a differing ambient read must not count as a re-measurement: %v", confirmed)
	}

	now = 15
	second := registry.Open(Binding{ds.Name, "second", "USER"}, []string{"app"}, true)
	if got := registry.FreshnessGate(registry.Find(second.ConnectionID), []string{"app"}); !equalStrings(got, []string{"app"}) {
		t.Errorf("unconfirmed content must still go stale on its original clock: %v", got)
	}
	// And the pooled structure is untouched: still the originally measured column.
	rows := registry.StructuralRows(registry.Find(second.ConnectionID))
	if len(rows) != 1 || rows[0].Column != "id" {
		t.Errorf("pooled structure was overwritten: %+v", rows)
	}
}

// case 11 — 🔒 adoption retains
func TestAdoptingRetainsThePooledFragmentSoItSurvivesTheOriginalHolderClosing(t *testing.T) {
	// Adoption takes a reference of its own. Without it the fragment would be released out from under
	// the adopter when the measuring connection closes, and structuralRows would silently go empty.
	ds := testDatasource(t)
	registry := NewConnectionCatalogRegistry()
	first := registry.Open(Binding{ds.Name, "first", "USER"}, []string{"app"}, false)
	registry.ApplyPush(push(ds, first, "app", "h1"), ds)
	key := registry.Find(first.ConnectionID).Held["app"].PooledRef

	second := registry.Open(Binding{ds.Name, "second", "USER"}, []string{"app"}, true)
	if pooled, _ := registry.PooledFor(key); pooled.RefCount != 3 { // authoritative + measurer + adopter
		t.Fatalf("refCount = %d, want 3", pooled.RefCount)
	}

	registry.Close(first.ConnectionID, ds.Name)
	if pooled, _ := registry.PooledFor(key); pooled.RefCount != 2 {
		t.Fatalf("refCount after the measurer closed = %d, want 2", pooled.RefCount)
	}
	rows := registry.StructuralRows(registry.Find(second.ConnectionID))
	if len(rows) != 1 || rows[0].Column != "id" {
		t.Errorf("the adopter must still resolve its structure after the measurer closed: %+v", rows)
	}

	registry.Close(second.ConnectionID, ds.Name)
	if pooled, _ := registry.PooledFor(key); pooled.RefCount != 1 { // authoritative alone
		t.Errorf("refCount = %d, want 1", pooled.RefCount)
	}
}

// case 12 — INV-A5-28
func TestASchemaWithNothingHeldIsStillFetchedWhenAdopting(t *testing.T) {
	// Adoption only skips work that is already done; it never skips the first measurement of a schema.
	ds := testDatasource(t)
	registry := NewConnectionCatalogRegistry()
	first := registry.Open(Binding{ds.Name, "first", "USER"}, []string{"app"}, false)
	registry.ApplyPush(push(ds, first, "app", "h1"), ds)

	second := registry.Open(Binding{ds.Name, "second", "USER"}, []string{"app", "other"}, true)
	if got := schemasOf(second.OnOpen); !equalStrings(got, []string{"other"}) {
		t.Fatalf("onOpen = %v, want [other]", got)
	}
	connection := registry.Find(second.ConnectionID)
	if _, ok := connection.Held["app"]; !ok {
		t.Error("app must be adopted")
	}
	if _, ok := connection.Pending["other"]; !ok {
		t.Error("other must be pending")
	}
}

// case 13 — 🔒 INV-A5-31
func TestUnchangedOnOpenCannotNoOpAnUnconditionalFirstFetch(t *testing.T) {
	// A fresh connection whose schema has no authoritative hash yet is issued an UNCONDITIONAL refetch
	// (pending.expectedHash == nil). A proxy that replies unchanged=true has nothing to adopt — this
	// must fail closed, never silently establish a held reference with no structure behind it.
	ds := testDatasource(t)
	registry := NewConnectionCatalogRegistry()
	opened := registry.Open(Binding{ds.Name, "fresh", "USER"}, []string{"app"}, false)
	rejected := mustRejected(t, registry.ApplyPush(push(ds, opened, "app", "h1", withUnchanged()), ds))
	if rejected.Code != codes.FailedPrecondition {
		t.Errorf("code = %v", rejected.Code)
	}
	connection := registry.Find(opened.ConnectionID)
	if _, ok := connection.Held["app"]; ok {
		t.Error("no held reference may be established")
	}
	if _, ok := connection.Pending["app"]; !ok {
		t.Error("still pending: the fetch was not satisfied")
	}
}

// openPushSystem opens a connection on ds scoped to one system schema and pushes a single-column
// fragment for it.
func openPushSystem(t *testing.T, registry *ConnectionCatalogRegistry, ds Datasource, schema, hash string) OpenConnection {
	t.Helper()
	opened := registry.Open(Binding{ds.Name, "p", "USER"}, []string{schema}, false)
	res := registry.ApplyPush(&pb.SchemaFragmentPush{
		ConnectionId:      opened.ConnectionID.Bytes(),
		DatasourceName:    ds.Name,
		Schema:            schema,
		ContentHash:       []byte(hash),
		BackendGeneration: 1,
		Columns: []*pb.Column{{
			Schema: schema, Table: "t", Column: "c", DataType: "bigint", Ordinal: 1, Nullable: false,
		}},
	}, ds)
	mustApplied(t, res)
	return opened
}

// case 14 — 🔒 INV-A5-35
func TestSystemSchemaFragmentsDedupAcrossDatasourcesOnTheSameEngineVersion(t *testing.T) {
	// Two distinct datasources on the SAME engine version share one pooled fragment for a system schema
	// (PoolKey scope "engine:<version>"), so the shared catalog build is stored once. A ds-scoped schema
	// would never collide like this.
	ds := testDatasource(t)
	registry := NewConnectionCatalogRegistry()
	dsA := ds
	dsA.ID, dsA.Name = 1, "dsA"
	dsB := ds
	dsB.ID, dsB.Name = 2, "dsB"
	a := openPushSystem(t, registry, dsA, "information_schema", "sys-h1")
	openPushSystem(t, registry, dsB, "information_schema", "sys-h1")
	key := registry.Find(a.ConnectionID).Held["information_schema"].PooledRef
	if got := registry.PoolSize(); got != 1 {
		t.Fatalf("poolSize = %d, want 1", got)
	}
	// dsA held + dsA authoritative + dsB held + dsB authoritative all reference the one pooled fragment.
	if pooled, _ := registry.PooledFor(key); pooled.RefCount != 4 {
		t.Errorf("refCount = %d, want 4", pooled.RefCount)
	}
}

// case 15 — 🔒 INV-A5-45
func TestInvalidatingADatasourceForcesTheNextConnectionToMeasureForItself(t *testing.T) {
	// Repointing a datasource at another database makes held structure describe a database that is no
	// longer there. Adoption would otherwise hand that structure to the next connection, which would
	// decide against a catalog its backend never had.
	ds := testDatasource(t)
	registry := NewConnectionCatalogRegistry()
	first := registry.Open(Binding{ds.Name, "first", "USER"}, []string{"app"}, false)
	registry.ApplyPush(push(ds, first, "app", "h1"), ds)
	key := registry.Find(first.ConnectionID).Held["app"].PooledRef

	adoptsBefore := registry.Open(Binding{ds.Name, "before", "USER"}, []string{"app"}, true)
	if len(adoptsBefore.OnOpen) != 0 {
		t.Fatalf("same target: adoption is expected, got %v", schemasOf(adoptsBefore.OnOpen))
	}

	if got := registry.InvalidateDatasource(ds.Name); !equalStrings(got, []string{"app"}) {
		t.Fatalf("invalidated = %v", got)
	}

	afterRetarget := registry.Open(Binding{ds.Name, "after", "USER"}, []string{"app"}, true)
	if got := schemasOf(afterRetarget.OnOpen); !equalStrings(got, []string{"app"}) {
		t.Fatalf("after a retarget the next connection must measure the new target itself: %v", got)
	}
	// The fetch is unconditional: there is no hash left to claim the new database matches the old.
	if len(afterRetarget.OnOpen[0].GetIfHashDiffers()) != 0 {
		t.Error("the retarget refetch must be unconditional")
	}
	// Connections that already hold the content keep it — their own reference is still counted.
	if pooled, _ := registry.PooledFor(key); pooled.RefCount != 2 {
		t.Errorf("refCount = %d, want 2", pooled.RefCount)
	}
}

// case 16 — 🔒 INV-A5-42
func TestOneDatasourcesAmbientRefreshCannotVouchForAnothersSchema(t *testing.T) {
	// System-schema content is pooled once per engine version and shared by every datasource on it, so a
	// measurement recorded against the shared content would let a datasource nobody read look freshly
	// verified. Freshness is evidence about one backend; only the content is shareable.
	ds := testDatasource(t)
	var now int64
	registry := NewConnectionCatalogRegistry(
		WithClockNanos(func() int64 { return now }), WithStalenessNanos(10),
	)
	dsA := ds
	dsA.ID, dsA.Name = 1, "dsA"
	dsB := ds
	dsB.ID, dsB.Name = 2, "dsB"
	openPushSystem(t, registry, dsA, "information_schema", "sys-h1")
	openPushSystem(t, registry, dsB, "information_schema", "sys-h1")

	now = 8
	// Only dsA is re-read. Its columns match, so dsA is confirmed — dsB must not be.
	confirmed := registry.RecordAmbientMeasurement(dsA.Name, map[string][]FragmentColumn{
		"information_schema": {{Schema: "information_schema", Table: "t", Column: "c", DataType: "bigint", Ordinal: 1, Nullable: false}},
	})
	if !equalStrings(confirmed, []string{"information_schema"}) {
		t.Fatalf("confirmed = %v", confirmed)
	}

	now = 15
	onA := registry.Open(Binding{dsA.Name, "p", "USER"}, []string{"information_schema"}, true)
	if len(onA.OnOpen) != 0 {
		t.Errorf("dsA was re-read, so its adopter is fresh: %v", schemasOf(onA.OnOpen))
	}
	onB := registry.Open(Binding{dsB.Name, "p", "USER"}, []string{"information_schema"}, true)
	got := registry.FreshnessGate(registry.Find(onB.ConnectionID), []string{"information_schema"})
	if !equalStrings(got, []string{"information_schema"}) {
		t.Errorf("dsB's backend was never re-read; dsA's refresh must not make it look fresh: %v", got)
	}
}

// case 17 — 🔒 INV-A5-33, INV-A5-46
func TestSameHashWithDifferentColumnsRejectsAndCloseIsIdempotentlyFailClosed(t *testing.T) {
	ds := testDatasource(t)
	registry := NewConnectionCatalogRegistry()
	first := registry.Open(Binding{ds.Name, "first", "USER"}, []string{"app"}, false)
	registry.ApplyPush(push(ds, first, "app", "h1", withColumnName("id")), ds)
	second := registry.Open(Binding{ds.Name, "second", "USER"}, []string{"app"}, false)
	alias := registry.ApplyPush(push(ds, second, "app", "h1", withColumnName("email")), ds)
	mustRejected(t, alias)

	mustApplied(t, registry.Close(first.ConnectionID, ds.Name))
	if got := mustRejected(t, registry.Close(first.ConnectionID, ds.Name)).Code; got != codes.NotFound {
		t.Errorf("second close code = %v, want NotFound", got)
	}
	if _, ok := registry.AuthoritativeFor(ds.Name, "app"); !ok {
		t.Error("the datasource's authoritative entry must survive a close")
	}
}

// ---- ADDED: coverage §9 names as missing ----------------------------------------------------

// §9 "Coverage gaps in A5": "sweepIdle has zero direct tests (INV-A5-47's double-check race, and the
// release-on-sweep path). It is the only backstop for a proxy that never sends CloseConnection."
func TestSweepIdleReleasesReferencesAndSpares(t *testing.T) {
	ds := testDatasource(t)
	var now int64
	registry := NewConnectionCatalogRegistry(WithClockNanos(func() int64 { return now }))
	idle := registry.Open(Binding{ds.Name, "idle", "USER"}, []string{"app"}, false)
	registry.ApplyPush(push(ds, idle, "app", "h1"), ds)
	key := registry.Find(idle.ConnectionID).Held["app"].PooledRef
	if pooled, _ := registry.PooledFor(key); pooled.RefCount != 2 { // authoritative + holder
		t.Fatalf("refCount = %d, want 2", pooled.RefCount)
	}

	// A connection USED just now is spared. WithConnection bumping lastUsedNanos is exactly the race
	// INV-A5-47's double-check exists for, so the bump is what this drives.
	now = 5_000_000
	if found, err := registry.WithConnection(idle.ConnectionID, func(*EnforcementConnection) error { return nil }); !found || err != nil {
		t.Fatalf("WithConnection: found=%v err=%v", found, err)
	}
	if swept := registry.SweepIdle(1); swept != 0 { // cutoff = 4ms; lastUsed = 5ms
		t.Fatalf("a freshly-used connection must be spared, swept %d", swept)
	}
	// Past the cutoff it goes, and its pooled reference is released — the authoritative one remains.
	now = 7_000_000 // cutoff = 6ms; lastUsed = 5ms
	if swept := registry.SweepIdle(1); swept != 1 {
		t.Fatalf("swept = %d, want 1", swept)
	}
	if registry.ConnectionCount() != 0 {
		t.Error("the swept connection must be gone from the map")
	}
	if pooled, _ := registry.PooledFor(key); pooled.RefCount != 1 {
		t.Errorf("refCount after sweep = %d, want 1 (authoritative alone)", pooled.RefCount)
	}
	// INV-A5-46's other half applies to sweep too: a later close fails closed.
	if got := mustRejected(t, registry.Close(idle.ConnectionID, ds.Name)).Code; got != codes.NotFound {
		t.Errorf("close after sweep = %v, want NotFound", got)
	}
}

// §9: "recover is untested at this layer … the 'already-live id is never overwritten' branch of
// INV-A5-26 is the one to verify."
func TestRecoverNeverOverwritesAnAlreadyLiveID(t *testing.T) {
	ds := testDatasource(t)
	registry := NewConnectionCatalogRegistry()
	id := ConnectionID("0123456789abcdef")
	first, ok := registry.Recover(id, Binding{ds.Name, "p", "USER"}, []string{"app"}, false)
	if !ok {
		t.Fatal("the first recover must succeed")
	}
	if !equalStrings(schemasOf(first.OnOpen), []string{"app"}) {
		t.Errorf("onOpen = %v", schemasOf(first.OnOpen))
	}
	if _, ok := registry.Recover(id, Binding{ds.Name, "other", "USER"}, []string{"app"}, false); ok {
		t.Error("an already-live id must never be overwritten")
	}
	if got := registry.Find(id).Binding.Principal; got != "p" {
		t.Errorf("the live record was replaced: principal = %q", got)
	}
}

// §9: "markCatalogMiss has no unit case; it is covered only indirectly through A6's enforcement
// suites. INV-A5-51's boundedness … is the specific thing to pin." The registry half is INV-A5-38:
// the emitted command is UNCONDITIONAL even when an authoritative hash exists.
func TestMarkCatalogMissForcesAnUnconditionalFetch(t *testing.T) {
	ds := testDatasource(t)
	registry := NewConnectionCatalogRegistry()
	opened := registry.Open(Binding{ds.Name, "p", "USER"}, []string{"app"}, false)
	registry.ApplyPush(push(ds, opened, "app", "h1"), ds)
	connection := registry.Find(opened.ConnectionID)

	cmds := registry.MarkCatalogMiss(connection, []string{"app"})
	if len(cmds) != 1 || len(cmds[0].GetIfHashDiffers()) != 0 {
		t.Fatalf("a catalog miss must force an unconditional fetch: %+v", cmds)
	}
	if pending := connection.Pending["app"]; pending.ExpectedHash != nil {
		t.Errorf("expectedHash must be nil, got %q", *pending.ExpectedHash)
	} else if pending.AuthoritativeAtIssue == nil || string(*pending.AuthoritativeAtIssue) != "h1" {
		t.Errorf("authoritativeAtIssue must carry the authoritative hash, got %v", pending.AuthoritativeAtIssue)
	}
	// 🔒 INV-A5-39 — a replay must not change the CAS token: markBeforeDecide over the same schema
	// keeps the unconditional command byte-identical.
	replay := registry.MarkBeforeDecide(connection, []string{"app"})
	if len(replay) != 1 || len(replay[0].GetIfHashDiffers()) != 0 {
		t.Errorf("getOrPut, never overwrite: %+v", replay)
	}
}

// INV-A5-40's sort, and the "absent pooled fragment contributes nothing" arm.
func TestStructuralRowsAreSortedBySchemaTableOrdinal(t *testing.T) {
	ds := testDatasource(t)
	registry := NewConnectionCatalogRegistry()
	opened := registry.Open(Binding{ds.Name, "p", "USER"}, []string{"app"}, false)
	res := registry.ApplyPush(&pb.SchemaFragmentPush{
		ConnectionId:      opened.ConnectionID.Bytes(),
		DatasourceName:    ds.Name,
		Schema:            "app",
		ContentHash:       []byte("h1"),
		BackendGeneration: 1,
		Columns: []*pb.Column{
			{Schema: "app", Table: "users", Column: "rrn", DataType: "text", Ordinal: 2},
			{Schema: "app", Table: "accounts", Column: "id", DataType: "bigint", Ordinal: 1},
			{Schema: "app", Table: "users", Column: "id", DataType: "bigint", Ordinal: 1},
		},
	}, ds)
	mustApplied(t, res)
	rows := registry.StructuralRows(registry.Find(opened.ConnectionID))
	got := make([]string, 0, len(rows))
	for _, r := range rows {
		got = append(got, r.Table+"."+r.Column)
	}
	want := []string{"accounts.id", "users.id", "users.rrn"}
	if !equalStrings(got, want) {
		t.Errorf("structuralRows = %v, want %v (sorted by schema, table, ordinal)", got, want)
	}
}

// Rung 2's Go-specific spelling: proto uint64 above 2^63-1 must reject, the way the JVM's signed
// read does.
func TestBackendGenerationAboveSignedRangeRejects(t *testing.T) {
	ds := testDatasource(t)
	registry := NewConnectionCatalogRegistry()
	opened := registry.Open(Binding{ds.Name, "p", "USER"}, []string{"app"}, false)
	p := push(ds, opened, "app", "h1")
	p.BackendGeneration = 1 << 63 // 2^63 — negative when read as a signed Long
	rejected := mustRejected(t, registry.ApplyPush(p, ds))
	if rejected.Code != codes.InvalidArgument || rejected.Description != "backend_generation exceeds signed range" {
		t.Errorf("rung 2 = %v %q", rejected.Code, rejected.Description)
	}
}

// The four remaining rejection rungs, so a port that reorders the ladder is caught.
func TestApplyPushValidationLadder(t *testing.T) {
	ds := testDatasource(t)
	registry := NewConnectionCatalogRegistry()
	opened := registry.Open(Binding{ds.Name, "p", "USER"}, []string{"app"}, false)

	unknown := registry.ApplyPush(&pb.SchemaFragmentPush{ConnectionId: []byte("nope"), DatasourceName: ds.Name}, ds)
	if got := mustRejected(t, unknown); got.Code != codes.NotFound || got.Description != "unknown connection_id" {
		t.Errorf("unknown connection = %v %q", got.Code, got.Description)
	}

	mismatch := push(ds, opened, "app", "h1")
	mismatch.DatasourceName = "other"
	if got := mustRejected(t, registry.ApplyPush(mismatch, ds)); got.Description != "datasource binding mismatch" {
		t.Errorf("rung 1 = %q", got.Description)
	}

	unsolicited := push(ds, opened, "unasked", "h1")
	if got := mustRejected(t, registry.ApplyPush(unsolicited, ds)); got.Description != "schema push has no pending REFETCH command" {
		t.Errorf("rung 4 = %q", got.Description)
	}

	wrongSchema := push(ds, opened, "app", "h1")
	wrongSchema.Columns[0].Schema = "elsewhere"
	if got := mustRejected(t, registry.ApplyPush(wrongSchema, ds)); got.Description != "fragment column schema mismatch" {
		t.Errorf("column schema mismatch = %q", got.Description)
	}
}

// HeldAndFreshSchemas is INV-A5-51's input; its membership must exclude a gated schema.
func TestHeldAndFreshSchemasExcludesGatedSchemas(t *testing.T) {
	ds := testDatasource(t)
	var now int64
	registry := NewConnectionCatalogRegistry(
		WithClockNanos(func() int64 { return now }), WithStalenessNanos(10),
	)
	opened := registry.Open(Binding{ds.Name, "p", "USER"}, []string{"app", "other"}, false)
	registry.ApplyPush(push(ds, opened, "app", "h1"), ds)
	registry.ApplyPush(push(ds, opened, "other", "h2"), ds)
	connection := registry.Find(opened.ConnectionID)

	fresh := registry.HeldAndFreshSchemas(connection)
	sort.Strings(fresh)
	if !equalStrings(fresh, []string{"app", "other"}) {
		t.Fatalf("fresh = %v", fresh)
	}
	now = 100 // everything is stale now
	if got := registry.HeldAndFreshSchemas(connection); len(got) != 0 {
		t.Errorf("stale schemas must not count as fresh: %v", got)
	}
}
