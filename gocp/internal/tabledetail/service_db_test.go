package tabledetail

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/core"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/engine"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
)

// ---------------------------------------------------------------------------------------------
// PORT of the two `TableDetailDbTest` overlay cases, which were KT-DEFER for the whole prototype
// because the PRODUCER did not exist: `internal/core/core.go` recorded TableDetailChannels as
// "REGISTRY-ONLY (its producer service is a later increment)", and `internal/app/http.go` passed a nil
// management.TableDetails. Both are now wired, so the cases are portable.
//
// WHAT THE KOTLIN'S assertRouteContract IS FOR, and what makes it more than a happy path:
//
//  1. THE OVERLAY. The proxy NEVER sends a classification (internal/engine/tabledetail.go:67-69). If the
//     control plane does not overlay it, the console's table view reports every column as unclassified —
//     an admin reviewing which columns hold PII reads "none" for a fully classified table.
//  2. NIL FOR A LIVE-ONLY COLUMN. A column the proxy sees but the stored catalog has never classified
//     must come back nil, not inherit a sibling's classification.
//  3. STATELESS. Reading a live detail must NOT write to the stored catalog and must NOT stamp
//     catalog_synced_at — otherwise browsing a table would silently adopt post-sync columns as
//     authorized catalog content, which A6 then decides against.
//
// ⚠️ SCOPE. These run at the PRODUCER, not through the HTTP route. The Kotlin drives
// `/api/datasources/{id}/table-detail`, but the Go route's own contract — selector validation, 404 vs
// 502, the ordering of its checks — is already covered by internal/management/datasource_db_test.go and
// internal/datasource's route tests. What was missing, and what this adds, is the overlay + resolveSchema
// behaviour that only exists here.
// ---------------------------------------------------------------------------------------------

// fakeTableDetailProxy is the Kotlin's `FakeTableDetailProxy`: it registers as an attached proxy, waits
// for the control plane's OpenTableDetail nudge, then claims the session and answers on it.
//
// 🔒 It goes through the REAL registry handshake — Attach(sessionID) then send on Inbound — because that
// correlation is exactly what the producer's dial + collect is being tested against. A fake that handed
// the producer a detail directly would prove nothing about the rendezvous.
type fakeTableDetailProxy struct {
	t        *testing.T
	hub      *core.ProxyEventsHub
	channels *core.TableDetailChannelRegistry
	sub      *core.EventSubscriber
	// reply decides what the proxy answers for a (schema, table) selector. Returning nil is "no such
	// table", which the producer turns into a nil detail.
	reply func(schema, table string) *engine.TableDetail
	// requests records every selector the control plane asked about, so a test can assert the proxy was
	// (or was not) consulted.
	requests chan [2]string
}

func newFakeProxy(
	t *testing.T, c *core.ControlPlaneCore, dsName string, reply func(schema, table string) *engine.TableDetail,
) *fakeTableDetailProxy {
	t.Helper()
	p := &fakeTableDetailProxy{
		t: t, hub: c.ProxyEventsHub, channels: c.TableDetailChannels,
		sub: core.NewEventSubscriber(), reply: reply, requests: make(chan [2]string, 16),
	}
	c.ProxyEventsHub.Register(dsName, p.sub)
	t.Cleanup(func() { c.ProxyEventsHub.Deregister(dsName, p.sub) })
	go p.serve()
	return p
}

// serve is the proxy's side of the exchange: drain control events, and on an OpenTableDetail claim the
// session and answer it.
func (p *fakeTableDetailProxy) serve() {
	for ev := range p.sub.C() {
		open := ev.GetOpenTableDetailChannel()
		if open == nil {
			continue
		}
		select {
		case p.requests <- [2]string{open.GetSchema(), open.GetTable()}:
		default:
		}

		outbound := make(chan *pb.ControlTableDetailMsg, 4)
		attached := p.channels.Attach(open.GetSessionId(), outbound)
		if attached == nil {
			// The producer already gave up; nothing to answer.
			continue
		}
		detail := p.reply(open.GetSchema(), open.GetTable())
		payload := "null"
		if detail != nil {
			raw, err := json.Marshal(detail)
			if err != nil {
				p.t.Errorf("fake proxy could not marshal its detail: %v", err)
				continue
			}
			payload = string(raw)
		}
		attached.Inbound <- &pb.ProxyTableDetailMsg{
			Kind: &pb.ProxyTableDetailMsg_Result{
				Result: &pb.TableDetailResult{Json: payload},
			},
		}
	}
}

// liveDetail is the shape the fake proxy reports: one column the stored catalog classifies, one it has
// never seen. Classification is left nil on BOTH, because the proxy never sends it.
func liveDetail(schema, table string) *engine.TableDetail {
	return &engine.TableDetail{
		Schema: schema,
		Table:  table,
		Columns: []engine.TableDetailColumn{
			{Name: "classified_secret", DataType: "text", Ordinal: 1, Nullable: false, PartOfIndex: true},
			{Name: "live_only", DataType: "text", Ordinal: 2, Nullable: true},
		},
		Indexes:      []engine.TableIndex{{Name: table + "_pkey", Unique: true, Columns: []engine.TableIndexColumn{{Name: "classified_secret", Position: 1}}}},
		Metadata:     engine.TableMetadata{},
		ForeignKeys:  []engine.TableRelation{},
		ReferencedBy: []engine.TableRelation{},
	}
}

type detailFixture struct {
	t       *testing.T
	ctx     context.Context
	core    *core.ControlPlaneCore
	svc     *Service
	ds      datasource.Datasource
	proxy   *fakeTableDetailProxy
	schema  string // the schema the proxy answers under (the RESOLVED one)
	request string // the schema selector the caller passes
	table   string
}

// newDetailFixture builds `createFixture(name, engine, schema, prefix)`: a datasource, a stored catalog
// carrying ONE classified column, and a fake proxy answering for the resolved schema.
func newDetailFixture(t *testing.T, engineName, requestSchema string) *detailFixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	c, err := core.New(db, core.Options{})
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	ctx := context.Background()
	seed := dbtest.NewSeed(t, db)

	const dbName = "detail_db"
	const table = "middle"
	dsID := seed.Datasource(dbtest.DatasourceSpec{
		Name: "detail-" + engineName, Engine: engineName,
		Host: "localhost", Port: 5432, DBName: dbName,
	})
	ds, found, err := c.DatasourceStore.Get(ctx, dsID)
	if err != nil || !found {
		t.Fatalf("Get(%d) = found %v, err %v", dsID, found, err)
	}

	// The schema the proxy must answer under, resolved the same way production does.
	resolved, err := datasource.ResolveSchema(ds.Engine, requestSchema, ds.DBName)
	if err != nil {
		t.Fatalf("ResolveSchema(%s, %s): %v", ds.Engine, requestSchema, err)
	}

	f := &detailFixture{
		t: t, ctx: ctx, core: c, ds: ds,
		schema: resolved, request: requestSchema, table: table,
	}
	// The stored catalog: `classified_secret` is classified, `live_only` is deliberately ABSENT so the
	// nil-overlay assertion is about a column the catalog has never seen.
	seed.CatalogColumns(dsID, dbtest.CatalogColumn{
		Schema: resolved, Table: table, Column: "classified_secret", DataType: "text", Ordinal: 1,
	})
	maskID := seed.MaskFn("partial", "partial")
	seed.Classify(dsID, resolved, table, "classified_secret", []string{"pii"}, &maskID)

	f.proxy = newFakeProxy(t, c, ds.Name, func(schema, table string) *engine.TableDetail {
		// The MySQL arm accepts BOTH the raw `public` selector and the resolved database, mirroring the
		// Kotlin fake — which is how the resolveSchema assertion stays honest rather than being enforced
		// by the fake refusing everything else.
		if (schema == requestSchema || schema == resolved) && table == f.table {
			return liveDetail(resolved, table)
		}
		return nil
	})
	f.svc = &Service{
		Channels: c.TableDetailChannels, Hub: c.ProxyEventsHub, Datasources: c.DatasourceStore,
		DialTimeoutMS: 5_000, ExchangeTimeoutMS: 5_000,
	}
	return f
}

func (f *detailFixture) fetch() (*engine.TableDetail, error) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, 20*time.Second)
	defer cancel()
	return f.svc.Fetch(ctx, f.ds.Name, f.request, f.table)
}

func (f *detailFixture) column(d *engine.TableDetail, name string) engine.TableDetailColumn {
	f.t.Helper()
	for _, c := range d.Columns {
		if c.Name == name {
			return c
		}
	}
	f.t.Fatalf("column %q not in the returned detail", name)
	return engine.TableDetailColumn{}
}

func (f *detailFixture) catalogRows() []datasource.CatalogColumn {
	f.t.Helper()
	rows, err := f.core.DatasourceStore.Catalog(f.ctx, f.ds.ID)
	if err != nil {
		f.t.Fatalf("Catalog: %v", err)
	}
	return rows
}

func (f *detailFixture) syncedAt() *string {
	f.t.Helper()
	ds, found, err := f.core.DatasourceStore.Get(f.ctx, f.ds.ID)
	if err != nil || !found {
		f.t.Fatalf("Get: found %v err %v", found, err)
	}
	return ds.CatalogSyncedAt
}

// assertRouteContract is the Kotlin's same-named helper, minus the HTTP-shape assertions the Go route
// tests already own.
func (f *detailFixture) assertContract() {
	f.t.Helper()
	beforeCatalog := f.catalogRows()
	beforeSynced := f.syncedAt()
	for _, c := range beforeCatalog {
		if c.Column == "live_only" {
			f.t.Fatal("`live_only` is already in the stored catalog; the nil-overlay assertion would be vacuous")
		}
	}

	detail, err := f.fetch()
	if err != nil {
		f.t.Fatalf("Fetch: %v", err)
	}
	if detail == nil {
		f.t.Fatal("Fetch returned no detail; the fake proxy should have answered for this selector")
	}

	// 🔒 The reply comes back under the RESOLVED schema, which for MySQL is the database rather than the
	// literal `public` the caller asked for.
	if detail.Schema != f.schema {
		f.t.Errorf("schema = %q, want the resolved %q (requested %q)", detail.Schema, f.schema, f.request)
	}
	if detail.Table != f.table {
		f.t.Errorf("table = %q, want %q", detail.Table, f.table)
	}

	// 1. THE OVERLAY.
	secret := f.column(detail, "classified_secret")
	if secret.Classification == nil {
		f.t.Fatal("persisted classification must overlay live proxy metadata — the proxy never sends one, " +
			"so a nil here means the console shows a classified PII column as unclassified")
	}
	if len(secret.Classification.Tags) != 1 || secret.Classification.Tags[0] != "pii" {
		f.t.Errorf("tags = %v, want [pii]", secret.Classification.Tags)
	}
	if secret.Classification.MaskFnName == nil || *secret.Classification.MaskFnName != "partial" {
		f.t.Errorf("maskFnName = %v, want partial — the console offers the mask from this field",
			secret.Classification.MaskFnName)
	}
	// The live metadata must survive the overlay rather than be replaced by it.
	if !secret.PartOfIndex {
		f.t.Error("partOfIndex was lost; the overlay must add classification, not rebuild the column")
	}

	// 2. NIL FOR A LIVE-ONLY COLUMN.
	if live := f.column(detail, "live_only"); live.Classification != nil {
		f.t.Errorf("live_only classification = %+v, want nil — a column the catalog has never classified "+
			"must not inherit a sibling's", *live.Classification)
	}

	// 3. STATELESS.
	if after := f.catalogRows(); len(after) != len(beforeCatalog) {
		f.t.Errorf("stored catalog rows %d → %d; reading a live detail must not write the catalog",
			len(beforeCatalog), len(after))
	}
	for _, c := range f.catalogRows() {
		if c.Column == "live_only" {
			f.t.Error("live detail persisted a post-sync column into the stored catalog — A6 would then " +
				"authorize statements against it as though it had been synced")
		}
	}
	if a, b := f.syncedAt(), beforeSynced; (a == nil) != (b == nil) || (a != nil && *a != *b) {
		f.t.Errorf("catalog_synced_at %v → %v; browsing a table must not look like a catalog sync", b, a)
	}
}

// KT: TableDetailDbTest.kt#postgres route assembles proxy detail overlays classification and stays stateless
func TestPostgresTableDetailOverlaysClassificationAndStaysStateless(t *testing.T) {
	newDetailFixture(t, "postgres", "detail_schema").assertContract()
}

// KT: TableDetailDbTest.kt#mysql route assembles proxy detail overlays classification and stays stateless
//
// 🔒 THE MySQL CASE CARRIES resolveSchema. The selector is the literal `public` default, which MySQL does
// not have; it must resolve to the datasource's DATABASE before the reply is validated and before the
// overlay's join key is built. A port that compared the reply against the raw request would accept a
// proxy answering `public`, and a port that keyed the overlay on `public` would find zero
// classifications and silently return every column unclassified.
func TestMysqlTableDetailResolvesPublicToTheDatabaseAndOverlays(t *testing.T) {
	f := newDetailFixture(t, "mysql", "public")
	if f.schema == f.request {
		t.Fatalf("resolveSchema left %q unchanged; this case exists to exercise the mapping", f.request)
	}
	f.assertContract()
}

// --- ADDED: the overlay's failure modes, which the Kotlin covers only implicitly ------------------

// TestAnUnexpectedTableInTheReplyIsRejected pins the mixup guard.
//
// 🔒 SERVING A MISMATCHED REPLY WOULD BE WORSE THAN AN ERROR: the columns of one table would be shown
// under another table's name, with THIS table's classifications overlaid onto them — so an admin could
// read "not PII" for a column that is, because the classification join found nothing for the foreign
// column names.
func TestAnUnexpectedTableInTheReplyIsRejected(t *testing.T) {
	db, _ := dbtest.MigratedStore(t)
	c, err := core.New(db, core.Options{})
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	ctx := context.Background()
	seed := dbtest.NewSeed(t, db)
	dsID := seed.Datasource(dbtest.DatasourceSpec{
		Name: "detail-mixup", Engine: "postgres", Host: "localhost", Port: 5432, DBName: "d",
	})
	ds, _, err := c.DatasourceStore.Get(ctx, dsID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	// The proxy answers for a DIFFERENT table than the one asked about.
	newFakeProxy(t, c, ds.Name, func(schema, _ string) *engine.TableDetail {
		return liveDetail(schema, "some_other_table")
	})
	svc := &Service{
		Channels: c.TableDetailChannels, Hub: c.ProxyEventsHub, Datasources: c.DatasourceStore,
		DialTimeoutMS: 5_000, ExchangeTimeoutMS: 5_000,
	}

	_, err = svc.Fetch(ctx, ds.Name, "public", "asked_for")
	if err == nil {
		t.Fatal("a reply for a different table must be rejected, not served")
	}
	if got := err.Error(); !strings.Contains(got, ErrMsgUnexpectedTable) {
		t.Errorf("error = %q, want it to contain %q", got, ErrMsgUnexpectedTable)
	}
}

// TestNoAttachedProxyIsAnExecFailure covers the dispatch arm: with nothing attached the producer must
// fail as a proxy fault (502), never hang until the dial timeout.
func TestNoAttachedProxyIsAnExecFailure(t *testing.T) {
	db, _ := dbtest.MigratedStore(t)
	c, err := core.New(db, core.Options{})
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	ctx := context.Background()
	dsID := dbtest.NewSeed(t, db).Datasource(dbtest.DatasourceSpec{
		Name: "detail-unattached", Engine: "postgres", Host: "localhost", Port: 5432, DBName: "d",
	})
	ds, _, err := c.DatasourceStore.Get(ctx, dsID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	svc := &Service{
		Channels: c.TableDetailChannels, Hub: c.ProxyEventsHub, Datasources: c.DatasourceStore,
		// A long dial timeout on purpose: if the NOT_ATTACHED arm were missing this would hang, and the
		// test would fail by timing out rather than passing slowly.
		DialTimeoutMS: 60_000, ExchangeTimeoutMS: 60_000,
	}

	start := time.Now()
	_, err = svc.Fetch(ctx, ds.Name, "public", "t")
	if err == nil {
		t.Fatal("with no proxy attached, Fetch must fail")
	}
	if got := err.Error(); !strings.Contains(got, ErrMsgNoProxy) {
		t.Errorf("error = %q, want it to contain %q", got, ErrMsgNoProxy)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %s — NOT_ATTACHED must fail fast, not wait out the dial timeout", elapsed)
	}
}

// TestTheSessionIsDeregisteredAfterEveryFetch guards the teardown.
//
// 🔒 A LEAKED REGISTRATION IS A SLOW RESOURCE LEAK plus a correctness hazard: the registry is the
// claim-once correlation, so an abandoned entry keeps a session id claimable by a late-dialing proxy.
func TestTheSessionIsDeregisteredAfterEveryFetch(t *testing.T) {
	f := newDetailFixture(t, "postgres", "detail_schema")
	pinned := "pinned-session-id"
	f.svc.NewSessionID = func() string { return pinned }

	if _, err := f.fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if left := f.core.TableDetailChannels.Remove(pinned); left != nil {
		t.Error("the session was still registered after a successful fetch; teardown must always deregister")
	}
}
