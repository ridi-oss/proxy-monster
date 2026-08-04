package management

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/engine"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// ---------------------------------------------------------------------------------------------
// `DatasourceManagementService` — and 🔒 INV-A11-28, whose write-side half A2 explicitly does NOT
// cover. 11-mcp-oauth-management.md §9: "INV-A11-28's reserved-tag write rejection (only the
// MARSHALLING half is tested, in A2)".
// ---------------------------------------------------------------------------------------------

// dsFixture extends [fixture] with the datasource store and the two seams A5/A10 still own.
type dsFixture struct {
	*fixture
	dsStore     *datasource.DatasourceStore
	attachments *fakeAttachments
	details     *fakeTableDetails
	service     *DatasourceService
	datasource  int64
}

// fakeAttachments is `ProxyEventsHub.attached()`. In-memory by nature — the real hub's set is the
// live gRPC streams this instance holds, which is exactly why `attached` cannot be derived from a
// column.
type fakeAttachments struct{ names map[string]struct{} }

func (f *fakeAttachments) Attached() map[string]struct{} { return f.names }

// fakeTableDetails is `TableDetailService.fetch`. The real one dials a proxy over a bidi gRPC
// channel; what this layer is specified to do with the three possible outcomes — a detail, a nil, and
// a TableDetailExecException — is independent of how they were produced.
type fakeTableDetails struct {
	detail *engine.TableDetail
	err    error
	calls  int
}

func (f *fakeTableDetails) Fetch(context.Context, string, string, string) (*engine.TableDetail, error) {
	f.calls++
	return f.detail, f.err
}

func newDatasourceFixture(t testing.TB) *dsFixture {
	t.Helper()
	base := newFixture(t)
	dsStore := datasource.NewDatasourceStore(base.db)
	attachments := &fakeAttachments{names: map[string]struct{}{}}
	details := &fakeTableDetails{}

	id := base.seed.Datasource(dbtest.DatasourceSpec{
		Name: "prod", Engine: "postgres", Host: "db.internal", Port: 5432, DBName: "app",
	})
	base.seed.Namespace(id, []string{"public"}, nil, "16.2")
	base.seed.CatalogColumns(id,
		dbtest.CatalogColumn{Schema: "public", Table: "users", Column: "id", DataType: "bigint", Ordinal: 1},
		dbtest.CatalogColumn{Schema: "public", Table: "users", Column: "email", DataType: "text", Ordinal: 2},
	)

	return &dsFixture{
		fixture:     base,
		dsStore:     dsStore,
		attachments: attachments,
		details:     details,
		service:     NewDatasourceService(dsStore, attachments, details),
		datasource:  id,
	}
}

// ---- 🔒 INV-A11-28 — the reserved-prefix tag write guard -----------------------------------------

// 🔒 A reserved-prefix tag cannot be set through the management API, through ANY of its overloads.
//
// This is the write-side half of A2's INV-A2-7, which enforces the same rule at Cedar marshalling.
// Both halves exist deliberately and neither is redundant: A2's proves a tag that somehow got STORED
// still cannot be asserted to Cedar (PresetPolicyDbTest case 9); this one is what stops it being
// stored. Without it an admin can mint `system:pii` through the API and every shipped system policy
// starts matching a column they chose.
func TestSetColumnClassificationRefusesAReservedTagThroughEveryOverload(t *testing.T) {
	f := newDatasourceFixture(t)
	const reserved = datasource.ReservedTagPrefix + "pii"

	t.Run("by name", func(t *testing.T) {
		_, err := f.service.SetColumnClassificationByName(f.ctx, "prod", ptr("public"), "users", "email",
			[]string{reserved}, nil)
		e := assertManagementCode(t, err, CodeReservedTag, "by name")
		assertParam(t, e, "tag", reserved, "by name")
	})
	t.Run("by id", func(t *testing.T) {
		_, err := f.service.SetColumnClassificationByID(f.ctx, f.datasource, ptr("public"), "users", "email",
			[]string{reserved}, nil)
		e := assertManagementCode(t, err, CodeReservedTag, "by id")
		assertParam(t, e, "tag", reserved, "by id")
	})
	t.Run("by name, on a caller's transaction", func(t *testing.T) {
		err := store.InTxDo(f.ctx, f.db.Pool, func(ctx context.Context, tx pgx.Tx) error {
			_, err := f.service.SetColumnClassificationByNameOn(ctx, tx, "prod", ptr("public"), "users",
				"email", []string{reserved}, nil)
			return err
		})
		e := assertManagementCode(t, err, CodeReservedTag, "on a transaction")
		assertParam(t, e, "tag", reserved, "on a transaction")
	})

	if n := f.scalarInt64(`SELECT COUNT(*) FROM column_classification WHERE datasource_id=$1`, f.datasource); n != 0 {
		t.Errorf("nothing may have been stored, got %d rows", n)
	}
}

// 🔒 It reports the FIRST offending tag, it is a PREFIX test rather than an equality test, and it
// runs BEFORE the write — so a list mixing one reserved tag with legitimate ones stores NONE of them.
func TestTheReservedTagGuardIsAPrefixTestAndRejectsTheWholeList(t *testing.T) {
	f := newDatasourceFixture(t)

	_, err := f.service.SetColumnClassificationByName(f.ctx, "prod", ptr("public"), "users", "email",
		[]string{"pii", "system:anything-at-all", "system:second"}, nil)
	e := assertManagementCode(t, err, CodeReservedTag, "mixed list")
	assertParam(t, e, "tag", "system:anything-at-all", "the FIRST offender is reported")

	if n := f.scalarInt64(`SELECT COUNT(*) FROM column_classification WHERE datasource_id=$1`, f.datasource); n != 0 {
		t.Errorf("the legitimate tags in the same list must not be stored either, got %d rows", n)
	}

	// ⚠️ Case-sensitive, matching the store's own strings.HasPrefix. `System:pii` is NOT reserved.
	// The two halves of the guard must agree about what "reserved" means, or a tag could pass this
	// check and then fail the store's, which surfaces as a 500 with no `{tag}` param.
	got, err := f.service.SetColumnClassificationByName(f.ctx, "prod", ptr("public"), "users", "email",
		[]string{"System:pii"}, nil)
	assertNoError(t, err, "a differently-cased prefix is not reserved")
	assertStrings(t, got.Tags, []string{"System:pii"}, "stored tags")
}

// The guard is at BOTH layers, deliberately (INV-A5-19). The store's own refusal is the backstop for
// a non-HTTP caller, and it is unreachable through this service precisely because the management
// check runs first — which is why its error is NOT a management failure and would surface as a 500.
// Both facts are pinned here so neither copy is deleted as "duplication".
func TestTheStoreKeepsItsOwnReservedTagBackstopWithADifferentErrorShape(t *testing.T) {
	f := newDatasourceFixture(t)

	_, err := f.dsStore.UpsertClassification(f.ctx, f.datasource, datasource.ClassificationInput{
		Schema: ptr("public"), Table: "users", Column: "email", Tags: []string{"system:pii"},
	})
	if !errors.Is(err, datasource.ErrReservedTag) {
		t.Fatalf("the store backstop must still refuse: got %v", err)
	}
	var me *Error
	if errors.As(err, &me) {
		t.Errorf("⚠️ the store's refusal is NOT a management failure (that is the reproduced "+
			"consequence: it would answer 500 and lose the {tag} param), got code %q", me.Err.Code)
	}
}

// ---- 🔒 INV-A11-29 — a null schema needs a resolvable default -------------------------------------

// A nil schema means "resolve the datasource's default". With no default captured — a datasource that
// has never been introspected — the answer is `datasource.schema_required` (400), NOT a silent write
// to some fallback. A classification landing on the wrong schema is a masking rule that never fires.
func TestANullSchemaRequiresAResolvableDefaultOnBothSetAndClear(t *testing.T) {
	f := newDatasourceFixture(t)
	bare := f.seed.Datasource(dbtest.DatasourceSpec{
		Name: "never-introspected", Engine: "postgres", Host: "h", Port: 5432, DBName: "app",
	})

	_, err := f.service.SetColumnClassificationByID(f.ctx, bare, nil, "users", "email", []string{"pii"}, nil)
	assertManagementCode(t, err, CodeSchemaRequired, "set with no default schema")

	_, err = f.service.ClearColumnClassificationByID(f.ctx, bare, nil, "users", "email")
	assertManagementCode(t, err, CodeSchemaRequired, "clear with no default schema")

	// With a default captured, the nil schema resolves and the write lands under it.
	f.seed.Namespace(bare, []string{"public"}, nil, "16.2")
	got, err := f.service.SetColumnClassificationByID(f.ctx, bare, nil, "users", "email", []string{"pii"}, nil)
	assertNoError(t, err, "set with a default schema")
	if got.Schema != "public" {
		t.Errorf("schema: got %q, want the resolved default %q", got.Schema, "public")
	}
}

// The two `required` calls every classification overload opens with, in the Kotlin's order: table,
// then column. Note the SCHEMA is deliberately NOT required — nil is a meaningful value there.
func TestClassificationOverloadsRequireTableAndColumnInThatOrder(t *testing.T) {
	f := newDatasourceFixture(t)

	_, err := f.service.SetColumnClassificationByName(f.ctx, "prod", ptr("public"), "", "", nil, nil)
	e := assertManagementCode(t, err, "common.field_required", "both blank")
	assertParam(t, e, "fields", "table", "table is checked first")

	_, err = f.service.SetColumnClassificationByName(f.ctx, "prod", ptr("public"), "users", "  ", nil, nil)
	e = assertManagementCode(t, err, "common.field_required", "blank column")
	assertParam(t, e, "fields", "column", "blank column")

	// 🔒 The field checks run BEFORE the datasource lookup: a request naming a nonexistent datasource
	// AND omitting the table answers common.field_required, not common.not_found.
	_, err = f.service.SetColumnClassificationByName(f.ctx, "no-such-datasource", ptr("public"), "", "email", nil, nil)
	assertManagementCode(t, err, "common.field_required", "blank table on an unknown datasource")
}

// Every datasource-addressed method answers `common.not_found{resource: datasource}` for an unknown
// name or id — the literal is `datasource`, not the route path.
func TestEveryDatasourceAddressedMethodAnswersNotFoundWithTheSameLiteral(t *testing.T) {
	f := newDatasourceFixture(t)
	const absent = int64(987654321)

	for name, call := range map[string]func() error{
		"getDatasource":  func() error { _, err := f.service.GetDatasource(f.ctx, "ghost"); return err },
		"liveness":       func() error { _, err := f.service.GetDatasourceLiveness(f.ctx, "ghost"); return err },
		"browseCatalog":  func() error { _, err := f.service.BrowseCatalog(f.ctx, "ghost"); return err },
		"listColumnTags": func() error { _, err := f.service.ListColumnTags(f.ctx, "ghost"); return err },
		"getTableDetail": func() error {
			_, err := f.service.GetTableDetail(f.ctx, "ghost", "public", "users")
			return err
		},
		"setByName": func() error {
			_, err := f.service.SetColumnClassificationByName(f.ctx, "ghost", ptr("public"), "users", "email", nil, nil)
			return err
		},
		"setById": func() error {
			_, err := f.service.SetColumnClassificationByID(f.ctx, absent, ptr("public"), "users", "email", nil, nil)
			return err
		},
		"clearByName": func() error {
			_, err := f.service.ClearColumnClassificationByName(f.ctx, "ghost", ptr("public"), "users", "email")
			return err
		},
		"clearById": func() error {
			_, err := f.service.ClearColumnClassificationByID(f.ctx, absent, ptr("public"), "users", "email")
			return err
		},
	} {
		e := assertManagementCode(t, call(), "common.not_found", name)
		assertParam(t, e, "resource", "datasource", name)
	}
}

// ---- The classification round trip ---------------------------------------------------------------

// A set followed by a clear, through the name-keyed overloads, with `listColumnTags` reading it back.
//
// ⚠️ A clear that matched nothing is `deleted: false` and NOT a 404 — the DeleteResult is a body.
func TestClassificationsRoundTripThroughSetListAndClear(t *testing.T) {
	f := newDatasourceFixture(t)
	maskFnID := f.seed.MaskFn("mask_email", "FIXED")

	got, err := f.service.SetColumnClassificationByName(f.ctx, "prod", ptr("public"), "users", "email",
		[]string{"pii"}, &maskFnID)
	assertNoError(t, err, "set")
	if got.MaskFnName == nil || *got.MaskFnName != "mask_email" {
		t.Errorf("maskFnName: got %v, want mask_email", got.MaskFnName)
	}

	tags, err := f.service.ListColumnTags(f.ctx, "prod")
	assertNoError(t, err, "listColumnTags")
	if len(tags) != 1 {
		t.Fatalf("listColumnTags: got %d entries, want 1 (%+v)", len(tags), tags)
	}
	if tags[0].Datasource != "prod" || tags[0].Column != "email" {
		t.Errorf("entry: got %+v, want the classified column flattened with its datasource name", tags[0])
	}
	assertStrings(t, tags[0].Tags, []string{"pii"}, "tags")

	cleared, err := f.service.ClearColumnClassificationByName(f.ctx, "prod", ptr("public"), "users", "email")
	assertNoError(t, err, "clear")
	if !cleared.Deleted {
		t.Errorf("clear: got deleted=false, want true")
	}
	cleared, err = f.service.ClearColumnClassificationByName(f.ctx, "prod", ptr("public"), "users", "email")
	assertNoError(t, err, "second clear")
	if cleared.Deleted {
		t.Errorf("a second clear is deleted=false, NOT a 404: got %+v", cleared)
	}
}

// ⚠️ `listColumnTags` keeps a classification with an EMPTY tag list — the Kotlin's `mapNotNull`
// filters on the classification being PRESENT, not on it being non-empty. So a column whose tags were
// emptied but whose row survives still appears, with `tags: []`.
func TestListColumnTagsKeepsAClassificationWhoseTagListIsEmpty(t *testing.T) {
	f := newDatasourceFixture(t)

	_, err := f.service.SetColumnClassificationByName(f.ctx, "prod", ptr("public"), "users", "email", nil, nil)
	assertNoError(t, err, "set with no tags")

	tags, err := f.service.ListColumnTags(f.ctx, "prod")
	assertNoError(t, err, "listColumnTags")
	if len(tags) != 1 {
		t.Fatalf("got %d entries, want the empty-tag classification kept (%+v)", len(tags), tags)
	}
	assertJSON(t, tags[0],
		`{"datasource":"prod","schema":"public","table":"users","column":"email","tags":[]}`,
		"an empty-tag entry marshals `[]` and omits maskFnName")

	// A datasource with no classifications at all answers `[]`, never null.
	f.seed.Datasource(dbtest.DatasourceSpec{Name: "other", Engine: "postgres", Host: "h", Port: 5432, DBName: "a"})
	empty, err := f.service.ListColumnTags(f.ctx, "other")
	assertNoError(t, err, "listColumnTags on an unclassified datasource")
	assertJSON(t, empty, `[]`, "no classifications")
}

// ---- Liveness and table detail — the two seams A5/A10 still own -----------------------------------

// 🔒 `attached` is IN-MEMORY state joined onto the row, not a column. A port that derived it from a
// recent `lastSeenAt` would answer true on an instance that has never spoken to the proxy.
func TestLivenessJoinsTheInMemoryAttachedSetOntoTheStoredTimestamps(t *testing.T) {
	f := newDatasourceFixture(t)

	live, err := f.service.GetDatasourceLiveness(f.ctx, "prod")
	assertNoError(t, err, "liveness, detached")
	if live.Attached {
		t.Errorf("attached: got true with an empty hub")
	}
	// catalog_synced_at was set by the fixture's Namespace call; last_seen_at never was.
	if live.CatalogSyncedAt == nil {
		t.Errorf("catalogSyncedAt must carry the stored timestamp")
	}
	if live.LastSeenAt != nil {
		t.Errorf("lastSeenAt must be ABSENT, not null, when the proxy has never reported: %v", live.LastSeenAt)
	}

	f.attachments.names["prod"] = struct{}{}
	live, err = f.service.GetDatasourceLiveness(f.ctx, "prod")
	assertNoError(t, err, "liveness, attached")
	if !live.Attached {
		t.Errorf("attached: got false with the datasource in the hub's set")
	}
}

// 🔒 A `TableDetailExecException` becomes `datasource.table_introspection_failed` — the ONE A11 code
// httpapi.RespondManagementError answers **502**, because the proxy failed, not the caller. Anything
// else passes through as a plain error and StatusPages answers 500. A TableDetails implementation
// that forgets to wrap [ErrTableDetailExec] turns a proxy-side timeout into a control-plane bug
// report.
func TestTableDetailMapsAnExecFailureTo502AndANilDetailTo404(t *testing.T) {
	f := newDatasourceFixture(t)

	f.details.err = fmt.Errorf("%w: no proxy is attached to this datasource", ErrTableDetailExec)
	_, err := f.service.GetTableDetail(f.ctx, "prod", "public", "users")
	e := assertManagementCode(t, err, CodeTableIntrospectionFailed, "exec failure")
	if e.Params["detail"] == "" {
		t.Errorf("the exception's message must ride along as {detail}, got %v", e.Params)
	}

	// A nil detail with no error is "the datasource exists but that table does not" ⇒ 404 `table`.
	f.details.err = nil
	f.details.detail = nil
	_, err = f.service.GetTableDetail(f.ctx, "prod", "public", "users")
	e = assertManagementCode(t, err, "common.not_found", "nil detail")
	assertParam(t, e, "resource", "table", "nil detail")

	// Anything NOT wrapping the sentinel is left alone — 500, not 502.
	f.details.err = errors.New("some unrelated internal failure")
	_, err = f.service.GetTableDetail(f.ctx, "prod", "public", "users")
	var me *Error
	if errors.As(err, &me) {
		t.Errorf("an unrecognised failure must not be mapped, got code %q", me.Err.Code)
	}

	// 🔒 The two `required` checks run BEFORE the transport is touched at all.
	before := f.details.calls
	_, err = f.service.GetTableDetail(f.ctx, "prod", "", "users")
	e = assertManagementCode(t, err, "common.field_required", "blank schema")
	assertParam(t, e, "fields", "schema", "blank schema")
	if f.details.calls != before {
		t.Errorf("a blank schema must not reach the proxy transport")
	}
}

// The list read answers `[]`, never null, on an empty store — INV-A1-4 at the service boundary rather
// than at the DTO.
func TestListDatasourcesAnswersAnArrayNotNull(t *testing.T) {
	base := newFixture(t)
	service := NewDatasourceService(datasource.NewDatasourceStore(base.db), nil, nil)

	got, err := service.ListDatasources(base.ctx)
	assertNoError(t, err, "listDatasources")
	assertJSON(t, got, `[]`, "no datasources")

	catalog, err := service.BrowseCatalog(base.ctx, "ghost")
	if catalog != nil {
		t.Errorf("a failed browse returns nil, not an empty slice: %v", catalog)
	}
	assertManagementCode(t, err, "common.not_found", "browse of an unknown datasource")
}
