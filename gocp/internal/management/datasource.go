package management

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/engine"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// `DatasourceManagementService` — ManagementServices.kt:73-206.
// ---------------------------------------------------------------------------------------------

// ProxyAttachments is the slice of `ProxyEventsHub` this service uses: `fun attached(): Set<String>`
// (ProxyEventsHub.kt:135), the set of datasource names with at least one live event stream.
//
// It is an interface because `ProxyEventsHub` is not ported yet (A5/A10 own it) and because this
// service needs exactly one method of it. A Set<String> is a `map[string]struct{}`: membership is
// the only thing asked of it, and a slice would invite an O(n) scan per liveness call.
type ProxyAttachments interface {
	Attached() map[string]struct{}
}

// TableDetails is the slice of `TableDetailService` this service uses:
// `suspend fun fetch(dsName, schema, table): TableDetail?` (TableDetailExec.kt:70). Interface for the
// same reason as [ProxyAttachments] — the real implementation dials a proxy over gRPC and belongs to
// A5/A10.
//
// A nil *engine.TableDetail with a nil error is the Kotlin's `null` return: the datasource exists but
// the live introspection produced no such table. The service turns that into
// `common.not_found{resource: table}`.
type TableDetails interface {
	Fetch(ctx context.Context, name, schema, table string) (*engine.TableDetail, error)
}

// ErrTableDetailExec is the port of `sealed class TableDetailExecException` (TableDetailExec.kt:56)
// as a sentinel a [TableDetails] implementation wraps, since Go has no sealed hierarchy and this
// package must not import the gRPC plumbing that raises it.
//
// 🔒 The distinction matters: an error that wraps this becomes
// `datasource.table_introspection_failed`, which httpapi.RespondManagementError answers **502** —
// "the proxy could not tell us". Any OTHER error passes through and StatusPages answers 500. A
// TableDetails implementation that forgets to wrap turns a proxy-side timeout into a control-plane
// bug report.
//
// The three Kotlin subclasses (NoTableDetailProxyAttached, ProxyTableDetailTimeout,
// ProxyTableDetail) are indistinguishable at this layer already — the Kotlin catches the sealed
// PARENT and puts only `e.message` in `{detail}` — so one sentinel loses nothing observable.
var ErrTableDetailExec = errors.New("table detail exec failed")

// DatasourceLiveness is `@Serializable data class DatasourceLiveness` (ManagementServices.kt:56).
type DatasourceLiveness struct {
	Datasource string `json:"datasource"`
	Attached   bool   `json:"attached"`
	// CatalogSyncedAt / LastSeenAt are `String?` — absent, never null, per INV-A1-4.
	CatalogSyncedAt *string `json:"catalogSyncedAt,omitempty"`
	LastSeenAt      *string `json:"lastSeenAt,omitempty"`
}

// ColumnTagEntry is `@Serializable data class ColumnTagEntry` (ManagementServices.kt:64) — one
// classified column, flattened with its datasource name.
type ColumnTagEntry struct {
	Datasource string   `json:"datasource"`
	Schema     string   `json:"schema"`
	Table      string   `json:"table"`
	Column     string   `json:"column"`
	Tags       []string `json:"tags"`
	// MaskFnName is `maskFnName: String? = null`.
	MaskFnName *string `json:"maskFnName,omitempty"`
}

// MarshalJSON normalises Tags to `[]` rather than `null` (INV-A1-4) and encodes without HTML
// escaping, as every wire DTO in the port does.
func (e ColumnTagEntry) MarshalJSON() ([]byte, error) {
	type alias ColumnTagEntry
	a := alias(e)
	if a.Tags == nil {
		a.Tags = []string{}
	}
	return types.MarshalWire(a)
}

// DatasourceService is `class DatasourceManagementService(store, eventsHub, tableDetailService)`
// (ManagementServices.kt:73).
//
// attachments and tableDetails may be nil for a caller that only needs the catalog and
// classification surface; the two methods that use them say so.
type DatasourceService struct {
	store        *datasource.DatasourceStore
	attachments  ProxyAttachments
	tableDetails TableDetails
}

// NewDatasourceService is the constructor, argument order included.
func NewDatasourceService(
	s *datasource.DatasourceStore, attachments ProxyAttachments, tableDetails TableDetails,
) *DatasourceService {
	return &DatasourceService{store: s, attachments: attachments, tableDetails: tableDetails}
}

// ListDatasources is `fun listDatasources(): List<Datasource>`.
func (s *DatasourceService) ListDatasources(ctx context.Context) ([]datasource.Datasource, error) {
	out, err := s.store.List(ctx)
	if err != nil {
		return nil, err
	}
	// `[]`, never nil — INV-A1-4.
	if out == nil {
		out = []datasource.Datasource{}
	}
	return out, nil
}

// GetDatasource is `fun getDatasource(name): Datasource`.
func (s *DatasourceService) GetDatasource(ctx context.Context, name string) (datasource.Datasource, error) {
	return s.datasourceByName(ctx, s.store.DB().Pool, name)
}

// GetDatasourceLiveness is `fun getDatasourceLiveness(name): DatasourceLiveness` — the datasource row
// joined with `eventsHub.attached()`.
//
// 🔒 `attached` is IN-MEMORY state, not a column: it is true iff this control-plane instance is
// holding a live event stream for the datasource. `lastSeenAt` is the durable half. A port that
// derived `attached` from `lastSeenAt` being recent would answer true on an instance that has never
// spoken to the proxy.
//
// Requires the [ProxyAttachments] seam; with a nil one, `attached` is false — the same answer a
// control plane with no attached proxy gives.
func (s *DatasourceService) GetDatasourceLiveness(ctx context.Context, name string) (DatasourceLiveness, error) {
	ds, err := s.datasourceByName(ctx, s.store.DB().Pool, name)
	if err != nil {
		return DatasourceLiveness{}, err
	}
	attached := false
	if s.attachments != nil {
		_, attached = s.attachments.Attached()[name]
	}
	return DatasourceLiveness{
		Datasource:      name,
		Attached:        attached,
		CatalogSyncedAt: ds.CatalogSyncedAt,
		LastSeenAt:      ds.LastSeenAt,
	}, nil
}

// BrowseCatalog is `fun browseCatalog(name): List<CatalogColumn>` — resolve the datasource by name,
// then read its stored catalog.
func (s *DatasourceService) BrowseCatalog(ctx context.Context, name string) ([]datasource.CatalogColumn, error) {
	ds, err := s.datasourceByName(ctx, s.store.DB().Pool, name)
	if err != nil {
		return nil, err
	}
	out, err := s.store.Catalog(ctx, ds.ID)
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []datasource.CatalogColumn{}
	}
	return out, nil
}

// GetTableDetail is `suspend fun getTableDetail(name, schema, table): TableDetail`
// (ManagementServices.kt:93).
//
// The order is the Kotlin's and is observable: `required("schema")`, `required("table")`, THEN the
// datasource lookup. A request that names a nonexistent datasource AND omits the table answers
// `common.field_required`, not `common.not_found`.
//
// A nil detail with no error ⇒ `common.not_found{resource: table}`; an error wrapping
// [ErrTableDetailExec] ⇒ `datasource.table_introspection_failed{detail}` (502).
func (s *DatasourceService) GetTableDetail(
	ctx context.Context, name, schema, table string,
) (engine.TableDetail, error) {
	if err := Required("schema", schema); err != nil {
		return engine.TableDetail{}, err
	}
	if err := Required("table", table); err != nil {
		return engine.TableDetail{}, err
	}
	if _, err := s.datasourceByName(ctx, s.store.DB().Pool, name); err != nil {
		return engine.TableDetail{}, err
	}
	if s.tableDetails == nil {
		return engine.TableDetail{}, Fail(CodeTableIntrospectionFailed, map[string]string{
			"detail": "no table-detail transport is configured",
		})
	}
	detail, err := s.tableDetails.Fetch(ctx, name, schema, table)
	if err != nil {
		if errors.Is(err, ErrTableDetailExec) {
			// `mapOf("detail" to (e.message ?: ""))` — the exception's own message, verbatim.
			return engine.TableDetail{}, Fail(CodeTableIntrospectionFailed, map[string]string{"detail": err.Error()})
		}
		return engine.TableDetail{}, err
	}
	if detail == nil {
		return engine.TableDetail{}, NotFound(ResourceTable)
	}
	return *detail, nil
}

// ListColumnTags is `fun listColumnTags(name): List<ColumnTagEntry>` — browseCatalog, keeping only
// the columns that carry a classification.
//
// ⚠️ A classification with an EMPTY tag list is still a row and is still returned, with `tags: []`.
// The Kotlin's `mapNotNull` filters on the classification being present, not on it being non-empty.
func (s *DatasourceService) ListColumnTags(ctx context.Context, name string) ([]ColumnTagEntry, error) {
	columns, err := s.BrowseCatalog(ctx, name)
	if err != nil {
		return nil, err
	}
	out := []ColumnTagEntry{}
	for _, column := range columns {
		if column.Classification == nil {
			continue
		}
		out = append(out, ColumnTagEntry{
			Datasource: name,
			Schema:     column.Schema,
			Table:      column.Table,
			Column:     column.Column,
			Tags:       column.Classification.Tags,
			MaskFnName: column.Classification.MaskFnName,
		})
	}
	return out, nil
}

// ---- setColumnClassification — three overloads -------------------------------------------------
//
// The Kotlin has three (ManagementServices.kt:111,122,142): by NAME on its own transaction, by ID on
// its own transaction, and by NAME on a caller's connection. There is deliberately NO by-ID
// caller's-connection form — reproduce the gap rather than filling it, since adding one changes
// nothing observable and filling gaps is how a port stops being a port.

// SetColumnClassificationByName is `setColumnClassification(datasourceName, …)`
// (ManagementServices.kt:111) — the name-keyed overload on its own transaction.
func (s *DatasourceService) SetColumnClassificationByName(
	ctx context.Context, name string, schema *string, table, column string, tags []string, maskFnID *int64,
) (datasource.Classification, error) {
	return store.InTx(ctx, s.store.DB().Pool, func(ctx context.Context, tx pgx.Tx) (datasource.Classification, error) {
		return s.SetColumnClassificationByNameOn(ctx, tx, name, schema, table, column, tags, maskFnID)
	})
}

// SetColumnClassificationByNameOn is `setColumnClassification(datasourceName, …, connection)`
// (ManagementServices.kt:142) — the composable form, for a caller landing another write atomically
// with the classification (the MCP mutation executor's audit row).
//
// 🔒 THE ORDER OF THE FOUR CHECKS IS THE CONTRACT, and it is the same in all six overloads:
//
//  1. `required("table")`, `required("column")` — a blank one is 400 common.field_required. Note
//     SCHEMA is NOT required here: nil means "resolve the default", which is step 3's job.
//  2. resolve the datasource ⇒ `common.not_found{resource: datasource}` (404).
//  3. 🔒 INV-A11-29 — a nil schema with NO resolvable default schema is
//     `datasource.schema_required` (400), NOT a silent write to some fallback schema. A
//     classification landing on the wrong schema is a masking rule that never fires.
//  4. 🔒 INV-A11-28 — a reserved-prefix tag is `datasource.reserved_tag{tag}`.
//
// 🔒 INV-A11-28 IN FULL: `tags.firstOrNull { it.startsWith(RESERVED_TAG_PREFIX) }` ⇒
// `datasource.reserved_tag{tag}`. This is the WRITE-SIDE half of A2's INV-A2-7, which enforces the
// same rule at Cedar marshalling. Both halves exist deliberately: the marshalling half proves a tag
// that somehow got STORED still cannot be asserted to Cedar (PresetPolicyDbTest case 9), and this
// half is what stops it being stored in the first place. Neither is redundant, and removing this one
// would let an admin mint `system:pii` through the API and have every shipped system policy start
// matching a column they chose.
//
// 🔒 It reports the FIRST offending tag, and the check runs BEFORE the write, so a list mixing one
// reserved tag with five legitimate ones stores NONE of them.
//
// ⚠️ datasource.DatasourceStore.UpsertClassificationOn ALSO refuses a reserved tag (INV-A5-19), and
// that duplication is deliberate: the store copy is the backstop for a non-HTTP caller. Its error is
// not a management failure, so it would fall through as 500 — unreachable via HTTP precisely because
// this check runs first. Do not delete either copy.
func (s *DatasourceService) SetColumnClassificationByNameOn(
	ctx context.Context, c store.Queryer,
	name string, schema *string, table, column string, tags []string, maskFnID *int64,
) (datasource.Classification, error) {
	if err := requireTableAndColumn(table, column); err != nil {
		return datasource.Classification{}, err
	}
	ds, err := s.datasourceByName(ctx, c, name)
	if err != nil {
		return datasource.Classification{}, err
	}
	return s.upsertClassification(ctx, c, ds.ID, schema, table, column, tags, maskFnID)
}

// SetColumnClassificationByID is `setColumnClassification(datasourceId, …)`
// (ManagementServices.kt:122) — the id-keyed REST overload, always on its own transaction.
func (s *DatasourceService) SetColumnClassificationByID(
	ctx context.Context, id int64, schema *string, table, column string, tags []string, maskFnID *int64,
) (datasource.Classification, error) {
	return store.InTx(ctx, s.store.DB().Pool, func(ctx context.Context, tx pgx.Tx) (datasource.Classification, error) {
		if err := requireTableAndColumn(table, column); err != nil {
			return datasource.Classification{}, err
		}
		ds, found, err := s.store.GetOn(ctx, tx, id)
		if err != nil {
			return datasource.Classification{}, err
		}
		if !found {
			return datasource.Classification{}, NotFound(ResourceDatasource)
		}
		return s.upsertClassification(ctx, tx, ds.ID, schema, table, column, tags, maskFnID)
	})
}

// upsertClassification is steps 3 and 4 plus the write — the tail all three set overloads share
// verbatim in the Kotlin.
func (s *DatasourceService) upsertClassification(
	ctx context.Context, c store.Queryer,
	id int64, schema *string, table, column string, tags []string, maskFnID *int64,
) (datasource.Classification, error) {
	// 🔒 INV-A11-29. Note the asymmetry with clearColumnClassification: THIS path only checks that a
	// default EXISTS and then hands the nil schema to the store, which resolves it again. The clear
	// path resolves it here and passes the resolved string down. Two shapes for one rule, reproduced.
	if schema == nil {
		if _, ok, err := s.store.DefaultSchemaOn(ctx, c, id); err != nil {
			return datasource.Classification{}, err
		} else if !ok {
			return datasource.Classification{}, Fail(CodeSchemaRequired, nil)
		}
	}
	// 🔒 INV-A11-28.
	if tag, ok := firstReservedTag(tags); ok {
		return datasource.Classification{}, Fail(CodeReservedTag, map[string]string{"tag": tag})
	}
	return s.store.UpsertClassificationOn(ctx, c, id, datasource.ClassificationInput{
		Schema: schema, Table: table, Column: column, Tags: tags, MaskFnID: maskFnID,
	})
}

// firstReservedTag is `tags.firstOrNull { it.startsWith(DatasourceStore.RESERVED_TAG_PREFIX) }`.
//
// 🔒 It is a PREFIX test on the raw tag, not an equality test and not case-insensitive: `system:pii`
// and `system:anything-at-all` are both refused, `System:pii` is not. Matching the store's own
// strings.HasPrefix keeps the two halves of the guard from disagreeing about what "reserved" means,
// which is the only way a tag could pass this check and then fail the store's.
func firstReservedTag(tags []string) (string, bool) {
	for _, tag := range tags {
		if strings.HasPrefix(tag, datasource.ReservedTagPrefix) {
			return tag, true
		}
	}
	return "", false
}

// ---- clearColumnClassification — three overloads ------------------------------------------------

// ClearColumnClassificationByName is `clearColumnClassification(datasourceName, …)`
// (ManagementServices.kt:163).
func (s *DatasourceService) ClearColumnClassificationByName(
	ctx context.Context, name string, schema *string, table, column string,
) (DeleteResult, error) {
	return store.InTx(ctx, s.store.DB().Pool, func(ctx context.Context, tx pgx.Tx) (DeleteResult, error) {
		return s.ClearColumnClassificationByNameOn(ctx, tx, name, schema, table, column)
	})
}

// ClearColumnClassificationByNameOn is `clearColumnClassification(datasourceName, …, connection)`
// (ManagementServices.kt:186).
//
// ⚠️ NO reserved-tag check — there are no tags to check, and clearing a column that a system
// manifest classified is allowed at this layer. The system tags are re-derived, not stored here.
//
// 🔒 Unlike the set path, the schema is RESOLVED here and the resolved string is passed down: the
// store's delete requires an explicit schema (it has no default-resolution of its own), so a nil
// schema with no default is `datasource.schema_required` rather than a DELETE that matches nothing.
func (s *DatasourceService) ClearColumnClassificationByNameOn(
	ctx context.Context, c store.Queryer, name string, schema *string, table, column string,
) (DeleteResult, error) {
	if err := requireTableAndColumn(table, column); err != nil {
		return DeleteResult{}, err
	}
	ds, err := s.datasourceByName(ctx, c, name)
	if err != nil {
		return DeleteResult{}, err
	}
	return s.deleteClassification(ctx, c, ds.ID, schema, table, column)
}

// ClearColumnClassificationByID is `clearColumnClassification(datasourceId, …)`
// (ManagementServices.kt:172).
func (s *DatasourceService) ClearColumnClassificationByID(
	ctx context.Context, id int64, schema *string, table, column string,
) (DeleteResult, error) {
	return store.InTx(ctx, s.store.DB().Pool, func(ctx context.Context, tx pgx.Tx) (DeleteResult, error) {
		if err := requireTableAndColumn(table, column); err != nil {
			return DeleteResult{}, err
		}
		ds, found, err := s.store.GetOn(ctx, tx, id)
		if err != nil {
			return DeleteResult{}, err
		}
		if !found {
			return DeleteResult{}, NotFound(ResourceDatasource)
		}
		return s.deleteClassification(ctx, tx, ds.ID, schema, table, column)
	})
}

func (s *DatasourceService) deleteClassification(
	ctx context.Context, c store.Queryer, id int64, schema *string, table, column string,
) (DeleteResult, error) {
	resolved := ""
	if schema != nil {
		resolved = *schema
	} else {
		def, ok, err := s.store.DefaultSchemaOn(ctx, c, id)
		if err != nil {
			return DeleteResult{}, err
		}
		if !ok {
			return DeleteResult{}, Fail(CodeSchemaRequired, nil)
		}
		resolved = def
	}
	deleted, err := s.store.DeleteClassificationOn(ctx, c, id, resolved, table, column)
	if err != nil {
		return DeleteResult{}, err
	}
	return DeleteResult{Deleted: deleted}, nil
}

// requireTableAndColumn is the `required("table"); required("column")` pair every classification
// overload opens with, in that order.
func requireTableAndColumn(table, column string) error {
	if err := Required("table", table); err != nil {
		return err
	}
	return Required("column", column)
}

// datasourceByName is `private fun datasource(name[, connection]): Datasource`
// (ManagementServices.kt:201,204) — resolve or `common.not_found{resource: datasource}`.
func (s *DatasourceService) datasourceByName(
	ctx context.Context, c store.Queryer, name string,
) (datasource.Datasource, error) {
	ds, found, err := s.store.GetByNameOn(ctx, c, name)
	if err != nil {
		return datasource.Datasource{}, err
	}
	if !found {
		return datasource.Datasource{}, NotFound(ResourceDatasource)
	}
	return ds, nil
}
