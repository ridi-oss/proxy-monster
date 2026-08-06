// Package tabledetail is the PRODUCER half of `TableDetailExec.kt` — the thing that dials a proxy over
// the bidirectional `TableDetailExec` stream, collects one live table detail, and overlays the
// classifications the control plane owns.
//
// WHY IT LIVES IN ITS OWN PACKAGE. It composes four things that belong to different areas —
// internal/core's channel registry + events hub, internal/datasource's engine schema resolution and
// stored catalog, internal/engine's TableDetail wire type, and internal/management's error sentinel.
// internal/management explicitly must not import the gRPC plumbing (see management's ErrTableDetailExec
// doc), so the composition cannot live there; and internal/core is where the registry lives, so it
// cannot depend on management. A small package that depends on all four and is depended on only by the
// composition root is the shape that does not invert anything.
//
// It is the last piece of A5/A10 that `internal/core/core.go` recorded as owed: "In-memory and
// REGISTRY-ONLY (its producer service is a later increment): TableDetailChannels".
package tabledetail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/core"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/engine"
	"github.com/ridi-oss/proxy-monster/gocp/internal/management"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
)

// ExchangeTimeoutMS is `TABLE_DETAIL_EXCHANGE_TIMEOUT_MS = 30_000` (TableDetailExec.kt:22).
//
// ⚠️ It is NOT config.ExchangeTimeoutMS (630s). A table detail is one information_schema read, not a
// user query, so it gets its own much shorter budget: a wedged introspection must surface as a 502
// while the admin is still looking at the page, and borrowing the query budget would hold the HTTP
// request open for ten minutes.
const ExchangeTimeoutMS int64 = 30_000

// The three `ProxyTableDetailException` messages that are asserted on, kept as constants because
// TableDetailDbTest matches them and the Kotlin's own text is the contract.
const (
	ErrMsgUnexpectedTable = "proxy returned table detail for an unexpected table"
	ErrMsgInvalidJSON     = "proxy sent invalid table-detail JSON"
	ErrMsgSecondReady     = "proxy sent TableDetailReady more than once"
	ErrMsgEmptyMessage    = "proxy sent an empty table-detail message"
	ErrMsgClosedEarly     = "proxy table-detail stream closed before a terminal response"
	ErrMsgIntrospection   = "proxy table introspection failed"
	ErrMsgNoProxy         = "no proxy is attached to this datasource"
	ErrMsgTimeout         = "the proxy table-detail channel timed out"
)

// Datasources is the slice of A5's store this needs: resolve the datasource by name, and read its
// stored catalog for the classification overlay.
type Datasources interface {
	GetByName(ctx context.Context, name string) (datasource.Datasource, bool, error)
	Catalog(ctx context.Context, id int64) ([]datasource.CatalogColumn, error)
}

// Service is `class TableDetailService(private val core: ControlPlaneCore)`.
//
// 🔒 Channels and Hub MUST be the same instances the gRPC surface holds, or the proxy's TableDetailReady
// lands on a registry nobody is waiting on and every fetch times out. internal/app passes core's.
type Service struct {
	Channels    *core.TableDetailChannelRegistry
	Hub         *core.ProxyEventsHub
	Datasources Datasources
	// DialTimeoutMS overrides config.DialTimeoutMS; zero takes the default.
	DialTimeoutMS int64
	// ExchangeTimeoutMS overrides [ExchangeTimeoutMS]; zero takes the default.
	ExchangeTimeoutMS int64
	// NewSessionID is overridable so a test can pin the correlation id. Nil uses a v4 UUID, which is
	// what `UUID.randomUUID().toString()` is.
	NewSessionID func() string
}

// execError wraps a message as a management.ErrTableDetailExec, so httpapi answers 502
// `datasource.table_introspection_failed{detail}` with this text — the Kotlin puts `e.message` in
// `{detail}` verbatim, so the message IS the wire value.
func execError(msg string) error {
	return fmt.Errorf("%s: %w", msg, management.ErrTableDetailExec)
}

func execErrorWrapping(msg string, cause error) error {
	return fmt.Errorf("%s: %v: %w", msg, cause, management.ErrTableDetailExec)
}

func (s *Service) sessionID() string {
	if s.NewSessionID != nil {
		return s.NewSessionID()
	}
	return uuid.NewString()
}

func (s *Service) dialTimeout() time.Duration {
	ms := s.DialTimeoutMS
	if ms <= 0 {
		ms = config.DialTimeoutMS
	}
	return time.Duration(ms) * time.Millisecond
}

func (s *Service) exchangeTimeout() time.Duration {
	ms := s.ExchangeTimeoutMS
	if ms <= 0 {
		ms = ExchangeTimeoutMS
	}
	return time.Duration(ms) * time.Millisecond
}

// Fetch is `suspend fun fetch(dsName, schema, table): TableDetail?` (TableDetailExec.kt:70-129), and it
// satisfies management.TableDetails.
//
// A nil detail with a nil error is the Kotlin's `null`: either the datasource does not exist, or the
// proxy's live introspection found no such table. The service above turns that into
// `common.not_found{resource: table}`.
func (s *Service) Fetch(ctx context.Context, dsName, schema, table string) (*engine.TableDetail, error) {
	ds, found, err := s.Datasources.GetByName(ctx, dsName)
	if err != nil {
		return nil, err
	}
	if !found {
		// `?: return null` — an absent datasource is indistinguishable from an absent table HERE. The
		// caller has already checked the datasource, so this arm is the concurrent-delete race.
		return nil, nil
	}

	// 🔒 THE SCHEMA THE PROXY MUST ANSWER UNDER, and the reason the check below is not tautological.
	// The `"public"` default selector maps to THIS engine's default schema — MySQL's database — while any
	// other value is an explicit schema. Comparing the reply against the raw REQUEST would accept a
	// MySQL proxy answering literally `public`, a schema MySQL does not have.
	expectedSchema, err := datasource.ResolveSchema(ds.Engine, schema, ds.DBName)
	if err != nil {
		return nil, err
	}

	sessionID := s.sessionID()
	pending := &core.PendingTableDetailSession{
		SessionID: sessionID,
		// Buffered: the gRPC handler's Attach must never block on a producer that has already timed out.
		Ready: make(chan *core.AttachedTableDetail, 1),
	}

	var (
		registered bool
		attached   *core.AttachedTableDetail
	)
	// The Kotlin's `finally`, as a closure so every early return goes through it.
	defer func() { s.teardown(sessionID, pending, registered, &attached) }()

	if !s.Channels.Register(pending) {
		// `check(putIfAbsent(...) == null)` — a duplicate id is a programming error, not a proxy fault,
		// so it must NOT wrap ErrTableDetailExec: 500, not 502.
		return nil, errors.New("table-detail session '" + sessionID + "' is already registered")
	}
	registered = true

	// 🔒 NOT_ATTACHED and WEDGED COLLAPSE TO ONE ERROR, exactly as the Kotlin does — both mean "no proxy
	// can answer", and the admin's remedy is identical.
	switch s.Hub.RequestOpenTableDetail(dsName, sessionID, schema, table) {
	case core.DispatchSent:
	default:
		return nil, execError(ErrMsgNoProxy)
	}

	attached, err = s.awaitReady(ctx, pending)
	if err != nil {
		return nil, err
	}

	detail, err := s.collectResponse(ctx, attached.Inbound)
	if err != nil {
		return nil, err
	}
	if detail == nil {
		return nil, nil
	}

	// The reply must be for the table that was asked about, under the RESOLVED schema. Anything else is
	// a channel or response mixup, and serving it would show an admin one table's columns under another
	// table's name — with this table's classifications overlaid onto it.
	if detail.Schema != expectedSchema || detail.Table != table {
		return nil, execError(ErrMsgUnexpectedTable)
	}

	if err := s.overlayClassifications(ctx, ds.ID, detail); err != nil {
		return nil, err
	}
	return detail, nil
}

// overlayClassifications is TableDetailExec.kt:108-116 — the whole reason the control plane sits in
// front of this call at all.
//
// 🔒 THE PROXY NEVER SENDS A CLASSIFICATION (internal/engine/tabledetail.go:67-69: "Classification is
// ALWAYS null from the proxy … The control plane owns that overlay"). Without this step the console's
// table view shows every column as unclassified, so an admin reviewing which columns are PII would read
// "none" for a table that is fully classified — a silent, confident wrong answer.
//
// The join key is the COLUMN IDENTITY (schema, table, column) against the stored catalog, filtered to
// the schema/table the proxy actually reported rather than the one requested — so the resolved-schema
// mapping above is what the overlay keys on too, and a MySQL `public` request cannot miss every column.
//
// A column present live but absent from the stored catalog gets nil, which is correct: it has never
// been classified. That is why the map is consulted per column instead of requiring a full match.
func (s *Service) overlayClassifications(ctx context.Context, datasourceID int64, detail *engine.TableDetail) error {
	catalog, err := s.Datasources.Catalog(ctx, datasourceID)
	if err != nil {
		return err
	}
	byColumn := make(map[string]*engine.Classification, len(detail.Columns))
	for _, c := range catalog {
		if c.Schema != detail.Schema || c.Table != detail.Table {
			continue
		}
		byColumn[c.Column] = toEngineClassification(c.Classification)
	}
	for i := range detail.Columns {
		detail.Columns[i].Classification = byColumn[detail.Columns[i].Name]
	}
	return nil
}

// awaitReady is `withTimeout(DIAL_TIMEOUT_MS) { pending.ready.await() }`.
//
// 🔒 A dial timeout is a PROXY fault, so it wraps ErrTableDetailExec and becomes a 502. A cancelled
// request (the admin closed the tab) is not, and passes through as ctx.Err() → 500 is never rendered
// because the connection is already gone.
func (s *Service) awaitReady(ctx context.Context, pending *core.PendingTableDetailSession) (*core.AttachedTableDetail, error) {
	timer := time.NewTimer(s.dialTimeout())
	defer timer.Stop()
	select {
	case a := <-pending.Ready:
		return a, nil
	case <-timer.C:
		return nil, execError(ErrMsgTimeout)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// collectResponse is `private suspend fun collectResponse(inbound)` (TableDetailExec.kt:131-157).
//
// Four arms, and the ORDER of the checks is the Kotlin's: result, error, a second sessionReady, then
// "empty". A `hasResult` carrying the literal string `null` is the not-found signal, NOT a parse error
// — that distinction is what makes a missing table a 404 instead of a 502.
//
// 🔒 A CLOSED STREAM WITH NO TERMINAL MESSAGE IS AN ERROR, never a silent nil. Returning nil there would
// render "table not found" for a proxy that crashed mid-introspection.
func (s *Service) collectResponse(ctx context.Context, inbound <-chan *pb.ProxyTableDetailMsg) (*engine.TableDetail, error) {
	timer := time.NewTimer(s.exchangeTimeout())
	defer timer.Stop()
	for {
		select {
		case msg, ok := <-inbound:
			if !ok {
				return nil, execError(ErrMsgClosedEarly)
			}
			switch {
			case msg.GetResult() != nil:
				payload := msg.GetResult().GetJson()
				if payload == "null" {
					return nil, nil
				}
				var detail engine.TableDetail
				if err := json.Unmarshal([]byte(payload), &detail); err != nil {
					return nil, execErrorWrapping(ErrMsgInvalidJSON, err)
				}
				return &detail, nil
			case msg.GetError() != nil:
				// `message.error.message.ifBlank { … }` — a blank proxy message still has to say something.
				text := msg.GetError().GetMessage()
				if text == "" {
					text = ErrMsgIntrospection
				}
				return nil, execError(text)
			case msg.GetSessionReady() != nil:
				// The FIRST Ready is consumed by the gRPC handler to claim the session, so seeing one here
				// means the proxy sent two.
				return nil, execError(ErrMsgSecondReady)
			default:
				return nil, execError(ErrMsgEmptyMessage)
			}
		case <-timer.C:
			return nil, execError(ErrMsgTimeout)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// teardown is the Kotlin's `finally` block, including the attach-vs-timeout race it calls out by name
// ("Resolve the same attach-vs-timeout race as RunExec").
//
// 🔒 THE RACE. Between the dial timing out and this running, the proxy may have claimed the session —
// in which case Remove finds nothing and the Ready channel holds an AttachedTableDetail nobody has
// taken. Dropping it would leak the proxy's stream: it waits for a Close that never comes until its own
// stream timeout. So when Remove returns nil while we never attached, the attachment is collected from
// Ready (non-blocking: the handler always sends before Remove can miss) and closed properly.
func (s *Service) teardown(
	sessionID string, pending *core.PendingTableDetailSession, registered bool, attached **core.AttachedTableDetail,
) {
	if !registered {
		return
	}
	if *attached == nil && s.Channels.Remove(sessionID) == nil {
		select {
		case a := <-pending.Ready:
			*attached = a
		default:
		}
	}
	if a := *attached; a != nil {
		// Best-effort Close so the proxy can end its stream promptly. A full buffer means the proxy is
		// already gone; its own timeout collects it.
		select {
		case a.Outbound <- &pb.ControlTableDetailMsg{
			Kind: &pb.ControlTableDetailMsg_Close{Close: &pb.TableDetailClose{}},
		}:
		default:
		}
	}
	s.Channels.Remove(sessionID)
}

// toEngineClassification converts A5's stored classification into the wire shape the TableDetail
// carries. The two structs are field-identical but live in different packages — internal/engine owns
// the `pmkotlin:"default"` tags that pin the Kotlin serialisation defaults, and internal/datasource
// owns the store row — so a conversion rather than a shared type is what keeps that ownership honest.
//
// nil in, nil out: an unclassified column stays unclassified.
func toEngineClassification(c *datasource.Classification) *engine.Classification {
	if c == nil {
		return nil
	}
	return &engine.Classification{
		Schema:     c.Schema,
		Table:      c.Table,
		Column:     c.Column,
		Tags:       c.Tags,
		MaskFnID:   c.MaskFnID,
		MaskFnName: c.MaskFnName,
	}
}
