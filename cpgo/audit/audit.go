// Package audit appends to the control plane's hash-chained audit log, interleaving with the Kotlin
// writer: both lock the same chain head row, and auditmon's canon package is the hash both produce.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/auditmon/canon"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

// Insert appends ev on tx, so it commits or rolls back with the change it records, and returns its id.
// ev.TSMicros of 0 means now.
func Insert(ctx context.Context, tx pgx.Tx, ev canon.AuditEvent) (int64, error) {
	q := db.New(tx)
	chainHead, err := q.LockAuditChainHead(ctx)
	lastID, head := chainHead.LastID, chainHead.HeadHash
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, errors.New("audit: chain head is missing")
	}
	if err != nil {
		return 0, err
	}
	if ev.TSMicros == 0 {
		ev.TSMicros = canon.EpochMicros(time.Now())
	}
	id := lastID + 1
	rowHash, err := canon.RowHash(id, ev, canon.ChainVersion, head)
	if err != nil {
		return 0, err
	}
	chainVersion := int32(canon.ChainVersion)
	if err := q.InsertAuditEvent(ctx, db.InsertAuditEventParams{
		ID: id, Ts: time.UnixMicro(ev.TSMicros).UTC(), Principal: ev.Principal, Roles: list(ev.Roles), Datasource: ev.Datasource,
		ClientAddr: ev.ClientAddr, Statement: ev.Statement, Decision: ev.Decision, FailedStage: ev.FailedStage,
		MaskedColumns: list(ev.MaskedColumns), PiiTouched: list(ev.PIITouched), LatencyMs: ev.LatencyMs, Detail: ev.Detail,
		EffectiveNamespace: list(ev.EffectiveNamespace), Channel: ev.Channel, ContextTags: list(ev.ContextTags),
		Action: ev.AuthzAction, Resource: ev.AuthzResource, Outcome: ev.Outcome, Kind: ev.Kind, RowsReturned: ev.RowsReturned,
		BytesReturned: ev.BytesReturned, DecisionID: ev.DecisionID, ChainVersion: &chainVersion, PrevHash: head, RowHash: rowHash,
	}); err != nil {
		return 0, fmt.Errorf("audit: inserting event %d: %w", id, err)
	}
	if err := q.AdvanceAuditChainHead(ctx, db.AdvanceAuditChainHeadParams{LastID: id, HeadHash: rowHash}); err != nil {
		return 0, fmt.Errorf("audit: advancing chain head: %w", err)
	}
	return id, nil
}

// Actor is who made a management change and from where.
type Actor struct {
	Principal  string
	ClientAddr string
	Channel    string
}

// Admin is ManagementAuditRecorder.record: a kind=admin event for a config change, on the change's tx.
func Admin(ctx context.Context, tx pgx.Tx, actor Actor, action, resource, summary string) error {
	return controlPlane(ctx, tx, "admin", "ALLOW", "ALLOW", actor, action, resource, summary, nil)
}

// Auth is AuthAuditRecorder.success: a kind=auth event for a credential change, on the change's tx.
func Auth(ctx context.Context, tx pgx.Tx, actor Actor, action, resource, summary string) error {
	return controlPlane(ctx, tx, "auth", "ALLOW", "SUCCESS", actor, action, resource, summary, nil)
}

// AuthDetail is Auth with the event's detail (why it happened).
func AuthDetail(ctx context.Context, tx pgx.Tx, actor Actor, action, resource, summary, detail string) error {
	return controlPlane(ctx, tx, "auth", "ALLOW", "SUCCESS", actor, action, resource, summary, &detail)
}

// AuthFailure is AuthAuditRecorder.failureBestEffort: a rejected attempt recorded in its own transaction,
// whose failure is logged and never changes the caller's answer.
func AuthFailure(ctx context.Context, pool *pgxpool.Pool, actor Actor, action, resource, summary, detail string) {
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		return controlPlane(ctx, tx, "auth", "DENY", "FAILURE", actor, action, resource, summary, &detail)
	})
	if err != nil {
		slog.Warn("audit: best-effort auth failure insert failed", "action", action, "err", err)
	}
}

func controlPlane(ctx context.Context, tx pgx.Tx, kind, decision, outcome string, actor Actor, action, resource, summary string, detail *string) error {
	var addr *string
	if actor.ClientAddr != "" {
		addr = &actor.ClientAddr
	}
	_, err := Insert(ctx, tx, canon.AuditEvent{
		Kind:          kind,
		Principal:     actor.Principal,
		Roles:         []string{},
		Datasource:    "control-plane",
		ClientAddr:    addr,
		Statement:     summary,
		Decision:      decision,
		Detail:        detail,
		Channel:       &actor.Channel,
		AuthzAction:   &action,
		AuthzResource: &resource,
		Outcome:       &outcome,
	})
	return err
}

// Entity is Kotlin's auditEntity: a display label `Type::"id"`, never parsed back as a Cedar UID.
func Entity(typ, id string) string { return typ + `::"` + id + `"` }

func list(v []string) []byte {
	if v == nil {
		v = []string{}
	}
	b, _ := json.Marshal(v)
	return b
}
