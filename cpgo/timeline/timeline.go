// Package timeline writes a workflow request's timeline, as Kotlin's RequestEvents.record does, so a request
// decided in either process gets the same rows.
package timeline

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

const (
	Requested  = "requested"
	Approved   = "approved"
	Rejected   = "rejected"
	Closed     = "closed"
	Comment    = "comment"
	LGTM       = "lgtm"
	CCAdded    = "cc_added"
	CCRemoved  = "cc_removed"
	Unapproved = "unapproved"
)

var decisions = map[string]bool{Approved: true, Rejected: true, Unapproved: true, "ran": true}

// Event is one timeline entry, Kotlin's RequestEvent.
type Event struct {
	ID        int64   `json:"id"`
	Kind      string  `json:"kind"`
	Actor     *string `json:"actor,omitempty"`
	Body      *string `json:"body,omitempty"`
	Revision  *int32  `json:"revision,omitempty"`
	Origin    string  `json:"origin"`
	CreatedAt string  `json:"createdAt"`
	EditedAt  *string `json:"editedAt,omitempty"`
	Deleted   bool    `json:"deleted"`
}

func toEvent(r db.RequestTimelineRow) Event {
	return Event{ID: r.ID, Kind: r.Kind, Actor: r.Actor, Body: r.Body, Revision: r.Revision, Origin: r.Origin,
		CreatedAt: api.JavaInstant(r.CreatedAt), EditedAt: api.OptInstant(r.EditedAt), Deleted: r.DeletedAt != nil}
}

// Record appends kind to the request's timeline on q's transaction and returns it, or nil for a request that is
// not a workflow request. A person's decision also lists them as an approver; a system: actor never is.
func Record(ctx context.Context, q db.DBTX, requestID int64, kind string, actor *string, origin string, body *string) (*Event, error) {
	queries := db.New(q)
	row, err := queries.RecordRequestEvent(ctx, db.RecordRequestEventParams{RequestID: requestID, Kind: kind, Actor: actor, Body: body, Origin: origin})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ev := toEvent(db.RequestTimelineRow(row))
	if actor == nil || !decisions[kind] || strings.HasPrefix(*actor, "system:") {
		return &ev, nil
	}
	return &ev, queries.AddApprover(ctx, db.AddApproverParams{RequestID: requestID, Principal: *actor})
}

// List is the request's timeline in order.
func List(ctx context.Context, q db.DBTX, requestID int64) ([]Event, error) {
	rows, err := db.New(q).RequestTimeline(ctx, requestID)
	out := make([]Event, len(rows))
	for i, r := range rows {
		out[i] = toEvent(r)
	}
	return out, err
}
