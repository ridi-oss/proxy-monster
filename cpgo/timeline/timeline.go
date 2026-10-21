// Package timeline writes a workflow request's timeline, as Kotlin's RequestEvents.record does, so a request
// decided in either process gets the same rows.
package timeline

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

const (
	Requested = "requested"
	Approved  = "approved"
	Rejected  = "rejected"
)

var decisions = map[string]bool{Approved: true, Rejected: true, "unapproved": true, "ran": true}

// Record appends kind to the request's timeline on q's transaction. A request that is not a workflow request
// gets no row. A person's decision also lists them as an approver; a system: actor never is.
func Record(ctx context.Context, q db.DBTX, requestID int64, kind string, actor *string, origin string, body *string) error {
	queries := db.New(q)
	_, err := queries.RecordRequestEvent(ctx, db.RecordRequestEventParams{RequestID: requestID, Kind: kind, Actor: actor, Body: body, Origin: origin})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil || actor == nil || !decisions[kind] || strings.HasPrefix(*actor, "system:") {
		return err
	}
	return queries.AddApprover(ctx, db.AddApproverParams{RequestID: requestID, Principal: *actor})
}
