package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/cpgo/audit"
)

func OptInstant(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := JavaInstant(*t)
	return &s
}

func OptText(b []byte) *string {
	if b == nil {
		return nil
	}
	s := string(b)
	return &s
}

func Forbidden(code string, params Params) error {
	return &ManagementError{Code: code, Params: params, Status: http.StatusForbidden}
}

func BadRequest(code string) error {
	return &ManagementError{Code: code, Status: http.StatusBadRequest}
}

func NonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type DBTX interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// WriteRows answers with every row as a JSON array, [] when there are none.
func WriteRows[R, T any](w http.ResponseWriter, rows []R, err error, to func(R) T) {
	if err != nil {
		Fail(w, err)
		return
	}
	out := make([]T, 0, len(rows))
	for _, r := range rows {
		out = append(out, to(r))
	}
	WriteJSON(w, http.StatusOK, out)
}

// ManagementError is Kotlin's ManagementException: an ApiError whose code picks the status, as
// respondManagementError does.
type ManagementError struct {
	Code   string
	Params Params
	Status int
}

func (e *ManagementError) Error() string { return e.Code }

func Required(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return &ManagementError{Code: "common.field_required", Params: Params{{"fields", field}}}
	}
	return nil
}

func NotFound(resource string) error {
	return &ManagementError{Code: "common.not_found", Params: Params{{"resource", resource}}}
}

// Unique turns a unique-constraint violation into common.already_exists, as Kotlin's unique() does.
func Unique(err error, resource, name string) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return &ManagementError{Code: "common.already_exists", Params: Params{{"resource", resource}, {"name", name}}}
	}
	return err
}

func UpdateSummary(typ, before, after string) string {
	if before == after {
		return "update " + typ + " '" + before + "'"
	}
	return "update " + typ + " '" + before + "' -> '" + after + "'"
}

// CedarErrors is a policy source the validator rejected; Kotlin answers it as 400 {"errors": [...]}.
type CedarErrors []string

func (CedarErrors) Error() string { return "invalid cedar policy" }

// Mutate runs change in one transaction with its audit rows, then afterCommit, then answers status with its
// result, or the management error it returned.
func Mutate(pool *pgxpool.Pool, w http.ResponseWriter, r *http.Request, status int, change func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error), afterCommit ...func(context.Context) error) {
	ctx := r.Context()
	var out any
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		var err error
		out, err = change(ctx, tx, ActorOf(ctx))
		return err
	})
	for _, f := range afterCommit {
		if err == nil {
			err = notify(ctx, f)
		}
	}
	switch {
	case err != nil:
		WriteMutationError(w, err)
	case out == nil:
		w.WriteHeader(status)
	default:
		WriteJSON(w, status, out)
	}
}

func ActorOf(ctx context.Context) audit.Actor {
	return audit.Actor{Principal: Principal(ctx), ClientAddr: RequesterIP(ctx), Channel: "console"}
}

// WriteMutationError answers a failed write: a management error with its status, else 500.
func WriteMutationError(w http.ResponseWriter, err error) {
	var me *ManagementError
	var ce CedarErrors
	switch {
	case errors.As(err, &ce):
		WriteJSON(w, http.StatusBadRequest, map[string][]string{"errors": ce})
	case errors.As(err, &me):
		code := http.StatusBadRequest
		switch me.Code {
		case "common.not_found":
			code = http.StatusNotFound
		case "role.system_immutable", "policy.system_immutable", "group.system_immutable":
			code = http.StatusConflict
		}
		if me.Status != 0 {
			code = me.Status
		}
		WriteErrorParams(w, code, me.Code, me.Params)
	default:
		Fail(w, err)
	}
}

// notify runs a post-commit signal even if the client has gone, retrying briefly: the change is already
// committed, so a lost signal would leave Kotlin deciding on the old state.
func notify(ctx context.Context, f func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	var err error
	for attempt := range 3 {
		if err = f(ctx); err == nil {
			return nil
		}
		slog.Warn("routes: post-commit signal failed", "attempt", attempt+1, "err", err)
		time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
	}
	return err
}

// DecodeBody reads exactly one JSON value sent as application/json; anything after it fails the request before it
// changes anything. Requiring the content type keeps a cross-site form post from reaching a write.
func DecodeBody(r *http.Request, v any) error {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return &ManagementError{Code: "common.invalid_value", Params: Params{{"field", "body"}}}
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil || dec.More() {
		return &ManagementError{Code: "common.invalid_value", Params: Params{{"field", "body"}}}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return &ManagementError{Code: "common.invalid_value", Params: Params{{"field", "body"}}}
	}
	return nil
}

func PathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil
}

// WithID answers a non-numeric {id} with 400 common.bad_id before anything else, as Kotlin's idParam does.
func WithID(next func(http.ResponseWriter, *http.Request, int64)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := PathID(r)
		if !ok {
			WriteError(w, http.StatusBadRequest, "common.bad_id", nil)
			return
		}
		next(w, r, id)
	}
}

func Fail(w http.ResponseWriter, err error) {
	slog.Error("routes: store query failed", "err", err)
	WriteError(w, http.StatusInternalServerError, "common.fallback", nil)
}

// JavaInstant formats t like java.time.Instant.toString: UTC, fractional seconds in groups of three
// digits, none when zero.
func JavaInstant(t time.Time) string {
	t = t.UTC()
	s := t.Format("2006-01-02T15:04:05")
	switch ns := t.Nanosecond(); {
	case ns == 0:
	case ns%1_000_000 == 0:
		s += "." + leftPad(ns/1_000_000, 3)
	case ns%1_000 == 0:
		s += "." + leftPad(ns/1_000, 6)
	default:
		s += "." + leftPad(ns, 9)
	}
	return s + "Z"
}

func leftPad(n, width int) string {
	s := strconv.Itoa(n)
	return strings.Repeat("0", width-len(s)) + s
}
