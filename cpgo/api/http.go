package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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

func NonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func RandomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func Truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// Found is Ktor's respondRedirect: a 302 with a Location and no body.
func Found(w http.ResponseWriter, location string) {
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

// WriteRows answers with every row as a JSON array, [] when there are none, or returns the query's error.
func WriteRows[R, T any](w http.ResponseWriter, rows []R, err error, to func(R) T) error {
	if err != nil {
		return err
	}
	out := make([]T, 0, len(rows))
	for _, r := range rows {
		out = append(out, to(r))
	}
	WriteJSON(w, http.StatusOK, out)
	return nil
}

// ManagementError is an ApiError a write returns; it answers with its code's status.
type ManagementError struct {
	Code   Code
	Params Params
}

func (e *ManagementError) Error() string { return e.Code.key }

// Write answers the error with its code's status.
func (e *ManagementError) Write(w http.ResponseWriter) { writeError(w, e.Code, e.Params) }

// Err is the code as a write's error, answered by WriteError with its status.
func (c Code) Err(kv ...string) error { return &ManagementError{c, pairs(kv)} }

func Required(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return CodeFieldRequired.Err("fields", field)
	}
	return nil
}

func NotFound(resource string) error {
	return CodeNotFound.Err("resource", resource)
}

// Unique turns a unique-constraint violation into common.already_exists, as Kotlin's unique() does.
func Unique(err error, resource, name string) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return CodeAlreadyExists.Err("resource", resource, "name", name)
	}
	return err
}

func UpdateSummary(typ, before, after string) string {
	if before == after {
		return "update " + typ + " '" + before + "'"
	}
	return "update " + typ + " '" + before + "' -> '" + after + "'"
}

// Mutate runs change in one transaction with its audit rows, then afterCommit, then answers status with its
// result, or returns the error.
func Mutate(pool *pgxpool.Pool, w http.ResponseWriter, r *http.Request, status int, change func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error), afterCommit ...func(context.Context) error) error {
	ctx := r.Context()
	var out any
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		var err error
		out, err = change(ctx, tx, ActorOf(ctx))
		return err
	})
	for _, f := range afterCommit {
		if err == nil {
			err = Notify(ctx, f)
		}
	}
	switch {
	case err != nil:
		return err
	case out == nil:
		w.WriteHeader(status)
	default:
		WriteJSON(w, status, out)
	}
	return nil
}

func ActorOf(ctx context.Context) audit.Actor {
	return audit.Actor{Principal: Principal(ctx), ClientAddr: RequesterIP(ctx), Channel: "console"}
}

// Notify runs a post-commit signal even if the client has gone, retrying briefly: the change is already
// committed, so a lost signal would leave Kotlin deciding on the old state.
func Notify(ctx context.Context, f func(context.Context) error) error {
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
		return CodeInvalidValue.Err("field", "body")
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil || dec.More() {
		return CodeInvalidValue.Err("field", "body")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return CodeInvalidValue.Err("field", "body")
	}
	return nil
}

func PathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil
}

// WithID answers a non-numeric {id} with 400 common.bad_id before anything else, as Kotlin's idParam does.
func WithID(next func(http.ResponseWriter, *http.Request, int64) error) Route {
	return func(w http.ResponseWriter, r *http.Request) error {
		id, ok := PathID(r)
		if !ok {
			return CodeBadID.Err()
		}
		return next(w, r, id)
	}
}

// Route answers a request's success itself and returns its failure for Serve to answer.
type Route func(w http.ResponseWriter, r *http.Request) error

// Serve answers a route's failure: a coded error with its code's status, a rejected policy source with 400
// {"errors": [...]}, anything else with a logged 500 common.fallback.
func Serve(route Route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := route(w, r)
		var me *ManagementError
		var ce CedarErrors
		switch {
		case err == nil:
		case errors.As(err, &me):
			me.Write(w)
		case errors.As(err, &ce):
			WriteJSON(w, http.StatusBadRequest, map[string][]string{"errors": ce})
		default:
			slog.Error("routes: request failed", "method", r.Method, "path", r.URL.Path, "err", err)
			WriteError(w, CodeFallback)
		}
	}
}

// CedarErrors is a policy source the validator rejected; Kotlin answers it as 400 {"errors": [...]}.
type CedarErrors []string

func (CedarErrors) Error() string { return "invalid cedar policy" }

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
