package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
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
}

func (e *ManagementError) Error() string { return e.Code }

func Required(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return &ManagementError{"common.field_required", Params{{"fields", field}}}
	}
	return nil
}

func NotFound(resource string) error {
	return &ManagementError{"common.not_found", Params{{"resource", resource}}}
}

// Unique turns a unique-constraint violation into common.already_exists, as Kotlin's unique() does.
func Unique(err error, resource, name string) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return &ManagementError{"common.already_exists", Params{{"resource", resource}, {"name", name}}}
	}
	return err
}

func UpdateSummary(typ, before, after string) string {
	if before == after {
		return "update " + typ + " '" + before + "'"
	}
	return "update " + typ + " '" + before + "' -> '" + after + "'"
}

// DecodeBody reads exactly one JSON value sent as application/json; anything after it fails the request before it
// changes anything. Requiring the content type keeps a cross-site form post from reaching a write.
func DecodeBody(r *http.Request, v any) error {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return &ManagementError{"common.invalid_value", Params{{"field", "body"}}}
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil || dec.More() {
		return &ManagementError{"common.invalid_value", Params{{"field", "body"}}}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return &ManagementError{"common.invalid_value", Params{{"field", "body"}}}
	}
	return nil
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil
}

// WithID answers a non-numeric {id} with 400 common.bad_id before anything else, as Kotlin's idParam does.
func WithID(next func(http.ResponseWriter, *http.Request, int64)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(r)
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
