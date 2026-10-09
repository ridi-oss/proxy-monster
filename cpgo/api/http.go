package api

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
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
