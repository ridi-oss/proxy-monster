package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteJSONMatchesKotlinBytes(t *testing.T) {
	w := httptest.NewRecorder()
	WriteJSON(w, http.StatusOK, map[string]string{"cedarSrc": `when { a < 1 && b > 2 }`})
	if got := w.Body.String(); got != `{"cedarSrc":"when { a < 1 && b > 2 }"}` {
		t.Fatalf("body %q", got)
	}
}

func TestErrorParamsKeepOrderWithoutEscaping(t *testing.T) {
	w := httptest.NewRecorder()
	WriteErrorParams(w, http.StatusBadRequest, "common.already_exists", Params{{"resource", "role"}, {"name", "R&D <x>"}})
	if got := w.Body.String(); got != `{"code":"common.already_exists","params":{"resource":"role","name":"R&D <x>"}}` {
		t.Fatalf("body %q", got)
	}
}
