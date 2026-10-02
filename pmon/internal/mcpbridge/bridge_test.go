package mcpbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeMCP is a Streamable HTTP endpoint that accepts only the tokens it is told are live.
type fakeMCP struct {
	mu       sync.Mutex
	live     map[string]bool
	headers  []http.Header
	handlers map[string]func(w http.ResponseWriter, msg map[string]any)
}

func (f *fakeMCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.headers = append(f.headers, r.Header.Clone())
	ok := f.live[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	f.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"common.invalid_token"}`))
		return
	}
	var msg map[string]any
	_ = json.NewDecoder(r.Body).Decode(&msg)
	method, _ := msg["method"].(string)
	if h := f.handlers[method]; h != nil {
		h(w, msg)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func jsonReply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// tokens hands out tok-1, tok-2, … and counts the mints.
type tokens struct {
	mu    sync.Mutex
	n     int
	url   string
	ttl   time.Duration
	fails error
}

func (t *tokens) source(context.Context) (Token, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fails != nil {
		return Token{}, t.fails
	}
	t.n++
	return Token{URL: t.url, Value: fmt.Sprintf("tok-%d", t.n), ExpiresAt: time.Now().Add(t.ttl)}, nil
}

func (t *tokens) minted() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.n
}

func run(t *testing.T, b *Bridge, input string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	b.In, b.Out = strings.NewReader(input), &out
	if b.HTTP == nil {
		b.HTTP = http.DefaultClient
	}
	if err := b.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var msgs []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("output line %q is not one JSON message: %v", line, err)
		}
		msgs = append(msgs, m)
	}
	return msgs
}

func TestRelaysJSONAndEventStreamResponses(t *testing.T) {
	f := &fakeMCP{live: map[string]bool{"tok-1": true}, handlers: map[string]func(http.ResponseWriter, map[string]any){
		"initialize": func(w http.ResponseWriter, msg map[string]any) {
			jsonReply(w, map[string]any{"jsonrpc": "2.0", "id": msg["id"], "result": map[string]any{"protocolVersion": "2025-06-18"}})
		},
		"tools/call": func(w http.ResponseWriter, msg map[string]any) {
			w.Header().Set("Content-Type", "text/event-stream")
			id, _ := json.Marshal(msg["id"])
			fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\n")
			fmt.Fprintf(w, "data: \"params\":{\"progress\":1}}\n\n")
			fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"a\\nb\"}]}}\n\n", id)
		},
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	src := &tokens{url: srv.URL + "/mcp", ttl: time.Hour}
	b := &Bridge{Tokens: src.source}

	input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"
	msgs := run(t, b, input)
	if len(msgs) != 1 || msgs[0]["id"] != float64(1) {
		t.Fatalf("initialize relay = %v, want one response and nothing for the notification", msgs)
	}

	msgs = run(t, b, `{"jsonrpc":"2.0","id":"call-7","method":"tools/call","params":{"name":"x"}}`+"\n")
	if len(msgs) != 2 || msgs[0]["method"] != "notifications/progress" || msgs[1]["id"] != "call-7" {
		t.Fatalf("event-stream relay = %v, want the progress event then the response", msgs)
	}
	text := msgs[1]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"]
	if text != "a\nb" {
		t.Errorf("relayed text = %q", text)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	last := f.headers[len(f.headers)-1]
	if last.Get("Authorization") != "Bearer tok-1" || !strings.Contains(last.Get("Accept"), "text/event-stream") {
		t.Errorf("forwarded headers = %v", last)
	}
	if last.Get("MCP-Protocol-Version") != "2025-06-18" {
		t.Errorf("MCP-Protocol-Version = %q, want the version initialize negotiated", last.Get("MCP-Protocol-Version"))
	}
}

func TestRemintsOnceOn401(t *testing.T) {
	f := &fakeMCP{live: map[string]bool{"tok-2": true}, handlers: map[string]func(http.ResponseWriter, map[string]any){
		"ping": func(w http.ResponseWriter, msg map[string]any) {
			jsonReply(w, map[string]any{"jsonrpc": "2.0", "id": msg["id"], "result": map[string]any{}})
		},
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	src := &tokens{url: srv.URL + "/mcp", ttl: time.Hour}

	msgs := run(t, &Bridge{Tokens: src.source}, `{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n")
	if len(msgs) != 1 || msgs[0]["result"] == nil {
		t.Fatalf("relay = %v, want the answer after one re-mint", msgs)
	}

	f.mu.Lock()
	f.live = map[string]bool{}
	f.mu.Unlock()
	before := src.minted()
	msgs = run(t, &Bridge{Tokens: src.source}, `{"jsonrpc":"2.0","id":2,"method":"ping"}`+"\n")
	if got := src.minted() - before; got != 2 {
		t.Errorf("minted %d tokens for one refused request, want the first plus one retry", got)
	}
	if len(msgs) != 1 || msgs[0]["error"] == nil || !strings.Contains(fmt.Sprint(msgs[0]["error"]), "HTTP 401") {
		t.Fatalf("relay of a refused request = %v, want a JSON-RPC error naming the 401", msgs)
	}
}

func TestRemintsAnExpiringToken(t *testing.T) {
	f := &fakeMCP{live: map[string]bool{"tok-1": true, "tok-2": true, "tok-3": true}, handlers: map[string]func(http.ResponseWriter, map[string]any){
		"ping": func(w http.ResponseWriter, msg map[string]any) {
			jsonReply(w, map[string]any{"jsonrpc": "2.0", "id": msg["id"], "result": map[string]any{}})
		},
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	src := &tokens{url: srv.URL + "/mcp", ttl: time.Second}
	run(t, &Bridge{Tokens: src.source}, `{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n")
	if src.minted() != 2 {
		t.Errorf("minted %d, want a fresh token for a request whose token was inside the expiry margin", src.minted())
	}
}

func TestFailsClearlyWhenNotLoggedIn(t *testing.T) {
	src := &tokens{fails: errors.New("not logged in to \"hr\" — run `pmon login hr`")}
	var out bytes.Buffer
	b := &Bridge{Tokens: src.source, HTTP: http.DefaultClient, In: strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n"), Out: &out}
	err := b.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "pmon login hr") {
		t.Errorf("Run = %v, want the login hint", err)
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want nothing before a login exists", out.String())
	}
}

func TestReadEventsJoinsDataLines(t *testing.T) {
	var got []string
	err := readEvents(io.NopCloser(strings.NewReader("id: 1\r\ndata: {\"a\":\r\ndata: 1}\r\n\r\n: comment\n\ndata: {\"b\":2}")), func(m []byte) {
		got = append(got, string(m))
	})
	if err != nil || len(got) != 2 || got[0] != "{\"a\":\n1}" || got[1] != "{\"b\":2}" {
		t.Errorf("readEvents = %q, %v", got, err)
	}
}
