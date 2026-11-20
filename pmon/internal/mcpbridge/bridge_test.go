package mcpbridge

import (
	"bufio"
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
	if caps := fmt.Sprint(msgs[0]["result"].(map[string]any)["capabilities"]); caps != "map[tools:map[listChanged:true]]" {
		t.Errorf("relayed capabilities = %s, want tools.listChanged, which the relay sends when the login ends", caps)
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
	s := startSession(t, &Bridge{Tokens: src.source})
	s.send(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	s.next()
	s.send(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	s.next()
	s.close()
	if src.minted() != 2 {
		t.Errorf("minted %d, want a fresh token for a request whose token was inside the expiry margin", src.minted())
	}
}

// session runs b over pipes, so a test can wait for each answer before sending the next message as a client does.
type session struct {
	t     *testing.T
	in    *io.PipeWriter
	lines *bufio.Scanner
	done  chan error
}

func startSession(t *testing.T, b *Bridge) *session {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	b.In, b.Out = inR, outW
	if b.HTTP == nil {
		b.HTTP = http.DefaultClient
	}
	s := &session{t: t, in: inW, lines: bufio.NewScanner(outR), done: make(chan error, 1)}
	go func() { s.done <- b.Run(context.Background()); outW.Close() }()
	return s
}

func (s *session) send(msg string) { fmt.Fprintln(s.in, msg) }

func (s *session) next() map[string]any {
	s.t.Helper()
	if !s.lines.Scan() {
		s.t.Fatalf("output ended: %v", s.lines.Err())
	}
	var m map[string]any
	if err := json.Unmarshal(s.lines.Bytes(), &m); err != nil {
		s.t.Fatalf("output line %q: %v", s.lines.Text(), err)
	}
	return m
}

func (s *session) close() {
	s.t.Helper()
	s.in.Close()
	if err := <-s.done; err != nil {
		s.t.Fatalf("Run: %v", err)
	}
}

func TestStartsLoggedOutWithTheLoginHint(t *testing.T) {
	src := &tokens{fails: errors.New("not logged in to \"hr\" — run `pmon login hr`")}
	s := startSession(t, &Bridge{Tokens: src.source})
	defer s.close()

	s.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	init, _ := s.next()["result"].(map[string]any)
	if init["protocolVersion"] != "2025-06-18" || !strings.Contains(fmt.Sprint(init["instructions"]), "pmon login hr") {
		t.Errorf("initialize = %v, want the client's version and the login hint", init)
	}
	s.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	s.send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if m := s.next(); m["id"] != float64(2) || fmt.Sprint(m["result"]) != "map[tools:[]]" {
		t.Errorf("tools/list = %v, want no tools", m)
	}
	s.send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_query"}}`)
	if m := s.next(); !strings.Contains(fmt.Sprint(m["error"]), "pmon login hr") {
		t.Errorf("tools/call = %v, want an error naming the login", m)
	}
}

type fakeOffline struct{}

func (fakeOffline) Instructions(err error) string { return "about hr. " + err.Error() }
func (fakeOffline) Tools() []map[string]any       { return []map[string]any{{"name": "login"}} }
func (fakeOffline) Call(_ context.Context, name string, args json.RawMessage) (string, error) {
	if name != "login" {
		return "", errors.New("no such tool")
	}
	return "opened " + string(args), nil
}

func TestServesOfflineToolsWhileLoggedOut(t *testing.T) {
	src := &tokens{fails: errors.New("run `pmon login hr`")}
	s := startSession(t, &Bridge{Tokens: src.source, Offline: fakeOffline{}})
	defer s.close()

	s.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if init, _ := s.next()["result"].(map[string]any); init["instructions"] != "about hr. run `pmon login hr`" {
		t.Errorf("instructions = %v, want Offline's", init["instructions"])
	}
	s.send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if m := s.next(); fmt.Sprint(m["result"]) != "map[tools:[map[name:login]]]" {
		t.Errorf("tools/list = %v, want Offline's tools", m)
	}
	s.send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"login","arguments":{"server":"hr"}}}`)
	if m := s.next(); fmt.Sprint(m["result"]) != `map[content:[map[text:opened {"server":"hr"} type:text]] isError:false]` {
		t.Errorf("tools/call login = %v", m)
	}
	s.send(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run_query"}}`)
	if m := s.next(); fmt.Sprint(m["result"]) != "map[content:[map[text:no such tool type:text]] isError:true]" {
		t.Errorf("tools/call run_query = %v, want a tool error", m)
	}
}

func TestConnectsOnceLoggedIn(t *testing.T) {
	var inits int
	f := &fakeMCP{live: map[string]bool{"tok-1": true}, handlers: map[string]func(http.ResponseWriter, map[string]any){
		"initialize": func(w http.ResponseWriter, msg map[string]any) {
			inits++
			w.Header().Set("Mcp-Session-Id", "sess-1")
			jsonReply(w, map[string]any{"jsonrpc": "2.0", "id": msg["id"], "result": map[string]any{"protocolVersion": "2025-06-18"}})
		},
		"tools/list": func(w http.ResponseWriter, msg map[string]any) {
			jsonReply(w, map[string]any{"jsonrpc": "2.0", "id": msg["id"], "result": map[string]any{"tools": []any{map[string]any{"name": "run_query"}}}})
		},
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	src := &tokens{url: srv.URL + "/mcp", ttl: time.Hour, fails: errors.New("run `pmon login`")}

	s := startSession(t, &Bridge{Tokens: src.source, LoginPoll: 10 * time.Millisecond})
	s.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	if m := s.next(); m["id"] != float64(1) {
		t.Fatalf("first message = %v, want the local initialize answer", m)
	}
	src.mu.Lock()
	src.fails = nil
	src.mu.Unlock()
	if m := s.next(); m["method"] != "notifications/tools/list_changed" {
		t.Fatalf("after login = %v, want tools/list_changed", m)
	}
	s.send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if m := s.next(); !strings.Contains(fmt.Sprint(m["result"]), "run_query") {
		t.Fatalf("tools/list after login = %v, want the server's tools", m)
	}
	s.close()

	f.mu.Lock()
	defer f.mu.Unlock()
	last := f.headers[len(f.headers)-1]
	if inits != 1 || last.Get("Mcp-Session-Id") != "sess-1" || last.Get("MCP-Protocol-Version") != "2025-06-18" {
		t.Errorf("upstream initialize count %d, last headers %v, want one replayed initialize and its session", inits, last)
	}
}

func TestARequestThatFindsTheLoginAlsoAnnouncesTools(t *testing.T) {
	f := &fakeMCP{live: map[string]bool{"tok-1": true}, handlers: map[string]func(http.ResponseWriter, map[string]any){
		"initialize": func(w http.ResponseWriter, msg map[string]any) {
			jsonReply(w, map[string]any{"jsonrpc": "2.0", "id": msg["id"], "result": map[string]any{"protocolVersion": "2025-06-18"}})
		},
		"ping": func(w http.ResponseWriter, msg map[string]any) {
			jsonReply(w, map[string]any{"jsonrpc": "2.0", "id": msg["id"], "result": map[string]any{}})
		},
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	src := &tokens{url: srv.URL + "/mcp", ttl: time.Hour, fails: errors.New("run `pmon login`")}

	s := startSession(t, &Bridge{Tokens: src.source, LoginPoll: time.Hour})
	s.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	s.next()
	src.mu.Lock()
	src.fails = nil
	src.mu.Unlock()
	s.send(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	if m := s.next(); m["method"] != "notifications/tools/list_changed" {
		t.Fatalf("first message after login = %v, want tools/list_changed", m)
	}
	if m := s.next(); m["id"] != float64(2) || m["result"] == nil {
		t.Fatalf("ping after login = %v, want the server's answer", m)
	}
	s.close()
}

func TestStaysLoggedOutWhenTheServerRefusesInitialize(t *testing.T) {
	f := &fakeMCP{live: map[string]bool{"tok-1": true}, handlers: map[string]func(http.ResponseWriter, map[string]any){
		"initialize": func(w http.ResponseWriter, msg map[string]any) {
			jsonReply(w, map[string]any{"jsonrpc": "2.0", "id": msg["id"], "error": map[string]any{"code": -32602, "message": "bad version"}})
		},
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	src := &tokens{url: srv.URL + "/mcp", ttl: time.Hour, fails: errors.New("run `pmon login`")}

	s := startSession(t, &Bridge{Tokens: src.source, LoginPoll: time.Hour})
	s.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	s.next()
	src.mu.Lock()
	src.fails = nil
	src.mu.Unlock()
	s.send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if m := s.next(); m["id"] != float64(2) || fmt.Sprint(m["result"]) != "map[tools:[]]" {
		t.Fatalf("tools/list after a refused initialize = %v, want still no tools", m)
	}
	s.close()
}

func TestFallsBackToOfflineToolsWhenTheLoginEnds(t *testing.T) {
	var inits int
	f := &fakeMCP{live: map[string]bool{"tok-1": true, "tok-2": true}, handlers: map[string]func(http.ResponseWriter, map[string]any){
		"initialize": func(w http.ResponseWriter, msg map[string]any) {
			inits++
			jsonReply(w, map[string]any{"jsonrpc": "2.0", "id": msg["id"], "result": map[string]any{"protocolVersion": "2025-06-18"}})
		},
		"tools/list": func(w http.ResponseWriter, msg map[string]any) {
			jsonReply(w, map[string]any{"jsonrpc": "2.0", "id": msg["id"], "result": map[string]any{"tools": []any{map[string]any{"name": "run_query"}}}})
		},
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	src := &tokens{url: srv.URL + "/mcp", ttl: time.Hour}
	b := &Bridge{Tokens: src.source, Offline: fakeOffline{}, LoginPoll: 10 * time.Millisecond}
	s := startSession(t, b)
	defer s.close()

	s.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	s.next()
	src.mu.Lock()
	src.fails = errors.New("run `pmon login hr`")
	src.mu.Unlock()
	b.tokMu.Lock()
	b.tok = Token{}
	b.tokMu.Unlock()

	s.send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if m := s.next(); m["method"] != "notifications/tools/list_changed" {
		t.Fatalf("after the login ended = %v, want tools/list_changed", m)
	}
	if m := s.next(); fmt.Sprint(m["result"]) != "map[tools:[map[name:login]]]" {
		t.Fatalf("tools/list after the login ended = %v, want the offline tools", m)
	}

	src.mu.Lock()
	src.fails = nil
	src.mu.Unlock()
	if m := s.next(); m["method"] != "notifications/tools/list_changed" {
		t.Fatalf("after signing in again = %v, want tools/list_changed", m)
	}
	s.send(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	if m := s.next(); !strings.Contains(fmt.Sprint(m["result"]), "run_query") {
		t.Fatalf("tools/list after signing in again = %v, want the server's tools", m)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if inits != 2 {
		t.Errorf("upstream initialize count %d, want the replay after the new login", inits)
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
