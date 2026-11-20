// Package mcpbridge relays stdio JSON-RPC to a Streamable HTTP MCP endpoint, one POST per message, and writes
// back each message the JSON or event-stream response carries.
package mcpbridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Token is an access token for URL.
type Token struct {
	URL       string
	Value     string
	ExpiresAt time.Time
}

// TokenSource mints a fresh token. Its error text reaches the user, so it should say how to recover.
type TokenSource func(ctx context.Context) (Token, error)

// expiryMargin re-mints this long before expiry, so no request leaves with a token that dies in flight.
const expiryMargin = 30 * time.Second

// loginError is a token that could not be minted, which is to say no usable login.
type loginError struct{ err error }

func (e *loginError) Error() string { return e.err.Error() }
func (e *loginError) Unwrap() error { return e.err }

// Offline is what a logged-out relay offers in place of the server's tools.
type Offline interface {
	// Instructions is the initialize instructions, given why no token could be minted.
	Instructions(loginErr error) string
	// Tools is the tools/list entries.
	Tools() []map[string]any
	// Call runs one of Tools; its text reaches the model.
	Call(ctx context.Context, name string, args json.RawMessage) (string, error)
}

// connectTimeout bounds the replayed initialize.
const connectTimeout = 10 * time.Second

// loginPoll is how often a logged-out relay checks for a login, so tools appear without restarting the app.
const loginPoll = 5 * time.Second

// Bridge relays In to the remote endpoint and the endpoint's messages to Out.
type Bridge struct {
	Tokens TokenSource
	HTTP   *http.Client
	In     io.Reader
	Out    io.Writer
	// LoginPoll overrides loginPoll.
	LoginPoll time.Duration
	// Offline serves the relay while logged out; nil lists no tools there.
	Offline Offline

	outMu sync.Mutex

	tokMu sync.Mutex
	tok   Token

	hdrMu           sync.Mutex
	protocolVersion string
	sessionID       string

	// While logged out, initialize is answered here and kept in initMsg, to replay upstream once a login exists.
	connMu  sync.Mutex
	initMsg []byte
	offline bool
}

// Run relays until In ends. A missing login does not stop it: the app would report the server as broken.
func (b *Bridge) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	watchCtx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	wg.Go(func() { b.watchLogin(watchCtx) })
	r := bufio.NewReader(b.In)
	for {
		line, err := r.ReadBytes('\n')
		if msg := bytes.TrimSpace(line); len(msg) > 0 {
			wg.Go(func() { b.relay(ctx, msg) })
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// envelope is the part of a JSON-RPC message the relay reads.
type envelope struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
}

func (b *Bridge) relay(ctx context.Context, msg []byte) {
	var env envelope
	_ = json.Unmarshal(msg, &env)
	isRequest := len(env.ID) > 0 && env.Method != ""
	if env.Method == "initialize" {
		b.connMu.Lock()
		b.initMsg = msg
		if _, err := b.token(ctx, false); err != nil {
			b.offline = true
			b.connMu.Unlock()
			b.answerInitialize(env.ID, msg, err)
			return
		}
		b.connMu.Unlock()
	} else if err := b.connect(ctx); err != nil {
		if isRequest {
			b.answerOffline(ctx, env, msg, err)
		}
		return
	}
	resp, err := b.post(ctx, msg, false)
	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		resp, err = b.post(ctx, msg, true)
	}
	var noLogin *loginError
	if errors.As(err, &noLogin) {
		// Logged out after start, or asked before initialize was answered.
		b.goOffline()
		if isRequest {
			b.answerOffline(ctx, env, msg, noLogin.err)
		}
		return
	}
	if err != nil {
		if isRequest {
			b.writeError(env.ID, err.Error())
		}
		return
	}
	defer resp.Body.Close()
	b.noteSessionID(resp)
	onMessage := func(m []byte) {
		if env.Method == "initialize" && b.noteProtocolVersion(m) {
			m = withToolsListChanged(m)
		}
		b.write(m)
	}
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch {
	case mediaType == "text/event-stream":
		if err := readEvents(resp.Body, onMessage); err != nil && isRequest {
			b.writeError(env.ID, fmt.Sprintf("the MCP event stream broke: %v", err))
		}
	default:
		body, err := io.ReadAll(resp.Body)
		trimmed := bytes.TrimSpace(body)
		switch {
		case err != nil:
			if isRequest {
				b.writeError(env.ID, fmt.Sprintf("reading the MCP response: %v", err))
			}
		case isJSONRPC(trimmed):
			onMessage(trimmed)
		case resp.StatusCode >= 300 && isRequest:
			b.writeError(env.ID, fmt.Sprintf("the MCP server answered HTTP %d: %s", resp.StatusCode, snippet(trimmed)))
		}
	}
}

// connect replays a locally answered initialize upstream once a login exists and tells the app its tools
// changed; it is a no-op when online.
func (b *Bridge) connect(ctx context.Context) error {
	b.connMu.Lock()
	defer b.connMu.Unlock()
	if !b.offline {
		return nil
	}
	// Every message waits on connMu, so a stalled server must not hold it.
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	b.hdrMu.Lock()
	b.sessionID = ""
	b.hdrMu.Unlock()
	resp, err := b.post(ctx, b.initMsg, false)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("the MCP server answered HTTP %d: %s", resp.StatusCode, snippet(body))
	}
	b.noteSessionID(resp)
	initialized := false
	note := func(m []byte) { initialized = b.noteProtocolVersion(m) || initialized }
	if mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mediaType == "text/event-stream" {
		_ = readEvents(bytes.NewReader(body), note)
	} else {
		note(body)
	}
	if !initialized {
		return fmt.Errorf("the MCP server refused initialize: %s", snippet(body))
	}
	if resp, err := b.post(ctx, []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), false); err == nil {
		resp.Body.Close()
	}
	b.offline = false
	b.write([]byte(`{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`))
	return nil
}

// goOffline switches an online relay to the offline tools once its login is gone, and tells the app.
func (b *Bridge) goOffline() {
	b.connMu.Lock()
	switched := !b.offline && b.initMsg != nil
	b.offline = b.offline || switched
	b.connMu.Unlock()
	if switched {
		b.write([]byte(`{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`))
	}
}

// watchLogin connects a logged-out relay as soon as a login exists, without waiting for the app's next request.
func (b *Bridge) watchLogin(ctx context.Context) {
	every := b.LoginPoll
	if every == 0 {
		every = loginPoll
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		b.connMu.Lock()
		offline := b.offline
		b.connMu.Unlock()
		if offline {
			_ = b.connect(ctx)
		}
	}
}

// answerInitialize stands in for the server while logged out; its instructions carry the login hint.
func (b *Bridge) answerInitialize(id json.RawMessage, msg []byte, loginErr error) {
	var req struct {
		Params struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"params"`
	}
	_ = json.Unmarshal(msg, &req)
	version := req.Params.ProtocolVersion
	if version == "" {
		version = "2025-06-18"
	}
	b.writeResult(id, map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": true}},
		"serverInfo":      map[string]any{"name": "pmon", "version": "logged-out"},
		"instructions":    b.offlineInstructions(loginErr),
	})
}

func (b *Bridge) offlineInstructions(loginErr error) string {
	if b.Offline == nil {
		return loginErr.Error()
	}
	return b.Offline.Instructions(loginErr)
}

// answerOffline serves Offline's tools while logged out, and names the login for anything else.
func (b *Bridge) answerOffline(ctx context.Context, env envelope, msg []byte, loginErr error) {
	switch {
	case env.Method == "ping":
		b.writeResult(env.ID, map[string]any{})
	case env.Method == "tools/list":
		tools := []map[string]any{}
		if b.Offline != nil {
			tools = b.Offline.Tools()
		}
		b.writeResult(env.ID, map[string]any{"tools": tools})
	case env.Method == "tools/call" && b.Offline != nil:
		var call struct {
			Params struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			} `json:"params"`
		}
		_ = json.Unmarshal(msg, &call)
		text, err := b.Offline.Call(ctx, call.Params.Name, call.Params.Arguments)
		if err != nil {
			text = err.Error()
		}
		b.writeResult(env.ID, map[string]any{
			"content": []any{map[string]any{"type": "text", "text": text}},
			"isError": err != nil,
		})
	case env.Method == "prompts/list":
		b.writeResult(env.ID, map[string]any{"prompts": []any{}})
	case env.Method == "resources/list":
		b.writeResult(env.ID, map[string]any{"resources": []any{}})
	default:
		b.writeError(env.ID, loginErr.Error())
	}
}

// withToolsListChanged claims tools.listChanged in an initialize result: the relay sends it when the login
// comes or goes, whatever the server itself says.
func withToolsListChanged(msg []byte) []byte {
	var m map[string]any
	if json.Unmarshal(msg, &m) != nil {
		return msg
	}
	result, _ := m["result"].(map[string]any)
	caps, _ := result["capabilities"].(map[string]any)
	if caps == nil {
		caps = map[string]any{}
		result["capabilities"] = caps
	}
	tools, _ := caps["tools"].(map[string]any)
	if tools == nil {
		tools = map[string]any{}
		caps["tools"] = tools
	}
	tools["listChanged"] = true
	out, err := json.Marshal(m)
	if err != nil {
		return msg
	}
	return out
}

func (b *Bridge) noteSessionID(resp *http.Response) {
	if id := resp.Header.Get("Mcp-Session-Id"); id != "" {
		b.hdrMu.Lock()
		b.sessionID = id
		b.hdrMu.Unlock()
	}
}

func (b *Bridge) post(ctx context.Context, msg []byte, fresh bool) (*http.Response, error) {
	tok, err := b.token(ctx, fresh)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tok.URL, bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+tok.Value)
	b.hdrMu.Lock()
	if b.protocolVersion != "" {
		req.Header.Set("MCP-Protocol-Version", b.protocolVersion)
	}
	if b.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", b.sessionID)
	}
	b.hdrMu.Unlock()
	return b.HTTP.Do(req)
}

// token returns the cached token or mints one; minting is serialized so requests after a 401 share one token.
func (b *Bridge) token(ctx context.Context, fresh bool) (Token, error) {
	b.tokMu.Lock()
	defer b.tokMu.Unlock()
	if !fresh && b.tok.Value != "" && time.Until(b.tok.ExpiresAt) > expiryMargin {
		return b.tok, nil
	}
	tok, err := b.Tokens(ctx)
	if err != nil {
		return Token{}, &loginError{err}
	}
	b.tok = tok
	return tok, nil
}

// noteProtocolVersion keeps the version an initialize result negotiated, and reports whether msg was one.
func (b *Bridge) noteProtocolVersion(msg []byte) bool {
	var res struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
	}
	if json.Unmarshal(msg, &res) == nil && res.Result.ProtocolVersion != "" {
		b.hdrMu.Lock()
		b.protocolVersion = res.Result.ProtocolVersion
		b.hdrMu.Unlock()
		return true
	}
	return false
}

// write emits one message on its own line; stdio framing forbids a newline inside a message.
func (b *Bridge) write(msg []byte) {
	var buf bytes.Buffer
	if json.Compact(&buf, msg) != nil {
		return
	}
	buf.WriteByte('\n')
	b.outMu.Lock()
	defer b.outMu.Unlock()
	_, _ = b.Out.Write(buf.Bytes())
}

func (b *Bridge) writeResult(id json.RawMessage, result any) {
	msg, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	b.write(msg)
}

func (b *Bridge) writeError(id json.RawMessage, message string) {
	msg, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": -32603, "message": message},
	})
	b.write(msg)
}

// readEvents calls onMessage with the data of each server-sent event.
func readEvents(r io.Reader, onMessage func([]byte)) error {
	br := bufio.NewReader(r)
	var data [][]byte
	dispatch := func() {
		if len(data) > 0 {
			onMessage(bytes.Join(data, []byte("\n")))
			data = nil
		}
	}
	for {
		line, err := br.ReadBytes('\n')
		trimmed := bytes.TrimRight(line, "\r\n")
		switch {
		case len(trimmed) == 0 && len(line) > 0:
			dispatch()
		case bytes.HasPrefix(trimmed, []byte("data:")):
			data = append(data, bytes.TrimPrefix(bytes.TrimPrefix(trimmed, []byte("data:")), []byte(" ")))
		}
		if errors.Is(err, io.EOF) {
			dispatch()
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// isJSONRPC tells a JSON-RPC message or batch from another body, such as an HTTP error the client cannot use.
func isJSONRPC(body []byte) bool {
	if len(body) > 0 && body[0] == '[' {
		return json.Valid(body)
	}
	var probe struct {
		JSONRPC string `json:"jsonrpc"`
	}
	return json.Unmarshal(body, &probe) == nil && probe.JSONRPC != ""
}

func snippet(body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	if s == "" {
		return "(empty body)"
	}
	return s
}
