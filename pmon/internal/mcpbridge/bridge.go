// Package mcpbridge relays a local stdio MCP client to a remote Streamable HTTP MCP endpoint. It forwards
// each newline-delimited JSON-RPC message as one POST and writes back every JSON-RPC message the response
// carries, whether a JSON body or a server-sent event stream. It does not interpret MCP beyond the two
// headers Streamable HTTP asks a client to echo.
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

// expiryMargin re-mints a token this long before it expires, so a request never leaves with one that dies
// in flight.
const expiryMargin = 30 * time.Second

// Bridge relays In to the remote endpoint and the endpoint's messages to Out.
type Bridge struct {
	Tokens TokenSource
	HTTP   *http.Client
	In     io.Reader
	Out    io.Writer

	outMu sync.Mutex

	tokMu sync.Mutex
	tok   Token

	hdrMu           sync.Mutex
	protocolVersion string
	sessionID       string
}

// Run mints a first token, so a missing login fails before any client traffic, then relays until In ends
// and every in-flight request has answered.
func (b *Bridge) Run(ctx context.Context) error {
	if _, err := b.token(ctx, false); err != nil {
		return err
	}
	r := bufio.NewReader(b.In)
	var wg sync.WaitGroup
	defer wg.Wait()
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

// envelope is the JSON-RPC shape the relay reads: whether a message is a request it owes an answer to, and
// whether it is the initialize whose result names the protocol version.
type envelope struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
}

func (b *Bridge) relay(ctx context.Context, msg []byte) {
	var env envelope
	_ = json.Unmarshal(msg, &env)
	isRequest := len(env.ID) > 0 && env.Method != ""
	resp, err := b.post(ctx, msg, false)
	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		resp, err = b.post(ctx, msg, true)
	}
	if err != nil {
		if isRequest {
			b.writeError(env.ID, err.Error())
		}
		return
	}
	defer resp.Body.Close()
	if id := resp.Header.Get("Mcp-Session-Id"); id != "" {
		b.hdrMu.Lock()
		b.sessionID = id
		b.hdrMu.Unlock()
	}
	onMessage := func(m []byte) {
		if env.Method == "initialize" {
			b.noteProtocolVersion(m)
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

// token returns the cached token, minting a new one when asked to, when there is none, or when it is about
// to expire. Minting is serialized so concurrent requests after a 401 share one new token.
func (b *Bridge) token(ctx context.Context, fresh bool) (Token, error) {
	b.tokMu.Lock()
	defer b.tokMu.Unlock()
	if !fresh && b.tok.Value != "" && time.Until(b.tok.ExpiresAt) > expiryMargin {
		return b.tok, nil
	}
	tok, err := b.Tokens(ctx)
	if err != nil {
		return Token{}, err
	}
	b.tok = tok
	return tok, nil
}

func (b *Bridge) noteProtocolVersion(msg []byte) {
	var res struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
	}
	if json.Unmarshal(msg, &res) == nil && res.Result.ProtocolVersion != "" {
		b.hdrMu.Lock()
		b.protocolVersion = res.Result.ProtocolVersion
		b.hdrMu.Unlock()
	}
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
