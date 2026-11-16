package httpdb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	forward = enginepb.HttpDbInstruction_HTTP_DB_INSTRUCTION_FORWARD_REQUEST
	admit   = enginepb.HttpDbInstruction_HTTP_DB_INSTRUCTION_REQUIRE_SQL_ADMISSION
	release = enginepb.HttpDbInstruction_HTTP_DB_INSTRUCTION_RELEASE_METADATA
	apply   = enginepb.HttpDbInstruction_HTTP_DB_INSTRUCTION_APPLY_ORIGINAL_CONTEXT
)

var (
	ownBinding   = bytes.Repeat([]byte{1}, 32)
	otherBinding = bytes.Repeat([]byte{2}, 32)
	pageDigest   = sha256.Sum256([]byte("columns"))
)

// gateEngine reads its operation kind from X-Kind and its references from the body {"ids":[...],"first":bool}.
type gateEngine struct {
	pad       int
	firstPage *bool
}

func (e *gateEngine) Operation(r *http.Request) (Operation, error) {
	kind, err := strconv.Atoi(r.Header.Get("X-Kind"))
	return Operation{Name: "op", Kind: Kind(kind)}, err
}

func (e *gateEngine) References(_ *http.Request, body []byte) ([]string, bool, error) {
	var refs struct {
		IDs   []string
		First bool
	}
	_ = json.Unmarshal(body, &refs)
	return refs.IDs, refs.First, nil
}

func (e *gateEngine) Authorization(x Exchange) *pb.RequestAuthorization {
	body := append(bytes.Clone(x.Body), make([]byte, e.pad)...)
	return &pb.RequestAuthorization{Operation: &pb.RequestAuthorization_Athena{Athena: &enginepb.AthenaNativeDescriptor{Phase: x.Phase, Body: body, CachedContexts: x.Contexts}}}
}

func (e *gateEngine) ReadSubmission([]byte) (Submission, error) {
	return Submission{Query: "SELECT 1"}, nil
}
func (e *gateEngine) WriteSubmission(body []byte, _ Submission) ([]byte, error) {
	return body, nil
}

func (e *gateEngine) CreatedResource(body []byte) (string, error) {
	var created struct{ ID string }
	return created.ID, json.Unmarshal(body, &created)
}

func (e *gateEngine) Observe([]byte) ([]Observation, error)                     { return nil, nil }
func (e *gateEngine) FilterListing(b []byte, _ map[string]bool) ([]byte, error) { return b, nil }

func (e *gateEngine) MaskResult(body []byte, _ *pb.Verdict, _ *int32, _ []byte, firstPage bool) ([]byte, []byte, error) {
	e.firstPage = &firstPage
	return body, pageDigest[:], nil
}

func (e *gateEngine) Authorize(*spi.Authorizer, *relay.ProxyCommandRunner, string, []string) spi.Verdict {
	return spi.Proceed{Decision: &spi.Decision{Action: relay.EnfActionName(pb.EnfAction_ALLOW)}}
}

func (e *gateEngine) NewProxyCommandRunner(*spi.Authorizer) (*relay.ProxyCommandRunner, error) {
	return &relay.ProxyCommandRunner{}, nil
}

func (e *gateEngine) SubmittedAfter(context.Context, string, time.Time) (bool, error) {
	return true, nil
}
func (e *gateEngine) AwaitExecution(context.Context, string) error { return nil }
func (e *gateEngine) WriteError(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_, _ = w.Write([]byte(code))
}
func (e *gateEngine) WriteDenied(w http.ResponseWriter, reason string) { e.WriteError(w, 403, reason) }

// gateControlPlane answers each phase with a canned result and opens connections as identity.
type gateControlPlane struct {
	spi.ControlPlane
	identity          string
	request, response *pb.RequestAuthorizationResult
	calls             atomic.Int32
}

func (*gateControlPlane) DatasourceName() string { return "ds" }

func (c *gateControlPlane) AuthorizeRequest(_ context.Context, r *pb.RequestAuthorization) (*pb.RequestAuthorizationResult, error) {
	c.calls.Add(1)
	if r.GetAthena().Phase == enginepb.HttpDbAuthorizationPhase_HTTP_DB_AUTHORIZATION_PHASE_RESPONSE {
		return c.response, nil
	}
	return c.request, nil
}

func (c *gateControlPlane) OpenConnection(string, string, pb.ConnectionDoor) (spi.Identity, error) {
	return spi.Identity{Principal: c.identity, ConnectionID: []byte("conn")}, nil
}

func (c *gateControlPlane) CloseConnection([]byte) error          { return nil }
func (c *gateControlPlane) ReportCompletion(spi.CompletionReport) {}

func grant(principal string, action enginepb.HttpDbInstruction, refs ...string) *pb.RequestAuthorizationResult {
	instructions := &enginepb.HttpDbInstructions{Action: action}
	for _, ref := range refs {
		id, contextID, _ := strings.Cut(ref, "=")
		instructions.Contexts = append(instructions.Contexts, &enginepb.HttpDbContextRef{ResourceId: id, ContextId: contextID})
	}
	return &pb.RequestAuthorizationResult{Allowed: true, Principal: principal, HttpDbInstructions: instructions}
}

func seeded(id, owner string, binding []byte, sanitize bool) *enginepb.HttpDbCachedContext {
	instructions, _ := proto.MarshalOptions{Deterministic: true}.Marshal(&pb.Verdict{Decision: pb.EnfAction_ALLOW, SanitizeDiagnostics: sanitize})
	return &enginepb.HttpDbCachedContext{Version: 1, ContextId: "ctx-" + id, ResourceId: id, Owner: owner, TargetBinding: binding,
		ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)), EnforcementInstructions: instructions}
}

type upstreamReply struct {
	status int
	header http.Header
	body   string
}

type gateHarness struct {
	engine   *gateEngine
	contexts *EnforcementContextCache
	rec      *httptest.ResponseRecorder
}

type gateCase struct {
	name              string
	kind              Kind
	body              string
	auth              []string
	identity          string
	request, response *pb.RequestAuthorizationResult
	seed              []*enginepb.HttpDbCachedContext
	pad               int
	upstream          upstreamReply
	wantStatus        int
	wantCode          string
	wantUpstream      bool
	check             func(*testing.T, gateHarness)
}

func TestServerGates(t *testing.T) {
	const submission = `{"sql":"SELECT 1"}`
	conflicting := seeded("r1", "bob", ownBinding, false)
	conflicting.RequestBinding = requestBinding([]byte(submission))
	cases := []gateCase{
		{name: "forward refuses a submission", kind: KindSubmission, body: submission, request: grant("alice", forward),
			wantStatus: 403, wantCode: "request_denied"},
		{name: "forward refuses a refused kind", kind: KindRefused, request: grant("alice", forward),
			wantStatus: 403, wantCode: "request_denied"},
		{name: "release metadata refuses a result page", kind: KindResultPage, response: grant("alice", release),
			wantStatus: 403, wantCode: "request_denied", wantUpstream: true},
		{name: "empty request principal", kind: KindMetadata, request: grant("", forward),
			wantStatus: 403, wantCode: "request_denied"},
		{name: "admitted identity differs", kind: KindSubmission, body: submission, identity: "mallory", request: grant("alice", admit),
			wantStatus: 403, wantCode: "request_denied"},
		{name: "response principal differs", kind: KindMetadata, response: grant("bob", release),
			wantStatus: 403, wantCode: "request_denied", wantUpstream: true},
		{name: "valid ref masks and rebinds the digest", kind: KindResultPage, body: `{"ids":["r1"]}`, seed: []*enginepb.HttpDbCachedContext{seeded("r1", "alice", ownBinding, false)},
			response: grant("alice", apply, "r1=ctx-r1"), wantStatus: 200, wantUpstream: true,
			check: func(t *testing.T, h gateHarness) {
				record, err := h.contexts.Find("ds", "r1")
				if err != nil || !bytes.Equal(record.MetadataDigest, pageDigest[:]) {
					t.Fatalf("digest not rebound: %v %x", err, record.GetMetadataDigest())
				}
			}},
		{name: "ref context id differs", kind: KindResultPage, body: `{"ids":["r1"]}`, seed: []*enginepb.HttpDbCachedContext{seeded("r1", "alice", ownBinding, false)},
			response: grant("alice", apply, "r1=ctx-other"), wantStatus: 409, wantCode: "original_context_unavailable", wantUpstream: true},
		{name: "ref owner differs", kind: KindResultPage, body: `{"ids":["r1"]}`, seed: []*enginepb.HttpDbCachedContext{seeded("r1", "bob", ownBinding, false)},
			response: grant("alice", apply, "r1=ctx-r1"), wantStatus: 409, wantCode: "original_context_unavailable", wantUpstream: true},
		{name: "ref target binding differs", kind: KindResultPage, body: `{"ids":["r1"]}`, seed: []*enginepb.HttpDbCachedContext{seeded("r1", "alice", otherBinding, false)},
			response: grant("alice", apply, "r1=ctx-r1"), wantStatus: 409, wantCode: "original_context_unavailable", wantUpstream: true},
		{name: "result page needs exactly one ref", kind: KindResultPage, body: `{"ids":["r1","r2"]}`,
			seed:     []*enginepb.HttpDbCachedContext{seeded("r1", "alice", ownBinding, false), seeded("r2", "alice", ownBinding, false)},
			response: grant("alice", apply, "r1=ctx-r1", "r2=ctx-r2"), wantStatus: 409, wantCode: "original_context_unavailable", wantUpstream: true},
		{name: "non-listing needs a ref", kind: KindMetadata, response: grant("alice", apply),
			wantStatus: 409, wantCode: "original_context_unavailable", wantUpstream: true},
		{name: "associate conflicts with another owner", kind: KindSubmission, body: submission, request: grant("alice", admit),
			seed: []*enginepb.HttpDbCachedContext{conflicting}, wantStatus: 409, wantCode: "original_context_unavailable", wantUpstream: true},
		{name: "error under a sanitizing context is redacted", kind: KindMetadata, body: `{"ids":["r1"]}`, seed: []*enginepb.HttpDbCachedContext{seeded("r1", "alice", ownBinding, true)},
			response: grant("alice", apply, "r1=ctx-r1"), upstream: upstreamReply{status: 400, body: `{"Message":"secret"}`}, wantStatus: 400, wantUpstream: true,
			check: func(t *testing.T, h gateHarness) {
				if strings.Contains(h.rec.Body.String(), "secret") {
					t.Fatalf("diagnostic released: %s", h.rec.Body)
				}
			}},
		{name: "descriptor over 1 MiB", kind: KindMetadata, pad: 1<<20 + 1, wantStatus: 413, wantCode: "request_too_large"},
		{name: "encoded response", kind: KindMetadata, upstream: upstreamReply{header: http.Header{"Content-Encoding": {"br"}}},
			wantStatus: 502, wantCode: "unsupported_response_encoding", wantUpstream: true},
		{name: "response over the limit", kind: KindMetadata, upstream: upstreamReply{body: strings.Repeat("x", 1<<20+1)},
			wantStatus: 502, wantCode: "response_too_large", wantUpstream: true},
		{name: "set-cookie stripped", kind: KindMetadata, upstream: upstreamReply{header: http.Header{"Set-Cookie": {"s=1"}, "X-Kept": {"1"}}},
			wantStatus: 200, wantUpstream: true,
			check: func(t *testing.T, h gateHarness) {
				if h.rec.Header().Get("Set-Cookie") != "" || h.rec.Header().Get("X-Kept") != "1" {
					t.Fatalf("response headers: %v", h.rec.Header())
				}
			}},
		{name: "two authorization headers", kind: KindMetadata, auth: []string{"Bearer tok", "Bearer tok"},
			wantStatus: 403, wantCode: "authentication_required"},
		{name: "token with whitespace", kind: KindMetadata, auth: []string{"Bearer to k"},
			wantStatus: 403, wantCode: "authentication_required"},
	}
	for _, first := range []bool{true, false} {
		cases = append(cases, gateCase{name: "first page " + strconv.FormatBool(first), kind: KindResultPage, body: `{"ids":["r1"],"first":` + strconv.FormatBool(first) + `}`,
			seed: []*enginepb.HttpDbCachedContext{seeded("r1", "alice", ownBinding, false)}, response: grant("alice", apply, "r1=ctx-r1"),
			wantStatus: 200, wantUpstream: true,
			check: func(t *testing.T, h gateHarness) {
				if h.engine.firstPage == nil || *h.engine.firstPage != first {
					t.Fatalf("MaskResult firstPage = %v, want %v", h.engine.firstPage, first)
				}
			}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var forwarded atomic.Int32
			target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				forwarded.Add(1)
				for name, values := range tc.upstream.header {
					w.Header()[name] = values
				}
				w.WriteHeader(max(tc.upstream.status, 200))
				body := tc.upstream.body
				if body == "" {
					body = `{"id":"r1"}`
				}
				_, _ = w.Write([]byte(body))
			}))
			defer target.Close()
			contexts, err := OpenContextCache(privateCachePath(t), testFormat, 16)
			if err != nil {
				t.Fatal(err)
			}
			defer contexts.Close()
			for _, record := range tc.seed {
				if err := contexts.Associate("ds", record); err != nil {
					t.Fatal(err)
				}
			}
			cp := &gateControlPlane{identity: "alice", request: grant("alice", forward), response: grant("alice", release)}
			if tc.identity != "" {
				cp.identity = tc.identity
			}
			if tc.request != nil {
				cp.request = tc.request
			}
			if tc.response != nil {
				cp.response = tc.response
			}
			engine := &gateEngine{pad: tc.pad}
			server := &Server{Engine: engine, Name: "t", Client: cp, Contexts: contexts, TargetBinding: ownBinding, ContextLifetime: time.Hour,
				Forward:       ForwardOptions{Endpoint: target.URL, MaxBodyBytes: 1 << 20, Sign: signTestRequest, Transport: target.Client().Transport},
				ResponseLimit: 1 << 20, DiagnosticKeys: []string{"Message"}}
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			request.Header.Set("X-Kind", strconv.Itoa(int(tc.kind)))
			request.Header["Authorization"] = []string{"Bearer tok"}
			if tc.auth != nil {
				request.Header["Authorization"] = tc.auth
			}
			rec := httptest.NewRecorder()
			server.ServeHTTP(rec, request)

			if rec.Code != tc.wantStatus || (tc.wantCode != "" && rec.Body.String() != "t."+tc.wantCode) {
				t.Fatalf("got %d %.200q, want %d %s", rec.Code, rec.Body, tc.wantStatus, tc.wantCode)
			}
			if got := forwarded.Load() > 0; got != tc.wantUpstream {
				t.Fatalf("upstream called = %v, want %v", got, tc.wantUpstream)
			}
			if tc.wantCode == "authentication_required" || tc.wantCode == "request_too_large" {
				if cp.calls.Load() != 0 {
					t.Fatal("control plane called before the gate")
				}
			}
			if tc.check != nil {
				tc.check(t, gateHarness{engine: engine, contexts: contexts, rec: rec})
			}
		})
	}
}
