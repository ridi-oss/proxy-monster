package httpdb

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

func TestAuthorizeResultRead(t *testing.T) {
	cases := []struct {
		name              string
		kind              Kind
		token, observed   string
		ids               []string
		owner             string
		binding           []byte
		request, response *pb.RequestAuthorizationResult
		want              error
	}{
		{name: "own context is read with its verdict"},
		{name: "no token", token: "-", want: ErrUnauthorized},
		{name: "not a result page", kind: KindMetadata, want: ErrUnauthorized},
		{name: "observed job differs", observed: "r2", want: ErrOriginalContextUnavailable},
		{name: "two jobs", ids: []string{"r1", "r2"}, want: ErrOriginalContextUnavailable},
		{name: "request phase not forwarded", request: grant("alice", release), want: ErrUnauthorized},
		{name: "request phase has no principal", request: grant("", forward), want: ErrUnauthorized},
		{name: "response principal differs", response: grant("bob", apply, "r1=ctx-r1"), want: ErrUnauthorized},
		{name: "response does not apply the context", response: grant("alice", release), want: ErrUnauthorized},
		{name: "context id differs", response: grant("alice", apply, "r1=ctx-other"), want: ErrOriginalContextUnavailable},
		{name: "context of another owner", owner: "bob", want: ErrOriginalContextUnavailable},
		{name: "context of another target", binding: otherBinding, want: ErrOriginalContextUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			contexts, err := OpenContextCache(privateCachePath(t), testFormat, 16)
			if err != nil {
				t.Fatal(err)
			}
			defer contexts.Close()
			owner, binding := "alice", ownBinding
			if tc.owner != "" {
				owner = tc.owner
			}
			if tc.binding != nil {
				binding = tc.binding
			}
			if err := contexts.Associate("ds", seeded("r1", owner, binding, true)); err != nil {
				t.Fatal(err)
			}
			cp := &gateControlPlane{request: grant("alice", forward), response: grant("alice", apply, "r1=ctx-r1")}
			if tc.request != nil {
				cp.request = tc.request
			}
			if tc.response != nil {
				cp.response = tc.response
			}
			server := &Server{Engine: &gateEngine{}, Name: "t", Client: cp, Contexts: contexts, TargetBinding: ownBinding, ContextLifetime: time.Hour}
			kind, token, observed, ids := KindResultPage, "tok", "r1", []string{"r1"}
			if tc.kind != 0 {
				kind = tc.kind
			}
			if tc.token == "-" {
				token = ""
			}
			if tc.observed != "" {
				observed = tc.observed
			}
			if tc.ids != nil {
				ids = tc.ids
			}
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Set("X-Kind", strconv.Itoa(int(kind)))
			request.Header["X-Id"] = ids

			read, err := server.AuthorizeResultRead(context.Background(), token, "192.0.2.1", request, &pb.HttpDbObservation{Id: observed})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.want == nil && (read.Principal != "alice" || read.Context.GetResourceId() != "r1" || !read.Verdict.GetSanitizeDiagnostics()) {
				t.Fatalf("read = %+v", read)
			}
			if tc.want == ErrUnauthorized && tc.token == "-" && cp.calls.Load() != 0 {
				t.Fatal("control plane asked without a token")
			}
		})
	}
}

func TestServerRoutesOnlyHTTP2GRPCToTheGRPCHandler(t *testing.T) {
	for _, tc := range []struct {
		name        string
		major       int
		contentType string
		grpc        bool
		want        bool
	}{
		{name: "h2 grpc", major: 2, contentType: "application/grpc", grpc: true, want: true},
		{name: "h2 grpc+proto", major: 2, contentType: "application/grpc+proto", grpc: true, want: true},
		{name: "http/1.1 grpc", major: 1, contentType: "application/grpc", grpc: true},
		{name: "h2 json", major: 2, contentType: "application/json", grpc: true},
		{name: "no grpc handler", major: 2, contentType: "application/grpc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var served bool
			server := &Server{Engine: &gateEngine{}, Name: "t"}
			if tc.grpc {
				server.GRPC = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served = true })
			}
			request := httptest.NewRequest(http.MethodPost, "/", nil)
			request.ProtoMajor = tc.major
			request.Header.Set("Content-Type", tc.contentType)
			server.ServeHTTP(httptest.NewRecorder(), request)
			if served != tc.want {
				t.Fatalf("gRPC handler served = %v, want %v", served, tc.want)
			}
		})
	}
}
