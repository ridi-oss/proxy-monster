package athena

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"google.golang.org/protobuf/proto"
)

type requestClient struct {
	spi.EnforcementClient
	authorize func(*pb.RequestAuthorization, *enginepb.AthenaNativeDescriptor) (*pb.RequestAuthorizationResult, error)
}

func (c requestClient) AuthorizeRequest(_ context.Context, request *pb.RequestAuthorization) (*pb.RequestAuthorizationResult, error) {
	if c.authorize == nil {
		return &pb.RequestAuthorizationResult{}, nil
	}
	var descriptor enginepb.AthenaNativeDescriptor
	if request.GetNative().GetDescriptorVersion() != 1 {
		return nil, ErrUnauthorized
	}
	if err := proto.Unmarshal(request.GetNative().GetDescriptorPayload(), &descriptor); err != nil {
		return nil, err
	}
	return c.authorize(request, &descriptor)
}

func nativePermission(t *testing.T, descriptor *enginepb.AthenaNativeDescriptor, principal string) *pb.RequestAuthorizationResult {
	t.Helper()
	action := enginepb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_FORWARD_REQUEST
	if descriptor.Phase == enginepb.NativeAuthorizationPhase_NATIVE_AUTHORIZATION_PHASE_RESPONSE {
		action = enginepb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_RELEASE_METADATA
	}
	instructions, err := proto.Marshal(&enginepb.AthenaNativeInstructions{Version: 1, Action: action})
	if err != nil {
		t.Fatal(err)
	}
	return &pb.RequestAuthorizationResult{Allowed: true, Principal: principal, ProviderInstructions: instructions}
}

func nativeTestRequest(operation, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://proxy.example/", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer test-login")
	request.Header.Set("X-Amz-Target", "AmazonAthena."+operation)
	request.Header.Set("Content-Type", "application/x-amz-json-1.1")
	request.RemoteAddr = "192.0.2.25:1234"
	return request
}

func TestNativeServerDeniesWithoutUpstreamCalls(t *testing.T) {
	upstreamCalls := 0
	target := testTarget(t, func(w http.ResponseWriter, request *http.Request) { upstreamCalls++; w.WriteHeader(500) })
	server := &nativeServer{target: target, options: spi.NativeServerOptions{Client: requestClient{}}}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, nativeTestRequest("ListWorkGroups", `{}`))
	if response.Code != http.StatusForbidden || upstreamCalls != 0 {
		t.Fatalf("denied request reached AWS: status %d calls %d", response.Code, upstreamCalls)
	}
}

func TestNativeServerRejectsBooleanOnlyAndWrongPhasePermission(t *testing.T) {
	for _, action := range []enginepb.AthenaNativeInstruction{enginepb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_UNSPECIFIED, enginepb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_RELEASE_METADATA} {
		target := testTarget(t, func(w http.ResponseWriter, request *http.Request) { t.Fatal("invalid instruction reached AWS") })
		client := requestClient{authorize: func(_ *pb.RequestAuthorization, _ *enginepb.AthenaNativeDescriptor) (*pb.RequestAuthorizationResult, error) {
			var instructions []byte
			if action != enginepb.AthenaNativeInstruction_ATHENA_NATIVE_INSTRUCTION_UNSPECIFIED {
				instructions, _ = proto.Marshal(&enginepb.AthenaNativeInstructions{Version: 1, Action: action})
			}
			return &pb.RequestAuthorizationResult{Allowed: true, Principal: "alice", ProviderInstructions: instructions}, nil
		}}
		server := &nativeServer{target: target, options: spi.NativeServerOptions{Client: client}}
		response := httptest.NewRecorder()
		server.ServeHTTP(response, nativeTestRequest("GetWorkGroup", `{"WorkGroup":"primary"}`))
		if response.Code != http.StatusForbidden {
			t.Fatalf("invalid instruction accepted: %d", response.Code)
		}
	}
}

func TestNativeServerChecksEachRequestAndPreservesNativeErrors(t *testing.T) {
	const native = `{"__type":"InvalidRequestException","Message":"AWS diagnostic","FutureError":1.00}`
	upstreamCalls, authorizations := 0, 0
	target := testTarget(t, func(w http.ResponseWriter, request *http.Request) {
		upstreamCalls++
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.Header().Set("X-Amzn-Requestid", "native-request-id")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, native)
	})
	client := requestClient{authorize: func(request *pb.RequestAuthorization, descriptor *enginepb.AthenaNativeDescriptor) (*pb.RequestAuthorizationResult, error) {
		authorizations++
		if request.Token != "test-login" || request.ClientAddr != "192.0.2.25" || descriptor.Operation != "GetWorkGroup" {
			return &pb.RequestAuthorizationResult{}, nil
		}
		for _, header := range descriptor.FunctionalHeaders {
			if strings.EqualFold(header.Name, "Authorization") {
				t.Fatal("credential leaked into native descriptor")
			}
		}
		return nativePermission(t, descriptor, "alice"), nil
	}}
	server := &nativeServer{target: target, options: spi.NativeServerOptions{Client: client}}
	for range 2 {
		response := httptest.NewRecorder()
		server.ServeHTTP(response, nativeTestRequest("GetWorkGroup", `{"WorkGroup":"primary"}`))
		if response.Code != 400 || response.Body.String() != native || response.Header().Get("X-Amzn-Requestid") != "native-request-id" {
			t.Fatalf("native error altered: %d %s", response.Code, response.Body.String())
		}
	}
	if authorizations != 4 || upstreamCalls != 2 {
		t.Fatalf("per-request authorization skipped: auth %d upstream %d", authorizations, upstreamCalls)
	}
}

func TestNativeServerClosesStreamingAndS3Paths(t *testing.T) {
	server := &nativeServer{options: spi.NativeServerOptions{Client: requestClient{}}}
	for _, path := range []string{"/GetQueryResultsStream", "/bucket/results.csv"} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://proxy.example"+path, nil)
		server.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("raw retrieval route accepted: %s", path)
		}
	}
}
