package front

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	testpb "google.golang.org/grpc/interop/grpc_testing"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type upstreamService struct {
	testpb.UnimplementedTestServiceServer
}

func (upstreamService) UnaryCall(ctx context.Context, req *testpb.SimpleRequest) (*testpb.SimpleResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if got := md.Get("x-secret"); len(got) != 1 || got[0] != "s3" {
		return nil, status.Error(codes.Unauthenticated, "missing secret")
	}
	if req.GetResponseStatus() != nil {
		return nil, status.Error(codes.Code(req.GetResponseStatus().GetCode()), req.GetResponseStatus().GetMessage())
	}
	_ = grpc.SetHeader(ctx, metadata.Pairs("x-header", "h"))
	_ = grpc.SetTrailer(ctx, metadata.Pairs("x-trailer", "t"))
	return &testpb.SimpleResponse{Payload: req.GetPayload()}, nil
}

func (upstreamService) FullDuplexCall(stream testpb.TestService_FullDuplexCallServer) error {
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := stream.Send(&testpb.StreamingOutputCallResponse{Payload: req.GetPayload()}); err != nil {
			return err
		}
	}
}

func startForwarder(t *testing.T) testpb.TestServiceClient {
	t.Helper()
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	up := grpc.NewServer(grpc.MaxRecvMsgSize(maxInboundMessageBytes))
	testpb.RegisterTestServiceServer(up, upstreamService{})
	go func() { _ = up.Serve(upLn) }()
	t.Cleanup(up.Stop)

	conn, err := DialUpstream(upLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	frontLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fs := NewGRPC(conn)
	go func() { _ = fs.Serve(frontLn) }()
	t.Cleanup(fs.Stop)

	cc, err := grpc.NewClient(frontLn.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return testpb.NewTestServiceClient(cc)
}

func withSecret(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return metadata.AppendToOutgoingContext(ctx, "x-secret", "s3")
}

func TestGRPCUnaryCarriesMetadataHeadersAndTrailers(t *testing.T) {
	client := startForwarder(t)
	var header, trailer metadata.MD
	body := make([]byte, 8<<20)
	resp, err := client.UnaryCall(withSecret(t), &testpb.SimpleRequest{Payload: &testpb.Payload{Body: body}},
		grpc.Header(&header), grpc.Trailer(&trailer), grpc.MaxCallRecvMsgSize(16<<20))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetPayload().GetBody()) != len(body) {
		t.Fatalf("payload %d bytes", len(resp.GetPayload().GetBody()))
	}
	if header.Get("x-header")[0] != "h" || trailer.Get("x-trailer")[0] != "t" {
		t.Fatalf("header %v trailer %v", header, trailer)
	}
}

func TestGRPCUpstreamStatusPassesThrough(t *testing.T) {
	client := startForwarder(t)
	_, err := client.UnaryCall(withSecret(t), &testpb.SimpleRequest{
		ResponseStatus: &testpb.EchoStatus{Code: int32(codes.PermissionDenied), Message: "denied"},
	})
	if s := status.Convert(err); s.Code() != codes.PermissionDenied || s.Message() != "denied" {
		t.Fatalf("status %v", s)
	}
	_, err = client.UnaryCall(context.Background(), &testpb.SimpleRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no secret: %v", err)
	}
}

func TestGRPCBidiStream(t *testing.T) {
	client := startForwarder(t)
	stream, err := client.FullDuplexCall(withSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if err := stream.Send(&testpb.StreamingOutputCallRequest{Payload: &testpb.Payload{Body: []byte{byte(i)}}}); err != nil {
			t.Fatal(err)
		}
		resp, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetPayload().GetBody()[0] != byte(i) {
			t.Fatalf("echo %d = %v", i, resp.GetPayload().GetBody())
		}
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("after close: %v", err)
	}
}
