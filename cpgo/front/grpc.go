package front

import (
	"context"
	"errors"
	"io"
	"math"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/mem"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// These mirror the Kotlin GrpcServer, which goproxy's keepalive and message sizes are tuned against.
const (
	maxInboundMessageBytes = 64 << 20
	keepaliveTime          = 30 * time.Second
	keepaliveTimeout       = 10 * time.Second
	permitKeepaliveTime    = 15 * time.Second
)

// frame is one gRPC message forwarded without decoding.
type frame struct{ data mem.BufferSlice }

// passthrough moves frames as raw bytes and leaves every other message to the proto codec, so services
// Go implements later can be registered on the same server.
type passthrough struct{ proto encoding.CodecV2 }

func (c passthrough) Name() string { return "proto" }

func (c passthrough) Marshal(v any) (mem.BufferSlice, error) {
	if f, ok := v.(*frame); ok {
		return f.data, nil
	}
	return c.proto.Marshal(v)
}

func (c passthrough) Unmarshal(data mem.BufferSlice, v any) error {
	if f, ok := v.(*frame); ok {
		data.Ref()
		f.data = data
		return nil
	}
	return c.proto.Unmarshal(data, v)
}

func newCodec() passthrough { return passthrough{proto: encoding.GetCodecV2("proto")} }

// DialUpstream connects to the Kotlin control plane's gRPC port on loopback.
func DialUpstream(target string) (*grpc.ClientConn, error) {
	return grpc.NewClient(target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.ForceCodecV2(newCodec()),
			grpc.MaxCallRecvMsgSize(math.MaxInt32),
			grpc.MaxCallSendMsgSize(math.MaxInt32),
		),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                keepaliveTime,
			Timeout:             keepaliveTimeout,
			PermitWithoutStream: true,
		}),
	)
}

// NewGRPC returns a server that forwards every call it has no handler for to upstream.
func NewGRPC(upstream *grpc.ClientConn, opts ...grpc.ServerOption) *grpc.Server {
	return grpc.NewServer(append([]grpc.ServerOption{
		grpc.ForceServerCodecV2(newCodec()),
		grpc.UnknownServiceHandler(func(_ any, ss grpc.ServerStream) error { return forward(upstream, ss) }),
		grpc.MaxRecvMsgSize(maxInboundMessageBytes),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: keepaliveTime, Timeout: keepaliveTimeout}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: permitKeepaliveTime, PermitWithoutStream: true}),
	}, opts...)...)
}

var forwardDesc = &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}

func forward(upstream *grpc.ClientConn, ss grpc.ServerStream) error {
	method, ok := grpc.MethodFromServerStream(ss)
	if !ok {
		return status.Error(codes.Internal, "no method on stream")
	}
	ctx, cancel := context.WithCancel(ss.Context())
	defer cancel()
	if md, ok := metadata.FromIncomingContext(ss.Context()); ok {
		out := md.Copy()
		for k := range out {
			// Pseudo-headers such as :authority belong to the incoming hop.
			if strings.HasPrefix(k, ":") {
				delete(out, k)
			}
		}
		ctx = metadata.NewOutgoingContext(ctx, out)
	}
	cs, err := upstream.NewStream(ctx, forwardDesc, method)
	if err != nil {
		return err
	}

	toUpstream := make(chan error, 1)
	go func() {
		for {
			f := &frame{}
			if err := ss.RecvMsg(f); err != nil {
				toUpstream <- err
				return
			}
			if err := cs.SendMsg(f); err != nil {
				// The upstream's status arrives through the response side.
				toUpstream <- nil
				return
			}
		}
	}()
	fromUpstream := make(chan error, 1)
	go func() {
		if md, err := cs.Header(); err == nil && md != nil {
			if err := ss.SendHeader(md); err != nil {
				fromUpstream <- err
				return
			}
		}
		for {
			f := &frame{}
			if err := cs.RecvMsg(f); err != nil {
				fromUpstream <- err
				return
			}
			if err := ss.SendMsg(f); err != nil {
				fromUpstream <- err
				return
			}
		}
	}()

	for {
		select {
		case err := <-toUpstream:
			toUpstream = nil
			if errors.Is(err, io.EOF) {
				_ = cs.CloseSend()
				continue
			}
			if err != nil {
				// The client went away; cancel drops the upstream call with it.
				return err
			}
		case err := <-fromUpstream:
			ss.SetTrailer(cs.Trailer())
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}
