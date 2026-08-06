package grpcsvc

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/ridi-oss/proxy-monster/gocp/internal/core"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
)

// TableDetailDbTest.kt case 3, `grpc table-detail stream claims once and relays both directions`.
//
// The Kotlin drives `ControlPlaneGrpcService(core).tableDetailExec(requests.consumeAsFlow())` directly
// — no gRPC server, no HTTP, and (despite the file's name) no database on this one case: the whole
// assertion is about the registry claim and the two relay directions. So this is the same shape, with a
// fake ServerStream standing in for the Kotlin's Flow/Channel pair, and a bare core carrying nothing but
// the registry.
//
// The other three cases of that file are KT-DEFERred in tabledetail_deferred_test.go — they assert
// TableDetailService, whose PRODUCER side is not ported.

// fakeTableDetailStream is pb.ControlPlane_TableDetailExecServer over two channels, which is exactly the
// Kotlin's `Channel<ProxyTableDetailMsg>` in / `Channel<ControlTableDetailMsg>` out.
type fakeTableDetailStream struct {
	grpc.ServerStream
	ctx  context.Context
	recv chan *pb.ProxyTableDetailMsg
	sent chan *pb.ControlTableDetailMsg
}

func (f *fakeTableDetailStream) Context() context.Context { return f.ctx }

func (f *fakeTableDetailStream) Send(msg *pb.ControlTableDetailMsg) error {
	f.sent <- msg
	return nil
}

// Recv returns errStreamEOF on a closed channel, which is what the handler's half-close arm reads.
func (f *fakeTableDetailStream) Recv() (*pb.ProxyTableDetailMsg, error) {
	msg, ok := <-f.recv
	if !ok {
		return nil, errStreamEOF
	}
	return msg, nil
}

// KT: TableDetailDbTest.kt#grpc table-detail stream claims once and relays both directions
func TestTableDetailExecClaimsOnceAndRelaysBothDirections(t *testing.T) {
	registry := core.NewTableDetailChannelRegistry()
	svc := NewService(&core.ControlPlaneCore{TableDetailChannels: registry}, 0, discardLogger())

	pending := &core.PendingTableDetailSession{
		SessionID: "grpc-table-detail",
		Ready:     make(chan *core.AttachedTableDetail, 1),
	}
	if !registry.Register(pending) {
		t.Fatal("register the pending session")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &fakeTableDetailStream{
		ctx:  ctx,
		recv: make(chan *pb.ProxyTableDetailMsg, 4),
		sent: make(chan *pb.ControlTableDetailMsg, 4),
	}
	served := make(chan error, 1)
	go func() { served <- svc.TableDetailExec(stream) }()

	// 1. The proxy's first message claims the session.
	stream.recv <- &pb.ProxyTableDetailMsg{
		Kind: &pb.ProxyTableDetailMsg_SessionReady{
			SessionReady: &pb.TableDetailReady{SessionId: pending.SessionID},
		},
	}
	var attached *core.AttachedTableDetail
	select {
	case attached = <-pending.Ready:
	case <-time.After(5 * time.Second):
		t.Fatal("the session was never claimed — pending.Ready did not complete")
	}

	// 2. PROXY → PRODUCER: a result message reaches the claimed session's inbound channel VERBATIM.
	result := &pb.ProxyTableDetailMsg{
		Kind: &pb.ProxyTableDetailMsg_Result{Result: &pb.TableDetailResult{Json: "null"}},
	}
	stream.recv <- result
	select {
	case got := <-attached.Inbound:
		if got != result {
			t.Errorf("inbound relayed %v, want the same message the proxy sent (%v)", got, result)
		}
		if got.GetResult().GetJson() != "null" {
			t.Errorf("inbound result json = %q, want %q", got.GetResult().GetJson(), "null")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the proxy's result never reached the producer's inbound channel")
	}

	// 3. PRODUCER → PROXY: a Close written to the claimed outbound channel reaches the wire.
	attached.Outbound <- &pb.ControlTableDetailMsg{
		Kind: &pb.ControlTableDetailMsg_Close{Close: &pb.TableDetailClose{}},
	}
	select {
	case got := <-stream.sent:
		if got.GetClose() == nil {
			t.Errorf("the control message on the wire was %v, want a Close", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the producer's Close never reached the wire")
	}

	// 4. The proxy half-closes; the handler returns cleanly, as the Kotlin's collectJob.join() asserts.
	//
	// ⚠️ One STRUCTURAL difference, and it is Go's channel semantics rather than a behaviour change: the
	// handler's last statement is `return <-sendErr`, so it waits for its outbound WRITER goroutine, which
	// exits when the outbound channel closes (or the 60 s stream deadline fires). The PRODUCER therefore
	// owns closing outbound — which the Kotlin's own FakeTableDetailProxy also does
	// (TableDetailDbTest.kt:433 `outbound.close()`), so closing it here is the faithful producer, not a
	// workaround. Kotlin's case 3 gets away without it only because its channelFlow terminates when the
	// upstream request flow does.
	close(attached.Outbound)
	close(stream.recv)
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("TableDetailExec returned %v, want nil after a clean half-close", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TableDetailExec did not return after the proxy half-closed")
	}

	// The claim is EXACTLY ONCE: the session is gone from the registry, so a second dial cannot claim it.
	if second := registry.Attach(pending.SessionID, make(chan *pb.ControlTableDetailMsg, 1)); second != nil {
		t.Error("a second Attach claimed the same session — the claim must be exactly once")
	}
}
