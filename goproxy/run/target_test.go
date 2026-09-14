package run

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

type operationTarget struct {
	spi.Target
	open func(context.Context, spi.RunSessionOptions) (spi.TargetDbSession, error)
	read func(context.Context, *enginepb.TableRef) (*spi.TableDetail, error)
}

func (t operationTarget) NewRunSession(ctx context.Context, options spi.RunSessionOptions) (spi.TargetDbSession, error) {
	return t.open(ctx, options)
}

func (t operationTarget) ReadTableDetail(ctx context.Context, selector *enginepb.TableRef) (*spi.TableDetail, error) {
	return t.read(ctx, selector)
}

func TestRunnerUsesTargetOperation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wantErr := errors.New("target open failed")
	connectionID := []byte("1234567890123456")
	calls := 0
	target := operationTarget{open: func(gotCtx context.Context, options spi.RunSessionOptions) (spi.TargetDbSession, error) {
		calls++
		if gotCtx != ctx || options.Token != "token" || !reflect.DeepEqual(options.ConnectionID, connectionID) || options.ReadTimeout != 45*time.Second {
			t.Fatalf("open context/options = %v/%+v", gotCtx, options)
		}
		if err := options.Guard(func() error { return wantErr }); !errors.Is(err, wantErr) {
			t.Fatalf("guard result = %v", err)
		}
		return nil, wantErr
	}}
	runner := NewRunner(nil, target, 15*time.Second)
	_, err := runner.factory(ctx, "token", connectionID, func(exec func() error) error { return exec() })
	if !errors.Is(err, wantErr) || calls != 1 {
		t.Fatalf("factory = %v, calls = %d", err, calls)
	}
}

type detailClient struct{ stream *detailStream }

func (c detailClient) OpenTableDetailStream(context.Context) (spi.TableDetailStream, error) {
	return c.stream, nil
}

type detailStream struct{ sent []*pb.ProxyTableDetailMsg }

func (s *detailStream) Send(message *pb.ProxyTableDetailMsg) error {
	s.sent = append(s.sent, message)
	return nil
}

func (*detailStream) Recv() (*pb.ControlTableDetailMsg, error) {
	return &pb.ControlTableDetailMsg{Kind: &pb.ControlTableDetailMsg_Close{Close: &pb.TableDetailClose{}}}, nil
}

func TestTableDetailRunnerUsesTargetOperation(t *testing.T) {
	stream := &detailStream{}
	catalog := "catalog"
	calls := 0
	target := operationTarget{read: func(ctx context.Context, selector *enginepb.TableRef) (*spi.TableDetail, error) {
		calls++
		if ctx.Err() != nil || !reflect.DeepEqual(selector, &enginepb.TableRef{Catalog: catalog, Schema: "public", Table: "orders"}) {
			t.Fatalf("read selector = %+v, context error = %v", selector, ctx.Err())
		}
		return nil, nil
	}}
	NewTableDetailRunner(detailClient{stream}, target).Run(&pb.OpenTableDetailChannel{SessionId: "detail", Catalog: &catalog, Schema: "public", Table: "orders"})
	if calls != 1 || len(stream.sent) != 2 || stream.sent[0].GetSessionReady().GetSessionId() != "detail" || stream.sent[1].GetResult().GetJson() != "null" {
		t.Fatalf("calls = %d, messages = %v", calls, stream.sent)
	}
}

func TestTableDetailRunnerRejectsExplicitBlankCatalog(t *testing.T) {
	stream := &detailStream{}
	blank := ""
	target := operationTarget{read: func(context.Context, *enginepb.TableRef) (*spi.TableDetail, error) {
		t.Fatal("blank catalog reached target operation")
		return nil, nil
	}}
	NewTableDetailRunner(detailClient{stream}, target).Run(&pb.OpenTableDetailChannel{SessionId: "detail", Catalog: &blank, Schema: "public", Table: "orders"})
	if len(stream.sent) != 2 || stream.sent[1].GetError() == nil {
		t.Fatalf("messages = %v", stream.sent)
	}
}
