package editor

import (
	"context"
	"errors"
	"testing"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/config"
	"github.com/ridi-oss/proxy-monster/goproxy/cp"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

type registerCP struct {
	spi.ControlPlane
	registerErr error
	registers   int
}

func (c *registerCP) Register(enginepb.Engine, string, int, string, []string, string, *string, bool, *pb.ConnectionInfo, *string) error {
	c.registers++
	return c.registerErr
}

func (c *registerCP) PushCatalog(*pb.CatalogRequest) error { return nil }

type unreadableTarget struct{ spi.Target }

func (unreadableTarget) Config() spi.TargetConfig           { return spi.TargetConfig{} }
func (unreadableTarget) ConnectionInfo() *pb.ConnectionInfo { return nil }
func (unreadableTarget) Introspect(context.Context) (*pb.CatalogRequest, error) {
	return nil, errors.New("target unreachable")
}

func TestRegisterAndPushCatalogReportsFailure(t *testing.T) {
	noChain := func() *string { return nil }

	incompatible := &registerCP{registerErr: cp.ErrIncompatibleControlPlane}
	err := NewServer(incompatible, unreadableTarget{}, 0).RegisterAndPushCatalog(&config.Config{}, engines.MySQL, noChain)
	if !errors.Is(err, cp.ErrIncompatibleControlPlane) || incompatible.registers != 1 {
		t.Fatalf("an incompatible control plane must fail at once: err=%v registers=%d", err, incompatible.registers)
	}

	// Without a pushed catalog every decision fails closed, so boot must see the failure rather than serve.
	unpushed := &registerCP{}
	err = NewServer(unpushed, unreadableTarget{}, 0).RegisterAndPushCatalog(&config.Config{}, engines.MySQL, noChain)
	if err == nil || unpushed.registers != bootRegisterAttempts {
		t.Fatalf("a catalog that never pushes must fail after every attempt: err=%v registers=%d", err, unpushed.registers)
	}
}
