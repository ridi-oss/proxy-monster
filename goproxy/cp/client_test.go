package cp

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

func wireVerdict(v *pb.Verdict) *pb.WireDecision {
	return &pb.WireDecision{Outcome: &pb.WireDecision_Verdict{Verdict: v}}
}

func wireBefore(commands ...*pb.ProxyCommand) *pb.WireDecision {
	return &pb.WireDecision{Outcome: &pb.WireDecision_BeforeDecide{BeforeDecide: &pb.BeforeDecide{Commands: commands}}}
}

func refetch(schema string, hash []byte) *pb.ProxyCommand {
	return &pb.ProxyCommand{Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{Schema: schema, IfHashDiffers: hash}}}
}

func TestDecisionFromWire(t *testing.T) {
	t.Run("before decide returns commands", func(t *testing.T) {
		commands, decision := decisionFromWire(wireBefore(refetch("app", []byte{1, 2})))
		if decision != nil {
			t.Fatalf("decision = %+v, want nil", decision)
		}
		want := []*pb.Refetch{{Schema: "app", IfHashDiffers: []byte{1, 2}}}
		if !reflect.DeepEqual(commands, want) {
			t.Fatalf("commands = %+v, want %+v", commands, want)
		}
	})

	t.Run("targeted after statement and generation survive", func(t *testing.T) {
		commands, got := decisionFromWire(wireVerdict(&pb.Verdict{
			Decision:            pb.EnfAction_MASK,
			DecisionId:          42,
			DenyReason:          "reason",
			EffectiveRoles:      []string{"analyst"},
			RewrittenSql:        proto.String("SELECT c FROM t"),
			UnmaskablePermitted: true,
			Masks:               []*pb.ColumnMask{{Column: "c", MaskFn: "mask", Kind: "FIXED", Ordinal: proto.Int32(2)}},
			AfterStatement:      []*pb.ProxyCommand{refetch("app", []byte("hash"))},
			Generation:          9,
		}))
		if commands != nil {
			t.Fatalf("commands = %+v, want nil", commands)
		}
		want := &engine.Decision{
			Action:              "MASK",
			DecisionID:          42,
			DenyReason:          "reason",
			Masks:               []*pb.ColumnMask{{Column: "c", MaskFn: "mask", Kind: "FIXED", Ordinal: proto.Int32(2)}},
			EffectiveRoles:      []string{"analyst"},
			RewrittenSQL:        proto.String("SELECT c FROM t"),
			UnmaskablePermitted: true,
			AfterStatement:      []*pb.Refetch{{Schema: "app", IfHashDiffers: []byte("hash")}},
			Generation:          9,
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("decision = %+v, want %+v", got, want)
		}
	})

	cases := []struct {
		name   string
		wire   *pb.WireDecision
		reason string
	}{
		{"missing outcome", &pb.WireDecision{}, "no verdict"},
		{"unknown before command", wireBefore(&pb.ProxyCommand{}), "malformed before-decision"},
		{"blank before schema", wireBefore(refetch("", nil)), "blank schema"},
		{"unknown after command", wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, AfterStatement: []*pb.ProxyCommand{{}}}), "malformed after-statement"},
		{"blank after schema", wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, AfterStatement: []*pb.ProxyCommand{refetch("", nil)}}), "blank schema"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			commands, got := decisionFromWire(tc.wire)
			if commands != nil {
				t.Fatalf("commands = %+v, want nil on malformed outcome", commands)
			}
			if got.Action != "DENY" || !strings.Contains(got.DenyReason, tc.reason) {
				t.Fatalf("decision = %+v, want fail-closed reason containing %q", got, tc.reason)
			}
		})
	}

	t.Run("unknown verdict enum denies", func(t *testing.T) {
		_, got := decisionFromWire(wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ENF_ACTION_UNSPECIFIED}))
		if got.Action != "DENY" {
			t.Fatalf("Action = %q, want DENY", got.Action)
		}
	})
	t.Run("absent mask ordinal stays unbound", func(t *testing.T) {
		_, got := decisionFromWire(wireVerdict(&pb.Verdict{Decision: pb.EnfAction_MASK, Masks: []*pb.ColumnMask{{Column: "c"}}}))
		if got.Masks[0].Ordinal != nil {
			t.Fatalf("ordinal = %v, want nil (absent, fails closed to unbound)", got.Masks[0].Ordinal)
		}
	})
}

func TestIdentityFromWire(t *testing.T) {
	connectionID := []byte("0123456789abcdef")
	wire := &pb.WireIdentity{
		Principal:    "alice@example.com",
		Roles:        []string{"analyst", "reader"},
		ConnectionId: connectionID,
		OnOpen:       []*pb.ProxyCommand{refetch("app", []byte("hash"))},
	}
	got, err := identityFromWire(wire)
	if err != nil {
		t.Fatalf("identityFromWire: %v", err)
	}
	want := spi.Identity{
		Principal:    "alice@example.com",
		Roles:        []string{"analyst", "reader"},
		ConnectionID: []byte("0123456789abcdef"),
		OnOpen:       []*pb.Refetch{{Schema: "app", IfHashDiffers: []byte("hash")}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("identity = %+v, want %+v", got, want)
	}
	wire.Roles[0] = "mutated"
	wire.ConnectionId[0] = 'x'
	wire.OnOpen[0].GetRefetch().IfHashDiffers[0] = 'x'
	if got.Roles[0] != "analyst" || string(got.ConnectionID) != "0123456789abcdef" || string(got.OnOpen[0].IfHashDiffers) != "hash" {
		t.Fatal("identityFromWire retained mutable proto backing arrays")
	}

	for _, tc := range []struct {
		name string
		wire *pb.WireIdentity
	}{
		{"short id", &pb.WireIdentity{ConnectionId: []byte("short")}},
		{"blank on-open schema", &pb.WireIdentity{ConnectionId: []byte("0123456789abcdef"), OnOpen: []*pb.ProxyCommand{refetch("", nil)}}},
		{"unknown on-open command", &pb.WireIdentity{ConnectionId: []byte("0123456789abcdef"), OnOpen: []*pb.ProxyCommand{{}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := identityFromWire(tc.wire); err == nil {
				t.Fatal("identityFromWire succeeded, want fail-closed mapping error")
			}
		})
	}
}

func TestValidateTokenAndDecideUnreachable(t *testing.T) {
	c, err := New("127.0.0.1:1", "", "ds")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.ValidateToken("token", ""); err == nil {
		t.Fatal("ValidateToken against unreachable control plane succeeded")
	}
	out := c.Decide(engine.DecideRequest{Token: "token", SQL: "SELECT 1"})
	if !out.IsErr() || out.Err == "" {
		t.Fatalf("Decide = %+v, want non-empty fail-closed error", out)
	}
}

func TestRegisterUnspecifiedEngineRejectedBeforeRPC(t *testing.T) {
	fake := &fakeControlPlane{}
	c := startFakeControlPlane(t, fake)
	if err := c.Register(enginepb.Engine_ENGINE_UNSPECIFIED, "localhost", 1234, "db", nil, "", nil, false); err == nil || !strings.Contains(err.Error(), "unspecified engine") {
		t.Fatalf("Register error = %v, want local unspecified-engine error", err)
	}
	fake.mu.Lock()
	reached := fake.lastRegisterReq
	fake.mu.Unlock()
	if reached != nil {
		t.Fatalf("unsupported Register reached server: %+v", reached)
	}
}

var _ engine.Decider = (*Client)(nil)

type fakeControlPlane struct {
	pb.UnimplementedControlPlaneServer

	mu sync.Mutex

	validateResp *pb.WireIdentity
	validateErr  error
	decideResp   *pb.WireDecision
	decideQueue  []*pb.WireDecision
	pushGen      uint64

	lastValidateReq  *pb.ValidateTokenRequest
	lastValidateMeta string
	decideReqs       []*pb.DecisionRequest
	lastDecideMeta   string
	lastRegisterReq  *pb.RegisterRequest
	lastRegisterMeta string
	lastCatalog      *pb.CatalogRequest
	lastCatalogMeta  string
	lastFragment     *pb.SchemaFragmentPush
	lastFragmentMeta string
	lastClose        *pb.CloseConnectionRequest
	lastCloseMeta    string
	events           []*pb.ControlEvent
	lastEventsReq    *pb.EventsRequest
	lastEventsMeta   string
}

func metaValue(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	values := md.Get(secretTokenHeader)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (f *fakeControlPlane) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.WireIdentity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastValidateReq = proto.Clone(req).(*pb.ValidateTokenRequest)
	f.lastValidateMeta = metaValue(ctx)
	if f.validateErr != nil {
		return nil, f.validateErr
	}
	if f.validateResp != nil {
		return f.validateResp, nil
	}
	return &pb.WireIdentity{Principal: "default@example.com", ConnectionId: []byte("0123456789abcdef")}, nil
}

func (f *fakeControlPlane) Decide(ctx context.Context, req *pb.DecisionRequest) (*pb.WireDecision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decideReqs = append(f.decideReqs, proto.Clone(req).(*pb.DecisionRequest))
	f.lastDecideMeta = metaValue(ctx)
	if len(f.decideQueue) > 0 {
		resp := f.decideQueue[0]
		f.decideQueue = f.decideQueue[1:]
		return resp, nil
	}
	if f.decideResp != nil {
		return f.decideResp, nil
	}
	return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, DecisionId: 7}), nil
}

func (f *fakeControlPlane) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastRegisterReq = proto.Clone(req).(*pb.RegisterRequest)
	f.lastRegisterMeta = metaValue(ctx)
	return &pb.RegisterResponse{Name: req.GetName()}, nil
}

func (f *fakeControlPlane) PushCatalog(ctx context.Context, req *pb.CatalogRequest) (*pb.CatalogResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastCatalog = proto.Clone(req).(*pb.CatalogRequest)
	f.lastCatalogMeta = metaValue(ctx)
	return &pb.CatalogResponse{Columns: int32(len(req.GetColumns()))}, nil
}

func (f *fakeControlPlane) PushSchemaFragment(ctx context.Context, req *pb.SchemaFragmentPush) (*pb.SchemaFragmentAck, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastFragment = proto.Clone(req).(*pb.SchemaFragmentPush)
	f.lastFragmentMeta = metaValue(ctx)
	return &pb.SchemaFragmentAck{Generation: f.pushGen}, nil
}

func (f *fakeControlPlane) CloseConnection(ctx context.Context, req *pb.CloseConnectionRequest) (*pb.CloseConnectionResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastClose = proto.Clone(req).(*pb.CloseConnectionRequest)
	f.lastCloseMeta = metaValue(ctx)
	return &pb.CloseConnectionResponse{}, nil
}

func (f *fakeControlPlane) Events(req *pb.EventsRequest, stream grpc.ServerStreamingServer[pb.ControlEvent]) error {
	f.mu.Lock()
	f.lastEventsReq = proto.Clone(req).(*pb.EventsRequest)
	f.lastEventsMeta = metaValue(stream.Context())
	events := append([]*pb.ControlEvent(nil), f.events...)
	f.mu.Unlock()
	for _, event := range events {
		if err := stream.Send(event); err != nil {
			return err
		}
	}
	return nil
}

func startFakeControlPlane(t *testing.T, fake *fakeControlPlane) *Client {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := grpc.NewServer()
	pb.RegisterControlPlaneServer(server, fake)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	client, err := New(listener.Addr().String(), "secret-abc", "ds-1")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestValidateTokenMapsRequestAndIdentity(t *testing.T) {
	fake := &fakeControlPlane{validateResp: &pb.WireIdentity{
		Principal:    "alice@example.com",
		Roles:        []string{"analyst"},
		ConnectionId: []byte("0123456789abcdef"),
		OnOpen:       []*pb.ProxyCommand{refetch("app", nil)},
	}}
	c := startFakeControlPlane(t, fake)
	got, err := c.ValidateToken("raw-token", "198.51.100.7:5432")
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if got.Principal != "alice@example.com" || !reflect.DeepEqual(got.OnOpen, []*pb.Refetch{{Schema: "app"}}) {
		t.Fatalf("identity = %+v", got)
	}
	fake.mu.Lock()
	req, meta := fake.lastValidateReq, fake.lastValidateMeta
	fake.mu.Unlock()
	if req.GetToken() != "raw-token" || req.GetDatasourceName() != "ds-1" || req.GetClientAddr() != "198.51.100.7:5432" {
		t.Fatalf("ValidateTokenRequest = %+v, want token, datasource and client_addr", req)
	}
	if meta != "secret-abc" {
		t.Fatalf("metadata = %q, want secret-abc", meta)
	}
}

func TestValidateTokenRejectedAndMalformed(t *testing.T) {
	t.Run("rejected", func(t *testing.T) {
		c := startFakeControlPlane(t, &fakeControlPlane{validateErr: status.Error(codes.Unauthenticated, "invalid token")})
		if _, err := c.ValidateToken("bad", ""); err == nil || !strings.Contains(err.Error(), "invalid token") {
			t.Fatalf("ValidateToken error = %v", err)
		}
	})
	t.Run("malformed id", func(t *testing.T) {
		c := startFakeControlPlane(t, &fakeControlPlane{validateResp: &pb.WireIdentity{ConnectionId: []byte("bad")}})
		if _, err := c.ValidateToken("token", ""); err == nil {
			t.Fatal("ValidateToken accepted malformed connection id")
		}
	})
}

func TestDecideMapsRequestAndRetriesBeforeDecide(t *testing.T) {
	fake := &fakeControlPlane{decideQueue: []*pb.WireDecision{
		wireBefore(refetch("app", []byte("old"))),
		wireVerdict(&pb.Verdict{Decision: pb.EnfAction_MASK, DecisionId: 99, Generation: 4}),
	}}
	c := startFakeControlPlane(t, fake)
	var run [][]*pb.Refetch
	request := engine.DecideRequest{
		Token:        "raw-token",
		SQL:          "SELECT 1",
		ClientAddr:   "10.0.0.9:5555",
		Namespace:    []string{"public", "app"},
		TempColumns:  []engine.TempColumn{{Schema: "pg_temp_3", Table: "t", Column: "c", SqlType: "text", Ordinal: 5}},
		ConnectionID: []byte("0123456789abcdef"),
		RunCommands: func(commands []*pb.Refetch) error {
			run = append(run, commands)
			return nil
		},
	}
	out := c.Decide(request)
	if out.IsErr() || out.Decision.Action != "MASK" || out.Decision.Generation != 4 {
		t.Fatalf("Decide = %+v", out)
	}
	if !reflect.DeepEqual(run, [][]*pb.Refetch{{{Schema: "app", IfHashDiffers: []byte("old")}}}) {
		t.Fatalf("RunCommands calls = %+v", run)
	}

	fake.mu.Lock()
	requests := append([]*pb.DecisionRequest(nil), fake.decideReqs...)
	meta := fake.lastDecideMeta
	fake.mu.Unlock()
	if len(requests) != 2 || !proto.Equal(requests[0], requests[1]) {
		t.Fatalf("retry requests are not byte-equivalent: %+v", requests)
	}
	req := requests[0]
	if req.GetToken() != request.Token || req.GetDatasourceName() != "ds-1" || req.GetSql() != request.SQL || req.GetClientAddr() != request.ClientAddr ||
		!reflect.DeepEqual(req.GetSearchPath(), request.Namespace) || !reflect.DeepEqual(req.GetConnectionId(), request.ConnectionID) {
		t.Fatalf("DecisionRequest = %+v", req)
	}
	if len(req.GetTempColumns()) != 1 || req.GetTempColumns()[0].GetOrdinal() != 5 {
		t.Fatalf("TempColumns = %+v", req.GetTempColumns())
	}
	if meta != "secret-abc" {
		t.Fatalf("metadata = %q", meta)
	}
}

func TestDecideBeforeDecideFailures(t *testing.T) {
	t.Run("missing runner", func(t *testing.T) {
		c := startFakeControlPlane(t, &fakeControlPlane{decideResp: wireBefore(refetch("app", nil))})
		out := c.Decide(engine.DecideRequest{})
		if !out.IsErr() || !strings.Contains(out.Err, "no runner") {
			t.Fatalf("Decide = %+v", out)
		}
	})
	t.Run("runner error", func(t *testing.T) {
		c := startFakeControlPlane(t, &fakeControlPlane{decideResp: wireBefore(refetch("app", nil))})
		out := c.Decide(engine.DecideRequest{RunCommands: func([]*pb.Refetch) error { return errors.New("probe failed") }})
		if !out.IsErr() || !strings.Contains(out.Err, "probe failed") {
			t.Fatalf("Decide = %+v", out)
		}
	})
	t.Run("bounded", func(t *testing.T) {
		fake := &fakeControlPlane{decideResp: wireBefore(refetch("app", nil))}
		c := startFakeControlPlane(t, fake)
		runs := 0
		out := c.Decide(engine.DecideRequest{RunCommands: func([]*pb.Refetch) error { runs++; return nil }})
		if !out.IsErr() || !strings.Contains(out.Err, "4 times") {
			t.Fatalf("Decide = %+v", out)
		}
		fake.mu.Lock()
		calls := len(fake.decideReqs)
		fake.mu.Unlock()
		if calls != 4 || runs != 3 {
			t.Fatalf("RPC calls/runs = %d/%d, want 4/3", calls, runs)
		}
	})
}

func TestRegisterAndPushCatalog(t *testing.T) {
	fake := &fakeControlPlane{}
	c := startFakeControlPlane(t, fake)
	chain := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	if err := c.Register(enginepb.Engine_MYSQL, "backend", 3306, "app", []string{"tag"}, "127.0.0.1:6033", &chain, true); err != nil {
		t.Fatalf("Register: %v", err)
	}
	catalog := &pb.CatalogRequest{Columns: []*pb.Column{{Schema: "s", Table: "t", Column: "c"}}}
	if err := c.PushCatalog(catalog); err != nil {
		t.Fatalf("PushCatalog: %v", err)
	}
	fake.mu.Lock()
	register, catalogReq := fake.lastRegisterReq, fake.lastCatalog
	fake.mu.Unlock()
	if register.GetEngine() != enginepb.Engine_MYSQL || register.GetName() != "ds-1" {
		t.Fatalf("RegisterRequest = %+v", register)
	}
	// The chain is the ONE thing a client needs to verify this proxy, so it has to reach the wire intact.
	if !strings.Contains(register.GetAdvertiseCertChain(), "BEGIN CERTIFICATE") {
		t.Errorf("AdvertiseCertChain did not reach the wire: %q", register.GetAdvertiseCertChain())
	}
	// The TLS requirement travels separately from the material: a client that only learned "here is a chain"
	// could not tell an attacker's plaintext greeting from a datasource that never had TLS.
	if !register.GetAdvertiseWireTls() {
		t.Error("advertise_wire_tls did not reach the wire, so a client cannot refuse a plaintext downgrade")
	}
	// Presence, not just value: nil must stay distinguishable from an explicit empty string, which is what
	// lets the control plane tell "no opinion" apart from "stop publishing".
	if register.AdvertiseCertChain == nil {
		t.Error("advertise_cert_chain arrived ABSENT; a sent chain must be present on the wire")
	}
	if register.GetAdvertiseAddr() != "127.0.0.1:6033" {
		t.Fatalf("advertise_addr not transmitted in Register: %q", register.GetAdvertiseAddr())
	}
	if catalogReq.GetDatasourceName() != "ds-1" || catalog.DatasourceName != "ds-1" {
		t.Fatalf("catalog datasource was not stamped: server=%q caller=%q", catalogReq.GetDatasourceName(), catalog.DatasourceName)
	}
}

func TestPushSchemaFragmentAndCloseConnection(t *testing.T) {
	fake := &fakeControlPlane{pushGen: 11}
	c := startFakeControlPlane(t, fake)
	connectionID := []byte("0123456789abcdef")
	generation, err := c.PushSchemaFragment(&pb.SchemaFragmentPush{
		ConnectionId:      connectionID,
		Schema:            "app",
		ContentHash:       []byte("hash"),
		Unchanged:         false,
		Columns:           []*pb.Column{{Schema: "app", Table: "t", Column: "c", DataType: "text", Ordinal: 2, Nullable: true}},
		BackendGeneration: 7,
	})
	if err != nil || generation != 11 {
		t.Fatalf("PushSchemaFragment = %d, %v", generation, err)
	}
	if err := c.CloseConnection(connectionID); err != nil {
		t.Fatalf("CloseConnection: %v", err)
	}
	fake.mu.Lock()
	fragment, fragmentMeta := fake.lastFragment, fake.lastFragmentMeta
	closeReq, closeMeta := fake.lastClose, fake.lastCloseMeta
	fake.mu.Unlock()
	if fragment.GetDatasourceName() != "ds-1" || !reflect.DeepEqual(fragment.GetConnectionId(), connectionID) || fragment.GetBackendGeneration() != 7 ||
		fragment.GetSchema() != "app" || string(fragment.GetContentHash()) != "hash" || len(fragment.GetColumns()) != 1 || !fragment.GetColumns()[0].GetNullable() {
		t.Fatalf("SchemaFragmentPush = %+v", fragment)
	}
	if closeReq.GetDatasourceName() != "ds-1" || !reflect.DeepEqual(closeReq.GetConnectionId(), connectionID) {
		t.Fatalf("CloseConnectionRequest = %+v", closeReq)
	}
	if fragmentMeta != "secret-abc" || closeMeta != "secret-abc" {
		t.Fatalf("metadata fragment/close = %q/%q", fragmentMeta, closeMeta)
	}
}

func TestStreamEventsDispatchesMappedRunOpen(t *testing.T) {
	connectionID := []byte("0123456789abcdef")
	fake := &fakeControlPlane{events: []*pb.ControlEvent{
		{Kind: &pb.ControlEvent_RefreshCatalog{RefreshCatalog: &pb.RefreshCatalog{}}},
		{Kind: &pb.ControlEvent_OpenRunChannel{OpenRunChannel: &pb.OpenRunChannel{
			SessionId: "sess-1", EphemeralToken: "eph-9", ConnectionId: connectionID, OnOpen: []*pb.ProxyCommand{refetch("app", nil)},
		}}},
		{Kind: &pb.ControlEvent_OpenTableDetailChannel{OpenTableDetailChannel: &pb.OpenTableDetailChannel{SessionId: "sess-2", Schema: "public", Table: "users"}}},
	}}
	c := startFakeControlPlane(t, fake)
	var refreshes int
	var openedRun spi.RunOpen
	var table []string
	err := c.StreamEvents(func() { refreshes++ }, func(open spi.RunOpen) { openedRun = open }, func(sessionID, schema, tableName string) {
		table = []string{sessionID, schema, tableName}
	})
	if err == nil {
		t.Fatal("StreamEvents returned nil, want EOF")
	}
	wantRun := spi.RunOpen{SessionID: "sess-1", Token: "eph-9", ConnectionID: connectionID, OnOpen: []*pb.Refetch{{Schema: "app"}}}
	if refreshes != 1 || !reflect.DeepEqual(openedRun, wantRun) || !reflect.DeepEqual(table, []string{"sess-2", "public", "users"}) {
		t.Fatalf("dispatch refresh/run/table = %d/%+v/%v", refreshes, openedRun, table)
	}
	fake.mu.Lock()
	req, meta := fake.lastEventsReq, fake.lastEventsMeta
	fake.mu.Unlock()
	if req.GetDatasourceName() != "ds-1" || meta != "secret-abc" {
		t.Fatalf("Events request/meta = %+v/%q", req, meta)
	}
}

func TestStreamEventsDispatchesMalformedRunOpen(t *testing.T) {
	fake := &fakeControlPlane{events: []*pb.ControlEvent{{Kind: &pb.ControlEvent_OpenRunChannel{OpenRunChannel: &pb.OpenRunChannel{
		SessionId: "bad", ConnectionId: []byte("short"), OnOpen: []*pb.ProxyCommand{refetch("", nil)},
	}}}}}
	c := startFakeControlPlane(t, fake)
	var openedRun spi.RunOpen
	_ = c.StreamEvents(func() {}, func(open spi.RunOpen) { openedRun = open }, func(string, string, string) {})
	if openedRun.SessionID != "bad" || openedRun.MapErr == nil {
		t.Fatalf("malformed run open was not dispatched with MapErr: %+v", openedRun)
	}
}

func TestStreamEventsReturnsErrDrainingOnDrainSignal(t *testing.T) {
	// A drain is neither an error nor a max-age expiry: streamEvents must surface it as errDraining so the
	// loop reconnects at once instead of waiting out the backoff.
	fake := &fakeControlPlane{events: []*pb.ControlEvent{
		{Kind: &pb.ControlEvent_Draining{Draining: &pb.Draining{}}},
	}}
	c := startFakeControlPlane(t, fake)
	err := c.StreamEvents(func() {}, func(spi.RunOpen) {}, func(string, string, string) {})
	if !errors.Is(err, errDraining) {
		t.Fatalf("StreamEvents err = %v, want errDraining", err)
	}
}

// drainingControlPlane answers every Events call with a single Draining signal, standing in for a control
// plane that is rolling and telling its proxies to re-home to the replacement instance.
type drainingControlPlane struct {
	pb.UnimplementedControlPlaneServer
	mu    sync.Mutex
	opens int
}

func (f *drainingControlPlane) Events(_ *pb.EventsRequest, stream grpc.ServerStreamingServer[pb.ControlEvent]) error {
	f.mu.Lock()
	f.opens++
	f.mu.Unlock()
	return stream.Send(&pb.ControlEvent{Kind: &pb.ControlEvent_Draining{Draining: &pb.Draining{}}})
}

func (f *drainingControlPlane) openCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.opens
}

func TestEventsLoopReconnectsFastOnDrain(t *testing.T) {
	// A drain reconnects on the short drain floor, not the error backoff — but paced, not a zero-backoff
	// spin. With a 3s error backoff and a ~500ms floor, three reopens land well inside 2s (not the ~6s two
	// backoffs would take), yet cannot arrive before two floors (~1s) have elapsed.
	const backoff = 3 * time.Second

	fake := &drainingControlPlane{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := grpc.NewServer()
	pb.RegisterControlPlaneServer(server, fake)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	c, err := New(listener.Addr().String(), "secret-abc", "ds-1")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(loopDone)
		c.runEventsLoop(ctx, eventLoopTimings{
			streamMaxAge: time.Minute, // long enough that only the drain path paces this test
			reconnect:    backoff,
		}, func() {}, func() {}, func(spi.RunOpen) {}, func(string, string, string) {})
	}()
	t.Cleanup(func() {
		cancel()
		<-loopDone
	})

	deadline := time.After(2 * time.Second)
	for fake.openCount() < 3 {
		select {
		case <-deadline:
			t.Fatalf("only %d reopens in 2s — a drain did not use the fast floor (looks like the error backoff)", fake.openCount())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if elapsed := time.Since(start); elapsed < 850*time.Millisecond {
		t.Fatalf("three reopens in %v — the ~500ms drain floor is not pacing the loop (looks like a zero-backoff spin)", elapsed)
	}
}

// holdOpenControlPlane never returns from Events, standing in for a control plane the proxy can reach but
// which will never send anything — the shape a stream left pointing at a replaced backend takes.
type holdOpenControlPlane struct {
	pb.UnimplementedControlPlaneServer
	mu    sync.Mutex
	opens int
	done  chan struct{}
}

func (f *holdOpenControlPlane) Events(_ *pb.EventsRequest, stream grpc.ServerStreamingServer[pb.ControlEvent]) error {
	f.mu.Lock()
	f.opens++
	if f.opens == 1 && f.done != nil {
		close(f.done)
	}
	f.mu.Unlock()
	<-stream.Context().Done()
	return stream.Context().Err()
}

func (f *holdOpenControlPlane) openCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.opens
}

func startHoldOpenControlPlane(t *testing.T, fake *holdOpenControlPlane) *Client {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := grpc.NewServer()
	pb.RegisterControlPlaneServer(server, fake)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	client, err := New(listener.Addr().String(), "secret-abc", "ds-1")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestStreamEventsEndsAtItsMaxAge(t *testing.T) {
	// The stream must not outlive its deadline even when the peer sends nothing and the connection stays
	// healthy. Without the bound this call blocks forever, which is exactly how a proxy ends up holding a
	// stream to a control plane that is gone: keepalive proves the connection, not the stream.
	fake := &holdOpenControlPlane{done: make(chan struct{})}
	c := startHoldOpenControlPlane(t, fake)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	start := time.Now()
	err := c.streamEvents(ctx, 300*time.Millisecond, func() {}, func(spi.RunOpen) {}, func(string, string, string) {})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected the stream to end at its max age")
	}
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("took %v — the deadline did not bound the stream", elapsed)
	}
}

func TestEventsLoopReopensAfterMaxAge(t *testing.T) {
	// Ending the stream is only useful if the loop opens another one: the reopen is what restores the
	// control plane's view of this datasource as attached.
	fake := &holdOpenControlPlane{done: make(chan struct{})}
	c := startHoldOpenControlPlane(t, fake)

	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		c.runEventsLoop(ctx, eventLoopTimings{
			streamMaxAge: 150 * time.Millisecond,
			reconnect:    10 * time.Millisecond,
		}, func() {}, func() {}, func(spi.RunOpen) {}, func(string, string, string) {})
	}()
	t.Cleanup(func() {
		cancel()
		<-loopDone
	})

	deadline := time.After(5 * time.Second)
	for {
		if fake.openCount() >= 3 {
			return // rotated more than once, so it is a loop and not a single retry
		}
		select {
		case <-deadline:
			t.Fatalf("only %d stream opens — the loop did not keep reopening", fake.openCount())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestEventsLoopReopensWithoutWaitingForResync(t *testing.T) {
	// resync introspects the whole catalog and retries with its own backoff. Run in line it delays the
	// reopen, and the datasource reads as unattached for that whole time — so a resync that never returns
	// must not stop the stream coming back.
	fake := &holdOpenControlPlane{done: make(chan struct{})}
	c := startHoldOpenControlPlane(t, fake)

	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	blocked := make(chan struct{})
	resync := func() {
		<-blocked // every background resync stays blocked until test cleanup releases it
	}
	go func() {
		defer close(loopDone)
		c.runEventsLoop(ctx, eventLoopTimings{
			streamMaxAge: 150 * time.Millisecond,
			reconnect:    10 * time.Millisecond,
		}, resync, func() {}, func(spi.RunOpen) {}, func(string, string, string) {})
	}()
	t.Cleanup(func() {
		cancel()
		<-loopDone
		close(blocked) // release the background resync goroutines after the loop exits
	})

	deadline := time.After(5 * time.Second)
	for {
		if fake.openCount() >= 3 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("only %d opens with a stuck resync — the reopen is behind it", fake.openCount())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// refusingControlPlane fails every Events call immediately, standing in for a control plane that is
// reachable but not serving — the shape a restart or a rollout takes from the proxy's side.
type refusingControlPlane struct {
	pb.UnimplementedControlPlaneServer
	mu    sync.Mutex
	opens []time.Time
}

func (f *refusingControlPlane) Events(_ *pb.EventsRequest, _ grpc.ServerStreamingServer[pb.ControlEvent]) error {
	f.mu.Lock()
	f.opens = append(f.opens, time.Now())
	f.mu.Unlock()
	return status.Error(codes.Unavailable, "not serving")
}

func (f *refusingControlPlane) openTimes() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.opens...)
}

func TestEventsLoopWaitsTheBackoffBetweenReopens(t *testing.T) {
	// A stream that fails to open returns immediately, so the backoff is the only thing pacing the loop.
	// Without it a control plane that is down turns into a hot reconnect loop that also launches a
	// catalog-introspecting resync per iteration. Asserting that reopens happen is not enough to catch
	// that: the reopens still happen, just unboundedly fast.
	const backoff = 120 * time.Millisecond

	fake := &refusingControlPlane{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := grpc.NewServer()
	pb.RegisterControlPlaneServer(server, fake)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	c, err := New(listener.Addr().String(), "secret-abc", "ds-1")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		c.runEventsLoop(ctx, eventLoopTimings{
			streamMaxAge: time.Minute, // long enough that only the backoff paces this test
			reconnect:    backoff,
		}, func() {}, func() {}, func(spi.RunOpen) {}, func(string, string, string) {})
	}()
	t.Cleanup(func() {
		cancel()
		<-loopDone
	})

	deadline := time.After(5 * time.Second)
	for len(fake.openTimes()) < 3 {
		select {
		case <-deadline:
			t.Fatalf("only %d opens against a refusing control plane — the loop is not reopening", len(fake.openTimes()))
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Compare against the whole backoff rather than a fraction of it: the gap is the wait plus the failed
	// RPC, so it can only run long. A loop that skipped the wait would show gaps near zero.
	opens := fake.openTimes()
	for i := 1; i < len(opens); i++ {
		if gap := opens[i].Sub(opens[i-1]); gap < backoff {
			t.Fatalf("reopen %d came %v after the previous one, faster than the %v backoff", i, gap, backoff)
		}
	}
}
