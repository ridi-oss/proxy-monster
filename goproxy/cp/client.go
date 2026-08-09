// Package cp is the proxy's gRPC client to the control plane.
//
// The proxy fronts ONE datasource (identified by datasourceName, its stable wire identity) and brokers
// to the backend itself, so it only needs the verdict + mask spec — it never sends rows to the control
// plane. Per-query enforcement re-sends the RAW token to Decide, which the control plane re-validates
// every call (closing the mid-session revocation gap): an authN failure (bad/revoked/expired token,
// deprovisioned principal) comes back as an error the caller fails closed on, distinct from a policy
// DENY verdict.
//
// The proxy<->control-plane hop is internal/trusted (loopback or tailnet), so the channel is plaintext;
// the end-user wire token travels inside the request, re-resolved server-side. secretToken (when set) is
// the shared transport secret attached to every call as x-pm-secret-token.
package cp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"

	// The shared proxymonster.v1.Engine enum lives in analyzer/probe/pb (see engine/engine.go's
	// import comment for why goproxy resolves it there instead of generating a second copy).
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// ProtocolVersion is this proxy's proxy<->control-plane wire-protocol version, exchanged at Register so a
// half-finished rollout (proxy and control-plane on different server-v* releases) fails fast with a clear
// error instead of a stalled run channel. Bump it on any incompatible wire change. It MUST match the
// control-plane's CONTROL_PROTOCOL_VERSION; the two are separate constants in separate languages kept in
// lockstep by hand — a server-v* release always ships both at the same value.
const ProtocolVersion int32 = 1

// ErrIncompatibleControlPlane means the control-plane speaks a different wire-protocol version than this
// proxy — a PERMANENT deploy-skew condition, not a transient failure. boot treats it as fatal (refuse to
// start) rather than retrying, so a half-finished rollout fails fast and legibly instead of attaching and
// stalling. Covers both the control-plane rejecting our version and an older control-plane that predates the
// version field (returns 0).
var ErrIncompatibleControlPlane = errors.New("control-plane wire-protocol version is incompatible with this proxy")

// protocolVersionRejectionMarker is a stable substring of the control-plane's version-mismatch rejection
// message (control-plane ControlPlaneGrpcService.register). Matching it lets boot treat that FAILED_PRECONDITION
// as this permanent condition, not a transient register failure to retry. Keep in sync with that message.
const protocolVersionRejectionMarker = "wire-protocol version"

const (
	// rpcDeadline bounds every unary call — a control plane that accepts but never completes a call must
	// not park the caller forever.
	rpcDeadline = 30 * time.Second
	// secretTokenHeader is the shared transport secret header the control plane expects.
	secretTokenHeader = "x-pm-secret-token"
	// eventsReconnectDefault is the backoff between Events stream reconnect attempts.
	eventsReconnectDefault = 5 * time.Second
	// eventsDrainReconnect paces the reconnect after a Draining signal: fast enough to re-home in about a
	// second (vs the full error backoff), but non-zero so a peer that keeps draining cannot spin the loop —
	// each reopen would otherwise launch a resync. The control plane sends GOAWAY before it closes the
	// stream, and that is what makes this reopen dial a FRESH connection rather than reuse this one —
	// re-homing to a live instance where a load balancer fronts several, or reconnecting once it is back.
	eventsDrainReconnect = 500 * time.Millisecond
	// eventsStreamMaxAge bounds how long one Events stream is used before it is replaced. HTTP/2 keepalive
	// proves the CONNECTION is alive, not that the stream on it still reaches a live control plane: a
	// load balancer that keeps a connection open toward a replaced backend leaves the proxy holding a
	// stream nothing will ever answer, and because the proxy's other calls are unary they open their own
	// connections and keep succeeding — so the catalog stays fresh while the control plane reports this
	// datasource as having no proxy attached, and every query against it is refused. Ending the stream on
	// a timer makes that state self-healing and bounds it to one period, without needing the control
	// plane to notice anything.
	eventsStreamMaxAgeDefault = 4 * time.Minute
	// keepaliveTime / keepaliveTimeout configure HTTP/2 keepalive so a half-open connection is detected
	// instead of silently wedging the long-lived Events stream.
	keepaliveTime    = 30 * time.Second
	keepaliveTimeout = 10 * time.Second
)

type eventLoopTimings struct {
	reconnect    time.Duration
	streamMaxAge time.Duration
}

func defaultEventLoopTimings() eventLoopTimings {
	return eventLoopTimings{
		reconnect:    eventsReconnectDefault,
		streamMaxAge: eventsStreamMaxAgeDefault,
	}
}

// Client is the proxy's gRPC client to the control plane. It satisfies engine.Decider.
type Client struct {
	conn           *grpc.ClientConn
	stub           pb.ControlPlaneClient
	secretToken    string
	datasourceName string
}

// New dials the control plane at grpcTarget (plaintext — internal/trusted hop) and returns a Client
// scoped to one datasource.
func New(grpcTarget, secretToken, datasourceName string) (*Client, error) {
	conn, err := grpc.NewClient(
		grpcTarget,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                keepaliveTime,
			Timeout:             keepaliveTimeout,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("cp: dialing control plane at %q: %w", grpcTarget, err)
	}
	return &Client{
		conn:           conn,
		stub:           pb.NewControlPlaneClient(conn),
		secretToken:    secretToken,
		datasourceName: datasourceName,
	}, nil
}

// Close shuts down the underlying gRPC connection (grpc.ClientConn.Close is itself graceful).
func (c *Client) Close() error {
	return c.conn.Close()
}

// outCtx attaches the shared transport secret (when set) to the outgoing call.
func (c *Client) outCtx(parent context.Context) context.Context {
	if c.secretToken == "" {
		return parent
	}
	return metadata.AppendToOutgoingContext(parent, secretTokenHeader, c.secretToken)
}

// refetchesFromWire unwraps the only supported mechanical command arm (Refetch) from the generic
// ProxyCommand envelope. Unknown arms and blank schemas are malformed and fail closed rather than degrading
// to a broader refresh. Each Refetch is deep-copied so the returned commands never alias the wire message's
// mutable backing arrays.
func refetchesFromWire(commands []*pb.ProxyCommand) ([]*pb.Refetch, error) {
	mapped := make([]*pb.Refetch, 0, len(commands))
	for i, command := range commands {
		refetch := command.GetRefetch()
		if refetch == nil {
			return nil, fmt.Errorf("command %d is not a refetch", i)
		}
		if refetch.GetSchema() == "" {
			return nil, fmt.Errorf("command %d has blank schema", i)
		}
		mapped = append(mapped, &pb.Refetch{
			Schema:        refetch.GetSchema(),
			IfHashDiffers: append([]byte(nil), refetch.GetIfHashDiffers()...),
		})
	}
	return mapped, nil
}

// identityFromWire maps the control plane's WireIdentity into the proxy's session identity. PURE function
// (no I/O) so it is directly unit-testable.
func identityFromWire(id *pb.WireIdentity) (spi.Identity, error) {
	if len(id.GetConnectionId()) != 16 {
		return spi.Identity{}, fmt.Errorf("control plane returned connection_id with %d bytes, want 16", len(id.GetConnectionId()))
	}
	onOpen, err := refetchesFromWire(id.GetOnOpen())
	if err != nil {
		return spi.Identity{}, fmt.Errorf("control plane returned malformed on_open: %w", err)
	}
	return spi.Identity{
		Principal:    id.GetPrincipal(),
		Roles:        append([]string(nil), id.GetRoles()...),
		ConnectionID: append([]byte(nil), id.GetConnectionId()...),
		OnOpen:       onOpen,
	}, nil
}

// ValidateToken authenticates the session-open token through the control plane. ANY failure, including an
// UNAUTHENTICATED status or an empty response, returns an error so the wire broker fails closed.
func (c *Client) ValidateToken(token, clientAddr string) (spi.Identity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcDeadline)
	defer cancel()

	resp, err := c.stub.ValidateToken(c.outCtx(ctx), &pb.ValidateTokenRequest{Token: token, DatasourceName: c.datasourceName, ClientAddr: clientAddr})
	if err != nil {
		if st, ok := status.FromError(err); ok {
			msg := st.Message()
			if msg == "" {
				msg = st.Code().String()
			}
			return spi.Identity{}, fmt.Errorf("%s", msg)
		}
		return spi.Identity{}, fmt.Errorf("control plane unreachable: %w", err)
	}
	if resp == nil {
		return spi.Identity{}, fmt.Errorf("control plane returned an empty identity")
	}
	return identityFromWire(resp)
}

// denyClosed builds a fail-closed DENY decision for a wire response the proxy cannot safely honor
// (an absent outcome, a not-yet-supported outcome arm, or an unhonorable command). Masks is an empty
// (non-nil) slice so callers never dereference a nil.
func denyClosed(reason string) *engine.Decision {
	return &engine.Decision{Action: "DENY", DenyReason: reason, Masks: []*pb.ColumnMask{}}
}

// decisionFromWire maps the control plane's WireDecision onto the engine's dialect-agnostic outcome.
// Before-decision commands are returned separately and take precedence over any verdict accessor.
func decisionFromWire(d *pb.WireDecision) ([]*pb.Refetch, *engine.Decision) {
	if before := d.GetBeforeDecide(); before != nil {
		commands, err := refetchesFromWire(before.GetCommands())
		if err != nil {
			return nil, denyClosed("control plane returned malformed before-decision commands: " + err.Error())
		}
		return commands, nil
	}

	v := d.GetVerdict()
	if v == nil {
		return nil, denyClosed("control plane returned no verdict")
	}

	action := engine.EnfActionName(v.GetDecision())

	// The proto ColumnMask is the mask data class — carry it through verbatim. An absent ordinal keeps its
	// explicit-presence nil (BindMasks fails closed on it); do NOT normalize it to a sentinel here.
	masks := v.GetMasks()

	var rewritten *string
	if v.RewrittenSql != nil {
		rewrittenSQL := *v.RewrittenSql
		rewritten = &rewrittenSQL
	}
	afterStatement, err := refetchesFromWire(v.GetAfterStatement())
	if err != nil {
		return nil, denyClosed("control plane returned malformed after-statement commands: " + err.Error())
	}

	return nil, &engine.Decision{
		Action:              action,
		DecisionID:          v.GetDecisionId(),
		DenyReason:          v.GetDenyReason(),
		Masks:               masks,
		EffectiveRoles:      append([]string(nil), v.GetEffectiveRoles()...),
		RewrittenSQL:        rewritten,
		UnmaskablePermitted: v.GetUnmaskablePermitted(),
		AfterStatement:      afterStatement,
		Generation:          v.GetGeneration(),
		SanitizeDiagnostics: v.GetSanitizeDiagnostics(),
	}
}

// Decide satisfies engine.Decider: it re-sends the same raw request after mechanically satisfying at
// most three before_decide command rounds. Every failure path yields a non-empty Err (fail closed).
func (c *Client) Decide(req engine.DecideRequest) engine.DecisionOutcome {
	temps := make([]*pb.TempColumn, 0, len(req.TempColumns))
	for _, t := range req.TempColumns {
		temps = append(temps, &pb.TempColumn{
			Schema:  t.Schema,
			Table:   t.Table,
			Column:  t.Column,
			SqlType: t.SqlType,
			Ordinal: int32(t.Ordinal),
		})
	}
	wireReq := &pb.DecisionRequest{
		Token:           req.Token,
		DatasourceName:  c.datasourceName,
		Sql:             req.SQL,
		SearchPath:      append([]string(nil), req.Namespace...),
		ClientAddr:      req.ClientAddr,
		TempColumns:     temps,
		ConnectionId:    append([]byte(nil), req.ConnectionID...),
		MysqlAnsiQuotes: req.MysqlAnsiQuotes,
	}

	for round := 0; ; round++ {
		ctx, cancel := context.WithTimeout(context.Background(), rpcDeadline)
		resp, err := c.stub.Decide(c.outCtx(ctx), wireReq)
		cancel()
		if err != nil {
			if st, ok := status.FromError(err); ok {
				msg := st.Message()
				if msg == "" {
					msg = st.Code().String()
				}
				return engine.DecisionOutcome{Err: msg}
			}
			return engine.DecisionOutcome{Err: "control plane unreachable: " + err.Error()}
		}
		if resp == nil {
			return engine.DecisionOutcome{Err: "control plane returned an empty decision"}
		}

		commands, decision := decisionFromWire(resp)
		if commands == nil {
			return engine.DecisionOutcome{Decision: decision}
		}
		if round >= 3 {
			return engine.DecisionOutcome{Err: fmt.Sprintf("control plane demanded pre-decision commands %d times", round+1)}
		}
		if req.RunCommands == nil {
			return engine.DecisionOutcome{Err: "control plane demanded pre-decision commands but no runner is configured"}
		}
		if err := req.RunCommands(commands); err != nil {
			return engine.DecisionOutcome{Err: "pre-decision commands failed: " + err.Error()}
		}
	}
}

// ReportCompletion sends a post-relay completion report (audit-only result volume) to the control plane.
// It is synchronous with its own deadline; callers keep it off the client session's critical path (see
// engine.EmitCompletion, which runs it on its own goroutine). A failure is logged, never returned — a lost
// completion only degrades the audit monitor's volume signal and must never affect the client session.
func (c *Client) ReportCompletion(report engine.CompletionReport) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcDeadline)
	defer cancel()
	if _, err := c.stub.ReportCompletion(c.outCtx(ctx), &pb.CompletionReport{
		DecisionId:    report.DecisionID,
		RowsReturned:  report.RowsReturned,
		BytesReturned: report.BytesReturned,
		Status:        report.Status,
		DurationMs:    report.DurationMs,
	}); err != nil {
		slog.Warn("cp: report completion failed",
			"datasource", c.datasourceName, "decision_id", report.DecisionID, "error", err)
	}
}

// Register upserts this proxy's datasource identity on boot. The provider supplies the protobuf
// registration identity; the client sends it without interpreting the dialect.
// wireTLS is sent independently of advertiseCertChain: an operator may serve TLS while publishing no chain,
// and a transient cert-read error sends no chain without TLS going away. A client needs the requirement, not
// just the material, to know that a plaintext greeting must be refused.
//
// advertiseCertChain is a pointer for explicit presence. nil means "no opinion" and preserves whatever the
// control plane stores (a transient read at re-register); a non-nil empty string is authoritative and CLEARS
// the stored chain, so an operator who stops publishing does not leave clients on dead roots.
func (c *Client) Register(registrationEngine enginepb.Engine, host string, port int, dbName string, tags []string, advertiseAddr string, advertiseCertChain *string, wireTLS bool) error {
	// Fail-closed defense-in-depth — never send an unspecified engine (boot already validated the provider).
	if registrationEngine == enginepb.Engine_ENGINE_UNSPECIFIED {
		return fmt.Errorf("cp: refusing to register datasource %q with an unspecified engine", c.datasourceName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), rpcDeadline)
	defer cancel()

	resp, err := c.stub.Register(c.outCtx(ctx), &pb.RegisterRequest{
		Name:               c.datasourceName,
		Engine:             registrationEngine,
		Host:               host,
		Port:               int32(port),
		DbName:             dbName,
		Tags:               tags,
		AdvertiseAddr:      advertiseAddr,
		AdvertiseCertChain: advertiseCertChain,
		AdvertiseWireTls:   wireTLS,
		ProtocolVersion:    ProtocolVersion,
	})
	if err != nil {
		// A control-plane on a LATER protocol rejects our version with FAILED_PRECONDITION — a permanent
		// deploy skew, so surface it as such (boot refuses to start) rather than a transient register failure.
		if st, ok := status.FromError(err); ok && st.Code() == codes.FailedPrecondition &&
			strings.Contains(st.Message(), protocolVersionRejectionMarker) {
			return fmt.Errorf("%w: %s", ErrIncompatibleControlPlane, st.Message())
		}
		return fmt.Errorf("cp: register datasource %q: %w", c.datasourceName, err)
	}
	// Mirror check: an OLDER control-plane that predates the version field cannot reject us, so it returns 0.
	// Refuse to run against it rather than proceed to a run channel it cannot speak.
	if resp.GetProtocolVersion() != ProtocolVersion {
		return fmt.Errorf(
			"%w: control-plane at version %d, this proxy at %d — deploy both from the same server-v* release",
			ErrIncompatibleControlPlane, resp.GetProtocolVersion(), ProtocolVersion,
		)
	}
	return nil
}

// PushCatalog sends the catalog this proxy introspected itself — the control plane never dials the
// target, so the proxy is the only source of the schema. It stamps DatasourceName before sending.
func (c *Client) PushCatalog(catalog *pb.CatalogRequest) error {
	catalog.DatasourceName = c.datasourceName

	ctx, cancel := context.WithTimeout(context.Background(), rpcDeadline)
	defer cancel()

	started := time.Now()
	ack, err := c.stub.PushCatalog(c.outCtx(ctx), catalog)
	if err != nil {
		return fmt.Errorf("cp: push catalog for %q: %w", c.datasourceName, err)
	}
	// Paired with introspect.Run's phase breakdown, this closes the refresh cycle: a slow refresh is
	// either the backend scan or this push, and the two logs together say which.
	slog.Info("pushed catalog", "datasource", c.datasourceName, "columns", ack.GetColumns(),
		"push_ms", time.Since(started).Milliseconds())
	return nil
}

// PushSchemaFragment applies one measured connection-local schema fragment and returns its generation.
// The fragment is the proto message the refetcher built; it stamps DatasourceName before sending (the
// refetcher does not know it), mirroring PushCatalog.
func (c *Client) PushSchemaFragment(push *pb.SchemaFragmentPush) (uint64, error) {
	push.DatasourceName = c.datasourceName
	ctx, cancel := context.WithTimeout(context.Background(), rpcDeadline)
	defer cancel()
	ack, err := c.stub.PushSchemaFragment(c.outCtx(ctx), push)
	if err != nil {
		return 0, fmt.Errorf("cp: push schema fragment for %q: %w", c.datasourceName, err)
	}
	return ack.GetGeneration(), nil
}

// CloseConnection evicts the control plane's connection-local catalog state.
func (c *Client) CloseConnection(connectionID []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), rpcDeadline)
	defer cancel()
	_, err := c.stub.CloseConnection(c.outCtx(ctx), &pb.CloseConnectionRequest{
		ConnectionId:   append([]byte(nil), connectionID...),
		DatasourceName: c.datasourceName,
	})
	if err != nil {
		return fmt.Errorf("cp: close connection for %q: %w", c.datasourceName, err)
	}
	return nil
}

// StreamEvents opens the proxy-initiated Events stream and dispatches refresh/run/table-detail
// nudges until the stream ends or errors. Blocks the calling goroutine for the stream's lifetime.
//
// Bounded by eventsStreamMaxAgeDefault rather than left open indefinitely. The open stream IS the liveness
// signal the control plane reads, so a stream that survives its control plane costs this datasource
// every query until something ends it — and nothing here would, because keepalive only proves the
// connection is alive. Expiry is a normal end: RunEventsLoop resyncs and reopens, and the control
// plane sees a detach immediately followed by an attach.
func (c *Client) StreamEvents(
	onRefresh func(),
	onOpenRun func(spi.RunOpen),
	onOpenTableDetail func(sessionID, schema, table string),
) error {
	timings := defaultEventLoopTimings()
	return c.streamEvents(context.Background(), timings.streamMaxAge, onRefresh, onOpenRun, onOpenTableDetail)
}

// errDraining is returned by streamEvents when the control plane signals a graceful shutdown over the
// stream. It selects the short-floor reconnect path in runEventsLoop, distinct from an error backoff or a
// max-age rotation, so a rolling control-plane restart reconnects promptly; the control plane's GOAWAY is
// what points that reconnect at a fresh connection.
var errDraining = errors.New("cp: control plane draining")

func (c *Client) streamEvents(
	parent context.Context,
	maxAge time.Duration,
	onRefresh func(),
	onOpenRun func(spi.RunOpen),
	onOpenTableDetail func(sessionID, schema, table string),
) error {
	ctx, cancel := context.WithTimeout(c.outCtx(parent), maxAge)
	defer cancel()
	stream, err := c.stub.Events(ctx, &pb.EventsRequest{DatasourceName: c.datasourceName})
	if err != nil {
		return fmt.Errorf("cp: opening events stream: %w", err)
	}
	for {
		ev, err := stream.Recv()
		if err != nil {
			return err
		}
		switch {
		case ev.GetDraining() != nil:
			// The control plane is shutting down and is about to close this stream. Return now so the loop
			// reopens on the short drain floor instead of the error backoff; the control plane's GOAWAY makes
			// that reopen dial a fresh connection (re-homing where an LB fronts several) rather than wait out
			// a max-age rotation.
			return errDraining
		case ev.GetRefreshCatalog() != nil:
			onRefresh()
		case ev.GetOpenRunChannel() != nil:
			e := ev.GetOpenRunChannel()
			onOpen, mapErr := refetchesFromWire(e.GetOnOpen())
			if len(e.GetConnectionId()) != 16 {
				mapErr = fmt.Errorf("control plane returned run connection_id with %d bytes, want 16", len(e.GetConnectionId()))
			}
			onOpenRun(spi.RunOpen{
				SessionID:    e.GetSessionId(),
				Token:        e.GetEphemeralToken(),
				ConnectionID: append([]byte(nil), e.GetConnectionId()...),
				OnOpen:       onOpen,
				MapErr:       mapErr,
			})
		case ev.GetOpenTableDetailChannel() != nil:
			t := ev.GetOpenTableDetailChannel()
			onOpenTableDetail(t.GetSessionId(), t.GetSchema(), t.GetTable())
		}
	}
}

// RunEventsLoop holds the Events stream open until ctx is cancelled. On a drop it waits
// eventsReconnectDefault, resyncs (re-registers + re-pushes the catalog, so a control plane that restarted
// with lost state re-learns this datasource) and reopens. Cancelling ctx returns the loop, which shutdown
// uses to stop new run dispatches before it drains the in-flight ones (the run-stream analogue of the wire
// server closing its listener).
//
// The resync runs in the background rather than in line. It introspects the whole catalog, which on a
// large database takes seconds and retries with its own backoff — done in line, a slow one delays the
// reopen, and the control plane reports this datasource unattached for exactly that long. The stream is
// what queries need; the catalog refresh is not, and it re-registers this datasource either way.
func (c *Client) RunEventsLoop(
	ctx context.Context,
	resync func(),
	onRefresh func(),
	onOpenRun func(spi.RunOpen),
	onOpenTableDetail func(sessionID, schema, table string),
) {
	c.runEventsLoop(ctx, defaultEventLoopTimings(), resync, onRefresh, onOpenRun, onOpenTableDetail)
}

func (c *Client) runEventsLoop(
	ctx context.Context,
	timings eventLoopTimings,
	resync func(),
	onRefresh func(),
	onOpenRun func(spi.RunOpen),
	onOpenTableDetail func(sessionID, schema, table string),
) {
	for {
		err := c.streamEvents(ctx, timings.streamMaxAge, onRefresh, onOpenRun, onOpenTableDetail)
		// A drain is the control plane leaving on purpose with a replacement already up: reconnect at once
		// so this datasource re-attaches to the new instance without a gap. An expiry is the bounded
		// rotation working, not a fault. Anything else is an error and waits out the backoff.
		reconnectIn := timings.reconnect
		switch {
		case errors.Is(err, errDraining):
			slog.Info("control plane draining; reconnecting to re-home", "reconnect_in", eventsDrainReconnect)
			reconnectIn = eventsDrainReconnect
		case errors.Is(err, context.DeadlineExceeded) || status.Code(err) == codes.DeadlineExceeded:
			slog.Info("events stream reached its max age; reopening", "max_age", timings.streamMaxAge)
		default:
			slog.Info("events stream ended; reconnecting", "error", err, "reconnect_in", timings.reconnect)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(reconnectIn):
		}

		go resync()
	}
}

// RunExec opens a proxy-dialed run stream. Deliberately not deadlined: it lives for the session.
func (c *Client) RunExec(ctx context.Context) (grpc.BidiStreamingClient[pb.ProxyRunMsg, pb.ControlRunMsg], error) {
	return c.stub.RunExec(c.outCtx(ctx))
}

// OpenRunStream exposes the run stream through the dependency-free SPI.
func (c *Client) OpenRunStream(ctx context.Context) (spi.RunStream, error) {
	return c.RunExec(ctx)
}

// TableDetailExec opens a short-lived proxy-dialed table-detail stream; the control plane owns its
// explicit timeout.
func (c *Client) TableDetailExec(ctx context.Context) (grpc.BidiStreamingClient[pb.ProxyTableDetailMsg, pb.ControlTableDetailMsg], error) {
	return c.stub.TableDetailExec(c.outCtx(ctx))
}

// OpenTableDetailStream exposes the table-detail stream through the dependency-free SPI.
func (c *Client) OpenTableDetailStream(ctx context.Context) (spi.TableDetailStream, error) {
	return c.TableDetailExec(ctx)
}

var (
	_ engine.Decider            = (*Client)(nil)
	_ engine.CompletionReporter = (*Client)(nil)
	_ spi.EnforcementClient     = (*Client)(nil)
	_ spi.RunClient             = (*Client)(nil)
	_ spi.TableDetailClient     = (*Client)(nil)
)
