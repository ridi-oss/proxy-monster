package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/authz"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/datasource"
	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/query"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/store"
)

// EnforcementOutcome is `sealed interface EnforcementOutcome` (05-datasources-catalog.md §6).
//
// 🔒 INV-A10-38 — the two arms are structurally exclusive, and a message carrying NEITHER must fail
// closed at the wire. Modelled as an interface pair (not a struct with two optional fields) so a
// caller cannot construct a both-set value and the mapper's `oneof` stays honest.
type EnforcementOutcome interface{ isEnforcementOutcome() }

// OutcomeVerdict is `Verdict(ctx, decisionId, generation, afterStatement)`.
type OutcomeVerdict struct {
	Ctx        query.DecisionContext
	DecisionID int64
	// Generation is the generation the decision was ANALYZED under (INV-A5-48), stamped at entry and
	// asserted unchanged at emit.
	Generation     int64
	AfterStatement []*pb.Refetch
}

// OutcomeBeforeDecide is `BeforeDecide(commands)` — run these, then re-send the same request.
//
// 🔒 INV-A5-49 — a BeforeDecide writes NO AUDIT ROW. All three of its return sites are before the
// decisionRecord/insert steps. A port that audited the gate would flood the hash chain and make every
// stale-catalog round-trip look like a decision.
type OutcomeBeforeDecide struct{ Commands []*pb.Refetch }

func (OutcomeVerdict) isEnforcementOutcome()      {}
func (OutcomeBeforeDecide) isEnforcementOutcome() {}

// DecideConnectionInput is `decideConnection`'s parameter list. Kotlin gives six of the twelve
// default values; a named-field struct expresses them exactly and removes positional binding — which
// matters here because the Kotlin's TENTH POSITIONAL ARGUMENT is `providedRoles`, and A10's `decide`
// passes `assumeRoles` into it (10-grpc.md §3.1 rule 14).
type DecideConnectionInput struct {
	ConnectionID datasource.ConnectionID
	Principal    string
	Datasource   datasource.Datasource
	SQL          string
	// SearchPath is the proxy's LIVE namespace, passed through verbatim.
	// 🔒 INV-A10-15 — an EMPTY list is NOT collapsed to the datasource default. "Absent = default"
	// would be fail-OPEN: a failed namespace probe would authorize against the stored default.
	SearchPath []string
	// ClientAddr is the end-client address. WIRE-channel decisions parse `requester_ip` from it.
	ClientAddr *string
	AnsiQuotes bool
	Channel    query.Channel
	// ProvidedRoles is the execute-under-R assume-role set. Non-nil REPLACES server role resolution
	// (A6 step 6). A pointer-to-slice because nil ("resolve") and the empty set ("no roles") are
	// different states.
	ProvidedRoles *[]string
	TempColumns   []datasource.CatalogColumn
	// HTTPRequesterIP is the IP recorded when the control plane MINTED an editor/workflow token.
	// 🔒 INV-A5-52 / INV-A10-44 — the requester_ip SOURCE is CHANNEL-SELECTED, never "whichever is
	// non-null": WIRE parses ClientAddr, every other channel uses this. A nullable fallback would let
	// a WIRE statement inherit another channel's HTTP IP and satisfy a network-gated policy it should
	// not.
	HTTPRequesterIP *string
}

// DecideConnection is `suspend fun decideConnection(...)` (05-datasources-catalog.md §6).
//
// found=false is Kotlin's null return: the connection disappeared mid-flight, which A10 maps to
// NOT_FOUND. The whole body runs inside [datasource.ConnectionCatalogRegistry.WithConnection], so the
// registry mutex is held from the freshness pre-gate through audit and verdict emission.
//
// 🔒 INV-A5-48 — the generation stamped on a verdict is EXACTLY the generation analyzed. Step 1
// captures it, step 16 asserts it is unchanged. That assertion is not redundant defensive code; it is
// the guard against a future refactor that releases the mutex mid-flow. Keep it.
func (c *ControlPlaneCore) DecideConnection(
	ctx context.Context, in DecideConnectionInput,
) (outcome EnforcementOutcome, found bool, err error) {
	found, err = c.ConnectionCatalog.WithConnection(in.ConnectionID, func(conn *datasource.EnforcementConnection) error {
		outcome, err = c.decideOnConnection(ctx, conn, in)
		return err
	})
	if err != nil {
		return nil, found, err
	}
	return outcome, found, nil
}

func (c *ControlPlaneCore) decideOnConnection(
	ctx context.Context, conn *datasource.EnforcementConnection, in DecideConnectionInput,
) (EnforcementOutcome, error) {
	ds := in.Datasource

	// STEP 1 — the generation at entry. Only an applyPush (which needs the same mutex) can bump it,
	// so it cannot move mid-flow; stamping and re-checking is the connection's compare-and-set.
	generationAtEntry := conn.Generation

	// STEP 2 — required = searchPath minus pg_temp*.
	// ⚠️ F31: this filter is case-INSENSITIVE while A10's editorTempOverlay filter is case-SENSITIVE.
	// The divergence is REPRODUCED, and the resolution stays fail-closed (no fragment AND no overlay
	// row ⇒ the name cannot resolve ⇒ DENY). It is flagged at both call sites so a deliberate Go-side
	// unification is a decision, not a transliteration.
	required := make([]string, 0, len(in.SearchPath))
	for _, s := range in.SearchPath {
		if strings.HasPrefix(strings.ToLower(s), "pg_temp") {
			continue
		}
		required = append(required, s)
	}

	// STEP 3 — pre-gate, BEFORE any analysis and before any audit row.
	if pre := c.ConnectionCatalog.FreshnessGate(conn, required); len(pre) > 0 {
		return OutcomeBeforeDecide{Commands: c.ConnectionCatalog.MarkBeforeDecide(conn, pre)}, nil
	}

	// STEP 4 — catalog segment + live classifications.
	// 🔒 INV-A5-18 — structure (the connection's fragments) and classification (this read) are
	// independently sourced, so a newly-tagged PII column takes effect on the NEXT statement with no
	// proxy round-trip.
	catalogName, err := datasource.CatalogName(ds.Engine, ds.DBName)
	if err != nil {
		return nil, err
	}
	classifications, err := c.DatasourceStore.ClassificationsFor(ctx, ds.ID)
	if err != nil {
		return nil, err
	}

	// STEP 5 — the enforcement catalog is the connection's HELD structure, never the global config
	// catalog. That is the whole point of the per-connection design.
	rows := c.ConnectionCatalog.StructuralRows(conn)
	catalog := make([]datasource.CatalogColumn, 0, len(rows))
	for _, r := range rows {
		col := datasource.CatalogColumn{
			Catalog:  catalogName,
			Schema:   r.Schema,
			Table:    r.Table,
			Column:   r.Column,
			DataType: r.DataType,
			SQLType:  datasource.SQLTypeFor(r.DataType),
			Ordinal:  r.Ordinal,
			Nullable: r.Nullable,
			// 🔒 INV-A5-1 — IsTemp is NEVER set here. Only A10's temp overlay sets it, and A6 reads an
			// IsTemp row UNMASKED without a Cedar grant.
		}
		if cl, ok := classifications[datasource.ColumnKey{Schema: r.Schema, Table: r.Table, Column: r.Column}]; ok {
			found := cl
			col.Classification = &found
		}
		catalog = append(catalog, col)
	}

	// STEP 6 — the latency clock starts here, so it measures the DECISION and not the gates.
	t0 := time.Now()

	// STEP 7 — requesterIp is selected by CHANNEL (INV-A5-52).
	var requesterIP *string
	if in.Channel == query.ChannelWire {
		requesterIP = query.ParseRequesterIp(in.ClientAddr)
	} else {
		requesterIP = in.HTTPRequesterIP
	}

	// STEP 8 — the decision.
	searchPath := in.SearchPath
	decision, err := query.DecideQuery(ctx, query.DecideQueryInput{
		Principal:            in.Principal,
		Datasource:           ds,
		SQL:                  in.SQL,
		Channel:              in.Channel,
		Catalog:              catalog,
		MaskFns:              c.MaskFns,
		UserGroups:           c.UserGroupStore,
		Roles:                c.RoleResolver,
		Authz:                c.Authz,
		ProvidedRoles:        in.ProvidedRoles,
		Context:              authz.AuthzContext{RequesterIP: requesterIP},
		LiveSearchPath:       &searchPath,
		LiveAnsiQuotes:       in.AnsiQuotes,
		SystemClassification: c.SystemClassification,
		TempColumns:          in.TempColumns,
	})
	if err != nil {
		return nil, err
	}

	// STEP 9 — post-gate over the schemas the ANALYZER discovered were touched.
	// 🔒 INV-A5-50 — dropping this lets a statement be authorized against a schema whose structure was
	// never verified (a fully-qualified reference outside the search path).
	if post := c.ConnectionCatalog.FreshnessGate(conn, decision.ReferencedSchemas); len(post) > 0 {
		return OutcomeBeforeDecide{Commands: c.ConnectionCatalog.MarkBeforeDecide(conn, post)}, nil
	}

	// STEP 10 — catalog-miss branch.
	// 🔒 INV-A5-51 — the refetch is BOUNDED by subtracting the held-AND-fresh schemas, so a genuinely
	// absent table cannot ping-pong before_decide forever: the second attempt has nothing left to
	// subtract and falls through to the DENY. The subtraction is ORDER-PRESERVING (Kotlin collects
	// into a LinkedHashSet), so the emitted commands keep schemaCandidates' order.
	if decision.CatalogMiss {
		fresh := map[string]struct{}{}
		for _, s := range c.ConnectionCatalog.HeldAndFreshSchemas(conn) {
			fresh[s] = struct{}{}
		}
		candidates := make([]string, 0, len(decision.SchemaCandidates))
		seen := map[string]struct{}{}
		for _, s := range decision.SchemaCandidates {
			if _, isFresh := fresh[s]; isFresh {
				continue
			}
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			candidates = append(candidates, s)
		}
		if len(candidates) > 0 {
			return OutcomeBeforeDecide{Commands: c.ConnectionCatalog.MarkCatalogMiss(conn, candidates)}, nil
		}
	}

	// STEP 11 — the wire self-approve gate.
	// ⚠️ Note it passes decision.EffectiveRoles (the PRE-override context's roles), and so does step
	// 15's CreateWireTask: wireTaskForbiddenDeny synthesizes a deny context and the task must record
	// the roles actually resolved.
	wireGateDenied := in.Channel == query.ChannelWire &&
		!c.AutoApproveTask(in.Principal, decision.EffectiveRoles, ds, authz.AuthzContext{RequesterIP: requesterIP}, query.ChannelWire)

	// STEP 12 — the effective context.
	effective := decision
	if wireGateDenied {
		effective = query.WireTaskForbiddenDeny(decision.EffectiveRoles, decision.ContextTags)
	}

	// STEP 13 — the after-statement refetch.
	// 🔒 INV-A5-53 — only on a NON-DENY catalog-changing statement. A DENY relayed nothing, so the
	// backend catalog cannot have changed; issuing a command would leave a pending entry gating the
	// NEXT statement for no reason.
	var afterStatement []*pb.Refetch
	if effective.Action != pb.EnfAction_DENY && effective.CatalogChanging {
		afterStatement = c.ConnectionCatalog.MarkAfterStatement(conn, append(append([]string{}, required...), effective.ReferencedSchemas...))
	}

	// STEP 14 — the audit row.
	ms := time.Since(t0).Milliseconds()
	record := query.DecisionRecord(in.Principal, ds, in.SQL, in.ClientAddr, effective, ms, in.SearchPath, in.Channel)

	// STEP 15 — audit + task, channel-dependent.
	var decisionID int64
	if in.Channel == query.ChannelWire {
		// 🔒 INV-A5-54 — the wire decision and its task are written in ONE transaction, so neither
		// record can exist without the other.
		decisionID, err = store.InTx(ctx, c.DB.Pool, func(ctx context.Context, tx pgx.Tx) (int64, error) {
			id, err := c.AuditStore.InsertOn(ctx, tx, record)
			if err != nil {
				return 0, err
			}
			// ⚠️ THE NESTING IS LOAD-BEARING. When wireGateDenied is true, effective.Action IS DENY
			// (that is what wireTaskForbiddenDeny produces), so flattening these two `if`s into
			// siblings would reach the fail-the-task branch with no taskId at all. A wire-gate refusal
			// creates NO task, only the audit row.
			if !wireGateDenied {
				taskID, err := c.AccessStore.CreateWireTask(ctx, tx, in.Principal, ds.ID, decision.EffectiveRoles, id)
				if err != nil {
					return 0, err
				}
				if effective.Action == pb.EnfAction_DENY {
					// A DENY relays nothing and produces no completion, so its task is failed INLINE.
					ok, err := c.AccessStore.ClaimExecutionOn(ctx, tx, taskID)
					if err != nil {
						return 0, err
					}
					if !ok {
						return 0, fmt.Errorf("new wire task %d was not claimable", taskID)
					}
					ok, err = c.AccessStore.MarkFailedOn(ctx, tx, taskID)
					if err != nil {
						return 0, err
					}
					if !ok {
						return 0, fmt.Errorf("wire task %d left EXECUTING", taskID)
					}
				}
			}
			return id, nil
		})
	} else {
		decisionID, err = c.AuditStore.Insert(ctx, record)
	}
	if err != nil {
		return nil, err
	}

	// STEP 16 — the compare-and-set (INV-A5-48).
	if conn.Generation != generationAtEntry {
		return nil, errors.New("connection generation changed during serialized decide")
	}

	// STEP 17.
	return OutcomeVerdict{
		Ctx:            effective,
		DecisionID:     decisionID,
		Generation:     generationAtEntry,
		AfterStatement: afterStatement,
	}, nil
}

// AutoApproveTask is `autoApproveTask(principal, ownRoles, ds, rawCtx, authz, channel)` (A7,
// 07-tasks-approvals-results.md §5) — the shared self-approve gate for EDITOR and WIRE tasks.
//
// 🔒 INV-A7-17 — a self-approved task must clear BOTH lifecycle checks a human request+approve
// would; either Deny fails it closed. `ownRoles` is the request-side snapshot, while the approve side
// re-resolves its own snapshot inside AuthorizeWithContext (A2 INV-A2-10).
//
// 🔒 INV-A7-19 — approver eligibility is a Cedar POLICY, never the datasource's approver group, and
// `requester != approver` comes from the shipped `no-self-approval` forbid rather than app code.
// That is precisely why this function passes requester == approver == principal and lets Cedar decide.
func (c *ControlPlaneCore) AutoApproveTask(
	principal string, ownRoles []string, ds datasource.Datasource, raw authz.AuthzContext, channel query.Channel,
) bool {
	taskCtx := raw
	value := channel.ContextValue()
	taskCtx.Channel = &value
	tags := c.Authz.ResolveContextTags(principal, ownRoles, ds.Name, taskCtx, ds.Tags)

	if !c.Authz.AuthorizeDatasourceAction(
		principal, ownRoles, authz.ActionTaskRequest, ds.Name, taskCtx.WithTags(tags), ds.Tags,
	).Allowed {
		return false
	}
	name := ds.Name
	return c.Authz.AuthorizeWithContext(
		principal,
		authz.ActionTaskApprove,
		authz.ResourceApprovalRequest{Requester: principal, Approver: &principal, DatasourceName: &name},
		taskCtx,
		&name,
		ds.Tags,
	).Allowed
}
