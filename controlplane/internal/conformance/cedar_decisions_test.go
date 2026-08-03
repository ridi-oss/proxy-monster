package conformance

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/authz"
)

// ============================================================================================
// CONTRACT 2b — Cedar DECISIONS, replayed against the frozen cedar-java verdicts.
//
// ORACLE: cedar-spike/corpus/verdicts.json — 90 records / 188 assertions extracted from the Kotlin
// test sources, each carrying the file:line it was frozen from. The corpus README is explicit that
// this is a transcription of ASSERTIONS, not a cedar-java run: "There is no Java runtime on this
// machine ... and no cedar-java jar in ~/.gradle/caches, so nothing here was measured against
// cedar-java." It also records a SECOND, independent oracle for the same expectations — Rust Cedar
// 4.3.3 via cedar-wasm, AGREE 184 / DISAGREE 0 over 186 records — which is what makes the frozen
// assertions worth replaying rather than merely re-reading.
//
// WHAT THIS ADDS OVER internal/authz's OWN SUITE, which already ports these cases by hand:
// there, the expected verdict is TRANSCRIBED INTO GO. Here it is READ FROM THE CORPUS at run time. So
// a corpus regenerated against a newer Kotlin — new policy sources, a changed expectation, a case
// deleted — fails HERE while every hand-ported test stays green. That is the only failure mode a
// hand-ported suite structurally cannot detect, and it is the one that matters during a cutover.
//
// THE ROSTER GATE. Replaying all 90 records would mean re-implementing internal/authz's whole test
// suite, which the brief forbids and which would be duplication rather than coverage. Instead every
// record is given an explicit DISPOSITION by rule (never by a transcribed list of 90 names), the
// per-disposition counts are asserted, and the counts are logged. A record that is added, removed or
// re-kinded therefore lands in a bucket whose count no longer matches, and the suite says so. Nothing
// is silently unexamined.
// ============================================================================================

//go:embed testdata/cedar-verdicts.json
var cedarVerdictsJSON []byte

type verdictAssertion struct {
	Kind     string          `json:"kind"`
	Input    json.RawMessage `json:"input"` // an object of overrides, or a bare label string
	Expected string          `json:"expected"`
}

type verdictRecord struct {
	TestFile   string             `json:"testFile"`
	TestCase   string             `json:"testCase"`
	Kind       string             `json:"kind"`
	Input      json.RawMessage    `json:"input"`
	Provenance string             `json:"provenance"`
	Assertions []verdictAssertion `json:"assertions"`
	Notes      string             `json:"notes"`
}

// File returns the Kotlin test file's basename, which is the family key.
func (r verdictRecord) File() string { return path.Base(r.TestFile) }

type policySet struct {
	Provenance string            `json:"provenance"`
	Policies   map[string]string `json:"policies"`
}

type verdictCorpus struct {
	PolicySets map[string]json.RawMessage `json:"policy_sets"`
	Verdicts   []verdictRecord            `json:"verdicts"`
}

func loadVerdictCorpus(t *testing.T) verdictCorpus {
	t.Helper()
	var c verdictCorpus
	if err := json.Unmarshal(cedarVerdictsJSON, &c); err != nil {
		t.Fatalf("unmarshal vendored cedar-verdicts.json: %v", err)
	}
	return c
}

// ---- dispositions ---------------------------------------------------------------------------

type disposition struct {
	replay bool
	bucket string // the roster line this record is counted on; empty when replayed
	reason string // why NOT replayed; empty when replayed
}

// replayFamilies are the Kotlin suites this package drives from the corpus. Each is a family whose
// records share ONE exported entry point, so the replay is a small interpreter rather than a
// per-case transcription.
var replayFamilies = map[string]string{
	"AuthzTest.kt":                 "Authz.Authorize — System / AuditRecord / AuditLog / Request resources",
	"AuthzDatasourceActionTest.kt": "Authz.AuthorizeDatasourceAction — the two once-per-query gates",
	"ColumnAuthzTest.kt":           "Authz.AuthorizeColumns — the per-column unmasked-then-masked batch",
	"ChannelContextAuthzTest.kt":   "Authz.AuthorizeDatasourceAction under a channel-conditioned context",
}

// skipReasons explains, per Kotlin suite, why its DECISION records are not driven from the corpus.
// Every reason names where the coverage actually lives, so a reader can check rather than trust.
var skipReasons = map[string]string{
	"ElevationContextTagTest.kt": "two-pass tag derivation: the record's inputs (requesterIp, datasourceTags, " +
		"a stateful RoleSource, a null datasourceName) do not share one call shape, so a corpus-driven " +
		"replay would be seven bespoke interpreters. Hand-ported at internal/authz/elevation_context_tag_test.go.",
	"TagResolutionTest.kt": "same two-pass shape, plus records that assert engine-internal counters " +
		"(BuildCount/EvalCount) and the dangling-tag lint rather than a verdict. Hand-ported at " +
		"internal/authz/tag_resolution_test.go.",
	"AdminGateTest.kt": "needs the 29 shipped enabled SYSTEM sources, which the corpus stores as ID LISTS " +
		"(policy_sets.MIGRATION_ENABLED.ids) not as sources. The sources live in the other package's " +
		"fixture, internal/authz/testdata/migration_enabled.json, where the cases are hand-ported at " +
		"internal/authz/admin_gate_test.go.",
	"AdminContextAuthzTest.kt": "the decision half is a plain Authorize, but the INPUT is produced by A12's " +
		"trusted-proxy / X-Forwarded-For resolution, which is not ported yet (TODO(A12) in " +
		"internal/authz/authz.go). Replaying only the Cedar half would assert something the corpus " +
		"record is not about.",
	"CedarPolicyOriginTest.kt": "decision-EQUIVALENCE between the migrated and oracle policy sets — needs both " +
		"sets plus the store, i.e. TODO(A2)'s CedarPolicyStore. DB-backed.",
	"PresetPolicyDbTest.kt": "DB-backed: the preset posture arrives via Flyway and CedarPolicyStore, and the " +
		"records assert whole role MATRICES over it. TODO(A2).",
}

// dispositionOf classifies one record. It is a RULE, deliberately — a transcribed list of 90 case
// names would have to be edited in lockstep with the corpus, which is exactly the coupling this gate
// exists to detect rather than absorb.
func dispositionOf(r verdictRecord) disposition {
	switch r.Kind {
	case "not_cedar":
		return disposition{
			bucket: "not a Cedar decision",
			reason: "not a Cedar decision (store / route / engine-counter behaviour)",
		}
	case "validate_accept", "validate_reject":
		return disposition{
			bucket: "policy VALIDATION",
			reason: "policy VALIDATION — every source is replayed in cedar_policies_test.go",
		}
	}
	if _, ok := replayFamilies[r.File()]; ok {
		return disposition{replay: true}
	}
	if reason, ok := skipReasons[r.File()]; ok {
		return disposition{bucket: strings.TrimSuffix(r.File(), ".kt"), reason: reason}
	}
	return disposition{bucket: "UNCLASSIFIED", reason: "UNCLASSIFIED"}
}

// TestVerdictCorpusRosterIsAccountedFor is the gate. Every record has a disposition, the counts are
// pinned, and an unclassified record is a hard failure.
func TestVerdictCorpusRosterIsAccountedFor(t *testing.T) {
	c := loadVerdictCorpus(t)
	if len(c.Verdicts) != 90 {
		t.Fatalf("corpus has %d verdict records, want 90", len(c.Verdicts))
	}

	counts := map[string]int{}
	replayed := 0
	for _, r := range c.Verdicts {
		d := dispositionOf(r)
		if d.replay {
			replayed++
			continue
		}
		if d.bucket == "UNCLASSIFIED" {
			t.Errorf("UNCLASSIFIED record %s / %q (kind %s). A new record must be given a disposition — "+
				"either replay it or record why not.", r.File(), r.TestCase, r.Kind)
		}
		counts[d.bucket]++
	}

	want := map[string]int{
		"not a Cedar decision":    26,
		"policy VALIDATION":       9,
		"ElevationContextTagTest": 6,
		"TagResolutionTest":       7,
		"AdminGateTest":           2,
		"AdminContextAuthzTest":   2,
		"CedarPolicyOriginTest":   1,
		"PresetPolicyDbTest":      4,
	}
	for k, v := range want {
		if counts[k] != v {
			t.Errorf("disposition %q = %d records, want %d", k, counts[k], v)
		}
	}
	for k, v := range counts {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected disposition bucket %q (%d records)", k, v)
		}
	}
	if replayed != 33 {
		t.Errorf("replayed records = %d, want 33", replayed)
	}

	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "verdict corpus roster: %d records — %d REPLAYED here", len(c.Verdicts), replayed)
	for _, k := range keys {
		fmt.Fprintf(&b, ", %d %s", counts[k], k)
	}
	t.Log(b.String())
}

// TestEverySkipReasonIsAttachedToRecordsThatExist keeps the skip table honest in the other direction.
//
// A reason left behind after its records were replayed or deleted is dead documentation that reads
// as live coverage accounting, which is the failure mode this whole roster exists to prevent.
func TestEverySkipReasonIsAttachedToRecordsThatExist(t *testing.T) {
	c := loadVerdictCorpus(t)
	seen := map[string]bool{}
	for _, r := range c.Verdicts {
		seen[r.File()] = true
	}
	for file := range skipReasons {
		if !seen[file] {
			t.Errorf("skipReasons names %s, which no longer appears in the corpus", file)
		}
	}
	for file := range replayFamilies {
		if !seen[file] {
			t.Errorf("replayFamilies names %s, which no longer appears in the corpus", file)
		}
		if _, both := skipReasons[file]; both {
			t.Errorf("%s is listed as BOTH a replay family and a skip", file)
		}
	}
}

// ---- the replay -----------------------------------------------------------------------------

// decisionInput is the merged view of a record's top-level `input` and one assertion's `input`. The
// corpus omits from an assertion whatever it inherits from the record, so an override is nil-checked
// rather than compared: absent means "keep the record's value".
type decisionInput struct {
	Policies        json.RawMessage   `json:"policies"`
	Roles           json.RawMessage   `json:"roles"` // map[principal][]role in AuthzTest; []role elsewhere
	Principal       *string           `json:"principal"`
	Action          *string           `json:"action"`
	Actions         []string          `json:"actions"`
	Resource        *string           `json:"resource"`
	ResourceParents []string          `json:"resource_parents"`
	Attrs           map[string]string `json:"attrs"`
	Datasource      *string           `json:"datasource"`
	DatasourceTags  []string          `json:"datasourceTags"`
	Columns         []corpusColumn    `json:"columns"`
	Context         *corpusContext    `json:"context"`
}

type corpusColumn struct {
	Key     string   `json:"key"`
	Catalog string   `json:"catalog"`
	Schema  string   `json:"schema"`
	Table   string   `json:"table"`
	Column  string   `json:"column"`
	Tags    []string `json:"tags"`
}

// corpusContext mirrors the Cedar context map the corpus records. `channel` is a POINTER because
// ABSENCE is the assertion in ChannelContextAuthzTest case 3 (INV-A2-8) — a missing key and an empty
// string are different requests and only one of them is what the Kotlin sent.
type corpusContext struct {
	Channel      *string  `json:"channel"`
	NetworkZones []string `json:"network_zones"`
	Tags         []string `json:"tags"`
	RequesterIP  *string  `json:"requester_ip"`
}

func (c *corpusContext) toAuthzContext() authz.AuthzContext {
	if c == nil {
		return authz.AuthzContext{}
	}
	return authz.AuthzContext{
		NetworkZones: c.NetworkZones,
		Channel:      c.Channel,
		RequesterIP:  c.RequesterIP,
		Tags:         c.Tags,
	}
}

// mergeAssertion overlays an assertion's override object onto the record's input. A bare-string
// assertion input is a human label and overrides nothing.
func mergeAssertion(t *testing.T, base decisionInput, raw json.RawMessage) decisionInput {
	t.Helper()
	if len(raw) == 0 || raw[0] != '{' {
		return base
	}
	var over decisionInput
	if err := json.Unmarshal(raw, &over); err != nil {
		t.Fatalf("assertion input: %v", err)
	}
	out := base
	if over.Principal != nil {
		out.Principal = over.Principal
	}
	if over.Action != nil {
		out.Action = over.Action
	}
	if over.Resource != nil {
		out.Resource = over.Resource
		// A new resource brings its own parents and attrs; inheriting the previous resource's would
		// silently attach the wrong Role/Datasource parent. Reset, then take the override's.
		out.ResourceParents = over.ResourceParents
		out.Attrs = over.Attrs
	} else {
		if over.ResourceParents != nil {
			out.ResourceParents = over.ResourceParents
		}
		if over.Attrs != nil {
			out.Attrs = over.Attrs
		}
	}
	if over.Datasource != nil {
		out.Datasource = over.Datasource
	}
	if over.DatasourceTags != nil {
		out.DatasourceTags = over.DatasourceTags
	}
	if over.Context != nil {
		out.Context = over.Context
	}
	return out
}

// resolvePolicies turns the record's `policies` field into an engine.
//
// The field is either a NAME into policy_sets or an inline {id: source} map. Both forms appear, and
// the named form is how several records share one fixture — which is itself part of what is being
// replayed, since the Kotlin suites share the same seedPolicies across cases.
func resolvePolicies(t *testing.T, c verdictCorpus, raw json.RawMessage) map[int64]string {
	t.Helper()
	var name string
	if err := json.Unmarshal(raw, &name); err == nil {
		set, ok := c.PolicySets[name]
		if !ok {
			t.Fatalf("policy set %q not in the corpus", name)
		}
		var ps policySet
		if err := json.Unmarshal(set, &ps); err != nil {
			t.Fatalf("policy set %q: %v", name, err)
		}
		return toIDMap(t, ps.Policies)
	}
	var inline map[string]string
	if err := json.Unmarshal(raw, &inline); err != nil {
		t.Fatalf("policies field is neither a name nor an {id: source} map: %s", raw)
	}
	return toIDMap(t, inline)
}

func toIDMap(t *testing.T, m map[string]string) map[int64]string {
	t.Helper()
	out := map[int64]string{}
	for k, v := range m {
		var id int64
		if _, err := fmt.Sscanf(k, "%d", &id); err != nil {
			t.Fatalf("policy id %q is not numeric", k)
		}
		out[id] = v
	}
	return out
}

// engineFrom builds a CedarEngine over the resolved sources, in ascending id order — the order
// CedarPolicyStore.enabledSources() returns and therefore the order the PolicySet is built in.
//
// 🔒 Construction VALIDATES every source (INV-A2-17), so this failing is itself a conformance result:
// it would mean cedar-go rejects a policy the Kotlin loads.
func engineFrom(t *testing.T, policies map[int64]string) *authz.CedarEngine {
	t.Helper()
	ids := make([]int64, 0, len(policies))
	for id := range policies {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	sources := make([]authz.PolicySource, 0, len(ids))
	for _, id := range ids {
		sources = append(sources, authz.PolicySource{ID: id, Src: policies[id]})
	}
	e, err := authz.NewCedarEngineFromSources(sources)
	if err != nil {
		t.Fatalf("CedarEngine construction failed on a policy set the Kotlin loads: %v", err)
	}
	return e
}

// parseResource turns the corpus's Cedar EUID string plus its attrs/parents into the typed
// AuthzResource the exported API takes.
//
// 02-authz.md §3's EUID table is the marshalling contract, and this is its inverse. Request is the
// interesting one: its EUID is "<requester>#<datasourceName or '-'>", its `requester` / `approver` /
// `executedBy` attributes are User EUIDs, and its Role / Datasource PARENTS are what a
// `resource in Role::"..."` scoped policy matches — the corpus records all three separately because
// all three are separately load-bearing.
func parseResource(t *testing.T, euid string, attrs map[string]string, parents []string) authz.AuthzResource {
	t.Helper()
	typ, id := splitEUID(t, euid)
	switch typ {
	case "System":
		return authz.ResourceSystem{}
	case "AuditLog":
		return authz.ResourceAuditLog{}
	case "AuditRecord":
		return authz.ResourceAuditRecord{Principal: id}
	case "Request":
		req := authz.ResourceApprovalRequest{Requester: strings.SplitN(id, "#", 2)[0]}
		if parts := strings.SplitN(id, "#", 2); len(parts) == 2 && parts[1] != "-" {
			ds := parts[1]
			req.DatasourceName = &ds
		}
		if v, ok := attrs["requester"]; ok {
			req.Requester = userIDOf(t, v)
		}
		if v, ok := attrs["approver"]; ok {
			a := userIDOf(t, v)
			req.Approver = &a
		}
		if v, ok := attrs["executedBy"]; ok {
			e := userIDOf(t, v)
			req.ExecutedBy = &e
		}
		for _, p := range parents {
			ptyp, pid := splitEUID(t, p)
			switch ptyp {
			case "Role":
				r := pid
				req.RoleName = &r
			case "Datasource":
				d := pid
				req.DatasourceName = &d
			default:
				t.Fatalf("unsupported Request parent type %q in %s", ptyp, p)
			}
		}
		return req
	default:
		t.Fatalf("unsupported resource type %q (corpus EUID %s)", typ, euid)
		return nil
	}
}

// splitEUID parses `Type::"id"`.
func splitEUID(t *testing.T, euid string) (string, string) {
	t.Helper()
	i := strings.Index(euid, `::"`)
	if i < 0 || !strings.HasSuffix(euid, `"`) {
		t.Fatalf("malformed EUID %q", euid)
	}
	return euid[:i], euid[i+3 : len(euid)-1]
}

func userIDOf(t *testing.T, euid string) string {
	t.Helper()
	typ, id := splitEUID(t, euid)
	if typ != "User" {
		t.Fatalf("expected a User EUID, got %q", euid)
	}
	return id
}

// TestReplayAuthzTestDecisions drives the 12 AuthzTest decision records through Authz.Authorize.
//
// The suite covers the admin gate, the audit two-tier read model, and the whole approval-authority
// shape — including 🔒 AuthzTest case 6, the self-approval hole. That case is why toAuthzDecision is
// ERRORS-FIRST: replayed against the shipped set with the Request entity omitted, the
// no-self-approval FORBID errors out, cedar-go DROPS it, and the system:admin PERMIT stands. A
// verdict-first mapping would let a system-admin approve their own request and would pass every other
// case in this file.
func TestReplayAuthzTestDecisions(t *testing.T) {
	c := loadVerdictCorpus(t)
	agree, disagree, records := 0, 0, 0

	for _, r := range c.Verdicts {
		if r.File() != "AuthzTest.kt" || !dispositionOf(r).replay {
			continue
		}
		records++
		t.Run(safeName(r.TestCase), func(t *testing.T) {
			var base decisionInput
			if err := json.Unmarshal(r.Input, &base); err != nil {
				t.Fatalf("record input: %v", err)
			}
			roleMap := map[string][]string{}
			if len(base.Roles) > 0 {
				if err := json.Unmarshal(base.Roles, &roleMap); err != nil {
					t.Fatalf("roles is not a principal -> roles map: %s", base.Roles)
				}
			}
			a := authz.New(engineFrom(t, resolvePolicies(t, c, base.Policies)), nil,
				authz.RoleSourceFunc(func(p string) []string { return roleMap[p] }))

			for i, as := range r.Assertions {
				want, ok := wantAllow(as.Kind)
				if !ok {
					continue // validate_* / not_cedar assertions inside a decision record
				}
				in := mergeAssertion(t, base, as.Input)

				// `actions` (plural) means the same principal/resource across several actions, one
				// assertion each — the corpus keeps them in order.
				action := ""
				switch {
				case in.Action != nil:
					action = *in.Action
				case len(base.Actions) > 0:
					var idx int
					for j := 0; j < i; j++ {
						if _, isDecision := wantAllow(r.Assertions[j].Kind); isDecision {
							idx++
						}
					}
					if idx < len(base.Actions) {
						action = base.Actions[idx]
					}
				}
				if action == "" {
					t.Fatalf("assertion %d has no action", i)
				}
				if in.Principal == nil {
					t.Fatalf("assertion %d has no principal", i)
				}
				if in.Resource == nil {
					t.Fatalf("assertion %d has no resource", i)
				}

				res := parseResource(t, *in.Resource, in.Attrs, in.ResourceParents)
				got := a.Authorize(*in.Principal, authz.AuthzAction(action), res, in.Context.toAuthzContext())

				if got.Allowed == want {
					agree++
				} else {
					disagree++
					t.Errorf("DISAGREE — cedar-java says %s, cedar-go says %s\n"+
						"  principal:  %s\n  action:     %s\n  resource:   %s\n  reason:     %s\n"+
						"  provenance: %s",
						allowWord(want), allowWord(got.Allowed), *in.Principal, action, *in.Resource,
						got.Reason, r.Provenance)
				}
			}
		})
	}

	t.Logf("AuthzTest decisions: %d records, AGREE %d / DISAGREE %d assertions", records, agree, disagree)
	if records != 12 {
		t.Errorf("replayed %d AuthzTest decision records, want 12", records)
	}
	// 22 is the count of decision_allow / decision_deny assertions across the 12 records; the pin
	// catches a corpus that grew or lost assertions inside a record it already had, which the roster
	// gate (which counts RECORDS) cannot see.
	if agree != 22 || disagree != 0 {
		t.Errorf("expected AGREE 22 / DISAGREE 0; got %d / %d", agree, disagree)
	}
}

// TestReplayDatasourceActionDecisions drives AuthzDatasourceActionTest through
// Authz.AuthorizeDatasourceAction — the two once-per-query gates.
//
// 🔒 INV-A2-2 — the Datasource resource is keyed by NAME, not numeric id, and this path deliberately
// does NOT route through Authorize/marshalResource. Case 5 ("the same grant on a different datasource
// name does not apply") is the one that fails if a port ever keys it off the id.
//
// Case 3 also exercises the posture-tag path: `sql.unmaskable` is permitted only when the datasource
// carries system:development, which reaches Cedar as a Tag PARENT of the Datasource entity
// (INV-A2-7 — posture tags are TYPE-SCOPED to Datasource and are the only datasource tags marshalled).
func TestReplayDatasourceActionDecisions(t *testing.T) {
	c := loadVerdictCorpus(t)
	agree, disagree, records := 0, 0, 0

	for _, r := range c.Verdicts {
		if r.File() != "AuthzDatasourceActionTest.kt" || !dispositionOf(r).replay {
			continue
		}
		records++
		t.Run(safeName(r.TestCase), func(t *testing.T) {
			var base decisionInput
			if err := json.Unmarshal(r.Input, &base); err != nil {
				t.Fatalf("record input: %v", err)
			}
			roles := rolesList(t, base.Roles)
			a := authz.New(engineFrom(t, resolvePolicies(t, c, base.Policies)), nil, authz.RoleSourceFunc(
				func(string) []string { return roles }))

			for i, as := range r.Assertions {
				want, ok := wantAllow(as.Kind)
				if !ok {
					continue
				}
				in := mergeAssertion(t, base, as.Input)
				if in.Principal == nil || in.Action == nil || in.Datasource == nil {
					t.Fatalf("assertion %d is missing principal/action/datasource", i)
				}
				got := a.AuthorizeDatasourceAction(*in.Principal, roles, authz.AuthzAction(*in.Action),
					*in.Datasource, in.Context.toAuthzContext(), in.DatasourceTags)

				if got.Allowed == want {
					agree++
				} else {
					disagree++
					t.Errorf("DISAGREE — cedar-java says %s, cedar-go says %s\n"+
						"  principal: %s  roles: %v\n  action:    %s\n  datasource: %s  tags: %v\n"+
						"  reason:    %s\n  provenance: %s",
						allowWord(want), allowWord(got.Allowed), *in.Principal, roles, *in.Action,
						*in.Datasource, in.DatasourceTags, got.Reason, r.Provenance)
				}
			}
		})
	}

	t.Logf("AuthzDatasourceActionTest: %d records, AGREE %d / DISAGREE %d assertions", records, agree, disagree)
	if records != 6 {
		t.Errorf("replayed %d datasource-action records, want 6", records)
	}
	if agree != 7 || disagree != 0 {
		t.Errorf("expected AGREE 7 / DISAGREE 0; got %d / %d", agree, disagree)
	}
}

// TestReplayColumnAuthzDecisions drives ColumnAuthzTest through Authz.AuthorizeColumns.
//
// The corpus records the FINAL per-column verdict as UNMASKED / MASKED / DENIED, which is exactly
// what ColumnVerdict.String() renders, so the comparison is against the Kotlin's own vocabulary
// rather than a re-encoding of it.
//
// 🔒 INV-A2-5 — every input column gets an explicit verdict; there is no "absent = allow". The map
// returned must have one entry per input key, and that is asserted here as well as the verdicts.
//
// 🔒 INV-A2-6 — case 3 is the delimiter guard, and the corpus flags it: "The two DENIED verdicts are
// decided BEFORE Cedar — a Go harness must reproduce the guard, not the engine, for these two." An
// identity containing '/' or '.' builds NO EUID and is denied without ever reaching the engine, which
// is what keeps the slash-joined EUID injective.
func TestReplayColumnAuthzDecisions(t *testing.T) {
	c := loadVerdictCorpus(t)
	agree, disagree, records := 0, 0, 0

	for _, r := range c.Verdicts {
		if r.File() != "ColumnAuthzTest.kt" || !dispositionOf(r).replay {
			continue
		}
		records++
		t.Run(safeName(r.TestCase), func(t *testing.T) {
			var base decisionInput
			if err := json.Unmarshal(r.Input, &base); err != nil {
				t.Fatalf("record input: %v", err)
			}
			roles := rolesList(t, base.Roles)
			a := authz.New(engineFrom(t, resolvePolicies(t, c, base.Policies)), nil, authz.RoleSourceFunc(
				func(string) []string { return roles }))

			cols := make([]authz.ColumnRef, 0, len(base.Columns))
			for _, col := range base.Columns {
				cols = append(cols, authz.ColumnRef{
					Key: col.Key, Catalog: col.Catalog, Schema: col.Schema,
					Table: col.Table, Column: col.Column, Tags: col.Tags,
				})
			}
			if base.Principal == nil || base.Datasource == nil {
				t.Fatal("record is missing principal/datasource")
			}

			verdicts := a.AuthorizeColumns(*base.Principal, roles, *base.Datasource, cols,
				base.Context.toAuthzContext(), nil, base.DatasourceTags)

			if len(verdicts) != len(cols) {
				t.Fatalf("INV-A2-5: %d verdicts for %d columns — every input must get one",
					len(verdicts), len(cols))
			}

			// The per-column expectations are the assertion `expected` values that name a verdict, in
			// column order. Assertions whose expected is prose (e.g. "not allowed", describing the
			// losing half of the unmasked-then-masked pair) are commentary on HOW the verdict was
			// reached, not the verdict.
			wants := make([]string, 0, len(cols))
			for _, as := range r.Assertions {
				switch as.Expected {
				case "UNMASKED", "MASKED", "DENIED":
					wants = append(wants, as.Expected)
				}
			}
			if len(wants) != len(cols) {
				t.Fatalf("corpus gives %d verdict expectations for %d columns (%s)",
					len(wants), len(cols), r.Provenance)
			}

			for i, col := range cols {
				got := verdicts[col.Key].String()
				if got == wants[i] {
					agree++
				} else {
					disagree++
					t.Errorf("DISAGREE on column %q — cedar-java says %s, cedar-go says %s\n"+
						"  identity:   %s.%s.%s.%s  tags %v\n  datasource: %s\n  provenance: %s",
						col.Key, wants[i], got, col.Catalog, col.Schema, col.Table, col.Column,
						col.Tags, *base.Datasource, r.Provenance)
				}
			}
		})
	}

	t.Logf("ColumnAuthzTest: %d records, AGREE %d / DISAGREE %d column verdicts", records, agree, disagree)
	if records != 11 {
		t.Errorf("replayed %d column records, want 11", records)
	}
	if agree != 15 || disagree != 0 {
		t.Errorf("expected AGREE 15 / DISAGREE 0; got %d / %d", agree, disagree)
	}
}

// channelFamilyDefaults are the principal / roles / action / datasource ChannelContextAuthzTest cases
// 2 and 3 INHERIT from case 1.
//
// The corpus omits them from those two records because the Kotlin file declares them once for the
// suite (ChannelContextAuthzTest.kt:30-36, the wireOnlyConnect fixture). They are written here rather
// than guessed: case 1's record carries all four explicitly, and this test asserts that these values
// ARE case 1's before using them anywhere else.
var channelFamilyDefaults = struct {
	principal, action, datasource string
	roles                         []string
}{principal: "alice", action: "datasource.connect", datasource: "acme-mysql", roles: []string{"wire-only"}}

// TestReplayChannelContextDecisions drives ChannelContextAuthzTest.
//
// 🔒 INV-A2-8 — optional-attribute ABSENCE is the fail-closed signal, and case 3 is the one that
// proves it. The channel key is OMITTED from the Cedar context map, not set to "": a policy guarded
// with `context has channel` simply does not fire, which denies. That is why AuthzContext.Channel is
// a *string — a plain string's zero value would be emitted as a present-but-empty channel, a
// different request from the one the Kotlin sends.
//
// Case 4 is a construction_throws record: an UNGUARDED optional-attribute read must be rejected by
// the strict validator, so the engine refuses to build (INV-A2-17, fail fast at startup). It is the
// cleanest single probe for whether cedar-go's strict validator matches cedar-java's on optional
// attributes, and it is replayed here as an engine-construction failure rather than as a verdict.
func TestReplayChannelContextDecisions(t *testing.T) {
	c := loadVerdictCorpus(t)
	agree, disagree, records, constructionChecks := 0, 0, 0, 0

	for _, r := range c.Verdicts {
		if r.File() != "ChannelContextAuthzTest.kt" || !dispositionOf(r).replay {
			continue
		}
		records++
		t.Run(safeName(r.TestCase), func(t *testing.T) {
			var base decisionInput
			if err := json.Unmarshal(r.Input, &base); err != nil {
				t.Fatalf("record input: %v", err)
			}

			if r.Kind == "construction_throws" {
				constructionChecks++
				policies := resolvePolicies(t, c, base.Policies)
				var sources []authz.PolicySource
				for id, src := range policies {
					sources = append(sources, authz.PolicySource{ID: id, Src: src})
				}
				if _, err := authz.NewCedarEngineFromSources(sources); err == nil {
					t.Errorf("DISAGREE — the Kotlin throws at engine construction, cedar-go accepted the "+
						"policy set\n  provenance: %s", r.Provenance)
					disagree++
				} else {
					agree++
				}
				return
			}

			// Cases 2 and 3 inherit the suite fixture; case 1 states it.
			principal, action, datasource := channelFamilyDefaults.principal,
				channelFamilyDefaults.action, channelFamilyDefaults.datasource
			roles := channelFamilyDefaults.roles
			if base.Principal != nil {
				if *base.Principal != principal {
					t.Fatalf("record states principal %q but the family default is %q — the default is "+
						"no longer derived from case 1", *base.Principal, principal)
				}
			}
			if base.Action != nil && *base.Action != action {
				t.Fatalf("record states action %q, family default %q", *base.Action, action)
			}
			if base.Datasource != nil && *base.Datasource != datasource {
				t.Fatalf("record states datasource %q, family default %q", *base.Datasource, datasource)
			}
			if len(base.Roles) > 0 {
				got := rolesList(t, base.Roles)
				if strings.Join(got, ",") != strings.Join(roles, ",") {
					t.Fatalf("record states roles %v, family default %v", got, roles)
				}
			}

			a := authz.New(engineFrom(t, resolvePolicies(t, c, base.Policies)), nil, authz.RoleSourceFunc(
				func(string) []string { return roles }))

			for i, as := range r.Assertions {
				want, ok := wantAllow(as.Kind)
				if !ok {
					continue
				}
				in := mergeAssertion(t, base, as.Input)
				ctx := in.Context.toAuthzContext()

				// INV-A2-8, asserted on the MARSHALLING and not only on the verdict: a nil Channel must
				// leave the key absent. A verdict-only assertion would also pass for an implementation
				// that emitted channel:"" against this policy, which denies for the wrong reason.
				if _, present := ctx.ToCedarMap(true).Get("channel"); present != (ctx.Channel != nil) {
					t.Errorf("assertion %d: `channel` key present=%v but Channel pointer non-nil=%v",
						i, present, ctx.Channel != nil)
				}

				got := a.AuthorizeDatasourceAction(principal, roles, authz.AuthzAction(action),
					datasource, ctx, in.DatasourceTags)
				if got.Allowed == want {
					agree++
				} else {
					disagree++
					t.Errorf("DISAGREE — cedar-java says %s, cedar-go says %s\n"+
						"  channel:    %v\n  reason:     %s\n  provenance: %s",
						allowWord(want), allowWord(got.Allowed), derefOr(ctx.Channel, "<absent>"),
						got.Reason, r.Provenance)
				}
			}
		})
	}

	t.Logf("ChannelContextAuthzTest: %d records, AGREE %d / DISAGREE %d (incl. %d construction check)",
		records, agree, disagree, constructionChecks)
	if records != 4 {
		t.Errorf("replayed %d channel-context records, want 4", records)
	}
	if agree != 4 || disagree != 0 {
		t.Errorf("expected AGREE 4 / DISAGREE 0; got %d / %d", agree, disagree)
	}
}

// ---- small helpers ---------------------------------------------------------------------------

// wantAllow maps an assertion kind to the expected verdict. The second result is false for the
// non-decision kinds the corpus mixes into decision records (validate_*, not_cedar).
func wantAllow(kind string) (bool, bool) {
	switch kind {
	case "decision_allow":
		return true, true
	case "decision_deny":
		return false, true
	default:
		return false, false
	}
}

func allowWord(b bool) string {
	if b {
		return "Allow"
	}
	return "Deny"
}

// rolesList decodes the `roles` field in its LIST form (the batch-path suites pass an explicit,
// already-resolved role set rather than a RoleSource map).
func rolesList(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	if len(raw) == 0 {
		return nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("roles is not a list: %s", raw)
	}
	return out
}

func derefOr(p *string, fallback string) string {
	if p == nil {
		return fallback
	}
	return *p
}

// safeName turns a Kotlin test-case sentence into a subtest name Go will not mangle further than
// necessary. The case name is kept VERBATIM apart from spacing so a failure can be grepped straight
// into the Kotlin source.
func safeName(s string) string {
	return strings.ReplaceAll(s, " ", "_")
}
