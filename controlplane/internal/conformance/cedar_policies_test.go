package conformance

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/authz"
)

// ============================================================================================
// CONTRACT 2a — Cedar POLICY VALIDATION, over the whole repo's policy corpus.
//
// ORACLE: cedar-spike/corpus/policies.json, vendored below. Its README states the constraint this
// package works under verbatim: "The oracle is the Kotlin test suite's frozen assertions, not a live
// cedar-java run. There is no Java runtime on this machine ... Every claim about cedar-java behaviour
// is cited either to a test assertion or to a source comment." Each record carries its own
// `expected_validate_evidence` naming the Kotlin file:line that froze it — e.g. the 10 `reject`
// records cite CedarPolicyStoreTest.kt:108/120/138, ChannelContextAuthzTest.kt:81,
// TagResolutionTest.kt:117 and AuthzTest.kt:240-249.
//
// WHY VENDORED: the corpus was built into a scratchpad under /private/tmp, which is ephemeral. A
// conformance suite that silently starts skipping when a tmp directory is reaped is worse than no
// suite. The two JSON files are copied verbatim (sha256 f0275053…6f2ef4 for policies.json and
// c9b07164…8b872b for verdicts.json at copy time) into testdata/, which is also the pattern
// internal/authz already established with testdata/migration_enabled.json.
//
// WHAT IT PROVES: cedar-go v1.8.0's STRICT VALIDATOR agrees with cedar-java 4.3.1's on every policy
// source that exists anywhere in this repo — shipped SYSTEM rows, test fixtures, and the deliberately
// malformed ones. That is the single question 02-authz.md calls the highest risk in the port ("the
// only area whose behaviour depends on a third-party policy engine whose Go implementation is not
// feature-matched with the JVM one"), asked against the real corpus rather than a sample.
// ============================================================================================

//go:embed testdata/cedar-policies.json
var cedarPoliciesJSON []byte

// policyRecord is one row of the corpus. Field names are the corpus's, not Go's.
type policyRecord struct {
	ID               *int64   `json:"id"`
	Origin           string   `json:"origin"`     // SYSTEM | TEST
	SystemKey        *string  `json:"system_key"` //nolint:unused // provenance, not asserted
	Name             *string  `json:"name"`
	Enabled          bool     `json:"enabled"`
	Source           string   `json:"source"`
	Provenance       string   `json:"provenance"`
	Templated        bool     `json:"templated"`
	TemplateVars     []string `json:"template_vars"`
	ExpandedFrom     *string  `json:"expanded_from"`
	ExpectedValidate string   `json:"expected_validate"` // accept | accept-after-substitution | reject | not-reached
	ExpectedEvidence string   `json:"expected_validate_evidence"`
}

func loadPolicyCorpus(t *testing.T) []policyRecord {
	t.Helper()
	var recs []policyRecord
	if err := json.Unmarshal(cedarPoliciesJSON, &recs); err != nil {
		t.Fatalf("unmarshal vendored cedar-policies.json: %v", err)
	}
	return recs
}

// templateSubstitutions resolves the Kotlin string interpolations the corpus preserved verbatim.
//
// 62 of the 186 records are `templated`: their source carries a Kotlin `$var` / `${expr}` whose value
// came from a live DB row at test time, so the corpus records the UNRESOLVED text plus
// expected_validate = "accept-after-substitution". Substituting is therefore part of replaying them,
// not a liberty taken with them.
//
// Almost every variable sits INSIDE a Cedar string literal — Role::"$roleName", Table::"$usersEuid",
// Datasource::"${ds.name}" — where Cedar accepts any string as an entity id, so the substituted value
// is arbitrary and only has to be stable. Two do not, and those are the ones that carry meaning:
//
//   - $kindActions expands into `action in [$kindActions]`, an ACTION EUID LIST. It must become an
//     EUID expression, not a bare identifier, or the policy fails to PARSE and the record would look
//     like a validator disagreement when it is a substitution bug.
//   - $action expands into `Action::"$action"`, and the Cedar schema validates action NAMES. The
//     substituted value therefore decides the answer, which makes this record ambiguous — see
//     TestPolicyCorpusValidationAgreement's note on it and the finding in the return.
var templateSubstitutions = map[string]string{
	// datasource names
	"${ds.name}":                     "conformance-ds",
	"${fx.datasource.name}":          "conformance-ds",
	"${fixture.datasource.name}":     "conformance-ds",
	"${datasource.name}":             "conformance-ds",
	"${enforcement.datasource.name}": "conformance-ds",
	"$datasourceName":                "conformance-ds",
	// role names
	"${enforcement.role}": "conformance-role",
	"$roleName":           "conformance-role",
	"$ROLE":               "conformance-role",
	"$role":               "conformance-role",
	// user principals
	"$requester": "conformance-user",
	"$caller":    "conformance-user",
	// table entity ids (catalog.schema.table, the shape Authz marshals)
	"$usersTableEuid":     "conformance-ds.public.users",
	"$usersEuid":          "conformance-ds.public.users",
	"$defaultTableEuid":   "conformance-ds.public.t",
	"$analyticsTableEuid": "conformance-ds.analytics.t",
	"$safeTable":          "conformance-ds.public.safe",
	"$table":              "conformance-ds.public.t",
	// the two that are NOT plain identifiers
	"$kindActions": `Action::"sql.select"`,
	"$action":      "sql.select",
}

// substitute replaces every template variable, LONGEST FIRST.
//
// The order is load-bearing: "$role" is a prefix of "$roleName", so a shortest-first pass would turn
// `Role::"$roleName"` into `Role::"conformance-roleName"` and silently change what is being tested.
func substitute(src string) (string, []string) {
	keys := make([]string, 0, len(templateSubstitutions))
	for k := range templateSubstitutions {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	var used []string
	out := src
	for _, k := range keys {
		if strings.Contains(out, k) {
			used = append(used, k)
			out = strings.ReplaceAll(out, k, templateSubstitutions[k])
		}
	}
	return out, used
}

// TestPolicyCorpusShapeIsUnchanged is the roster gate on the corpus itself.
//
// Every count below is a fact about the vendored file. If one moves, the corpus was regenerated or
// edited, and the agreement numbers reported by the next test are no longer comparable with the ones
// in this suite's history — which is exactly when a reviewer needs to be told, rather than reading a
// green run and assuming nothing changed.
func TestPolicyCorpusShapeIsUnchanged(t *testing.T) {
	recs := loadPolicyCorpus(t)
	if len(recs) != 186 {
		t.Fatalf("corpus has %d policy records, want 186", len(recs))
	}

	byExpectation := map[string]int{}
	byOrigin := map[string]int{}
	templated, enabled, expanded := 0, 0, 0
	for _, r := range recs {
		byExpectation[r.ExpectedValidate]++
		byOrigin[r.Origin]++
		if r.Templated {
			templated++
		}
		if r.Enabled {
			enabled++
		}
		if r.ExpandedFrom != nil {
			expanded++
		}
	}

	for what, got := range map[string]struct{ got, want int }{
		"expected_validate=accept":                    {byExpectation["accept"], 112},
		"expected_validate=accept-after-substitution": {byExpectation["accept-after-substitution"], 62},
		"expected_validate=reject":                    {byExpectation["reject"], 10},
		"expected_validate=not-reached":               {byExpectation["not-reached"], 2},
		"origin=SYSTEM":                               {byOrigin["SYSTEM"], 40},
		"origin=TEST":                                 {byOrigin["TEST"], 146},
		"templated":                                   {templated, 62},
		"enabled":                                     {enabled, 173},
		"expanded_from":                               {expanded, 5},
	} {
		if got.got != got.want {
			t.Errorf("corpus %s = %d, want %d", what, got.got, got.want)
		}
	}

	// Every record must carry its evidence. A record with no provenance is an assertion with no
	// oracle, which in this package is the same as no assertion at all.
	for i, r := range recs {
		if strings.TrimSpace(r.Provenance) == "" {
			t.Errorf("record %d (%s) has no provenance", i, r.Source)
		}
		if strings.TrimSpace(r.ExpectedEvidence) == "" {
			t.Errorf("record %d (%s) has no expected_validate_evidence", i, r.Source)
		}
	}
}

// TestPolicyCorpusValidationAgreement is the headline assertion: every one of the 186 records,
// replayed through authz.DefaultSchema.Validate, must land where the Kotlin says it lands.
//
// AGREE / DISAGREE counts are LOGGED unconditionally so a passing run still reports its coverage —
// "184 agree, 0 disagree, 2 not-reached" is information; a bare PASS is not.
//
// ⚠️ ONE RECORD IS AMBIGUOUS IN THE CORPUS, and it is called out rather than quietly resolved.
// `permit(principal, action == Action::"$action", resource);` (AuthzTest.kt:245) is recorded as
// accept-after-substitution, but the five records the corpus EXPANDED from that same line — the
// retired workflow.* action ids — are all recorded as `reject`. Both readings are right about
// different substitutions: the schema validates action names, so a live id accepts and a retired id
// rejects. This test substitutes a live id (sql.select) and relies on the five expansions to cover the
// rejecting half, which they do.
func TestPolicyCorpusValidationAgreement(t *testing.T) {
	recs := loadPolicyCorpus(t)

	var agree, disagree, notReached int
	for _, r := range recs {
		src := r.Source
		if r.Templated {
			var used []string
			src, used = substitute(src)
			if len(used) == 0 {
				t.Errorf("record marked templated but no substitution applied — vars %v, source: %s",
					r.TemplateVars, r.Source)
			}
			if strings.Contains(src, "$") {
				t.Errorf("unresolved template variable remains after substitution: %s\n  (declared vars: %v)",
					src, r.TemplateVars)
			}
		}

		errs := authz.DefaultSchema.Validate(src)
		accepted := len(errs) == 0

		switch r.ExpectedValidate {
		case "accept", "accept-after-substitution":
			if accepted {
				agree++
			} else {
				disagree++
				t.Errorf("DISAGREE — cedar-java accepts, cedar-go REJECTS\n"+
					"  source:     %s\n  provenance: %s\n  evidence:   %s\n  errors:     %v",
					src, r.Provenance, r.ExpectedEvidence, errs)
			}
		case "reject":
			if !accepted {
				agree++
			} else {
				disagree++
				t.Errorf("DISAGREE — cedar-java rejects, cedar-go ACCEPTS (a policy that must not load)\n"+
					"  source:     %s\n  provenance: %s\n  evidence:   %s",
					src, r.Provenance, r.ExpectedEvidence)
			}
		case "not-reached":
			// The Kotlin never validates these: the SYSTEM-immutability guard fires FIRST, so the
			// observable outcome is SystemPolicyImmutableException, not InvalidCedarPolicyException.
			// There is no validator expectation to agree with — but there IS a checkable fact, namely
			// that the source is genuinely un-parseable, which is what makes the ORDERING observable at
			// all. If it validated, the two exceptions would be indistinguishable and the corpus note
			// ("Ordering-sensitive: a Go port that validates first changes the error") would be moot.
			notReached++
			if accepted {
				t.Errorf("not-reached record VALIDATES, which would make the guard-order defect "+
					"unobservable\n  source: %s\n  provenance: %s", src, r.Provenance)
			}
		default:
			t.Fatalf("unknown expected_validate %q on %s", r.ExpectedValidate, r.Provenance)
		}
	}

	t.Logf("cedar policy validation: AGREE %d / DISAGREE %d / not-reached %d (of %d records)",
		agree, disagree, notReached, len(recs))
	if agree+disagree+notReached != len(recs) {
		t.Errorf("accounting error: %d + %d + %d != %d", agree, disagree, notReached, len(recs))
	}
	if agree != 184 || disagree != 0 || notReached != 2 {
		t.Errorf("expected AGREE 184 / DISAGREE 0 / not-reached 2; got %d / %d / %d. "+
			"A change here is a cross-language validator divergence, not a test to adjust.",
			agree, disagree, notReached)
	}
}

// TestRetiredWorkflowActionIdsStayRejected isolates the five expanded records, because they are the
// only ones in the corpus that assert a policy MUST NOT LOAD for a reason that is neither a syntax
// error nor a schema typo.
//
// AuthzTest case 13 ("retired action ids are rejected by the bundled schema", AuthzTest.kt:240-249)
// exists so that a policy written against the pre-rename `workflow.*` vocabulary cannot silently do
// nothing: it is REJECTED at write time instead of loading and matching no action. If cedar-go
// accepted them, an operator restoring an old policy file would get a policy set that validates and
// grants nothing, and the failure would surface as "my approval policy stopped working".
func TestRetiredWorkflowActionIdsStayRejected(t *testing.T) {
	recs := loadPolicyCorpus(t)
	found := 0
	for _, r := range recs {
		if r.ExpandedFrom == nil || r.Name == nil || !strings.HasPrefix(*r.Name, "retired-action:") {
			continue
		}
		found++
		if errs := authz.DefaultSchema.Validate(r.Source); len(errs) == 0 {
			t.Errorf("%s VALIDATES but must be rejected — %s", *r.Name, r.Provenance)
		}
	}
	if found != 5 {
		t.Errorf("found %d retired-action records, want 5", found)
	}

	// And the live vocabulary must still accept, so the rejection above is about the retired NAMES and
	// not about the policy shape.
	live := `permit(principal, action == Action::"task.request", resource);`
	if errs := authz.DefaultSchema.Validate(live); len(errs) > 0 {
		t.Errorf("the live replacement action is rejected too, so the retired-id assertion proves "+
			"nothing about the vocabulary: %v", errs)
	}
}

// TestShippedSystemPoliciesAllValidate narrows the corpus to the 40 SYSTEM-origin rows — the ones
// V8__seed.sql actually ships.
//
// This is the subset with production consequences. 🔒 INV-A2-17 makes CedarEngine construction
// validate every ENABLED source and fail fast, so a single shipped row that cedar-go rejects is not a
// failing test — it is a control plane that will not boot after cutover.
func TestShippedSystemPoliciesAllValidate(t *testing.T) {
	recs := loadPolicyCorpus(t)
	var system, systemEnabled int
	for _, r := range recs {
		if r.Origin != "SYSTEM" {
			continue
		}
		system++
		if r.Enabled {
			systemEnabled++
		}
		src := r.Source
		if r.Templated {
			src, _ = substitute(src)
		}
		if errs := authz.DefaultSchema.Validate(src); len(errs) > 0 {
			name := "(unnamed)"
			if r.Name != nil {
				name = *r.Name
			}
			t.Errorf("shipped SYSTEM policy %s does not validate under cedar-go: %v\n  source: %s\n  %s",
				name, errs, src, r.Provenance)
		}
	}
	if system != 40 {
		t.Errorf("SYSTEM-origin records = %d, want 40", system)
	}
	t.Logf("shipped SYSTEM policies: %d total, %d enabled — all validate", system, systemEnabled)
}
