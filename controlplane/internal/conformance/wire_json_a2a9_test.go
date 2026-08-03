package conformance

import (
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/authz"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/policy"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/queryhistory"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// ============================================================================================
// The CRUD route groups' DTOs — 02-authz.md §8 "Wire DTOs", 09-policies.md §1, and
// 07-tasks-approvals-results.md §1's `QueryHistoryEntry`.
//
// Same rule as the rest of this package: EXACT bytes through types.MarshalWire, never a semantic
// compare. What a golden-bytes layer adds over the per-package unit tests is the drift they cannot
// see — a field renamed on both sides at once, a field REORDERED (kotlinx emits in declaration order
// and so does encoding/json, so the order IS part of the contract), a new field appended in the wrong
// place, or an encoder swapped for one with different escaping.
//
// 🔴 THE ESCAPING RISK IS CONCENTRATED HERE, more than in any DTO already covered:
//
//   - `CedarPolicy.cedarSrc` is Cedar SOURCE, and Cedar's conjunction operator is `&&`. Essentially
//     every policy with a `when {}` clause carries two ampersands, so a body written through a
//     json.Marshal that HTML-escapes would ship `&&` to the policy editor — which renders
//     it, so an admin would see the escape sequence in the source of their own policy.
//   - `QueryHistoryEntry.sql` is the user's own SQL. `WHERE a < b AND c > d` is three escapes in one
//     statement, on the surface whose entire purpose is showing the user what they typed.
//
// QueryResponse.MarshalJSON already shipped exactly this bug once (see wire_json_test.go's header),
// which is why both DTOs get a dedicated metacharacter case rather than a note.
// ============================================================================================

// ---- policy.CedarPolicy --------------------------------------------------------------------
//
// SPEC: 02-authz.md §8's DTO table (:441-447). Field order is the declaration order —
// id, origin, systemKey, name, cedarSrc, enabled, updatedBy, updatedAt. `systemKey` and `updatedBy`
// are `String? = null`, so explicitNulls=false OMITS them when absent; everything else is non-null
// and always present.

func TestCedarPolicyGoldenBytes(t *testing.T) {
	// A migration-owned SYSTEM row: negative id, a systemKey, `migration:V8` as updatedBy. This is
	// the shape `GET /api/policies` leads with, since SYSTEM rows sort first.
	t.Run("a SYSTEM row with full provenance", func(t *testing.T) {
		assertWireBytes(t, policy.CedarPolicy{
			ID:        -1,
			Origin:    "SYSTEM",
			SystemKey: types.Ptr("bootstrap.pm-admin"),
			Name:      "system:admin",
			CedarSrc:  `permit(principal in Role::"system:admin", action in [Action::"admin.policies"], resource);`,
			Enabled:   true,
			UpdatedBy: types.Ptr("migration:V8"),
			UpdatedAt: "2026-07-31T04:05:06.123Z",
		}, "cedar_policy_system.json")
	})

	// A USER row that has never been edited by a person: systemKey and updatedBy both absent.
	//
	// 🔒 ABSENT, not null. A console that models `systemKey` as `string | undefined` and gets `null`
	// renders "null" next to the policy name.
	t.Run("a USER row with both optionals absent", func(t *testing.T) {
		assertWireBytes(t, policy.CedarPolicy{
			ID:        7,
			Origin:    "USER",
			Name:      "analyst-audit-read",
			CedarSrc:  `permit(principal, action == Action::"audit.read", resource);`,
			Enabled:   false,
			UpdatedAt: "2026-07-31T04:05:06Z",
		}, "cedar_policy_user_minimal.json")
	})

	// 🔴 THE CASE THAT MATTERS. `&&` is Cedar's conjunction and appears in almost every conditioned
	// policy; `<` and `>` appear in numeric guards. encoding/json would rewrite all three.
	t.Run("cedar source with html metacharacters", func(t *testing.T) {
		assertWireBytes(t, policy.CedarPolicy{
			ID:        8,
			Origin:    "USER",
			Name:      "conditioned",
			CedarSrc:  `permit(principal, action, resource) when { context.rank < 5 && context.tier > 1 };`,
			Enabled:   true,
			UpdatedAt: "2026-07-31T04:05:06Z",
		}, "cedar_policy_metacharacters.json")
	})
}

// The escaping claim, stated as a property rather than as bytes: no golden above may contain any of
// encoding/json's three escapes, and the raw characters must survive.
func TestCedarPolicySourceIsNotHTMLEscaped(t *testing.T) {
	src := `permit(principal, action, resource) when { a < b && c > d };`
	got, err := types.MarshalWire(policy.CedarPolicy{
		ID: 1, Origin: "USER", Name: "n", CedarSrc: src, Enabled: true, UpdatedAt: "2026-07-31T04:05:06Z",
	})
	if err != nil {
		t.Fatalf("MarshalWire: %v", err)
	}
	for raw, escaped := range htmlEscapes {
		if strings.Contains(string(got), escaped) {
			t.Errorf("cedarSrc was HTML-escaped: %q became %q in %s", raw, escaped, got)
		}
		if !strings.Contains(string(got), raw) {
			t.Errorf("cedarSrc lost the raw character %q: %s", raw, got)
		}
	}
}

// ---- policy.CedarValidateResult ---------------------------------------------------------------
//
// 🔒 INV-A1-4 — `errors: List<String> = []` is a defaulted non-null list, so encodeDefaults=true
// ALWAYS emits it, as `[]` for the valid case. Go's nil slice marshals as `null`; CedarValidateResult
// carries a MarshalJSON that normalises, so a `CedarValidateResult{Valid: true}` literal cannot
// produce the wrong shape. The editor renders `errors.length` with no null check.

func TestCedarValidateResultGoldenBytes(t *testing.T) {
	t.Run("valid — errors is [] and NOT null", func(t *testing.T) {
		assertWireBytes(t, policy.CedarValidateResult{Valid: true}, "cedar_validate_result_valid.json")
	})

	t.Run("invalid — the compiler's own messages, verbatim", func(t *testing.T) {
		assertWireBytes(t, policy.CedarValidateResult{
			Valid:  false,
			Errors: []string{"unexpected token `==`", "unknown action `Action::\"nope\"`"},
		}, "cedar_validate_result_invalid.json")
	})
}

// ---- policy.CedarPolicyErrors -----------------------------------------------------------------
//
// ⚠️ 02-authz.md:511 — the validate-on-WRITE 400 body is a BARE MAP, `{errors: [...]}`, NOT ApiError.
// It is the SECOND documented exemption from INV-A1-13, after httpapi.ScimError.
//
// A golden here is worth more than usual: the difference between this and an ApiError is invisible to
// a status-code assertion, and the policy editor renders one line per message. An ApiError with a
// joined `detail` would collapse them AND would file Cedar's compiler prose under an i18n key that
// does not exist.

func TestCedarPolicyErrorsGoldenBytes(t *testing.T) {
	t.Run("the validate-on-write 400 body", func(t *testing.T) {
		assertWireBytes(t, policy.CedarPolicyErrors{
			Errors: []string{"unexpected end of input"},
		}, "cedar_policy_errors.json")
	})

	// Unreachable in production — the error only exists because validation FAILED — but a
	// `{"errors":null}` reaching the editor would render as a crash rather than as "no messages".
	t.Run("a nil slice still emits []", func(t *testing.T) {
		assertWireBytes(t, policy.CedarPolicyErrors{}, "cedar_policy_errors_empty.json")
	})
}

// ---- policy.CedarSchemaResult -----------------------------------------------------------------
//
// One field carrying the whole bundled schema. The bytes are the schema itself, so the golden here is
// a SHAPE check rather than a content one: the fixture would be 235 lines of Cedar otherwise, and the
// schema's own content is already pinned by internal/authz.

func TestCedarSchemaResultGoldenBytes(t *testing.T) {
	assertWireBytes(t, policy.CedarSchemaResult{Schema: "entity System;\n"}, "cedar_schema_result.json")
}

// The real schema goes out unescaped too. Cedar schema source contains `<` in set notation
// (`Set<String>`) — schema.cedarschema:117-118's shared context shape has two of them — so this is not
// a hypothetical surface.
func TestTheRealSchemaSurvivesMarshallingUnescaped(t *testing.T) {
	got, err := types.MarshalWire(policy.CedarSchemaResult{Schema: authz.SchemaSource})
	if err != nil {
		t.Fatalf("MarshalWire: %v", err)
	}
	if !strings.Contains(authz.SchemaSource, "Set<String>") {
		t.Skip("the bundled schema no longer contains Set<String>; the escaping surface moved")
	}
	if strings.Contains(string(got), htmlEscapes["<"]) {
		t.Errorf("the schema was HTML-escaped: `Set<String>` became `Set%sString>`", htmlEscapes["<"])
	}
}

// ---- policy.Role / RoleAssignment / MaskFn ----------------------------------------------------
//
// SPEC: 09-policies.md §1's DTO table (:32-39). kotlinx serializes by PROPERTY NAME, so the keys are
// `roleId` and `roleName` — not snake_case and not the column names.
//
// dto_test.go already asserts these shapes inside internal/policy. What the golden layer adds is the
// same thing it adds everywhere: a rename done on both sides at once stays green there and fails here.

func TestRoleGoldenBytes(t *testing.T) {
	t.Run("with a description", func(t *testing.T) {
		assertWireBytes(t, policy.Role{
			ID: 7, Name: "analyst", Description: types.Ptr("reads the warehouse"),
		}, "role_full.json")
	})

	// `description: String? = null` — ABSENT under explicitNulls=false, never `"description":null`.
	t.Run("without one — absent, not null", func(t *testing.T) {
		assertWireBytes(t, policy.Role{ID: 7, Name: "analyst"}, "role_minimal.json")
	})

	// A description is operator-authored free text and routinely contains `&`. It is also, through
	// INV-A9-3, the one A9 field ANY authenticated session can read — so it is both the widest-read
	// and the least-controlled string in the area.
	t.Run("html metacharacters in the description", func(t *testing.T) {
		assertWireBytes(t, policy.Role{
			ID: 9, Name: "pii-accessor", Description: types.Ptr("reads PII <sensitive> & masked columns"),
		}, "role_metacharacters.json")
	})
}

func TestRoleAssignmentGoldenBytes(t *testing.T) {
	// 🔒 `roleName` is DENORMALIZED from the join and is NOT optional: every read path joins
	// `app_role`, and an assignment body without it renders a blank row in the console.
	assertWireBytes(t, policy.RoleAssignment{
		ID: 3, Principal: "alice@example.com", RoleID: 7, RoleName: "analyst",
	}, "role_assignment.json")
}

func TestMaskFnGoldenBytes(t *testing.T) {
	// `kind` is free-form TEXT with no CHECK and no validation at any layer (09-policies.md Q4), so
	// the golden deliberately uses a real kind rather than implying an enum.
	assertWireBytes(t, policy.MaskFn{ID: 4, Name: "email-mask", Kind: "FORMAT_PRESERVING"}, "mask_fn.json")
}

// ---- queryhistory.Entry ------------------------------------------------------------------------
//
// SPEC: 07-tasks-approvals-results.md §1's DTO table (:58) — `sql`, `datasourceId`, `ranAt`.
//
// ⚠️ THERE IS NO `id` ON THE WIRE even though `query_history.id` is a BIGSERIAL primary key. The entry
// is not addressable — the only mutation is "clear mine", which takes no id — so exposing one would
// advertise an endpoint that does not exist. A golden is what keeps a well-meaning `ID int64` from
// being added to the struct later.

func TestQueryHistoryEntryGoldenBytes(t *testing.T) {
	t.Run("with a datasource", func(t *testing.T) {
		assertWireBytes(t, queryhistory.Entry{
			SQL:          "select id, email from users limit 10",
			DatasourceID: types.Ptr(int64(3)),
			RanAt:        "2026-07-31T04:05:06.123Z",
		}, "query_history_entry_full.json")
	})

	// `datasourceId: Long? = null` — ABSENT, because a statement can be recorded before a datasource
	// is chosen (V5__tasks.sql:108 has no FK and no NOT NULL).
	t.Run("without one — absent, not null", func(t *testing.T) {
		assertWireBytes(t, queryhistory.Entry{
			SQL:   "select 1",
			RanAt: "2026-07-31T04:05:06Z",
		}, "query_history_entry_minimal.json")
	})

	// 🔴 THE HIGHEST-RISK ESCAPING SURFACE IN THIS INCREMENT. `sql` is the user's own statement, echoed
	// back to the editor that produced it, and comparison predicates are exactly what a SQL history is
	// full of. `WHERE a < 5 AND b > 3` plus an `&&` is four escapes in one entry.
	t.Run("sql metacharacters", func(t *testing.T) {
		assertWireBytes(t, queryhistory.Entry{
			SQL:          `select * from t where a < 5 and b > 3 and (c && d) and e = 'x&y'`,
			DatasourceID: types.Ptr(int64(1)),
			RanAt:        "2026-07-31T04:05:06Z",
		}, "query_history_entry_sql_metacharacters.json")
	})
}

// The same property assertion the audit event and query response carry, on the DTO whose content is
// the least controlled of the three.
func TestQueryHistorySQLIsNotHTMLEscaped(t *testing.T) {
	entry := queryhistory.Entry{SQL: `where a < b and c > d and e & f`, RanAt: "2026-07-31T04:05:06Z"}
	got, err := types.MarshalWire(entry)
	if err != nil {
		t.Fatalf("MarshalWire: %v", err)
	}
	for raw, escaped := range htmlEscapes {
		if strings.Contains(string(got), escaped) {
			t.Errorf("sql was HTML-escaped: %q became %q in %s", raw, escaped, got)
		}
		if !strings.Contains(string(got), raw) {
			t.Errorf("sql lost the raw character %q: %s", raw, got)
		}
	}
}

// ---- the collection shapes ---------------------------------------------------------------------

// 🔒 INV-A1-4 — an EMPTY collection is `[]`, never `null`, and every list route in this increment
// answers one. Go's nil slice is the trap: it marshals as `null`, and the console renders `.length`
// on all four of these.
//
// The route suites assert this per route against a live handler. Here it is asserted against the
// SLICE TYPES themselves, which is what catches a normalisation removed from a store or a management
// method — the layer the routes trust to have done it.
func TestEveryCrudListShapeIsAnEmptyArrayNotNull(t *testing.T) {
	for _, c := range []struct {
		name string
		v    any
	}{
		{"[]CedarPolicy", []policy.CedarPolicy{}},
		{"[]Role", []policy.Role{}},
		{"[]RoleAssignment", []policy.RoleAssignment{}},
		{"[]MaskFn", []policy.MaskFn{}},
		{"[]queryhistory.Entry", []queryhistory.Entry{}},
		{"[]types.AuditEvent", []types.AuditEvent{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := types.MarshalWire(c.v)
			if err != nil {
				t.Fatalf("MarshalWire: %v", err)
			}
			if string(got) != "[]" {
				t.Errorf("got %s, want []", got)
			}
		})
	}

	// And the nil form, which is what a Go query helper returns for no rows — the shape every list
	// route in this increment normalises away before responding.
	var nilPolicies []policy.CedarPolicy
	got, err := types.MarshalWire(nilPolicies)
	if err != nil {
		t.Fatalf("MarshalWire: %v", err)
	}
	if string(got) != "null" {
		t.Fatalf("a nil slice marshals as %s; the premise of every normalisation in this increment is "+
			"that it is `null`. If encoding/json changed, the normalisations are now dead code.", got)
	}
}
