package management

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ridi-oss/proxy-monster/gocp/internal/policy"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// The shared helpers of ManagementServices.kt:716-732 — `required`, `notFound`, `unique` — plus the
// two exception types. No DB: these are pure translations and every one of them is a wire contract.
// ---------------------------------------------------------------------------------------------

// 🔒 `required(field, value)` rejects blank, and the param key is `fields` — PLURAL — carrying a
// SINGLE field name. That spelling is on the wire, because `web/` interpolates `{fields}` into a
// localized sentence; renaming it to `field` would render the raw code instead of a message.
func TestRequiredRejectsBlankAndNamesTheFieldUnderThePluralKey(t *testing.T) {
	for _, blank := range []string{"", " ", "\t", "\n", "   \t \n "} {
		err := Required("principal", blank)
		e := assertManagementCode(t, err, "common.field_required", fmt.Sprintf("blank %q", blank))
		assertParam(t, e, "fields", "principal", fmt.Sprintf("blank %q", blank))
	}
	if err := Required("principal", "alice@example.com"); err != nil {
		t.Errorf("non-blank: got %v, want nil", err)
	}
	// Kotlin's isBlank() is true for a string of only whitespace, and FALSE for one with any
	// non-whitespace character — including a leading/trailing space around real content, which is
	// therefore ACCEPTED and stored with its spaces. Reproduced: no trimming happens on the value.
	if err := Required("principal", "  alice  "); err != nil {
		t.Errorf("padded but non-blank: got %v, want nil", err)
	}
}

// `notFound(resource)` is `common.not_found{resource}`, which httpapi.RespondManagementError answers
// 404. The resource literal is a per-call-site string, not the route path.
func TestNotFoundCarriesTheCallSitesResourceLiteral(t *testing.T) {
	e := assertManagementCode(t, NotFound(ResourceGroup), "common.not_found", "group")
	assertParam(t, e, "resource", "group", "group")

	// 🔒 replaceDirectRoles interpolates the OFFENDING ROLE into the literal, because the caller
	// asked for a SET and the whole request fails on any one member.
	e = assertManagementCode(t, NotFound("role 'no-such-role'"), "common.not_found", "interpolated")
	assertParam(t, e, "resource", "role 'no-such-role'", "interpolated")
}

// ⚠️ The user resource literals DISAGREE by design: a 404 says `user`, a duplicate says `principal`.
// Two different call sites in ManagementServices.kt:523,532, two different i18n keys on the wire.
// Pinned so a later tidy-up is a deliberate edit rather than a silent message change.
func TestUserResourceLiteralsDisagreeBetweenNotFoundAndUnique(t *testing.T) {
	if ResourceUser == ResourcePrincipal {
		t.Fatalf("the two literals must stay different: notFound(%q) vs unique(%q)",
			ResourceUser, ResourcePrincipal)
	}
	if ResourceUser != "user" || ResourcePrincipal != "principal" {
		t.Errorf("literals drifted: user=%q principal=%q", ResourceUser, ResourcePrincipal)
	}
}

// 🔒 `unique(resource, name) { }` maps SQLSTATE **23505** and nothing else. This is the mapping A11
// §9 lists as untested.
func TestUniqueMapsSqlstate23505AndPassesEverythingElseThrough(t *testing.T) {
	dup := &pgconn.PgError{Code: "23505", Message: `duplicate key value violates unique constraint "app_group_name_key"`}

	e := assertManagementCode(t, Unique(dup, ResourceGroup, ptr("engineering")), "common.already_exists", "23505")
	assertParam(t, e, "resource", "group", "23505")
	assertParam(t, e, "name", "engineering", "23505")

	// It unwraps: a 23505 buried under fmt.Errorf still maps, because store.IsUniqueViolation uses
	// errors.As. A store that annotates its errors must not lose the mapping.
	e = assertManagementCode(t, Unique(fmt.Errorf("create group: %w", dup), ResourceGroup, nil),
		"common.already_exists", "wrapped 23505")
	assertParam(t, e, "resource", "group", "wrapped 23505")
	if _, present := e.Params["name"]; present {
		t.Errorf("a nil name must be OMITTED from the params, got %v", e.Params)
	}

	// ⚠️ 23503 — foreign-key violation — is deliberately NOT matched (F29). It passes through and
	// StatusPages answers 500 common.fallback. Adding an arm here would change an observable status.
	fk := &pgconn.PgError{Code: "23503", Message: "insert violates foreign key constraint"}
	if got := Unique(fk, ResourceGroup, nil); !errors.Is(got, fk) {
		t.Errorf("23503 must pass through untouched, got %#v", got)
	}
	var me *Error
	if errors.As(Unique(fk, ResourceGroup, nil), &me) {
		t.Errorf("23503 must NOT become a management failure, got code %q", me.Err.Code)
	}

	if got := Unique(nil, ResourceGroup, nil); got != nil {
		t.Errorf("nil in, nil out: got %v", got)
	}
}

// 🔒 THE ALIAS IS THE POINT. `management.Error` and `policy.ManagementError` must be ONE type, or
// every cross-package errors.As silently stops matching — the failure mode that compiles, passes a
// package-local test, and turns a 409 into a 500 at the route layer.
func TestManagementErrorIsTheSameTypeAsPolicysNotACopy(t *testing.T) {
	// Built here, matched as internal/policy's.
	var fromPolicy *policy.ManagementError
	if !errors.As(error(Fail("role.system_immutable", nil)), &fromPolicy) {
		t.Fatalf("a management.Error must match *policy.ManagementError")
	}
	// Built as internal/policy's own type, matched as this package's.
	var fromManagement *Error
	if !errors.As(error(&policy.ManagementError{Err: types.ApiError{Code: "common.not_found"}}), &fromManagement) {
		t.Fatalf("a policy.ManagementError must match *management.Error")
	}
	// Error() is the CODE, never the params — a log line carrying the error string cannot leak an
	// interpolated resource name into somewhere that is not the wire.
	if got := Fail("group.system_immutable", map[string]string{"resource": "secret-group"}).Error(); got != "group.system_immutable" {
		t.Errorf("Error() = %q, want the bare code", got)
	}
}

// [CedarValidationError] is the ONE management failure that does not carry an ApiError, because its
// wire body is `{errors: [...]}` — a bare map. It must NOT be matchable as a [Error], or the route
// layer would answer it with an ApiError body and lose the array the policy editor renders.
func TestCedarValidationErrorIsNotAManagementError(t *testing.T) {
	err := error(&CedarValidationError{Errors: []string{"unrecognized entity type", "unexpected token `;`"}})

	var me *Error
	if errors.As(err, &me) {
		t.Fatalf("a Cedar validation failure must not match *management.Error (got code %q)", me.Err.Code)
	}
	var cve *CedarValidationError
	if !errors.As(err, &cve) {
		t.Fatalf("must match *management.CedarValidationError")
	}
	if len(cve.Errors) != 2 {
		t.Errorf("the validator's raw array must be preserved verbatim, got %v", cve.Errors)
	}
}

// The A11 §8 codes httpapi.RespondManagementError switches on. A typo in one is a silent 400 for
// something that should be a 409 or a 502, which no other test would notice.
func TestTheNonCommonCodesAreSpelledExactlyAsTheEdgeSwitchExpects(t *testing.T) {
	for code, want := range map[string]string{
		CodeGroupSystemImmutable:     "group.system_immutable",
		CodeReservedTag:              "datasource.reserved_tag",
		CodeSchemaRequired:           "datasource.schema_required",
		CodeTableIntrospectionFailed: "datasource.table_introspection_failed",
	} {
		if code != want {
			t.Errorf("code drifted: got %q, want %q", code, want)
		}
	}
}

// INV-A1-4 on the two bodies this package owns: `[]` never null, absent never null.
func TestWireShapesFollowEncodeDefaultsAndExplicitNulls(t *testing.T) {
	assertJSON(t, DeleteResult{Deleted: false}, `{"deleted":false}`, "DeleteResult")

	// A group whose roles were all removed answers `[]`. A console handed `null` renders "no data"
	// rather than "no roles" — a different sentence for a state the user just created.
	assertJSON(t, GroupRolesResult{Group: "engineering"},
		`{"group":"engineering","roleNames":[]}`, "GroupRolesResult with no roles")
	assertJSON(t, GroupRolesResult{Group: "engineering", RoleNames: []string{"reader"}},
		`{"group":"engineering","roleNames":["reader"]}`, "GroupRolesResult")

	// maskFnName absent, not null; tags `[]`, not null.
	assertJSON(t, ColumnTagEntry{Datasource: "prod", Schema: "public", Table: "users", Column: "email"},
		`{"datasource":"prod","schema":"public","table":"users","column":"email","tags":[]}`,
		"ColumnTagEntry with no tags")
	assertJSON(t, ColumnTagEntry{
		Datasource: "prod", Schema: "public", Table: "users", Column: "email",
		Tags: []string{"pii"}, MaskFnName: ptr("mask_email"),
	},
		`{"datasource":"prod","schema":"public","table":"users","column":"email","tags":["pii"],"maskFnName":"mask_email"}`,
		"ColumnTagEntry")

	// catalogSyncedAt / lastSeenAt absent when the datasource has never been introspected or seen.
	assertJSON(t, DatasourceLiveness{Datasource: "prod", Attached: false},
		`{"datasource":"prod","attached":false}`, "DatasourceLiveness")
}
