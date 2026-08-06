package policy

import (
	"encoding/json"
	"fmt"

	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
)

// ---------------------------------------------------------------------------------------------
// kotlinx's REQUIRED-FIELD enforcement, for A9's and A2's input DTOs.
//
// 🔒 WHY A 500 IS THE CORRECT ANSWER HERE, however wrong it looks. A Kotlin `@Serializable` class with
// a non-nullable property and no default makes that property REQUIRED: kotlinx throws
// MissingFieldException when the body omits it, and StatusPages turns that into 500 common.fallback
// before any route code runs. Go's encoding/json instead leaves the zero value in place, so the body
// sailed through to the service layer and got a tidy 400.
//
// A tidy 400 is the better answer, and it is still the wrong one for this port. The migration policy is
// bug-for-bug: reproduce the Kotlin, then decide as a product question whether to fix it on both sides.
// Answering 400 where the shipped control-plane answers 500 means the console's error handling is being
// written against a contract the running system does not have.
//
// MEASURED, not inferred — internal/conformance/differential asked the running Kotlin nine times and
// got 500 every time: r3-mask-fn-missing-name / -missing-kind / -null-kind, r3-policy-missing-src /
// -missing-name / -null-src, r3-assignment-missing-principal / -missing-roleid, and
// r2-create-role-empty-object / -null-name.
//
// ⚠️ ABSENT AND EXPLICIT-NULL ARE THE SAME THING for a non-nullable field, which is why every probe
// below is a POINTER and both arms collapse to one check. A PRESENT-BUT-BLANK value is deliberately NOT
// rejected: kotlinx only checks presence, and blankness is `required(…)`'s 400 further in. Collapsing
// those two would turn that 400 into a 500 — the same mistake in the opposite direction.
// ---------------------------------------------------------------------------------------------

// UnmarshalJSON enforces `name: String` (RoleInput). `description` has a default and stays optional.
func (i *RoleInput) UnmarshalJSON(b []byte) error {
	var raw struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if raw.Name == nil {
		return fmt.Errorf("%w: name (RoleInput)", session.ErrMissingField)
	}
	i.Name, i.Description = *raw.Name, raw.Description
	return nil
}

// UnmarshalJSON enforces `name` and `kind` (MaskFnInput) — both non-nullable with no default.
func (i *MaskFnInput) UnmarshalJSON(b []byte) error {
	var raw struct {
		Name *string `json:"name"`
		Kind *string `json:"kind"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		v    *string
	}{{"name", raw.Name}, {"kind", raw.Kind}} {
		if f.v == nil {
			return fmt.Errorf("%w: %s (MaskFnInput)", session.ErrMissingField, f.name)
		}
	}
	i.Name, i.Kind = *raw.Name, *raw.Kind
	return nil
}

// UnmarshalJSON enforces `principal` and `roleId` (RoleAssignmentInput).
//
// ⚠️ `roleId` matters as much as `principal`: without the check an omitted id decoded to 0, the service
// looked up role 0, and the route answered 404 — a plausible-looking answer to a malformed request,
// where the Kotlin never reaches the lookup at all (r3-assignment-missing-roleid: kotlin=500, go=404).
func (i *RoleAssignmentInput) UnmarshalJSON(b []byte) error {
	var raw struct {
		Principal *string `json:"principal"`
		RoleID    *int64  `json:"roleId"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if raw.Principal == nil {
		return fmt.Errorf("%w: principal (RoleAssignmentInput)", session.ErrMissingField)
	}
	if raw.RoleID == nil {
		return fmt.Errorf("%w: roleId (RoleAssignmentInput)", session.ErrMissingField)
	}
	i.Principal, i.RoleID = *raw.Principal, *raw.RoleID
	return nil
}
