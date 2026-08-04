package policy

import (
	"encoding/json"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// The wire contract of 09-policies.md §1. There is no Kotlin test to port — A9 has none at all
// (F10) — so these assert the shape kotlinx produces under the application-wide
// `Json { encodeDefaults = true; explicitNulls = false }` (INV-A1-4) directly.
//
// The one that would be easy to get wrong is `description`: it is `String? = null`, and with
// explicitNulls = false a null is ABSENT from the body, not `"description": null`. web/ reads these
// bodies, so the two shapes are not interchangeable.

func TestRole_JSONShape(t *testing.T) {
	cases := []struct {
		name string
		in   Role
		want string
	}{
		{
			name: "with a description",
			in:   Role{ID: 7, Name: "analyst", Description: types.Ptr("reads the warehouse")},
			want: `{"id":7,"name":"analyst","description":"reads the warehouse"}`,
		},
		{
			name: "without one — absent, not null (explicitNulls = false)",
			in:   Role{ID: 7, Name: "analyst"},
			want: `{"id":7,"name":"analyst"}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := types.MarshalWire(c.in)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(got) != c.want {
				t.Errorf("Role JSON =\n  %s\nwant\n  %s", got, c.want)
			}
		})
	}
}

// RoleAssignment carries the DENORMALIZED roleName from the join — the UI shows the name, so every
// read path joins app_role. The keys are the Kotlin property names verbatim (kotlinx serializes by
// property name): `roleId` and `roleName`, not `role_id` / the column names.
func TestRoleAssignment_JSONShape(t *testing.T) {
	got, err := types.MarshalWire(RoleAssignment{ID: 3, Principal: "a@example.com", RoleID: 9, RoleName: "analyst"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"id":3,"principal":"a@example.com","roleId":9,"roleName":"analyst"}`
	if string(got) != want {
		t.Errorf("RoleAssignment JSON =\n  %s\nwant\n  %s", got, want)
	}
}

func TestMaskFn_JSONShape(t *testing.T) {
	got, err := types.MarshalWire(MaskFn{ID: 1, Name: "rrn-last4", Kind: "LAST_N"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"id":1,"name":"rrn-last4","kind":"LAST_N"}`
	if string(got) != want {
		t.Errorf("MaskFn JSON =\n  %s\nwant\n  %s", got, want)
	}
}

// The three Input DTOs are request bodies, so what matters is what they accept.
func TestInputs_Unmarshal(t *testing.T) {
	var role RoleInput
	if err := json.Unmarshal([]byte(`{"name":"analyst"}`), &role); err != nil {
		t.Fatalf("RoleInput: %v", err)
	}
	if role.Name != "analyst" || role.Description != nil {
		t.Errorf("RoleInput = %+v, want {analyst <nil>}: description defaults to null", role)
	}

	var assignment RoleAssignmentInput
	if err := json.Unmarshal([]byte(`{"principal":"a@example.com","roleId":42}`), &assignment); err != nil {
		t.Fatalf("RoleAssignmentInput: %v", err)
	}
	if assignment.Principal != "a@example.com" || assignment.RoleID != 42 {
		t.Errorf("RoleAssignmentInput = %+v, want {a@example.com 42}", assignment)
	}

	var maskFn MaskFnInput
	if err := json.Unmarshal([]byte(`{"name":"rrn-last4","kind":"LAST_N"}`), &maskFn); err != nil {
		t.Fatalf("MaskFnInput: %v", err)
	}
	if maskFn.Name != "rrn-last4" || maskFn.Kind != "LAST_N" {
		t.Errorf("MaskFnInput = %+v, want {rrn-last4 LAST_N}", maskFn)
	}
}
