package policy

// The six wire DTOs, 09-policies.md §1. Each is a `@Serializable data class` in `Policies.kt:22-27`,
// and kotlinx serializes by PROPERTY NAME — so the JSON keys are the Kotlin property names verbatim
// (`roleId`, `roleName`), not snake_case and not the column names.
//
// Optionality follows INV-A1-4's `explicitNulls = false`: a null `description` is ABSENT from the
// body, never `"description": null`. That is `*string` + `omitempty`, the convention
// internal/types/audit_event.go already established for the port.

// Role is one `app_role` row as the API returns it.
type Role struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	// Description is `description: String? = null`. NULL in the column, absent on the wire.
	Description *string `json:"description,omitempty"`
}

// RoleInput is the POST/PUT body for a role.
type RoleInput struct {
	Name string `json:"name"`
	// Description is `description: String? = null`.
	Description *string `json:"description,omitempty"`
}

// RoleAssignment is one `principal_role` row.
//
// RoleName is DENORMALIZED from the join (09-policies.md §1): the UI shows the name, so every read
// path in this package joins `app_role`. It is not stored on the row.
type RoleAssignment struct {
	ID        int64  `json:"id"`
	Principal string `json:"principal"`
	RoleID    int64  `json:"roleId"`
	RoleName  string `json:"roleName"`
}

// RoleAssignmentInput is the POST body for an assignment. There is no `roleName` here — the caller
// names the role by id, and the response carries the name back.
type RoleAssignmentInput struct {
	Principal string `json:"principal"`
	RoleID    int64  `json:"roleId"`
}

// MaskFn is one `mask_fn` row.
//
// Kind is free-form at THIS layer — `TEXT NOT NULL` with no CHECK (V2__catalog.sql:67-71) and no
// validation in `Policies.kt`. The transform is selected by kind alone downstream
// (FIXED | LAST_N | FORMAT_PRESERVING | NULL), so an admin can create a mask fn the engine cannot
// apply. 09-policies.md Q4 is open on whether anything validates it; nothing here does, and that is
// REPRODUCE.
type MaskFn struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// MaskFnInput is the POST/PUT body for a mask function.
type MaskFnInput struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}
