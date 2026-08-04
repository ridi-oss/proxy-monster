package identity

import (
	"encoding/json"

	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// The `/api/users**` + `/api/groups**` wire contract — `Users.kt:25-65`, every one a
// `@Serializable data class`. kotlinx serializes by PROPERTY NAME, so the JSON keys are the Kotlin
// property names verbatim (`displayName`, `externalId`, `memberCount`), never the column names.
//
// 🔒 INV-A1-4 governs every field here, and Go's encoding/json defaults are the OPPOSITE of it on
// both halves:
//
//   - `explicitNulls = false` ⇒ a null optional is ABSENT, never `"field": null`. That is
//     `*T` + `,omitempty`, the convention internal/policy/dto.go and internal/types/audit_event.go
//     already established.
//   - `encodeDefaults = true` ⇒ a defaulted NON-null property is always emitted, so
//     `groups: List<GroupRef> = emptyList()` is `"groups": []` on a user with no groups. Go marshals
//     a nil slice as `null`, which is why [AppUser] and [AppGroup] carry a MarshalJSON.
//
// These live in this package rather than in internal/management because `Users.kt` owns them and A3
// owns `Users.kt`; the management layer is a consumer of the shape, not its author.

// GroupRef is `data class GroupRef(val id: Long, val name: String)` (Users.kt:25) — the trimmed
// group shape embedded in a user, and the trimmed role shape embedded in a group. One class serving
// two relations is the Kotlin's, not a simplification.
type GroupRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// AppUser is one `app_user` row as the API returns it, with its groups joined in.
//
// Source is `LOCAL | SCIM` and is NOT settable through [AppUserInput] — the column defaults to
// 'LOCAL' and only the SCIM upserts write 'SCIM' (V1__identity.sql:22). ExternalID is likewise
// SCIM-only.
type AppUser struct {
	ID        int64  `json:"id"`
	Principal string `json:"principal"`
	// DisplayName is `displayName: String? = null`.
	DisplayName *string `json:"displayName,omitempty"`
	// Email is `email: String? = null`.
	Email  *string `json:"email,omitempty"`
	Source string  `json:"source"`
	// ExternalID is `externalId: String? = null` — the SCIM externalId, absent for a LOCAL row.
	ExternalID *string `json:"externalId,omitempty"`
	Active     bool    `json:"active"`
	// CreatedAt is `getTimestamp("created_at").toInstant().toString()` — see instant.Format for the
	// trailing-zero rule that makes this NOT RFC3339Nano.
	CreatedAt string `json:"createdAt"`
	// Groups is `groups: List<GroupRef> = emptyList()`; `[]`, never null.
	Groups []GroupRef `json:"groups"`
}

// MarshalJSON normalises Groups to `[]` rather than `null`, and encodes through types.MarshalWire so
// a display name carrying '<' '&' '>' is not HTML-escaped the way kotlinx would not escape it.
func (u AppUser) MarshalJSON() ([]byte, error) {
	type alias AppUser
	a := alias(u)
	if a.Groups == nil {
		a.Groups = []GroupRef{}
	}
	return types.MarshalWire(a)
}

// AppUserInput is the POST/PUT body for a user.
//
// ⚠️ `active: Boolean = true` is a DEFAULT, and Go's zero value for bool is the opposite one. A body
// that omits `active` must create an ACTIVE user; plain encoding/json would create an inactive one
// and — because a create with `active=false` also revokes that principal's existing credentials —
// silently tear down credentials the caller never asked to touch. [AppUserInput.UnmarshalJSON]
// reproduces the Kotlin default.
type AppUserInput struct {
	Principal string `json:"principal"`
	// DisplayName is `displayName: String? = null`.
	DisplayName *string `json:"displayName,omitempty"`
	// Email is `email: String? = null`.
	Email  *string `json:"email,omitempty"`
	Active bool    `json:"active"`
}

// UnmarshalJSON decodes with `active` defaulting to TRUE — see the type's own ⚠️ note.
func (in *AppUserInput) UnmarshalJSON(b []byte) error {
	type alias AppUserInput
	a := alias{Active: true}
	// `ignoreUnknownKeys = true` (INV-A1-4) is encoding/json's default, so nothing extra is needed
	// for it — only the defaulted field above.
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*in = AppUserInput(a)
	return nil
}

// AppGroup is one `app_group` row as the API returns it, with its member count and roles joined in.
type AppGroup struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	// Description is `description: String? = null`.
	Description *string `json:"description,omitempty"`
	Source      string  `json:"source"`
	// ExternalID is `externalId: String? = null`.
	ExternalID *string `json:"externalId,omitempty"`
	// MemberCount is `memberCount: Int = 0` — Kotlin `Int`, so int32, and always emitted.
	MemberCount int32 `json:"memberCount"`
	// Roles is `roles: List<GroupRef> = emptyList()`; `[]`, never null.
	Roles []GroupRef `json:"roles"`
}

// MarshalJSON normalises Roles to `[]` rather than `null`. See [AppUser.MarshalJSON].
func (g AppGroup) MarshalJSON() ([]byte, error) {
	type alias AppGroup
	a := alias(g)
	if a.Roles == nil {
		a.Roles = []GroupRef{}
	}
	return types.MarshalWire(a)
}

// AppGroupInput is the POST/PUT body for a group. `source` and `externalId` are deliberately absent:
// a group created through this surface is LOCAL by definition.
type AppGroupInput struct {
	Name string `json:"name"`
	// Description is `description: String? = null`.
	Description *string `json:"description,omitempty"`
}

// GroupMemberEntry is one `group_member` row, denormalised with the member's principal.
type GroupMemberEntry struct {
	UserID    int64  `json:"userId"`
	Principal string `json:"principal"`
	// DisplayName is `displayName: String? = null`.
	DisplayName *string `json:"displayName,omitempty"`
}

// GroupMemberInput is the POST body for a membership — BY USER ID, not by principal. The name-keyed
// management overload resolves a principal to this id itself.
type GroupMemberInput struct {
	UserID int64 `json:"userId"`
}

// GroupRoleEntry is one `group_role` row, denormalised with the role's name.
type GroupRoleEntry struct {
	RoleID   int64  `json:"roleId"`
	RoleName string `json:"roleName"`
}

// GroupRoleInput is the POST body for a group→role mapping.
type GroupRoleInput struct {
	RoleID int64 `json:"roleId"`
}
