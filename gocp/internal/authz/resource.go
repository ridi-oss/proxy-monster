package authz

import (
	"strconv"

	"github.com/cedar-policy/cedar-go/types"
)

// Cedar entity type names. Ported from Authz.kt:201-215's EntityTypeName.parse(...).get() constants.
const (
	typeUser        = types.EntityType("User")
	typeRole        = types.EntityType("Role")
	typeAction      = types.EntityType("Action")
	typeSystem      = types.EntityType("System")
	typeDatasource  = types.EntityType("Datasource")
	typeRequest     = types.EntityType("Request")
	typeAccessGrant = types.EntityType("AccessGrant")
	typeToken       = types.EntityType("Token")
	typeAuditRecord = types.EntityType("AuditRecord")
	typeAuditLog    = types.EntityType("AuditLog")
	typeTable       = types.EntityType("Table")
	typeColumn      = types.EntityType("Column")
	typeTag         = types.EntityType("Tag")
	typeFunction    = types.EntityType("Function")
	typeUtility     = types.EntityType("Utility")
)

// TokenKind is the `proxy_token` row kind. Ported from Tokens.kt:31-36, which A4 owns — the constant
// VALUES are the Kotlin enum constant NAMES because Authz.kt:421,424 marshals `kind?.name` into both
// the Token EUID and the Cedar `kind` attribute, so the name is a wire contract here.
//
// TODO(A4): when the tokens area lands, this should become an alias of A4's type rather than a second
// declaration — see 04-auth-session-tokens.md.
type TokenKind string

const (
	TokenKindSession      TokenKind = "SESSION"       // daemon-held short-lived session (`pm login`)
	TokenKindUser         TokenKind = "USER"          // generated PAT, pasted / injected by the user
	TokenKindEditor       TokenKind = "EDITOR"        // stateful editor session
	TokenKindApproverExec TokenKind = "APPROVER_EXEC" // approver running an approved query under role R
)

// AuthzResource is the Cedar-side resource an AuthzAction applies to — Authz.kt:62-94's
// `sealed interface AuthzResource` with its six variants. Marshalled to Cedar entities by Authz;
// callers never touch cedar-go types directly.
//
// Go has no sealed interfaces, so the seal is an unexported marker method: only this package can
// implement AuthzResource, which is the property the Kotlin `sealed` keyword buys.
//
// 🔒 INV-A2-2 — there is deliberately NO Datasource variant. All five batch/extension entry points key
// Datasource::"<name>" themselves and do NOT route through Authz.Authorize or marshalResource.
// Authz.kt:756-758 documents an `AuthzResource.Datasource` variant that keys off the numeric id; that
// variant does not exist (marshalResource has exactly six branches). Per F1 the stale KDoc is the OMIT
// half — a comment with no call path has no observable behaviour — while the name-keyed marshalling it
// warns about is REPRODUCEd verbatim in authz.go.
type AuthzResource interface {
	isAuthzResource()
}

// ResourceSystem is the instance-wide admin scope: admin.* actions are not scoped to one entity.
// EUID System::"system", no attributes, no parents.
type ResourceSystem struct{}

// ResourceAuditRecord is one audit decision, carrying the principal that owns the record.
// EUID AuditRecord::"<principal>", attribute principal: User::"<principal>".
type ResourceAuditRecord struct {
	Principal string
}

// ResourceAuditLog is the whole audit collection, for policies granting a global read capability.
// EUID AuditLog::"all", no attributes, no parents.
type ResourceAuditLog struct{}

// ResourceApprovalRequest is a task request. Datasource and Role parents support scoped lifecycle
// policies. EUID Request::"<requester>#<datasourceName or "-">".
//
// Approver and ExecutedBy are POINTERS because the schema declares them optional and Authz.kt:394-395
// marshals them only when present: absence is what a `resource has approver` guard reads, and emitting
// a placeholder would make a pre-decision task satisfy an approver-conditioned policy.
type ResourceApprovalRequest struct {
	Requester      string
	Approver       *string
	ExecutedBy     *string
	DatasourceName *string
	RoleName       *string
}

// ResourceAccessGrant is an issued JIT access grant (`access_grant` row). Owner is the elevated
// principal, so an ownership policy scopes read/revoke (resource.owner == principal).
// DatasourceName/RoleName, when set, attach the grant's Datasource/Role as Cedar parents so a
// per-datasource / per-role revoke policy matches. ID only disambiguates the EUID.
// EUID AccessGrant::"<owner>#<id>".
type ResourceAccessGrant struct {
	Owner          string
	ID             int64
	DatasourceName *string
	RoleName       *string
}

// ResourceToken is a wire/personal-access token being minted or managed (`proxy_token` row).
// EUID Token::"<owner>#<kind or "-">".
//
// 🔒 INV-A2-3 — Kind ABSENCE is meaningful. A nil Kind (e.g. listing a principal's tokens) leaves the
// Cedar `kind` attribute ABSENT, which is what lets a policy permit short sessions while forbidding
// long-lived PATs. Emitting kind: "" or kind: "null" would break those policies, so this is a pointer
// and the attribute is omitted, never defaulted.
type ResourceToken struct {
	Owner string
	Kind  *TokenKind
}

func (ResourceSystem) isAuthzResource()          {}
func (ResourceAuditRecord) isAuthzResource()     {}
func (ResourceAuditLog) isAuthzResource()        {}
func (ResourceApprovalRequest) isAuthzResource() {}
func (ResourceAccessGrant) isAuthzResource()     {}
func (ResourceToken) isAuthzResource()           {}

// marshalResource ports Authz.kt:362-428. Returns the resource EUID plus every entity that must be in
// the batch for it — 02-authz.md §3's EUID table is the complete marshalling contract and every format
// below is a wire contract.
//
// The returned entity ORDER matters: it is the order dedupeEntities sees, and dedupe is FIRST-wins
// (see entities.go). Kotlin builds `listOf(theResource) + extraEntities`, so the resource entity
// always precedes the bare Datasource/Role placeholders it references.
func marshalResource(resource AuthzResource) (types.EntityUID, []types.Entity) {
	switch r := resource.(type) {
	case ResourceSystem:
		return types.NewEntityUID(typeSystem, "system"), nil

	case ResourceAuditRecord:
		euid := types.NewEntityUID(typeAuditRecord, types.String(r.Principal))
		ent := types.Entity{
			UID: euid,
			Attributes: types.NewRecord(types.RecordMap{
				"principal": types.NewEntityUID(typeUser, types.String(r.Principal)),
			}),
		}
		return euid, []types.Entity{ent}

	case ResourceAuditLog:
		return types.NewEntityUID(typeAuditLog, "all"), nil

	case ResourceApprovalRequest:
		var extra []types.Entity
		var parents []types.EntityUID
		if r.DatasourceName != nil {
			ds := types.NewEntityUID(typeDatasource, types.String(*r.DatasourceName))
			parents = append(parents, ds)
			extra = append(extra, types.Entity{UID: ds})
		}
		if r.RoleName != nil {
			role := types.NewEntityUID(typeRole, types.String(*r.RoleName))
			parents = append(parents, role)
			extra = append(extra, types.Entity{UID: role})
		}
		// EUID: Request::"<requester>#<datasourceName ?: "-">".
		dsPart := "-"
		if r.DatasourceName != nil {
			dsPart = *r.DatasourceName
		}
		euid := types.NewEntityUID(typeRequest, types.String(r.Requester+"#"+dsPart))
		attrs := types.RecordMap{
			"requester": types.NewEntityUID(typeUser, types.String(r.Requester)),
		}
		if r.Approver != nil {
			attrs["approver"] = types.NewEntityUID(typeUser, types.String(*r.Approver))
		}
		if r.ExecutedBy != nil {
			attrs["executedBy"] = types.NewEntityUID(typeUser, types.String(*r.ExecutedBy))
		}
		req := types.Entity{
			UID:        euid,
			Attributes: types.NewRecord(attrs),
			Parents:    types.NewEntityUIDSet(parents...),
		}
		return euid, append([]types.Entity{req}, extra...)

	case ResourceAccessGrant:
		var extra []types.Entity
		var parents []types.EntityUID
		if r.DatasourceName != nil {
			ds := types.NewEntityUID(typeDatasource, types.String(*r.DatasourceName))
			parents = append(parents, ds)
			extra = append(extra, types.Entity{UID: ds})
		}
		if r.RoleName != nil {
			role := types.NewEntityUID(typeRole, types.String(*r.RoleName))
			parents = append(parents, role)
			extra = append(extra, types.Entity{UID: role})
		}
		euid := types.NewEntityUID(typeAccessGrant, types.String(r.Owner+"#"+strconv.FormatInt(r.ID, 10)))
		grant := types.Entity{
			UID: euid,
			Attributes: types.NewRecord(types.RecordMap{
				"owner": types.NewEntityUID(typeUser, types.String(r.Owner)),
			}),
			Parents: types.NewEntityUIDSet(parents...),
		}
		return euid, append([]types.Entity{grant}, extra...)

	case ResourceToken:
		kindPart := "-"
		attrs := types.RecordMap{
			"owner": types.NewEntityUID(typeUser, types.String(r.Owner)),
		}
		// INV-A2-3: absent, never "" and never "null".
		if r.Kind != nil {
			kindPart = string(*r.Kind)
			attrs["kind"] = types.String(*r.Kind)
		}
		euid := types.NewEntityUID(typeToken, types.String(r.Owner+"#"+kindPart))
		return euid, []types.Entity{{UID: euid, Attributes: types.NewRecord(attrs)}}
	}

	// Unreachable: AuthzResource is sealed by the unexported marker method, so the six cases above are
	// exhaustive. Kotlin's `when` over a sealed interface is checked by the compiler; Go's type switch
	// is not, so this arm exists to make a future seventh variant fail loudly rather than authorize
	// against a zero EUID.
	panic("authz: marshalResource: unhandled AuthzResource variant")
}
