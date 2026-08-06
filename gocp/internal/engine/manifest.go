package engine

import "strconv"

// The shipped system classification (docs/system-classification.md, 13-engine.md §3.1). Every object in
// an exposed system schema is one of four `system:` tags; only the dangerous overrides are enumerated —
// everything else defaults to `system:catalog` (open browsing). These tags are a product fact, immutable
// and bundled per engine MAJOR version; policy over them lives in Cedar (access-model.md).
//
// That is why this area has no DB table and no admin route: an operator can change the POLICY over a tag
// but never the tag. A port that moved the manifests into the database would turn a product fact into
// operator-editable data — i.e. into a way to downgrade pg_authid from the admin console.

// SystemTag is the four-value strength lattice. Ports classification/SystemManifest.kt's enum.
//
// 🔒 INV-A13-18: the DECLARATION ORDER IS THE STRENGTH ORDER, and the ordinal is the comparison.
// Reordering these four constants silently inverts every precedence decision and every boot validation.
// Strongest-wins exists because over-classifying is safe while under-classifying a credential/data
// surface is the leak this guards.
type SystemTag int

const (
	// TagCritical is Kotlin SystemTag.CRITICAL, ordinal 0 — the strongest.
	TagCritical SystemTag = iota
	// TagDataLeak is Kotlin SystemTag.DATA_LEAK, ordinal 1.
	TagDataLeak
	// TagActivity is Kotlin SystemTag.ACTIVITY, ordinal 2.
	TagActivity
	// TagCatalog is Kotlin SystemTag.CATALOG, ordinal 3 — the weakest, the in-system-schema floor.
	TagCatalog
)

// systemTagIDs is the manifest/wire spelling of each tag, indexed by ordinal.
var systemTagIDs = [...]string{"system:critical", "system:data-leak", "system:activity", "system:catalog"}

// ID is Kotlin's `val id: String` — the manifest and Cedar spelling.
func (t SystemTag) ID() string {
	if t < 0 || int(t) >= len(systemTagIDs) {
		return ""
	}
	return systemTagIDs[t]
}

// Strength is Kotlin's enum `ordinal` — the strength rank, LOWER IS STRONGER (INV-A13-18). Named
// `strength` rather than `ordinal` per 13-engine.md §4.4's Go shape ("an int-backed enum with the same
// order plus an explicit strength accessor, NOT a string comparison"), which is also the name A5's
// datasource.SystemTag seam expects. Exposed because checkNoDowngrade compares it directly.
func (t SystemTag) Strength() int { return int(t) }

// String renders the Kotlin enum CONSTANT name (CRITICAL, DATA_LEAK, ...), not the id. Kotlin
// interpolates the enum into three SystemManifestException messages ("with conflicting tags $prev/$tag",
// "(tag $exactTag)", "(tag $familyTag)"), and Kotlin's Enum.toString() is the constant name — so the
// constant name, not the `system:` id, is what those messages must contain.
func (t SystemTag) String() string {
	switch t {
	case TagCritical:
		return "CRITICAL"
	case TagDataLeak:
		return "DATA_LEAK"
	case TagActivity:
		return "ACTIVITY"
	case TagCatalog:
		return "CATALOG"
	default:
		return "SystemTag(" + strconv.Itoa(int(t)) + ")"
	}
}

// systemTagByID ports the companion's `byId` map.
var systemTagByID = map[string]SystemTag{
	"system:critical":  TagCritical,
	"system:data-leak": TagDataLeak,
	"system:activity":  TagActivity,
	"system:catalog":   TagCatalog,
}

// SystemTagFromID is the companion's fromId: the tag for a manifest string, or ok=false if it is not
// one of the four reserved `system:` tags.
func SystemTagFromID(id string) (SystemTag, bool) {
	t, ok := systemTagByID[id]
	return t, ok
}

// StrongerTag is the companion's `stronger(a, b)` — the classifier's precedence combinator. The
// stronger (LOWER-ordinal) of two tags; ties keep a, matching Kotlin's `if (a.ordinal <= b.ordinal) a`.
func StrongerTag(a, b SystemTag) SystemTag {
	if a.Strength() <= b.Strength() {
		return a
	}
	return b
}

// SystemSchema is an exposed system schema. `catalog: "*"` = any catalog (PostgreSQL, where system
// schemas repeat in every database); a pinned catalog ("def" for MySQL) must match.
type SystemSchema struct {
	Catalog string `json:"catalog"`
	Schema  string `json:"schema"`
}

// ObjectRule is an exact object rule: schema + object name → tag. `schema: "*"` is legal only on a
// FUNCTION rule (INV-A13-20); a "*" relation rule aborts boot.
type ObjectRule struct {
	Schema string `json:"schema"`
	Name   string `json:"name"`
	Tag    string `json:"tag"`
}

// FamilyRule is a validated prefix family (e.g. pg_stat_progress_*) → tag. Prefix match only, no regex.
type FamilyRule struct {
	Schema string `json:"schema"`
	Prefix string `json:"prefix"`
	Tag    string `json:"tag"`
}

// CommandRule is a utility command → the resource it exposes + that resource's tag (SHOW/DESCRIBE/…).
//
// F31: Resource is decoded from every shipped manifest and NEVER READ by any code in the repo —
// commandTags consumes only Id and Tag. It is documentation inside a data file. Keep the field (it is
// part of the manifest contract and round-trips), but do not model it as behaviour.
type CommandRule struct {
	ID       string `json:"id"`
	Resource string `json:"resource"`
	Tag      string `json:"tag"`
}

// SystemManifest is one bundled manifest, decoded from manifests/<engine>/<series>.json. Declarative:
// schemas + exact/family relation & function rules + the utility-command map. Series is the engine major
// (PostgreSQL "17", MySQL "8.0"/"8.4").
//
// The Kotlin decodes this with `Json { ignoreUnknownKeys = true }`, so a manifest may carry extra
// provenance keys — Go's encoding/json ignores unknown keys by default, which matches. All fields use the
// Kotlin property name verbatim (no @SerialName anywhere in the area), so the JSON tags below are the
// Kotlin property names unchanged.
//
// Every list field defaults to empty in Kotlin; a nil slice here is the same observable thing (len 0).
// ManifestVersion is read but never validated or compared anywhere, and CuratedThrough is provenance
// only, never read by code — both REPRODUCEd as decoded-and-unused (13-engine.md Q8).
type SystemManifest struct {
	Engine          string `json:"engine"`
	Series          string `json:"series"`
	ManifestVersion int    `json:"manifestVersion"`
	CuratedThrough  string `json:"curatedThrough"`

	SystemSchemas []SystemSchema `json:"systemSchemas"`
	// LogicalFunctionSchemas are resource-only Function namespaces never introspected as real databases
	// (MySQL def/__builtin__). F30: their Catalog is never consulted — see classifier.go.
	LogicalFunctionSchemas []SystemSchema `json:"logicalFunctionSchemas"`

	Relations        []ObjectRule  `json:"relations"`
	RelationFamilies []FamilyRule  `json:"relationFamilies"`
	Functions        []ObjectRule  `json:"functions"`
	FunctionFamilies []FamilyRule  `json:"functionFamilies"`
	Commands         []CommandRule `json:"commands"`
}
