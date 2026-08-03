package authz

import (
	"strings"

	"github.com/cedar-policy/cedar-go/types"
)

// 🔒 INV-A2-7 — reserved tag namespaces are TYPE-SCOPED, enforced HERE at Cedar marshalling, not only
// at the admin write API (Authz.kt:232-234).
//
//   - system:development / system:production marshal ONLY onto a Datasource (datasourceEntity filters
//     to datasourcePostureTags; all other datasource tags are dropped as parents, though free-form tags
//     are carried and inert).
//   - Every other system:* tag (system:critical, activity, data-leak, catalog) attaches to a Table/
//     Column/Function/Utility ONLY from the shipped manifest, passed in as systemTags — never honoured
//     from a user-authored column tag.
//   - Column parents are built from tags filtered by !isReservedTag. A column's real system tag is
//     inherited transitively through its Table parent.
//   - udf:output-vouched is valid only on a UDF Function.
//
// Attack this prevents: a Column whose catalog row carried a hand-written system:development (or a
// forged system:critical) would satisfy a preset permit or bypass a shipped forbid and LEAK CLEARTEXT.
// PresetPolicyDbTest case 9 is the regression test.
var datasourcePostureTags = map[string]bool{
	"system:development": true,
	"system:production":  true,
}

func isReservedTag(t string) bool {
	return strings.HasPrefix(t, "system:") || t == "udf:output-vouched"
}

// tagEuidCache is the port of the `HashMap<String, EntityUID>` every batch entry point threads through
// its marshalling (Authz.kt:471 and friends) so ONE Tag EUID object is reused across the batch. In Go
// an EntityUID is a comparable value, not an object identity, so the map is not strictly needed for
// sharing — but it is retained because the SET OF KEYS is what tagEntities is built from, and dropping
// it would change which bare Tag entities land in the batch.
type tagEuidCache struct {
	order []string // insertion order — HashMap.values() order is unspecified in Kotlin, so any stable
	seen  map[string]types.EntityUID
}

func newTagEuidCache() *tagEuidCache {
	return &tagEuidCache{seen: map[string]types.EntityUID{}}
}

// getOrPut mirrors Kotlin's tagEuids.getOrPut(tag) { TAG_TYPE.of(tag) }.
func (c *tagEuidCache) getOrPut(tag string) types.EntityUID {
	if u, ok := c.seen[tag]; ok {
		return u
	}
	u := types.NewEntityUID(typeTag, types.String(tag))
	c.seen[tag] = u
	c.order = append(c.order, tag)
	return u
}

// entities returns one bare Tag entity per cached EUID — Kotlin's `tagEuids.values.map { Entity(it) }`.
func (c *tagEuidCache) entities() []types.Entity {
	out := make([]types.Entity, 0, len(c.order))
	for _, t := range c.order {
		out = append(out, types.Entity{UID: c.seen[t]})
	}
	return out
}

// datasourceEntity ports Authz.kt:239-249: the Datasource entity carrying ONLY its recognized POSTURE
// Tag parents (every other tag dropped), so a policy's `resource in Tag::"system:development"` matches
// this datasource AND — transitively via the Datasource parent — every Table/Column/Function under it.
func datasourceEntity(dsEuid types.EntityUID, name string, datasourceTags []string, tags *tagEuidCache) types.Entity {
	var parents []types.EntityUID
	for _, t := range datasourceTags {
		if datasourcePostureTags[t] {
			parents = append(parents, tags.getOrPut(t))
		}
	}
	return types.Entity{
		UID:        dsEuid,
		Attributes: types.NewRecord(types.RecordMap{"name": types.String(name)}),
		Parents:    types.NewEntityUIDSet(parents...),
	}
}

// principalEntities ports the four lines every entry point opens with (e.g. Authz.kt:345-348): the
// User entity carrying its resolved roles as Cedar graph parents, plus one BARE Role entity each.
//
// The principal entity and the role entities are returned separately because the batch entry points
// interleave the datasource entity between them (Authz.kt:519) and dedupeEntities is FIRST-wins, so
// the group order is part of the port.
func principalEntities(principal string, roles []string) (types.EntityUID, types.Entity, []types.Entity) {
	roleEuids := make([]types.EntityUID, 0, len(roles))
	for _, r := range roles {
		roleEuids = append(roleEuids, types.NewEntityUID(typeRole, types.String(r)))
	}
	principalEuid := types.NewEntityUID(typeUser, types.String(principal))
	principalEntity := types.Entity{UID: principalEuid, Parents: types.NewEntityUIDSet(roleEuids...)}
	roleEntities := make([]types.Entity, 0, len(roleEuids))
	for _, re := range roleEuids {
		roleEntities = append(roleEntities, types.Entity{UID: re})
	}
	return principalEuid, principalEntity, roleEntities
}

// dedupeEntities ports dedupeByEuid (Authz.kt:254-258): FIRST-wins collapse of entities sharing an
// EUID, via LinkedHashMap.putIfAbsent.
//
// Why the Kotlin has it: cedar-java rejects a set containing two distinct Entity objects for one
// EntityUID outright ("duplicate entity entry"), EVEN when structurally identical. That is load-bearing
// in authorizeAs — an ApprovalRequest.roleName equal to one of the principal's own roles produces
// exactly that collision (AuthzTest case 8).
//
// Why the port keeps it anyway. cedar-go models entities as a map keyed by UID, so a naive
// `m[e.UID] = e` collapses duplicates for free — but LAST-wins, which is a different function from
// Kotlin's FIRST-wins. The spike (S6/W7) measured that every collision reachable today is between
// STRUCTURALLY EQUAL entities, so the two agree at every live call site, and recommended OMIT + a guard
// test. 02-authz.md §11 Q2 takes the opposite line: "a map-keyed Go entity set that silently last-wins
// is a behaviour change". This port takes the strictly safer intersection — reproduce FIRST-wins
// explicitly (three lines) so the two implementations agree by CONSTRUCTION rather than by an
// invariant that one refactor away from authorizeColumns' un-deduped per-ColumnRef append could break.
// The W7 guard test is kept as well; with first-wins it can only ever pass.
//
// The one behaviour deliberately NOT reproduced is cedar-java's duplicate-entity ERROR. No test asserts
// it (verified by the spike: zero hits for "duplicate entity"/"dedupeByEuid" in control-plane/src/test),
// and it is unreachable anyway because dedupeByEuid runs first on every path.
func dedupeEntities(groups ...[]types.Entity) types.EntityMap {
	m := types.EntityMap{}
	for _, g := range groups {
		for _, e := range g {
			if _, exists := m[e.UID]; !exists {
				m[e.UID] = e
			}
		}
	}
	return m
}

// hasColumnDelim is the delimiter guard for columns and tables — Authz.kt:482.
//
// 🔒 INV-A2-6 — both '/' (the EUID join) and '.' (the analyzer key join) are legal INSIDE a quoted SQL
// identifier. A component containing either would let two distinct identities render to one EUID —
// schema "public/a" + table "users" and schema "public" + table "a/users" both become
// ".../public/a/users" — a wrong-grant collision. Any ref whose resolved identity (INCLUDING the
// datasource name) contains a delimiter builds NO EUID and is DENIED fail-closed.
func hasColumnDelim(s string) bool {
	return strings.ContainsAny(s, "/.")
}

// hasNameDelim is the delimiter guard for functions and utilities — Authz.kt:650, :715. '/' ONLY.
//
// 🔒 INV-A2-6, second half. The asymmetry with hasColumnDelim is INTENTIONAL (a function name cannot
// carry the analyzer's dot-qualification) but is a sharp edge — replicate exactly, do not unify.
func hasNameDelim(s string) bool {
	return strings.Contains(s, "/")
}
