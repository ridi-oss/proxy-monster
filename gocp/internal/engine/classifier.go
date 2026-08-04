package engine

import (
	"fmt"
	"strings"
)

// SystemManifestError is a manifest that fails boot validation (docs/system-classification.md) —
// fail-closed, aborts startup. Ports `class SystemManifestException(message: String) : Exception`.
//
// 🔒 INV-A13-19: ANY manifest problem aborts startup, "like a failed Flyway migration". The Kotlin
// throws from a constructor; Go returns this from NewSystemClassifier / LoadSystemClassificationStore
// and the caller must treat it as fatal. Coverage gaps here are security gaps: a manifest that loads
// half-validated silently downgrades a credential surface.
type SystemManifestError struct{ Message string }

func (e *SystemManifestError) Error() string { return e.Message }

func manifestErrf(format string, args ...any) *SystemManifestError {
	return &SystemManifestError{Message: fmt.Sprintf(format, args...)}
}

// schemaName is the (folded schema, folded name) key of the two exact maps. Go's map key rules make
// Kotlin's Pair unnecessary.
type schemaName struct {
	schema string
	name   string
}

// prefixTag is one entry of a schema's family list: (folded prefix, tag).
type prefixTag struct {
	prefix string
	tag    SystemTag
}

// SystemClassifier is a compiled, validated SystemManifest that classifies a resource into exactly one
// SystemTag (or none, when the object is not in an exposed system surface). Compilation builds hash maps
// plus schema-scoped prefix lists so a decision classifies each distinct key once, rather than scanning
// every rule.
//
// 🔒 INV-A13-25: matching is case-insensitive and SCOPED to the manifest's own schemas. System schemas
// and their objects are conventionally lower-case and matching only happens inside the manifest's
// schemas, so folding cannot catch a user object — which is what lets a manifest store the canonical
// server spelling (information_schema.USER_PRIVILEGES) and still match a lower-cased resolved identity.
//
// The caller passes an already schema-resolved (catalog, schema, name) identity
// (mapping-schema-construction.md); the classifier owns only the manifest lookup, never namespace
// resolution.
type SystemClassifier struct {
	manifest SystemManifest

	systemSchemas map[string]struct{}
	// logicalSchemas is keyed by FOLDED SCHEMA ONLY — F30: the entry's catalog is dropped here and never
	// consulted by classifyFunction, unlike systemSchemas which isSystemSchema does check. A MySQL
	// manifest's `def` pin on def/__builtin__ is therefore inert: a function in schema __builtin__ under
	// ANY catalog takes the CATALOG default plus the in-schema rules. The direction is fail-safe
	// (over-classify), so it is REPRODUCEd as-is.
	logicalSchemas map[string]struct{}

	relationExact    map[schemaName]SystemTag
	functionExact    map[schemaName]SystemTag
	relationFamilies map[string][]prefixTag
	functionFamilies map[string][]prefixTag
	// commandTags is keyed by the RAW command id with no fold, unlike everything else. Command ids are
	// analyzer-emitted constants (SHOW_PROCESSLIST), so this is consistent in practice — but it is an
	// inconsistency to replicate exactly, not to "unify" (13-engine.md §4.4, Q9).
	commandTags map[string]SystemTag
	// functionAnySchema holds the cross-schema (schema "*") function rules, keyed by folded name.
	functionAnySchema map[string]SystemTag
}

// Manifest returns the manifest this classifier compiled. Kotlin exposes it as `val manifest`.
func (c *SystemClassifier) Manifest() SystemManifest { return c.manifest }

// fold is Kotlin's `private fun fold(s: String) = s.lowercase()` — a FULL Unicode, locale-independent
// lowering, not the ASCII-only fold the Kotlin doc comment claims (13-engine.md Q3). Go's
// strings.ToLower is also full Unicode and locale-independent, so the two agree today.
func fold(s string) string { return strings.ToLower(s) }

// NewSystemClassifier compiles and VALIDATES a manifest, returning a *SystemManifestError on any
// violation (bad tag, duplicate exact identity with a different tag, overlapping families with different
// tags, or an exact rule that would downgrade a stronger family by match ordering).
//
// Build order is load-bearing and matches Kotlin exactly: the property initializers — which call
// requireTag — run BEFORE validate(). So a manifest with both a non-system tag and a wildcard relation
// rule surfaces the TAG error, not the wildcard error, and the error strings stay comparable across the
// port. Within the initializers the order is the Kotlin declaration order: systemSchemas,
// logicalSchemas, relationExact, functionExact, relationFamilies, functionFamilies, commandTags,
// functionAnySchema.
func NewSystemClassifier(manifest SystemManifest) (*SystemClassifier, error) {
	c := &SystemClassifier{manifest: manifest}
	id := c.manifestID()

	c.systemSchemas = foldedSchemaSet(manifest.SystemSchemas)
	c.logicalSchemas = foldedSchemaSet(manifest.LogicalFunctionSchemas)

	var err error
	if c.relationExact, err = exactMap(id, manifest.Relations, "relation"); err != nil {
		return nil, err
	}
	if c.functionExact, err = exactMap(id, manifest.Functions, "function"); err != nil {
		return nil, err
	}
	if c.relationFamilies, err = familyMap(id, manifest.RelationFamilies); err != nil {
		return nil, err
	}
	if c.functionFamilies, err = familyMap(id, manifest.FunctionFamilies); err != nil {
		return nil, err
	}

	// F32 (00-INDEX ledger F37) / 🔒 INV-A13-35 — REPRODUCE + PIN, the disposition the ledger records
	// ("last-pair-wins is observable at boot and can silently downgrade a credential surface — a security
	// path"). Kotlin builds commandTags with `associate`, whose documented
	// behaviour is LAST-PAIR-WINS on a repeated key: no conflict check, no strongest-first combination.
	// Two `commands` entries with the same id and different tags load silently and the LATER one wins even
	// when it is WEAKER — [{SHOW_GRANTS, system:critical}, {SHOW_GRANTS, system:catalog}] compiles to
	// CATALOG, a silent downgrade of a credential surface at boot with no error. Contrast exactMap below,
	// which THROWS on a conflicting duplicate. Verified latent, not live-wrong (no shipped manifest has a
	// duplicate command id), but it is observable, so the last-wins is reproduced here and pinned by a test
	// asserting the buggy result. Folding it into exactMap's reject-on-conflict path is the right change,
	// taken separately (13-engine.md Q9).
	c.commandTags = make(map[string]SystemTag, len(manifest.Commands))
	for _, r := range manifest.Commands {
		tag, err := requireTag(id, r.Tag, "command "+r.ID)
		if err != nil {
			return nil, err
		}
		c.commandTags[r.ID] = tag // last-wins, deliberately unchecked — F32
	}

	// F32 second half: the cross-schema (schema "*") function rules get NO duplicate check anywhere —
	// exactMap explicitly skips "*" rules, so they are never keyed there either, and `associate` here is
	// last-wins for the same reason. Also pinned by a test.
	c.functionAnySchema = make(map[string]SystemTag)
	for _, r := range manifest.Functions {
		if r.Schema != "*" {
			continue
		}
		tag, err := requireTag(id, r.Tag, "function *."+r.Name)
		if err != nil {
			return nil, err
		}
		c.functionAnySchema[fold(r.Name)] = tag // last-wins, deliberately unchecked — F32
	}

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func foldedSchemaSet(schemas []SystemSchema) map[string]struct{} {
	out := make(map[string]struct{}, len(schemas))
	for _, s := range schemas {
		out[fold(s.Schema)] = struct{}{}
	}
	return out
}

// ClassifyRelation returns the system tag for a relation, or ok=false when (catalog, schema) is not an
// exposed system schema (the caller then applies ordinary user classification).
//
// 🔒 INV-A13-22: OUTSIDE an exposed system schema the answer is absent, and INSIDE it the floor is
// CATALOG, never absent. The two are different signals to A5/A6: absent means "not a system object, apply
// ordinary user classification"; CATALOG means "a system object that is open for browsing". Collapsing
// them would either expose pg_authid as an ordinary user table or deny pg_class to everyone.
func (c *SystemClassifier) ClassifyRelation(catalog, schema, name string) (SystemTag, bool) {
	if !c.isSystemSchema(catalog, schema) {
		return 0, false
	}
	s := fold(schema)
	n := fold(name)
	tag := TagCatalog
	if t, ok := c.relationExact[schemaName{s, n}]; ok {
		tag = StrongerTag(tag, t)
	}
	for _, f := range c.relationFamilies[s] {
		if strings.HasPrefix(n, f.prefix) {
			tag = StrongerTag(tag, f.tag)
		}
	}
	return tag, true
}

// ClassifyFunction returns the system tag for a function, or ok=false when it is neither in an
// exposed/logical system schema nor a shipped cross-schema dangerous function.
//
// 🔒 INV-A13-24: a recognized cross-schema function is classified WHEREVER it is installed, and
// over-classifying a same-named user function is accepted (fail-closed). An extension can be installed
// into any schema, so scoping the rule to one schema would let `CREATE EXTENSION dblink SCHEMA myapp`
// evade the forbid. Cross-schema rules cover exacts (dblink) AND families (pageinspect heap_page_,
// bt_page_).
func (c *SystemClassifier) ClassifyFunction(catalog, schema, name string) (SystemTag, bool) {
	n := fold(name)
	s := fold(schema)
	var tag SystemTag
	var have bool
	if t, ok := c.functionAnySchema[n]; ok {
		tag, have = combine(tag, have, t)
	}
	for _, f := range c.functionFamilies["*"] {
		if strings.HasPrefix(n, f.prefix) {
			tag, have = combine(tag, have, f.tag)
		}
	}
	// In an exposed system schema (or the logical builtin schema): the catalog default + in-schema rules.
	// F30: the logicalSchemas test consults NO catalog, unlike isSystemSchema.
	_, logical := c.logicalSchemas[s]
	if c.isSystemSchema(catalog, schema) || logical {
		tag, have = combine(tag, have, TagCatalog)
		if t, ok := c.functionExact[schemaName{s, n}]; ok {
			tag, have = combine(tag, have, t)
		}
		for _, f := range c.functionFamilies[s] {
			if strings.HasPrefix(n, f.prefix) {
				tag, have = combine(tag, have, f.tag)
			}
		}
	}
	return tag, have
}

// ClassifyBareFunction classifies an UNQUALIFIED function call (docs/facts-emission.md). sqlglot drops a
// function's schema qualifier at parse time — pg_catalog.pg_read_file, mysql.rds_kill and a bare
// pg_read_file are indistinguishable post-parse — so the analyzer can only emit the bare name. It is
// resolved against the cross-schema ("*") rules AND every system/logical schema the manifest governs,
// taking the strongest tag.
//
// 🔒 INV-A13-23: unlike ClassifyFunction this NEVER adds the CATALOG default. A bare name that matches no
// dangerous rule is an ordinary safe builtin (now/count/lower) and stays UNCLASSIFIED (ok=false), so the
// control plane marshals a Cedar Function only for the dangerous ones — never a forbid on every
// projection. This is the load-bearing half of A2's INV-A2-11 ("authorizeFunctions: the caller passes
// ONLY dangerous-classified functions"): if this ever returned CATALOG, every now() and lower() in every
// query would be marshalled as a Cedar Function with no permit, and deny-by-default would break every
// query in the system. The function model is enumerate-dangerous / allow-safe — the exact inverse of the
// utility model (ClassifyCommand below).
func (c *SystemClassifier) ClassifyBareFunction(name string) (SystemTag, bool) {
	n := fold(name)
	var tag SystemTag
	var have bool
	if t, ok := c.functionAnySchema[n]; ok {
		tag, have = combine(tag, have, t)
	}
	for _, f := range c.functionFamilies["*"] {
		if strings.HasPrefix(n, f.prefix) {
			tag, have = combine(tag, have, f.tag)
		}
	}
	// Kotlin iterates `systemSchemas + logicalSchemas`, a Set union over two unordered HashSets. Iteration
	// order is not observable: every hit goes through the strongest-first combinator.
	for s := range c.systemSchemas {
		tag, have = c.combineSchemaRules(tag, have, s, n)
	}
	for s := range c.logicalSchemas {
		if _, dup := c.systemSchemas[s]; dup {
			continue // Kotlin's Set union visits a schema present in both exactly once.
		}
		tag, have = c.combineSchemaRules(tag, have, s, n)
	}
	return tag, have
}

func (c *SystemClassifier) combineSchemaRules(tag SystemTag, have bool, s, n string) (SystemTag, bool) {
	if t, ok := c.functionExact[schemaName{s, n}]; ok {
		tag, have = combine(tag, have, t)
	}
	for _, f := range c.functionFamilies[s] {
		if strings.HasPrefix(n, f.prefix) {
			tag, have = combine(tag, have, f.tag)
		}
	}
	return tag, have
}

// combine ports `private fun combine(cur: SystemTag?, new: SystemTag)`. Go has no nullable enum, so the
// Kotlin `null` is carried as a separate `have` flag rather than collapsed into a sentinel value —
// SystemTag's zero value is TagCritical, so a sentinel would silently mean "critical".
func combine(cur SystemTag, have bool, next SystemTag) (SystemTag, bool) {
	if !have {
		return next, true
	}
	return StrongerTag(cur, next), true
}

// ClassifyCommand returns the system tag of the resource a utility command exposes, or ok=false if the
// command is unmapped. Exact, UNFOLDED, no default.
//
// An absent tag here does NOT mean "safe": A5's tagForCommand and A6 step 13 make an unclassified
// RECOGNIZED utility a hard deny, precisely because an untagged Cedar Utility (Datasource parent only, no
// forbid) would be PERMITTED by a broad read grant (A2 INV-A2-11). Opposite polarity to
// ClassifyBareFunction; do not unify them.
func (c *SystemClassifier) ClassifyCommand(id string) (SystemTag, bool) {
	t, ok := c.commandTags[id]
	return t, ok
}

// isSystemSchema ports the private predicate.
//
// INV-A13-26: `catalog: "*"` matches any catalog; a pinned catalog must match exactly (folded). The
// manifest may pin a catalog ("def" for MySQL) or wildcard it ("*" for PostgreSQL, since system schemas
// repeat in every database). Step 2 is a LINEAR SCAN of the raw list, so the folded systemSchemas set in
// step 1 is only a fast reject; and `it.catalog == "*"` is an UNFOLDED literal compare.
func (c *SystemClassifier) isSystemSchema(catalog, schema string) bool {
	if _, ok := c.systemSchemas[fold(schema)]; !ok {
		return false
	}
	for _, s := range c.manifest.SystemSchemas {
		if fold(s.Schema) == fold(schema) && (s.Catalog == "*" || fold(s.Catalog) == fold(catalog)) {
			return true
		}
	}
	return false
}

// requireTag ports `private fun requireTag(id: String, where: String): SystemTag`. The `where` strings are
// "command <id>", "function *.<name>", "<kind> <schema>.<name>" and "family <schema>.<prefix>*".
func requireTag(manifestID, id, where string) (SystemTag, error) {
	t, ok := SystemTagFromID(id)
	if !ok {
		return 0, manifestErrf("%s: %s has non-system tag '%s'", manifestID, where, id)
	}
	return t, nil
}

// exactMap ports `private fun exactMap`. It skips `schema == "*"` rules (cross-schema functions are
// handled separately and are not a keyed exact), calls requireTag, keys on (folded schema, folded name),
// and REJECTS a duplicate key with a different tag. An identical duplicate is silently accepted.
//
// F25: do NOT carry the Kotlin comment "deduped strongest-first so the exact-map value is already the
// winning tag" — it is stale. Conflicts are rejected, not resolved strongest-first.
func exactMap(manifestID string, rules []ObjectRule, kind string) (map[schemaName]SystemTag, error) {
	out := make(map[schemaName]SystemTag, len(rules))
	for _, r := range rules {
		if r.Schema == "*" {
			continue // cross-schema function handled separately; not a keyed exact
		}
		tag, err := requireTag(manifestID, r.Tag, fmt.Sprintf("%s %s.%s", kind, r.Schema, r.Name))
		if err != nil {
			return nil, err
		}
		key := schemaName{fold(r.Schema), fold(r.Name)}
		if prev, ok := out[key]; ok && prev != tag {
			return nil, manifestErrf(
				"%s: duplicate exact %s %s.%s with conflicting tags %v/%v",
				manifestID, kind, r.Schema, r.Name, prev, tag,
			)
		}
		out[key] = tag
	}
	return out, nil
}

// familyMap ports `private fun familyMap`. No dedup, no sort — list order is manifest order, and since
// matching combines strongest-wins, order is not observable.
func familyMap(manifestID string, rules []FamilyRule) (map[string][]prefixTag, error) {
	out := make(map[string][]prefixTag)
	for _, r := range rules {
		tag, err := requireTag(manifestID, r.Tag, fmt.Sprintf("family %s.%s*", r.Schema, r.Prefix))
		if err != nil {
			return nil, err
		}
		key := fold(r.Schema)
		out[key] = append(out[key], prefixTag{fold(r.Prefix), tag})
	}
	return out, nil
}

// validate is the boot gate. Three checks, in Kotlin's order.
func (c *SystemClassifier) validate() error {
	id := c.manifestID()

	// 🔒 INV-A13-20 — the wildcard schema "*" is valid ONLY on a function rule (a cross-schema extension
	// function), never on a relation: a "*" relation would be silently un-keyed and classify nothing
	// (OPEN). exactMap skips "*" rules, so a "*" relation rule lands nowhere and pg_authid would classify
	// as plain CATALOG. This is a fail-open trap turned into a boot abort. Kotlin builds
	// `relations.map{schema} + relationFamilies.map{schema}` and takes the FIRST "*" — the concatenation
	// order (relations before relationFamilies) decides nothing observable, since the message names
	// neither rule.
	for _, r := range c.manifest.Relations {
		if r.Schema == "*" {
			return manifestErrf("%s: wildcard schema \"*\" is only valid on a function rule, not a relation", id)
		}
	}
	for _, r := range c.manifest.RelationFamilies {
		if r.Schema == "*" {
			return manifestErrf("%s: wildcard schema \"*\" is only valid on a function rule, not a relation", id)
		}
	}

	// F29 (00-INDEX ledger F38) — REPRODUCE, against the area doc's own "fix in the port" recommendation:
	// the ledger settles it as REPRODUCE because the hole is observable at boot.
	// Kotlin writes `for ((schema, families) in relationFamilies + functionFamilies)`,
	// where `+` on two Maps is Kotlin's Map.plus: for any schema key present in BOTH maps the right
	// operand (functionFamilies) WINS and the left operand's family list is NEVER overlap-validated.
	// The overlap is present in all four shipped manifests (pg_catalog in postgres/16 and /17, mysql in
	// mysql/8.0 and /8.4), so those relation families are currently exempt from this check. Verified
	// latent, not live-wrong — no shipped manifest is presently ambiguous — but a manifest that
	// docs/system-classification.md says must be rejected would not be. Iterating the two maps separately
	// is the fix; it is a post-cutover PR, not a change to make invisible inside a rewrite (Q6).
	shadowed := make(map[string][]prefixTag, len(c.relationFamilies)+len(c.functionFamilies))
	for schema, families := range c.relationFamilies {
		shadowed[schema] = families
	}
	for schema, families := range c.functionFamilies {
		shadowed[schema] = families // Map.plus: right operand wins, left operand's list goes unvalidated
	}
	for schema, families := range shadowed {
		// Overlapping families with different tags are ambiguous (which wins?). Reject.
		for i := range families {
			for j := range families {
				if i == j {
					continue
				}
				pa, ta := families[i].prefix, families[i].tag
				pb, tb := families[j].prefix, families[j].tag
				if strings.HasPrefix(pa, pb) && ta != tb {
					return manifestErrf(
						"%s: overlapping families in %s ('%s' ⊂ '%s') with conflicting tags %v/%v",
						id, schema, pa, pb, ta, tb,
					)
				}
			}
		}
	}

	// 🔒 INV-A13-21 — reject a manifest that merely LOOKS like it relies on match ordering. A weaker exact
	// rule whose name matches a stronger family prefix in the same schema would APPEAR to downgrade the
	// family. The strongest-first combinator already prevents the downgrade, but the doc requires
	// rejecting such a manifest anyway, so it is surfaced at boot rather than trusted to the runtime
	// combinator. This is defence-in-depth against a FUTURE refactor of the combinator, not against
	// today's runtime: dropping it because "the combinator already handles it" removes the guard that
	// makes the combinator safe to touch.
	if err := checkNoDowngrade(id, c.relationExact, c.relationFamilies, "relation"); err != nil {
		return err
	}
	// The two map pairs are passed SEPARATELY — which is why F29's Map.plus shadowing does not affect this
	// check.
	return checkNoDowngrade(id, c.functionExact, c.functionFamilies, "function")
}

// checkNoDowngrade ports the private helper. The comparison is strictly `>` on the ordinal, so equal tags
// are fine and a STRONGER exact over a weaker family is fine (the normal "raise one object out of a
// family" pattern). Iteration order over a Kotlin HashMap is unspecified, so WHICH violation is reported
// first is not contract — only that one is. Go's map iteration order is likewise unspecified, matching.
func checkNoDowngrade(manifestID string, exact map[schemaName]SystemTag, families map[string][]prefixTag, kind string) error {
	for key, exactTag := range exact {
		for _, f := range families[key.schema] {
			if strings.HasPrefix(key.name, f.prefix) && exactTag.Strength() > f.tag.Strength() {
				return manifestErrf(
					"%s: exact %s %s.%s (tag %v) is weaker than the family '%s*' (tag %v) it matches — would rely on match ordering",
					manifestID, kind, key.schema, key.name, exactTag, f.prefix, f.tag,
				)
			}
		}
	}
	return nil
}

// manifestID prefixes every exception message: "<engine>/<series>".
func (c *SystemClassifier) manifestID() string {
	return c.manifest.Engine + "/" + c.manifest.Series
}
