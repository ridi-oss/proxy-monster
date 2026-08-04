package differential

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------------------------
// THE NORMALISER — the only place in this harness where a real divergence could hide.
//
// 🔒 EVERY RULE HERE IS A LIABILITY. A normaliser that is too aggressive turns the whole harness into a
// green light that proves nothing, and unlike a missing test that failure is invisible: the report says
// "0 divergences" either way. So each rule below states WHAT varies, WHY it cannot be pinned, and is
// scoped to the narrowest field that fixes it.
//
// The rules fall into exactly three admissible classes. Anything that is not one of these three is a
// REAL divergence and must be reported:
//
//  1. IDENTIFIERS assigned by the database. Two separately-migrated stores hand out the same sequence
//     values for the same seeded rows, but a write case's new row gets an id that depends on how many
//     rows preceded it — which the two planes' own seed data can legitimately differ on.
//  2. CLOCKS. Timestamps, and any deadline computed from `now()`.
//  3. SECRETS AND DIGESTS. Tokens, session ids, cookie values, hash chains — CSPRNG output by
//     construction, so equality would be a bug, not a property.
//
// ⚠️ NOT admissible, and deliberately absent: any rule touching a status code, an error `code`, a field
// NAME, a field's PRESENCE, an array's LENGTH, or a boolean. Those are exactly what a port gets wrong.
// ---------------------------------------------------------------------------------------------

// volatileKeys are JSON object keys whose VALUE is replaced by a placeholder. The key itself, and
// therefore its presence, is still compared — so a plane that omitted `expiresAt` entirely still fails.
var volatileKeys = map[string]string{
	// (1) database-assigned identity.
	"id":         "<id>",
	"roleId":     "<id>",
	"sessionId":  "<id>",
	"decisionId": "<id>",
	"maskFnId":   "<id>",

	// (2) clocks. Every one of these is `now()` or a deadline derived from it.
	"now":               "<time>",
	"createdAt":         "<time>",
	"updatedAt":         "<time>",
	"decidedAt":         "<time>",
	"requestedAt":       "<time>",
	"executingAt":       "<time>",
	"executedAt":        "<time>",
	"expiresAt":         "<time>",
	"idleExpiresAt":     "<time>",
	"absoluteExpiresAt": "<time>",
	"lastSeenAt":        "<time>",
	"catalogSyncedAt":   "<time>",
	"endedAt":           "<time>",

	// (3) secrets and digests.
	"token":        "<secret>",
	"renewalToken": "<secret>",
	"rowHash":      "<digest>",
	"prevHash":     "<digest>",
	"headHash":     "<digest>",
}

// timestampLike catches an ISO-8601 instant appearing somewhere volatileKeys does not reach — inside a
// message string, say. Scoped to the full-instant shape so it cannot eat an ordinary number or a date
// that is part of a fixture.
var timestampLike = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})`)

// Normalize canonicalises one response body for comparison.
//
// A body that is not JSON is returned with only the timestamp rule applied — it is still compared
// byte-for-byte otherwise, which is what keeps the SCIM and OAuth bodies honest.
func Normalize(body string) string {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return ""
	}
	var v any
	if err := json.Unmarshal([]byte(trimmed), &v); err != nil {
		return timestampLike.ReplaceAllString(trimmed, "<time>")
	}
	// Re-marshal through the walker: this also canonicalises key ORDER, which differs between kotlinx
	// and encoding/json without being a divergence anyone can observe through a JSON client.
	out, err := json.Marshal(walk(v))
	if err != nil {
		return trimmed
	}
	return timestampLike.ReplaceAllString(string(out), "<time>")
}

// walk applies volatileKeys recursively and sorts arrays of objects by their remaining content, so a
// listing endpoint's ORDER does not have to match unless the order is itself meaningful.
//
// ⚠️ SORTING ARRAYS IS THE MOST DANGEROUS RULE IN THIS FILE, because several endpoints DO have a
// contractual order (A9's `ORDER BY name`, and RoleResolver's effectiveRoles whose order reaches the
// wire). It is applied only AFTER normalisation and only to arrays whose elements are objects, and the
// harness's own `OrderSensitive` list opts specific paths out. If in doubt the answer is to opt out:
// a false "same" on ordering is exactly the class of bug this harness exists to catch.
func walk(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if placeholder, volatile := volatileKeys[k]; volatile {
				// Preserve the DISTINCTION between null and present-but-volatile: a plane that returns
				// null where the other returns a value is a divergence, not noise.
				if val == nil {
					out[k] = nil
					continue
				}
				out[k] = placeholder
				continue
			}
			out[k] = walk(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = walk(e)
		}
		return out
	default:
		return v
	}
}

// SortArrays is applied only to cases NOT in OrderSensitive. Kept separate from walk so the harness
// decides per case rather than globally.
func SortArrays(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = SortArrays(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = SortArrays(e)
		}
		keys := make([]string, len(out))
		for i, e := range out {
			b, _ := json.Marshal(e)
			keys[i] = string(b)
		}
		idx := make([]int, len(out))
		for i := range idx {
			idx[i] = i
		}
		sort.SliceStable(idx, func(a, b int) bool { return keys[idx[a]] < keys[idx[b]] })
		sorted := make([]any, len(out))
		for i, j := range idx {
			sorted[i] = out[j]
		}
		return sorted
	default:
		return v
	}
}

// OrderSensitive names the cases whose array order IS contractual, so the harness compares them
// unsorted. Each entry cites why.
var OrderSensitive = map[string]string{
	// A9: `SELECT … ORDER BY name` — the console renders the list as returned.
	"roles":                      "PolicyStore.listRoles orders by name; the console does not re-sort",
	"list-roles-after-create":    "same ORDER BY name, and the new row's position in it is the assertion",
	"mask-fns":                   "listMaskFns orders by name",
	"list-mask-fns-after-create": "same",
	// A9: `ORDER BY pr.principal, r.name`.
	"role-assignments": "listAssignments orders by principal then role name",
	// A2: policy listing order drives the Cedar PolicySet build order.
	"policies": "CedarPolicyStore ordering feeds the engine's PolicySet",
	// A4: /auth/me's roles are effectiveRoles, whose order reaches the wire (RoleResolver doc).
	"auth-me": "effectiveRoles order is observable (RoleResolver: no ORDER BY, deliberately)",
}
