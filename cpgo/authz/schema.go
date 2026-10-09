// Package authz decides Cedar authorization in Go with cedar-go, building the same entities and context the
// Kotlin Authz does, so a decision made here matches one made there.
package authz

import (
	_ "embed"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// schemaText is the authorization schema. It is a copy of the Kotlin control plane's
// control-plane/src/main/resources/authz/schema.cedarschema; a test fails when the two differ.
//
//go:embed schema.cedarschema
var schemaText string

var (
	contextTagAction = regexp.MustCompile(`Action::"context\.tag::([^"]+)"`)
	cedarEscape      = regexp.MustCompile(`\\(u\{([0-9A-Fa-f]{1,6})\}|.)`)
	actionDecl       = regexp.MustCompile(`action\s+((?:"[^"]+"\s*,?\s*)+?)(?:in\s*\[([^\]]*)])?\s*appliesTo`)
	quoted           = regexp.MustCompile(`"([^"]+)"`)
)

// actionParents maps each schema action to the action groups it is declared in.
var actionParents = func() map[string][]string {
	out := map[string][]string{}
	for _, m := range actionDecl.FindAllStringSubmatch(schemaText, -1) {
		var parents []string
		for _, p := range quoted.FindAllStringSubmatch(m[2], -1) {
			parents = append(parents, p[1])
		}
		for _, n := range quoted.FindAllStringSubmatch(m[1], -1) {
			out[n[1]] = append(out[n[1]], parents...)
		}
	}
	return out
}()

// actionAncestry is the action and every group above it, each with its direct parents; empty for an action
// in no group. Cedar evaluates schema-free, so the groups must ride in as entities.
func actionAncestry(action string) map[string][]string {
	out := map[string][]string{}
	pending := []string{action}
	for len(pending) > 0 {
		a := pending[0]
		pending = pending[1:]
		if _, seen := out[a]; seen {
			continue
		}
		out[a] = actionParents[a]
		pending = append(pending, actionParents[a]...)
	}
	if len(out) == 1 && len(out[action]) == 0 {
		return nil
	}
	return out
}

// contextTagNames are the tags a policy source derives: the T of each Action::"context.tag::T".
func contextTagNames(src string) []string {
	var out []string
	for _, m := range contextTagAction.FindAllStringSubmatch(src, -1) {
		if !slices.Contains(out, m[1]) {
			out = append(out, m[1])
		}
	}
	return out
}

// unescapeCedarString decodes a Cedar string literal's escapes, so two spellings of one tag name collapse.
func unescapeCedarString(s string) string {
	return cedarEscape.ReplaceAllStringFunc(s, func(m string) string {
		sub := cedarEscape.FindStringSubmatch(m)
		if sub[2] != "" {
			n, err := strconv.ParseUint(sub[2], 16, 32)
			if err != nil || n > 0x10FFFF || !utf8.ValidRune(rune(n)) {
				return m
			}
			return string(rune(n))
		}
		switch sub[1] {
		case "n":
			return "\n"
		case "r":
			return "\r"
		case "t":
			return "\t"
		case "0":
			return "\x00"
		case `\`, "'", `"`:
			return sub[1]
		}
		return sub[1]
	})
}

// schemaTextFor is the schema with a context.tag::<name> action declared for each tag the policies derive.
func schemaTextFor(tagNames []string) string {
	if len(tagNames) == 0 {
		return schemaText
	}
	seen := map[string]bool{}
	var names []string
	for _, n := range tagNames {
		if key := unescapeCedarString(n); !seen[key] {
			seen[key] = true
			names = append(names, n)
		}
	}
	slices.Sort(names)
	var b strings.Builder
	b.WriteString(schemaText)
	b.WriteString("\n")
	for i, n := range names {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(`action "context.tag::` + n + `" appliesTo { principal: [User, Role], resource: [Datasource], ` +
			`context: { channel?: String, requester_ip?: ipaddr, tailscale_caps?: Set<String>, native_operation?: String } };`)
	}
	return b.String()
}
