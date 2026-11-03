package workload

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

type Kind string

const (
	KindGeneric       Kind = "generic"
	KindGitHubActions Kind = "github-actions"
	KindAWSSTS        Kind = "aws-sts"
	KindHCPTerraform  Kind = "hcp-terraform"
	KindKubernetes    Kind = "kubernetes"
)

var kinds = []Kind{KindGeneric, KindGitHubActions, KindAWSSTS, KindHCPTerraform, KindKubernetes}

const awsNamespace = "https://sts.amazonaws.com/"

func inferKind(u *url.URL) Kind {
	host := strings.ToLower(u.Hostname())
	switch {
	case host == "token.actions.githubusercontent.com":
		return KindGitHubActions
	case strings.HasSuffix(host, ".tokens.sts.global.api.aws"):
		return KindAWSSTS
	case host == "app.terraform.io":
		return KindHCPTerraform
	case strings.HasPrefix(host, "oidc.eks.") && strings.HasSuffix(host, ".amazonaws.com"):
		return KindKubernetes
	}
	return KindGeneric
}

func (k Kind) algorithms() []string {
	if k == KindAWSSTS {
		return []string{"ES384", "RS256"}
	}
	return []string{"RS256"}
}

func ApplyKinds(issuers []Issuer, raw string) ([]Issuer, error) {
	out := slices.Clone(issuers)
	for entry := range strings.SplitSeq(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, kind, ok := strings.Cut(entry, "=")
		name, kind = strings.TrimSpace(name), strings.TrimSpace(kind)
		i := slices.IndexFunc(out, func(c Issuer) bool { return c.Name == name })
		if !ok || i < 0 || !slices.Contains(kinds, Kind(kind)) {
			return nil, fmt.Errorf("PM_WORKLOAD_ISSUER_KINDS entry '%s' must be '<issuer name>=<%s>' naming a PM_CI_OIDC_ISSUERS issuer",
				entry, strings.Join(kindNames(), "|"))
		}
		out[i].Kind = Kind(kind)
	}
	return out, nil
}

func kindNames() []string {
	out := make([]string, len(kinds))
	for i, k := range kinds {
		out[i] = string(k)
	}
	return out
}

type Claims map[string][]string

const (
	flattenDepth = 4
	claimsKept   = 64
	claimValue   = 512
)

var registered = []string{"iss", "aud", "exp", "iat", "nbf", "jti"}

func flatten(raw map[string]any) Claims {
	out := Claims{}
	var walk func(prefix string, v any, depth int)
	walk = func(prefix string, v any, depth int) {
		if len(out) >= claimsKept || depth > flattenDepth {
			return
		}
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			for _, k := range keys {
				key := k
				if prefix != "" {
					key = prefix + "." + k
				}
				walk(key, x[k], depth+1)
			}
		case []any:
			for _, e := range x {
				if s, ok := scalar(e); ok {
					out[prefix] = append(out[prefix], s)
				}
			}
		default:
			if s, ok := scalar(x); ok {
				out[prefix] = []string{s}
			}
		}
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		switch {
		case slices.Contains(registered, k):
		case k == awsNamespace:
			walk("", raw[k], 0)
		default:
			walk(k, raw[k], 1)
		}
	}
	return out
}

func scalar(v any) (string, bool) {
	var s string
	switch x := v.(type) {
	case string:
		s = x
	case json.Number:
		s = x.String()
	case bool:
		s = fmt.Sprint(x)
	default:
		return "", false
	}
	if len(s) > claimValue {
		s = s[:claimValue]
	}
	return s, true
}
