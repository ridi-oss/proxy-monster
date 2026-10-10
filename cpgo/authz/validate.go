package authz

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cedar-policy/cedar-go"
	xast "github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/schema/validate"
)

var validators sync.Map // tag-name key → *validate.Validator

func validatorFor(tagNames []string) (*validate.Validator, error) {
	key := strings.Join(tagNames, "\x00")
	if v, ok := validators.Load(key); ok {
		return v.(*validate.Validator), nil
	}
	var s schema.Schema
	if err := s.UnmarshalCedar([]byte(schemaTextFor(tagNames))); err != nil {
		return nil, err
	}
	resolved, err := s.Resolve()
	if err != nil {
		return nil, err
	}
	v := validate.New(resolved)
	validators.Store(key, v)
	return v, nil
}

// Validate checks one policy source against the authorization schema, plus the house rules the Kotlin
// validator adds: retired utility names and the @cap annotation's syntax and placement. No errors means valid.
func Validate(src string) []string {
	if strings.TrimSpace(src) == "" {
		return []string{"cedar policy source must not be blank"}
	}
	list, err := cedar.NewPolicyListFromBytes("candidate", []byte(src))
	if err != nil {
		return []string{err.Error()}
	}
	if len(list) != 1 {
		return []string{fmt.Sprintf("expected exactly one policy, found %d", len(list))}
	}
	policy := list[0]
	v, err := validatorFor(contextTagNames(src))
	if err != nil {
		return []string{"invalid context.tag action name: " + err.Error()}
	}
	var out []string
	if err := v.Policy("candidate", (*xast.Policy)(policy.AST())); err != nil {
		for _, line := range strings.Split(err.Error(), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				out = append(out, line)
			}
		}
	}
	if m := unsupportedExtension.FindStringSubmatch(src); m != nil {
		out = append(out, m[1]+" is not a valid function")
	}
	out = append(out, retiredUtilityErrors(src)...)
	return append(out, capErrors(policy, src)...)
}

var retiredUtilities = []struct{ command, replacement string }{
	{"SHOW_GRANTS", `Action::"stmt.kind.show_grants" (or stmt.cat.admin.account)`},
	{"SHOW_PROCESSLIST", `Action::"stmt.kind.show_processlist" (or stmt.cat.admin.process)`},
}

func retiredUtilityErrors(src string) []string {
	var out []string
	for _, r := range retiredUtilities {
		if regexp.MustCompile(`Utility::"[^"]*/` + r.command + `"`).MatchString(src) {
			out = append(out, `Utility::"…/`+r.command+`" is no longer emitted — this policy would never match. Use `+r.replacement+` instead.`)
		}
	}
	return out
}

// cedar-go validates the datetime extension; the Kotlin engine's cedar-java does not have it.
var unsupportedExtension = regexp.MustCompile(`\b(datetime|duration)\s*\(`)

var resultCapAction = regexp.MustCompile(`Action::"result\.cap"`)

func capErrors(policy *cedar.Policy, src string) []string {
	raw, ok := policy.Annotations()["cap"]
	if !ok {
		return nil
	}
	empty, err := parseCap(string(raw))
	if err != nil {
		return []string{err.Error()}
	}
	if !empty && !resultCapAction.MatchString(src) {
		return []string{`a @cap annotation belongs on an Action::"result.cap" policy`}
	}
	return nil
}

var (
	capAmount = regexp.MustCompile(`(?i)^(\d+)\s*([KMG]B)?$`)
	capWindow = regexp.MustCompile(`(?i)^(\d+)\s*([mhd])$`)
)

// parseCap checks a @cap value the way Kotlin's ResultCap.parse does, reporting whether it sets no limit.
func parseCap(raw string) (bool, error) {
	empty := true
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return false, fmt.Errorf(`@cap has an empty entry in "%s"`, raw)
		}
		amount, window, isRate := strings.Cut(entry, "/")
		if err := checkCapAmount(amount); err != nil {
			return false, err
		}
		if isRate {
			if err := checkCapWindow(window); err != nil {
				return false, err
			}
		}
		empty = false
	}
	return empty, nil
}

func checkCapAmount(raw string) error {
	m := capAmount.FindStringSubmatch(strings.TrimSpace(raw))
	var (
		n   int64
		err error
	)
	if m != nil {
		n, err = strconv.ParseInt(m[1], 10, 64)
	}
	if m == nil || err != nil || n <= 0 {
		return fmt.Errorf(`@cap amount must be a positive row count or bytes with a KB/MB/GB suffix, got "%s"`, raw)
	}
	mult := map[byte]int64{'K': 1_000, 'M': 1_000_000, 'G': 1_000_000_000}[strings.ToUpper(m[2] + " ")[0]]
	if mult != 0 && n > math.MaxInt64/mult {
		return errors.New("cap annotation overflows")
	}
	return nil
}

func checkCapWindow(raw string) error {
	m := capWindow.FindStringSubmatch(strings.TrimSpace(raw))
	var (
		n   int64
		err error
	)
	if m != nil {
		n, err = strconv.ParseInt(m[1], 10, 64)
	}
	if m == nil || err != nil || n <= 0 {
		return fmt.Errorf(`@cap rate window must be <n>m, <n>h, or <n>d, got "%s"`, raw)
	}
	unit := map[string]time.Duration{"m": time.Minute, "h": time.Hour, "d": 24 * time.Hour}[strings.ToLower(m[2])]
	if n > int64(31*24*time.Hour/unit) {
		return fmt.Errorf(`@cap rate window must not exceed 31d, got "%s"`, raw)
	}
	return nil
}
