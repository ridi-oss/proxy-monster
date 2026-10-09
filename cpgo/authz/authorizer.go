package authz

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

// Local answers the decisions Go routes ask for from the Go engine. Kotlin still decides the query path
// from its own cache, so a policy change is still signalled to it.
type Local struct {
	Engine *Engine
	Kotlin interface {
		PoliciesChanged(context.Context) error
	}
}

func (l Local) Authorize(ctx context.Context, principal, action string, r bridge.Resource, ip string) (bool, string, error) {
	roles, err := l.Engine.Roles(ctx, principal)
	if err != nil {
		return false, "", err
	}
	d, err := l.Engine.AuthorizeAs(ctx, principal, roles, action, r, Context{RequesterIP: ip})
	return d.Allow, d.Reason, err
}

func (l Local) AuthorizeEach(ctx context.Context, principal, action string, rs []bridge.Resource, ip string) ([]bool, error) {
	if len(rs) == 0 {
		return nil, nil
	}
	roles, err := l.Engine.Roles(ctx, principal)
	if err != nil {
		return nil, err
	}
	out := make([]bool, len(rs))
	for i, r := range rs {
		d, err := l.Engine.AuthorizeAs(ctx, principal, roles, action, r, Context{RequesterIP: ip})
		if err != nil {
			return nil, err
		}
		out[i] = d.Allow
	}
	return out, nil
}

// MayConnect is mayConnectById for each datasource: false for a missing datasource or a deactivated
// principal, else datasource.connect with the datasource's context tags derived first.
func (l Local) MayConnect(ctx context.Context, principal string, ids []int64, ip string) ([]bool, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	out := make([]bool, len(ids))
	deactivated, err := l.Engine.deactivated(ctx, principal)
	if err != nil || deactivated {
		return out, err
	}
	roles, err := l.Engine.Roles(ctx, principal)
	if err != nil {
		return nil, err
	}
	for i, id := range ids {
		row, err := db.New(l.Engine.pool).DatasourceNameTags(ctx, id)
		if err != nil {
			continue
		}
		name, tags := row.Name, row.Tags
		raw := Context{RequesterIP: ip}
		if raw.Tags, err = l.Engine.ContextTags(ctx, principal, roles, name, tags, raw); err != nil {
			return nil, err
		}
		d, err := l.Engine.DatasourceAction(ctx, principal, roles, "datasource.connect", name, tags, raw)
		if err != nil {
			return nil, err
		}
		out[i] = d.Allow
	}
	return out, nil
}

func (l Local) Validate(_ context.Context, src string) ([]string, error) { return Validate(src), nil }

func (l Local) PoliciesChanged(ctx context.Context) error { return l.Kotlin.PoliciesChanged(ctx) }

// Authorizer is what both engines answer; it matches api.Authorizer.
type Authorizer interface {
	Authorize(ctx context.Context, principal, action string, r bridge.Resource, ip string) (bool, string, error)
	AuthorizeEach(ctx context.Context, principal, action string, rs []bridge.Resource, ip string) ([]bool, error)
	MayConnect(ctx context.Context, principal string, ids []int64, ip string) ([]bool, error)
	Validate(ctx context.Context, src string) ([]string, error)
	PoliciesChanged(ctx context.Context) error
}

// Shadow answers with Primary and asks Candidate the same question, logging every disagreement, so the Go
// engine is checked against Kotlin's on real traffic before it decides anything.
type Shadow struct {
	Primary, Candidate Authorizer
	Mismatches         *atomic.Int64
}

func (s Shadow) mismatch(what string, args ...any) {
	if s.Mismatches != nil {
		s.Mismatches.Add(1)
	}
	slog.Warn("authz: shadow mismatch "+what, args...)
}

func (s Shadow) Authorize(ctx context.Context, principal, action string, r bridge.Resource, ip string) (bool, string, error) {
	ok, reason, err := s.Primary.Authorize(ctx, principal, action, r, ip)
	if err == nil {
		cok, creason, cerr := s.Candidate.Authorize(ctx, principal, action, r, ip)
		if cerr != nil || cok != ok || !SameReason(reason, creason) {
			s.mismatch("authorize", "principal", principal, "action", action, "resource", r, "ip", ip,
				"kotlin", ok, "kotlin_reason", reason, "go", cok, "go_reason", creason, "go_err", cerr)
		}
	}
	return ok, reason, err
}

func (s Shadow) AuthorizeEach(ctx context.Context, principal, action string, rs []bridge.Resource, ip string) ([]bool, error) {
	out, err := s.Primary.AuthorizeEach(ctx, principal, action, rs, ip)
	if err == nil {
		cout, cerr := s.Candidate.AuthorizeEach(ctx, principal, action, rs, ip)
		if cerr != nil || !slices.Equal(out, cout) {
			s.mismatch("authorize-each", "principal", principal, "action", action, "resources", rs, "kotlin", out, "go", cout, "go_err", cerr)
		}
	}
	return out, err
}

func (s Shadow) MayConnect(ctx context.Context, principal string, ids []int64, ip string) ([]bool, error) {
	out, err := s.Primary.MayConnect(ctx, principal, ids, ip)
	if err == nil {
		cout, cerr := s.Candidate.MayConnect(ctx, principal, ids, ip)
		if cerr != nil || !slices.Equal(out, cout) {
			s.mismatch("may-connect", "principal", principal, "ids", ids, "ip", ip, "kotlin", out, "go", cout, "go_err", cerr)
		}
	}
	return out, err
}

// Validate compares only valid/invalid: the two validators word their errors differently.
func (s Shadow) Validate(ctx context.Context, src string) ([]string, error) {
	errs, err := s.Primary.Validate(ctx, src)
	if err == nil {
		cerrs, cerr := s.Candidate.Validate(ctx, src)
		if cerr != nil || (len(errs) == 0) != (len(cerrs) == 0) {
			s.mismatch("validate", "source", src, "kotlin", errs, "go", cerrs, "go_err", cerr)
		}
	}
	return errs, err
}

func (s Shadow) PoliciesChanged(ctx context.Context) error { return s.Primary.PoliciesChanged(ctx) }

// SameReason compares deny reasons as sets of policy ids, since Kotlin lists them in no fixed order.
func SameReason(a, b string) bool {
	norm := func(s string) string {
		head, ids, ok := strings.Cut(s, ": ")
		if !ok || head != "denied by policy" {
			return s
		}
		parts := strings.Split(ids, ", ")
		slices.Sort(parts)
		return head + ": " + strings.Join(parts, ", ")
	}
	return norm(a) == norm(b)
}
