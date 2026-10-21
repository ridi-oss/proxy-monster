package policies

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

type cedarPolicyInput struct {
	Name     string `json:"name"`
	CedarSrc string `json:"cedarSrc"`
	Enabled  *bool  `json:"enabled"`
}

func (in cedarPolicyInput) enabled() bool { return in.Enabled == nil || *in.Enabled }

func getPolicy(ctx context.Context, tx pgx.Tx, id int64, lock bool) (*cedarPolicy, error) {
	var (
		row db.PolicyRow
		err error
	)
	if lock {
		var locked db.LockPolicyRow
		locked, err = db.New(tx).LockPolicy(ctx, id)
		row = db.PolicyRow(locked)
	} else {
		row, err = db.New(tx).Policy(ctx, id)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, api.NotFound("policy")
	}
	c := cedarPolicy{ID: row.ID, Origin: row.Origin, SystemKey: row.SystemKey, Name: row.Name, CedarSrc: row.CedarSrc,
		Enabled: row.Enabled, UpdatedBy: row.UpdatedBy, UpdatedAt: api.JavaInstant(row.UpdatedAt)}
	return &c, err
}

// checkSource is CedarPolicyStore's write guard: no system: names, and a source the validator accepts.
func (p policies) checkSource(ctx context.Context, name, src string) error {
	if strings.HasPrefix(name, "system:") {
		return api.CodePolicyReservedName.Err()
	}
	errs, err := p.authz.Validate(ctx, src)
	if err != nil {
		return err
	}
	if len(errs) > 0 {
		return api.CedarErrors(errs)
	}
	return nil
}

func uniquePolicy(err error) error {
	if api.Unique(err, "policy", "") != err {
		return api.CodeAlreadyExists.Err("resource", "policy")
	}
	return err
}

func recordPolicy(ctx context.Context, tx pgx.Tx, actor audit.Actor, id int64, summary string) error {
	return audit.Admin(ctx, tx, actor, "admin.policies", audit.Entity("Policy", strconv.FormatInt(id, 10)), summary)
}

func (p policies) changed(ctx context.Context) error { return p.kotlin.PoliciesChanged(ctx) }

func (p policies) createPolicy(w http.ResponseWriter, r *http.Request) error {
	var in cedarPolicyInput
	decodeErr := api.DecodeBody(r, &in)
	return api.Mutate(p.pool, w, r, http.StatusCreated, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		if decodeErr != nil {
			return nil, decodeErr
		}
		if err := api.Required("name", in.Name); err != nil {
			return nil, err
		}
		if err := api.Required("cedarSrc", in.CedarSrc); err != nil {
			return nil, err
		}
		if err := p.checkSource(ctx, in.Name, in.CedarSrc); err != nil {
			return nil, err
		}
		principal := api.Principal(ctx)
		id, err := db.New(tx).CreatePolicy(ctx, db.CreatePolicyParams{Name: in.Name, CedarSrc: in.CedarSrc, Enabled: in.enabled(), UpdatedBy: &principal})
		if err != nil {
			return nil, uniquePolicy(err)
		}
		created, err := getPolicy(ctx, tx, id, false)
		if err != nil {
			return nil, err
		}
		return created, recordPolicy(ctx, tx, actor, id, "create policy '"+created.Name+"'")
	}, p.changed)
}

func (p policies) updatePolicy(w http.ResponseWriter, r *http.Request, id int64) error {
	var in cedarPolicyInput
	decodeErr := api.DecodeBody(r, &in)
	return api.Mutate(p.pool, w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		if decodeErr != nil {
			return nil, decodeErr
		}
		if err := api.Required("name", in.Name); err != nil {
			return nil, err
		}
		if err := api.Required("cedarSrc", in.CedarSrc); err != nil {
			return nil, err
		}
		current, err := getPolicy(ctx, tx, id, true)
		if err != nil {
			return nil, err
		}
		if current.Origin == "SYSTEM" {
			return nil, api.CodePolicySystemImmutable.Err()
		}
		if err := p.checkSource(ctx, in.Name, in.CedarSrc); err != nil {
			return nil, err
		}
		principal := api.Principal(ctx)
		if err := db.New(tx).UpdatePolicy(ctx, db.UpdatePolicyParams{Name: in.Name, CedarSrc: in.CedarSrc, Enabled: in.enabled(), UpdatedBy: &principal, ID: id}); err != nil {
			return nil, uniquePolicy(err)
		}
		updated, err := getPolicy(ctx, tx, id, false)
		if err != nil {
			return nil, err
		}
		return updated, recordPolicy(ctx, tx, actor, id, api.UpdateSummary("policy", current.Name, updated.Name))
	}, p.changed)
}

func (p policies) deletePolicy(w http.ResponseWriter, r *http.Request, id int64) error {
	deleted := false
	return api.Mutate(p.pool, w, r, http.StatusNoContent, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		current, err := getPolicy(ctx, tx, id, true)
		if err != nil {
			return nil, err
		}
		if current.Origin == "SYSTEM" {
			return nil, api.CodePolicySystemImmutable.Err()
		}
		n, err := db.New(tx).DeletePolicy(ctx, id)
		if err != nil || n == 0 {
			return nil, err
		}
		deleted = true
		return nil, recordPolicy(ctx, tx, actor, id, "delete policy '"+current.Name+"'")
	}, func(ctx context.Context) error {
		if !deleted {
			return nil
		}
		return p.changed(ctx)
	})
}

func (p policies) setPolicyEnabled(enabled bool) func(http.ResponseWriter, *http.Request, int64) error {
	verb := "disable"
	if enabled {
		verb = "enable"
	}
	return func(w http.ResponseWriter, r *http.Request, id int64) error {
		return api.Mutate(p.pool, w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
			current, err := getPolicy(ctx, tx, id, true)
			if err != nil {
				return nil, err
			}
			if enabled {
				errs, err := p.authz.Validate(ctx, current.CedarSrc)
				if err != nil {
					return nil, err
				}
				if len(errs) > 0 {
					return nil, api.CedarErrors(errs)
				}
			}
			principal := api.Principal(ctx)
			if err := db.New(tx).SetPolicyEnabled(ctx, db.SetPolicyEnabledParams{Enabled: enabled, UpdatedBy: &principal, ID: id}); err != nil {
				return nil, err
			}
			updated, err := getPolicy(ctx, tx, id, false)
			if err != nil {
				return nil, err
			}
			return updated, recordPolicy(ctx, tx, actor, id, verb+" policy '"+current.Name+"'")
		}, p.changed)
	}
}

// validatePolicy is the editor's dry run: {valid, errors}, nothing stored.
func (p policies) validatePolicy(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		CedarSrc string `json:"cedarSrc"`
	}
	if err := api.DecodeBody(r, &in); err != nil {
		return api.CodeInvalidValue.Err("field", "body")
	}
	if strings.TrimSpace(in.CedarSrc) == "" {
		return api.CodeFieldRequired.Err("fields", "cedarSrc")
	}
	errs, err := p.authz.Validate(r.Context(), in.CedarSrc)
	if err != nil {
		return err
	}
	api.WriteJSON(w, http.StatusOK, struct {
		Valid  bool     `json:"valid"`
		Errors []string `json:"errors"`
	}{len(errs) == 0, api.NonNil(errs)})
	return nil
}

// schema derives its tag actions from every live policy, disabled ones included: drafts are edited too.
func (p policies) schema(w http.ResponseWriter, r *http.Request) error {
	rows, err := db.New(p.pool).Policies(r.Context())
	if err != nil {
		return err
	}
	srcs := make([]string, len(rows))
	for i, row := range rows {
		srcs[i] = row.CedarSrc
	}
	api.WriteJSON(w, http.StatusOK, struct {
		Schema string `json:"schema"`
	}{p.authz.SchemaText(srcs)})
	return nil
}
