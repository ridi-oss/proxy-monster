package routes

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
		return nil, notFound("policy")
	}
	c := cedarPolicy{ID: row.ID, Origin: row.Origin, SystemKey: row.SystemKey, Name: row.Name, CedarSrc: row.CedarSrc,
		Enabled: row.Enabled, UpdatedBy: row.UpdatedBy, UpdatedAt: javaInstant(row.UpdatedAt)}
	return &c, err
}

// checkSource is CedarPolicyStore's write guard: no system: names, and a source the validator accepts.
func (p policies) checkSource(ctx context.Context, name, src string) error {
	if strings.HasPrefix(name, "system:") {
		return &managementError{"policy.reserved_name", nil}
	}
	errs, err := p.authz.Validate(ctx, src)
	if err != nil {
		return err
	}
	if len(errs) > 0 {
		return cedarErrors(errs)
	}
	return nil
}

func uniquePolicy(err error) error {
	if unique(err, "policy", "") != err {
		return &managementError{"common.already_exists", api.Params{{"resource", "policy"}}}
	}
	return err
}

func recordPolicy(ctx context.Context, tx pgx.Tx, actor audit.Actor, id int64, summary string) error {
	return audit.Admin(ctx, tx, actor, "admin.policies", audit.Entity("Policy", strconv.FormatInt(id, 10)), summary)
}

func (p policies) changed(ctx context.Context) error { return p.authz.PoliciesChanged(ctx) }

func (p policies) createPolicy(w http.ResponseWriter, r *http.Request) {
	var in cedarPolicyInput
	decodeErr := decodeBody(r, &in)
	p.mutate(w, r, http.StatusCreated, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		if decodeErr != nil {
			return nil, decodeErr
		}
		if err := required("name", in.Name); err != nil {
			return nil, err
		}
		if err := required("cedarSrc", in.CedarSrc); err != nil {
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

func (p policies) updatePolicy(w http.ResponseWriter, r *http.Request, id int64) {
	var in cedarPolicyInput
	decodeErr := decodeBody(r, &in)
	p.mutate(w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		if decodeErr != nil {
			return nil, decodeErr
		}
		if err := required("name", in.Name); err != nil {
			return nil, err
		}
		if err := required("cedarSrc", in.CedarSrc); err != nil {
			return nil, err
		}
		current, err := getPolicy(ctx, tx, id, true)
		if err != nil {
			return nil, err
		}
		if current.Origin == "SYSTEM" {
			return nil, &managementError{"policy.system_immutable", nil}
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
		return updated, recordPolicy(ctx, tx, actor, id, updateSummary("policy", current.Name, updated.Name))
	}, p.changed)
}

func (p policies) deletePolicy(w http.ResponseWriter, r *http.Request, id int64) {
	deleted := false
	p.mutate(w, r, http.StatusNoContent, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		current, err := getPolicy(ctx, tx, id, true)
		if err != nil {
			return nil, err
		}
		if current.Origin == "SYSTEM" {
			return nil, &managementError{"policy.system_immutable", nil}
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

func (p policies) setPolicyEnabled(enabled bool) func(http.ResponseWriter, *http.Request, int64) {
	verb := "disable"
	if enabled {
		verb = "enable"
	}
	return func(w http.ResponseWriter, r *http.Request, id int64) {
		p.mutate(w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
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
					return nil, cedarErrors(errs)
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
func (p policies) validatePolicy(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CedarSrc string `json:"cedarSrc"`
	}
	if err := decodeBody(r, &in); err != nil {
		api.WriteErrorParams(w, http.StatusBadRequest, "common.invalid_value", api.Params{{"field", "body"}})
		return
	}
	if strings.TrimSpace(in.CedarSrc) == "" {
		api.WriteErrorParams(w, http.StatusBadRequest, "common.field_required", api.Params{{"fields", "cedarSrc"}})
		return
	}
	errs, err := p.authz.Validate(r.Context(), in.CedarSrc)
	if err != nil {
		fail(w, err)
		return
	}
	api.WriteJSON(w, http.StatusOK, struct {
		Valid  bool     `json:"valid"`
		Errors []string `json:"errors"`
	}{len(errs) == 0, nonNil(errs)})
}
