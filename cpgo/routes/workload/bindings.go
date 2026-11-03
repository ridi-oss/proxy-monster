package workload

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

const adminAction = "admin.identity"

type IssuerInfo struct {
	Name string `json:"name"`
	Kind Kind   `json:"kind"`
	URL  string `json:"url"`
}

type Bindings struct {
	Pool    *pgxpool.Pool
	Issuers []Issuer
}

func (v *Verifier) Issuers() []Issuer {
	if v == nil {
		return nil
	}
	return v.issuers
}

func registerBindings(mux *http.ServeMux, gate api.Gate, b Bindings) {
	admin := func(h api.Route) http.HandlerFunc { return gate.RequireAdmin(adminAction, api.Serve(h)) }
	mux.HandleFunc("GET /api/workload-issuers", admin(b.listIssuers))
	mux.HandleFunc("GET /api/workload-bindings", admin(b.list))
	mux.HandleFunc("POST /api/workload-bindings", admin(b.create))
	mux.HandleFunc("PUT /api/workload-bindings/{id}", admin(api.WithID(b.update)))
	mux.HandleFunc("DELETE /api/workload-bindings/{id}", admin(api.WithID(b.delete)))
}

func (b Bindings) listIssuers(w http.ResponseWriter, _ *http.Request) error {
	out := make([]IssuerInfo, 0, len(b.Issuers))
	for _, i := range b.Issuers {
		out = append(out, IssuerInfo{Name: i.Name, Kind: i.Kind, URL: i.URL})
	}
	api.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (b Bindings) list(w http.ResponseWriter, r *http.Request) error {
	rows, err := db.New(b.Pool).WorkloadBindings(r.Context())
	if err != nil {
		return err
	}
	out := make([]Binding, 0, len(rows))
	for _, row := range rows {
		out = append(out, toBinding(db.WorkloadBindingRow(row)))
	}
	api.WriteJSON(w, http.StatusOK, out)
	return nil
}

func decodeBinding(r *http.Request, issuers []Issuer) (validBinding, error) {
	var in bindingInput
	if err := api.DecodeBody(r, &in); err != nil {
		return validBinding{}, err
	}
	return in.validate(issuers)
}

func getBinding(ctx context.Context, q db.DBTX, id int64) (*Binding, error) {
	row, err := db.New(q).WorkloadBinding(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, api.NotFound("workload_binding")
	}
	if err != nil {
		return nil, err
	}
	out := toBinding(row)
	return &out, nil
}

func entity(name string) string { return audit.Entity("WorkloadBinding", name) }

func (b Bindings) create(w http.ResponseWriter, r *http.Request) error {
	in, err := decodeBinding(r, b.Issuers)
	if err != nil {
		return err
	}
	return api.Mutate(b.Pool, w, r, http.StatusCreated, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		conditions, _ := json.Marshal(in.conditions)
		id, err := db.New(tx).CreateWorkloadBinding(ctx, db.CreateWorkloadBindingParams{Name: in.name, Description: in.description,
			Issuer: in.issuer, Subject: in.subject, Conditions: conditions, Principal: in.principal, Purposes: in.purposes,
			McpScopes: in.mcpScopes, TtlSeconds: in.ttl, Enabled: in.enabled})
		if err != nil {
			return nil, api.Unique(err, "workload_binding", in.name)
		}
		out, err := getBinding(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		return out, audit.Admin(ctx, tx, actor, adminAction, entity(out.Name), "create workload binding '"+out.Name+"' -> "+out.Principal)
	})
}

func (b Bindings) update(w http.ResponseWriter, r *http.Request, id int64) error {
	in, err := decodeBinding(r, b.Issuers)
	if err != nil {
		return err
	}
	return api.Mutate(b.Pool, w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		before, err := getBinding(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		if in.name != before.Name {
			return nil, api.CodeInvalidValue.Err("field", "name")
		}
		q := db.New(tx)
		conditions, _ := json.Marshal(in.conditions)
		if _, err := q.UpdateWorkloadBinding(ctx, db.UpdateWorkloadBindingParams{ID: id, Description: in.description, Issuer: in.issuer,
			Subject: in.subject, Conditions: conditions, Principal: in.principal, Purposes: in.purposes, McpScopes: in.mcpScopes,
			TtlSeconds: in.ttl, Enabled: in.enabled}); err != nil {
			return nil, err
		}
		after, err := getBinding(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		summary := "update workload binding '" + after.Name + "'"
		if narrowed(*before, *after) {
			revoked, err := revoke(ctx, q, *before)
			if err != nil {
				return nil, err
			}
			summary += "; revoked " + revoked + " token(s)"
		}
		return after, audit.Admin(ctx, tx, actor, adminAction, entity(after.Name), summary)
	})
}

func (b Bindings) delete(w http.ResponseWriter, r *http.Request, id int64) error {
	return api.Mutate(b.Pool, w, r, http.StatusNoContent, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		before, err := getBinding(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		q := db.New(tx)
		if _, err := q.DeleteWorkloadBinding(ctx, id); err != nil {
			return nil, err
		}
		revoked, err := revoke(ctx, q, *before)
		if err != nil {
			return nil, err
		}
		return nil, audit.Admin(ctx, tx, actor, adminAction, entity(before.Name),
			"delete workload binding '"+before.Name+"'; revoked "+revoked+" token(s)")
	})
}

func narrowed(before, after Binding) bool {
	return !after.Enabled || before.Issuer != after.Issuer || before.Subject != after.Subject || before.Principal != after.Principal ||
		!sameConditions(before.Conditions, after.Conditions) || !subset(before.Purposes, after.Purposes) || !subset(before.MCPScopes, after.MCPScopes)
}

func sameConditions(a, b map[string][]string) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func subset(have, within []string) bool {
	return !slices.ContainsFunc(have, func(s string) bool { return !slices.Contains(within, s) })
}

func revoke(ctx context.Context, q *db.Queries, b Binding) (string, error) {
	n, err := q.RevokeWorkloadBindingTokens(ctx, &b.ID)
	if err != nil {
		return "", err
	}
	if err := q.RevokeWorkloadBindingConsents(ctx, b.ClientID()); err != nil {
		return "", err
	}
	return strconv.FormatInt(n, 10), nil
}
