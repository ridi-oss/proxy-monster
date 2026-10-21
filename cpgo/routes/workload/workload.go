// Package workload serves the CI OIDC token exchange: a CI job's OIDC JWT for a WORKLOAD bearer token.
package workload

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/tokens"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/websession"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

const (
	tokenTTL = 15 * 60
	action   = "auth.workload.exchange"
	// auditedLimit is Kotlin's auditedValue bound on a caller-supplied value in an audit row.
	auditedLimit = 200
)

// claimAttributes are the claims a WORKLOAD token keeps, in Kotlin's WORKLOAD_CLAIM_ATTRIBUTES order.
var claimAttributes = []string{"repository", "repository_id", "ref", "base_ref", "workflow_ref", "event_name", "actor"}

type exchange struct {
	websession.Auth
	verifier *Verifier
}

func Register(mux *http.ServeMux, au websession.Auth, v *Verifier) {
	x := exchange{Auth: au, verifier: v}
	mux.HandleFunc("POST /api/workload/token", api.Serve(x.exchange))
}

func (x exchange) exchange(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Token *string `json:"token"`
	}
	if api.DecodeBody(r, &in) != nil || in.Token == nil || strings.TrimSpace(*in.Token) == "" {
		return api.CodeFieldRequired.Err("fields", "token")
	}
	if !x.verifier.configured() {
		return api.CodeWorkloadNotConfigured.Err()
	}
	ctx := r.Context()
	ip := x.RequesterIP(r)
	unattributed := audit.Actor{Principal: "unknown", ClientAddr: ip, Channel: "workload"}
	issuer, claims, err := x.verifier.Verify(ctx, *in.Token)
	var untrustedErr untrusted
	var invalidErr invalid
	switch {
	case errors.As(err, &untrustedErr):
		iss := untrustedErr.iss
		if iss == "" {
			iss = "-"
		}
		audit.AuthRejected(context.WithoutCancel(ctx), x.Pool, unattributed, action, audit.Entity("Workload", api.Truncate(iss, auditedLimit)),
			"CI OIDC token from an untrusted issuer")
		return api.CodeIssuerNotTrusted.Err()
	case errors.As(err, &invalidErr):
		name := issuer.Name
		if name == "" {
			name = "-"
		}
		audit.AuthFailure(context.WithoutCancel(ctx), x.Pool, unattributed, action, audit.Entity("Workload", name),
			"CI OIDC token rejected", api.Truncate(invalidErr.reason, auditedLimit))
		return api.CodeInvalidToken.Err("kind", "ci_oidc")
	case err != nil:
		return err
	}
	kept := map[string]string{}
	var detail []string
	for _, k := range claimAttributes {
		if v, ok := claims[k].(string); ok {
			kept[k] = v
			detail = append(detail, k+"="+v)
		}
	}
	keptJSON, _ := json.Marshal(kept)
	token, hash := tokens.NewSecret("pmw_")
	var out tokens.IssuedToken
	err = pgx.BeginFunc(ctx, x.Pool, func(tx pgx.Tx) error {
		minted, err := db.New(tx).MintWorkloadToken(ctx, db.MintWorkloadTokenParams{
			TokenHash: hash, Principal: "workload:" + issuer.Name, Ttl: tokenTTL, Claims: keptJSON,
		})
		if err != nil {
			return err
		}
		out = tokens.IssuedToken{Token: token, ID: minted.ID, Kind: "WORKLOAD", ExpiresAt: api.JavaInstant(minted.ExpiresAt)}
		return audit.AuthDetail(ctx, tx, audit.Actor{Principal: "workload:" + issuer.Name, ClientAddr: ip, Channel: "workload"},
			action, audit.Entity("Workload", issuer.Name), "Exchanged a CI OIDC token for a workload token",
			api.Truncate(strings.Join(detail, " "), auditedLimit))
	})
	if err != nil {
		return err
	}
	api.WriteJSON(w, http.StatusOK, out)
	return nil
}
