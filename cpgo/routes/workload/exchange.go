package workload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/tokens"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

const exchangeAction = "auth.workload.bind"

var errReplayed = errors.New("workload token already exchanged")

var auditedClaims = []string{"aws_account", "lambda_source_function_arn", "ec2_instance_source_vpc",
	"principal_tags.kubernetes-namespace", "principal_tags.kubernetes-service-account", "repository", "environment", "ref",
	"terraform_workspace_name", "terraform_run_phase", "terraform_run_id", "kubernetes.io.namespace"}

type mcpToken struct {
	AccessToken string `json:"accessToken"`
	ExpiresAt   string `json:"expiresAt"`
	Scope       string `json:"scope"`
}

func (x exchange) bind(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Token   *string  `json:"token"`
		Purpose *string  `json:"purpose"`
		Scopes  []string `json:"scopes"`
	}
	if api.DecodeBody(r, &in) != nil || in.Token == nil || strings.TrimSpace(*in.Token) == "" {
		return api.CodeFieldRequired.Err("fields", "token")
	}
	if in.Purpose == nil || !slices.Contains(purposes, *in.Purpose) {
		return api.CodeInvalidValue.Err("field", "purpose")
	}
	if !x.verifier.configured() {
		return api.CodeWorkloadNotConfigured.Err()
	}
	ctx := r.Context()
	ip := x.RequesterIP(r)
	unattributed := audit.Actor{Principal: "unknown", ClientAddr: ip, Channel: "workload"}
	issuer, raw, err := x.verifier.Verify(ctx, *in.Token)
	var untrustedErr untrusted
	var invalidErr invalid
	switch {
	case errors.As(err, &untrustedErr):
		audit.AuthRejected(context.WithoutCancel(ctx), x.Pool, unattributed, exchangeAction,
			audit.Entity("Workload", api.Truncate(orDash(untrustedErr.iss), auditedLimit)), "workload token from an untrusted issuer")
		return api.CodeIssuerNotTrusted.Err()
	case errors.As(err, &invalidErr):
		audit.AuthFailure(context.WithoutCancel(ctx), x.Pool, unattributed, exchangeAction, audit.Entity("Workload", orDash(issuer.Name)),
			"workload token rejected", api.Truncate(invalidErr.reason, auditedLimit))
		return api.CodeInvalidToken.Err("kind", "workload_oidc")
	case err != nil:
		return err
	}
	sub, _ := raw["sub"].(string)
	claims := flatten(raw)
	summary := "sub=" + sub + " " + claimDetail(claims)
	refuse := func(code api.Code, reason string, binding string) error {
		audit.AuthFailure(context.WithoutCancel(ctx), x.Pool, unattributed, exchangeAction,
			audit.Entity("WorkloadBinding", orDash(binding)), "workload token not bound: "+reason, api.Truncate(summary, auditedLimit))
		return code.Err()
	}
	rows, err := db.New(x.Pool).IssuerWorkloadBindings(ctx, issuer.Name)
	if err != nil {
		return err
	}
	var matched []Binding
	for _, row := range rows {
		if b := toBinding(db.WorkloadBindingRow(row)); b.matches(sub, claims) {
			matched = append(matched, b)
		}
	}
	switch len(matched) {
	case 0:
		return refuse(api.CodeNoBinding, "no binding matches", issuer.Name)
	case 1:
	default:
		return refuse(api.CodeAmbiguousBinding, "several bindings match", issuer.Name)
	}
	b := matched[0]
	if !b.allows(*in.Purpose) {
		return refuse(api.CodePurposeNotAllowed, "purpose "+*in.Purpose+" not allowed", b.Name)
	}
	scopes := b.MCPScopes
	if *in.Purpose == PurposeMCP && len(in.Scopes) > 0 {
		for _, s := range in.Scopes {
			if !slices.Contains(b.MCPScopes, s) {
				return refuse(api.CodeScopeNotAllowed, "scope "+api.Truncate(s, 64)+" not allowed", b.Name)
			}
		}
		scopes = sortedUnique(in.Scopes)
	}
	actor := audit.Actor{Principal: b.Principal, ClientAddr: ip, Channel: "workload"}
	var out any
	err = pgx.BeginFunc(ctx, x.Pool, func(tx pgx.Tx) error {
		q := db.New(tx)
		if err := q.PruneWorkloadTokenUse(ctx); err != nil {
			return err
		}
		used, err := q.UseWorkloadToken(ctx, db.UseWorkloadTokenParams{Issuer: issuer.Name, Jti: tokenID(raw, *in.Token),
			ExpiresAt: seconds(raw["exp"]).Add(clockSkew)})
		if err != nil {
			return err
		}
		if used == 0 {
			return errReplayed
		}
		now := time.Now().Truncate(time.Microsecond)
		var minted string
		if *in.Purpose == PurposeWire {
			token, hash := tokens.NewSecret("pms_")
			kept, _ := json.Marshal(claims)
			name := b.Name
			row, err := q.MintServiceToken(ctx, db.MintServiceTokenParams{TokenHash: hash, Principal: b.Principal, Name: &name,
				ExpiresAt: b.ttl(now, 0), Claims: kept, WorkloadBindingID: &b.ID})
			if err != nil {
				return err
			}
			out = tokens.IssuedToken{Token: token, ID: row.ID, Kind: "SERVICE", Name: &name, ExpiresAt: api.JavaInstant(row.ExpiresAt)}
			minted = strconv.FormatInt(row.ID, 10)
		} else {
			settings := x.Sessions.Settings()
			scope := session.CanonicalScopes(scopes)
			clientID := b.ClientID()
			consentID, err := q.UpsertConsent(ctx, db.UpsertConsentParams{Principal: b.Principal, ClientID: clientID,
				Resource: settings.MCPResource, Scope: scope})
			if err != nil {
				return err
			}
			access, family := "pma_"+api.RandomToken(32), "pmf_"+api.RandomToken(24)
			expires := b.ttl(now, time.Duration(settings.MCPAccessTTL)*time.Second)
			id, err := q.MintWorkloadMcpToken(ctx, db.MintWorkloadMcpTokenParams{TokenHash: session.TokenHash(access), Principal: b.Principal,
				ExpiresAt: expires, Resource: &settings.MCPResource, ClientID: &clientID, Scope: &scope, RefreshFamily: &family,
				ConsentID: &consentID, WorkloadBindingID: &b.ID})
			if err != nil {
				return err
			}
			out = mcpToken{AccessToken: access, ExpiresAt: api.JavaInstant(expires), Scope: scope}
			minted = strconv.FormatInt(id, 10)
		}
		return audit.AuthDetail(ctx, tx, actor, exchangeAction, audit.Entity("WorkloadBinding", b.Name),
			"Exchanged a workload token for a "+*in.Purpose+" token", api.Truncate("token="+minted+" "+summary, auditedLimit))
	})
	if errors.Is(err, errReplayed) {
		return refuse(api.CodeTokenReplayed, "token already exchanged", b.Name)
	}
	if err != nil {
		return err
	}
	api.WriteJSON(w, http.StatusOK, out)
	return nil
}

func tokenID(raw map[string]any, jwt string) string {
	if jti, ok := raw["jti"].(string); ok && jti != "" && len(jti) <= 256 {
		return jti
	}
	sum := sha256.Sum256([]byte(jwt))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func claimDetail(c Claims) string {
	var parts []string
	for _, k := range auditedClaims {
		if v, ok := c[k]; ok {
			parts = append(parts, k+"="+strings.Join(v, ","))
		}
	}
	return strings.Join(parts, " ")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
