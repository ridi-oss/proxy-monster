package oidc

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// SignatureAlgorithm is the ONE algorithm an id_token may be signed with.
//
// 🔒 INV-A14-30 — the algorithm is PINNED to RS256, reproducing
// `JWSVerificationKeySelector(JWSAlgorithm.RS256, jwkSource)` (auth/Oidc.kt:72). Three attacks are
// closed by the pin, and all three re-open if a port "generalises" it to "any asymmetric alg":
//
//   - `alg: none` — an unsecured JWT with no signature at all.
//   - the classic algorithm-confusion attack: an HS256 token whose HMAC secret is the IdP's PUBLIC
//     RSA key, which an attacker can read from jwks_uri.
//   - ES256/PS256 tokens, which widen the accepted set for no product reason.
//
// go-jose enforces this at PARSE time: jose.ParseSigned takes the permitted algorithms as an argument
// and refuses anything else before a key is ever selected, which is the same ordering
// DefaultJWTProcessor uses.
var SignatureAlgorithm = jose.RS256

// MaxClockSkew is the leeway applied to `exp` (and to `nbf` when present).
//
// ⚠️ Unverified, and deliberately made EXPLICIT here rather than inherited from a library default.
// 14-auth.md records the evidence and its limits: nimbus-jose-jwt 9.40's
// DefaultJWTClaimsVerifier.DEFAULT_MAX_CLOCK_SKEW_SECONDS is believed to be 60, and the jar is not
// present on this machine to confirm it (`find ~/.gradle ~/.m2 -name 'nimbus-jose-jwt-9.40*.jar'` ⇒
// no output). The in-repo constraint is real though: IdTokenValidatorTest case 6 builds its expired
// token with `expiresInSeconds = -60` and requires it to FAIL, which holds only if the skew is ≤ 60s,
// and Nimbus's own comparison is strict (`exp > now - skew`), so exactly-60 is rejected. This package
// therefore uses 60s with a strict comparison — the single value consistent with the frozen test.
const MaxClockSkew = 60 * time.Second

// ValidatedIDToken is `data class ValidatedIdToken` (auth/Oidc.kt:53-58).
//
// ⚠️ F28 — Nonce is populated and read by NOBODY. The only `.nonce` reads in the Kotlin tree are of
// OAuthNonceSession (the EXPECTED nonce), not of this field. Dead field, reproduced because
// IdTokenValidatorTest cases 1 and 3 assert on it.
type ValidatedIDToken struct {
	Subject string
	Email   *string
	Groups  []string
	Nonce   *string
}

// IDTokenValidator is `class IdTokenValidator(discovery, issuer, clientId)` (auth/Oidc.kt:60-94).
//
// Contract: [IDTokenValidator.Validate] returns claims for a token that verifies against the IdP's
// JWKS and satisfies issuer, audience, expiry and (optionally) nonce — otherwise nil. It NEVER
// returns an error.
type IDTokenValidator struct {
	discovery *Discovery
	issuer    string
	clientID  string

	// http fetches the JWKS.
	//
	// ⚠️ DEVIATION, language-forced and visible in the constructor signature. Kotlin's validator
	// takes no HttpClient because Nimbus's RemoteJWKSet does its own raw java.net call, entirely
	// outside the injected ktor client — IdTokenValidatorTest's own KDoc says so, and it is why that
	// suite needs a real loopback socket rather than a mocked client. Go has no such hidden
	// retriever, so the client becomes an explicit dependency. No behaviour changes; the fetch is
	// the same GET to the same URL.
	http *http.Client
	log  *slog.Logger
}

// NewIDTokenValidator wires a validator for one issuer/client pair.
func NewIDTokenValidator(d *Discovery, issuer, clientID string, hc *http.Client, log *slog.Logger) *IDTokenValidator {
	if log == nil {
		log = slog.Default()
	}
	return &IDTokenValidator{discovery: d, issuer: issuer, clientID: clientID, http: hc, log: log}
}

// Validate is `suspend fun validate(idToken: String, expectedNonce: String?): ValidatedIdToken?`
// (auth/Oidc.kt:65-93).
//
// 🔒 INV-A14-29 — FAIL CLOSED, AND LOG ONCE. The Kotlin wraps its whole body in
// `catch (e: Exception) { log.warn(...); null }`. No validation failure ever propagates into a login
// route, and the REASON is logged server-side and never returned to the client, so the login endpoint
// is not an oracle for which check failed. That is why this method returns a bare *ValidatedIDToken
// and no error: an error return would let a caller surface the reason by accident. Every `return nil`
// below is preceded by the one warn line.
//
// 🔒 INV-A14-31 — the nonce is checked ONLY when the caller supplies one. expectedNonce == nil skips
// the check entirely, and both modes are used deliberately: the web authorization-code flow passes the
// cookie-stored nonce, while the daemon liveness re-check passes nil because a refresh-grant id_token
// legitimately carries no nonce. Making the check unconditional breaks daemon liveness.
//
// Ordering note (INV-A14-29b): the Kotlin's `withContext(Dispatchers.IO)` hop vanishes here — Go has
// no coloured functions and no dispatcher — but the fact underneath it does not. This performs a
// synchronous outbound HTTP request and takes its deadline from ctx.
func (v *IDTokenValidator) Validate(ctx context.Context, idToken string, expectedNonce *string) *ValidatedIDToken {
	claims, err := v.verify(ctx, idToken)
	if err != nil {
		v.log.Warn("id_token validation failed", "err", err)
		return nil
	}

	// Step 3 — `claims.subject ?: return null`. A token with no `sub` is rejected. Note this is an
	// APP-level check: `sub` is not in the Kotlin's requiredClaims set, so the verifier lets it
	// through and this line is the only thing that catches it.
	sub, _ := claims["sub"].(string)
	if sub == "" {
		v.log.Warn("id_token validation failed", "err", "no sub claim")
		return nil
	}

	// Step 4 — `claims.getClaim("nonce") as? String`. A NON-STRING nonce claim becomes nil via the
	// safe cast and then mismatches, so it is rejected. The comparison is a plain !=, not
	// constant-time: reproduced, since the nonce is a value the browser already holds.
	var actualNonce *string
	if s, ok := claims["nonce"].(string); ok {
		actualNonce = &s
	}
	if expectedNonce != nil {
		if actualNonce == nil || *actualNonce != *expectedNonce {
			v.log.Warn("id_token validation failed", "err", "nonce mismatch")
			return nil
		}
	}

	// Step 5 — a non-string `email` claim silently becomes nil.
	var email *string
	if s, ok := claims["email"].(string); ok {
		email = &s
	}

	return &ValidatedIDToken{
		Subject: sub,
		Email:   email,
		Groups:  groupsClaim(claims["groups"]),
		Nonce:   actualNonce,
	}
}

// groupsClaim is
// `(claims.getClaim("groups") as? List<*>)?.mapNotNull { it as? String } ?: emptyList()`
// (auth/Oidc.kt:86).
//
// ⚠️ 🔒 F24 / INV-A14-32 — REPRODUCED, AND PINNED. A `groups` claim of the wrong SHAPE fails the list
// cast and silently becomes an EMPTY list:
//
//   - `"groups": "engineering"` — a bare string. Some IdPs emit a single group this way.
//   - `"groups": "engineering,eng-leads"` — comma-joined. Others emit this.
//   - `"groups": {"values": [...]}` — an object.
//
// All three take the same path as an ABSENT claim, which IdTokenValidatorTest case 8 documents as
// intentional ("a missing groups claim resolves to an empty list, not a failure"). The severity comes
// from what happens next: [DirectoryProvisioner.Provision] RECONCILES membership to exactly this list
// (INV-A14-37), so an IdP claim-shape change strips every group from every user on their next login —
// `system:admin` included — with no error logged anywhere.
//
// Non-string ELEMENTS inside a valid list are dropped individually by mapNotNull, which is the same
// hazard at element granularity: `["a", 7, "b"]` yields ["a","b"], not a failure.
//
// 00-INDEX.md:36 puts F24 under REPRODUCE + PIN. The pinning tests are
// TestValidate_F24_MalformedGroupsClaimSilentlyBecomesEmpty and
// TestProvision_F24_MalformedShapeStripsSystemAdmin. If either ever fails because someone "fixed"
// this function, that is the fix being noticed — which is the entire point of pinning it.
func groupsClaim(raw any) []string {
	list, ok := raw.([]any)
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// verify is the Kotlin's `withContext(Dispatchers.IO) { … processor.process(idToken, null) }` — JWKS
// fetch, kid selection, RS256-pinned signature verification, then the claims verifier.
//
// It returns the raw claim map rather than a typed struct because the Kotlin reads `nonce`, `email`
// and `groups` through `getClaim(...) as? T`, whose "wrong type ⇒ null/empty" semantics (F24) are
// exactly what a typed decode would turn into a parse ERROR. Decoding into map[string]any and casting
// per claim is the only shape that reproduces them.
func (v *IDTokenValidator) verify(ctx context.Context, idToken string) (map[string]any, error) {
	// 🔒 INV-A14-30 — the permitted-algorithm list is passed to the PARSER, so `alg: none`, an
	// HMAC-signed token and an ES256 token are all rejected before any key is selected.
	sig, err := jose.ParseSigned(idToken, []jose.SignatureAlgorithm{SignatureAlgorithm})
	if err != nil {
		return nil, fmt.Errorf("parse id_token: %w", err)
	}

	doc, err := v.discovery.Document(ctx)
	if err != nil {
		return nil, err
	}
	// ⚠️ F36 — the JWKS is fetched on EVERY validation, because the Kotlin constructs
	// `RemoteJWKSet(URL(...))` per call and throws away Nimbus's internal cache with it. A hot login
	// path hammers the IdP's jwks_uri. The observable consequence is real and must be preserved: a
	// rotated key takes effect IMMEDIATELY here, where a caching port would lag by its TTL.
	keys, err := v.fetchJWKS(ctx, doc.JwksURI)
	if err != nil {
		return nil, err
	}

	payload, err := verifySignature(sig, keys)
	if err != nil {
		return nil, err
	}

	var claims map[string]any
	dec := json.NewDecoder(bytes.NewReader(payload))
	// UseNumber keeps `exp`/`nbf` exact. Without it a large timestamp round-trips through float64,
	// which is lossless at today's magnitudes but is not a property to depend on silently.
	dec.UseNumber()
	if err := dec.Decode(&claims); err != nil {
		return nil, fmt.Errorf("decode id_token claims: %w", err)
	}
	if err := v.verifyClaims(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// verifySignature does Nimbus's key SELECTION and verification: match on `kid` when the header
// carries one, otherwise try every RSA key in the set.
//
// The fallback is not laxness — it is what JWKMatcher does. Nimbus builds its matcher FROM the JWS
// header: a header with a `kid` matches only that key id, a header without one matches on key type
// and algorithm alone, i.e. every RSA key in the set. IdTokenValidatorTest case 7 ("a token signed by
// an untrusted key fails closed") uses the SAME kid with different key material, so it is the
// signature check and not the selection that must reject it.
func verifySignature(sig *jose.JSONWebSignature, keys *jose.JSONWebKeySet) ([]byte, error) {
	if len(sig.Signatures) != 1 {
		return nil, fmt.Errorf("id_token carries %d signatures, want exactly 1", len(sig.Signatures))
	}
	kid := sig.Signatures[0].Header.KeyID

	candidates := keys.Keys
	if kid != "" {
		candidates = keys.Key(kid)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no JWKS key matches kid %q", kid)
	}

	var lastErr error
	for _, key := range candidates {
		// Only RSA public keys can carry an RS256 signature. Skipping the rest reproduces the key
		// TYPE half of Nimbus's matcher and keeps a symmetric key in the set from ever being tried.
		if _, ok := key.Key.(*rsa.PublicKey); !ok {
			continue
		}
		payload, err := sig.Verify(key)
		if err == nil {
			return payload, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("JWKS holds no RSA public key")
	}
	return nil, fmt.Errorf("id_token signature verification failed: %w", lastErr)
}

// fetchJWKS reads and parses the key set. No cache — see F36 on the caller.
func (v *IDTokenValidator) fetchJWKS(ctx context.Context, jwksURI string) (*jose.JSONWebKeySet, error) {
	var keys jose.JSONWebKeySet
	if err := getJSON(ctx, v.http, jwksURI, &keys); err != nil {
		return nil, fmt.Errorf("fetch jwks_uri: %w", err)
	}
	if len(keys.Keys) == 0 {
		return nil, errors.New("jwks_uri returned an empty key set")
	}
	return &keys, nil
}

// verifyClaims is
// `DefaultJWTClaimsVerifier(JWTClaimsSet.Builder().issuer(issuer).audience(clientId).build(), setOf("exp"))`
// (auth/Oidc.kt:73-76) — the TWO-argument (exactMatchClaims, requiredClaims) constructor.
//
// Which constructor it is matters: the three-argument overload takes an `acceptedAudience` and has
// different — "contains" — audience semantics. This is the two-arg one.
//
// 🔒 `iss` must equal `issuer` EXACTLY. No trailing-slash normalisation, unlike
// [Discovery.Document] which normalises both sides. A port must not normalise here; case 5 of
// IdTokenValidatorTest ("a wrong issuer fails closed") pins the rejection.
//
// 🔒 F39/F43 — `aud` is an EXACT-MATCH claim, so a MULTI-AUDIENCE token is REJECTED. See
// audienceMatches for the full derivation and the pinning test.
//
// `exp` is required. `nbf`, `iat`, `sub` and `azp` are NOT in requiredClaims and are not
// exact-matched, so `azp` is never checked at all and `sub` is enforced only by the app-level check
// in Validate. `nbf` IS still checked when present — Nimbus's verifier tests it independently of
// requiredClaims — which is the fail-closed direction either way.
func (v *IDTokenValidator) verifyClaims(claims map[string]any) error {
	iss, _ := claims["iss"].(string)
	if iss != v.issuer {
		return fmt.Errorf("iss claim %q does not equal the configured issuer %q", iss, v.issuer)
	}
	if !audienceMatches(claims["aud"], v.clientID) {
		return fmt.Errorf("aud claim %v is not exactly [%q]", claims["aud"], v.clientID)
	}

	now := time.Now()
	exp, ok, err := numericDate(claims["exp"])
	if err != nil {
		return fmt.Errorf("exp claim: %w", err)
	}
	if !ok {
		// The one claim in requiredClaims. Absent ⇒ reject, which is the difference between
		// "required" and "checked when present".
		return errors.New("exp claim is required and absent")
	}
	// Nimbus: `DateUtils.isAfter(exp, now, skew)` ⇒ exp > now - skew. STRICT, so an exp exactly
	// MaxClockSkew in the past is expired — which is what IdTokenValidatorTest case 6 requires.
	if !exp.After(now.Add(-MaxClockSkew)) {
		return fmt.Errorf("id_token expired at %s", exp.UTC().Format(time.RFC3339))
	}

	if nbf, ok, err := numericDate(claims["nbf"]); err == nil && ok {
		// Nimbus: `DateUtils.isBefore(nbf, now, skew)` ⇒ nbf < now + skew.
		if !nbf.Before(now.Add(MaxClockSkew)) {
			return fmt.Errorf("id_token not valid before %s", nbf.UTC().Format(time.RFC3339))
		}
	}
	return nil
}

// audienceMatches reproduces the exact-match semantics of the two-argument DefaultJWTClaimsVerifier.
//
// 🔒 F39 / F43 — INVESTIGATED AGAINST THE KOTLIN SOURCE THIS SESSION, and it REPRODUCES. The chain:
//
//  1. auth/Oidc.kt:73-76 uses `DefaultJWTClaimsVerifier(exactMatchClaims, requiredClaims)` — the
//     two-arg form. The three-arg form, which takes an `acceptedAudience` and does a CONTAINS check,
//     is not used.
//  2. `JWTClaimsSet.Builder().audience(clientId)` stores `aud` as a ONE-ELEMENT List<String>.
//  3. With no acceptedAudience, the verifier treats `aud` as just another exact-match claim and
//     compares it with equals() — List.equals, i.e. same size, same order.
//
// So `aud: ["<clientId>", "<other>"]` — which Okta and Entra DO emit when a second resource is
// requested — is REJECTED, while `aud: "<clientId>"` (a bare string, normalised by the JWT parser to
// a singleton list) is accepted.
//
// A Go port written with the usual `slices.Contains(aud, clientID)` would ACCEPT the multi-audience
// token: a WIDENING divergence on an authentication path, i.e. the port would authenticate a token
// the Kotlin rejects. That is the failure this function exists to avoid, and
// TestValidate_F43_MultiAudienceTokenIsRejected pins it.
//
// ⚠️ Unverified in ONE respect, stated so it is not read as settled: nimbus-jose-jwt 9.40's jar is
// still not on this machine (14-auth.md records the same failed `find`), so steps 2 and 3 are read
// off the library's documented constructor semantics and the Kotlin call site, not off its bytecode.
// The in-repo evidence does not decide it either — IdTokenValidatorTest.kt's `claims()` helper
// defaults `audience: String = clientId` and case 4 only tries a WRONG SINGLE audience — which is
// precisely coverage gap 13. The pinning test added here is therefore the port's OWN oracle for this
// behaviour, and 04/14's Q11 stays open until someone runs the Kotlin suite with a multi-aud token.
func audienceMatches(raw any, clientID string) bool {
	switch aud := raw.(type) {
	case string:
		// A bare-string `aud` is normalised to a singleton list by every JWT parser, Nimbus's
		// included, so it matches a singleton expectation.
		return aud == clientID
	case []any:
		if len(aud) != 1 {
			return false
		}
		s, ok := aud[0].(string)
		return ok && s == clientID
	default:
		return false
	}
}

// numericDate reads a JWT NumericDate claim (RFC 7519 §2: seconds since the epoch, integer or
// fractional). ok=false means the claim was absent or null.
func numericDate(raw any) (time.Time, bool, error) {
	switch v := raw.(type) {
	case nil:
		return time.Time{}, false, nil
	case json.Number:
		if secs, err := v.Int64(); err == nil {
			return time.Unix(secs, 0), true, nil
		}
		f, err := v.Float64()
		if err != nil {
			return time.Time{}, false, fmt.Errorf("%q is not a NumericDate", v.String())
		}
		return time.Unix(int64(f), 0), true, nil
	case float64:
		return time.Unix(int64(v), 0), true, nil
	default:
		return time.Time{}, false, fmt.Errorf("%v is not a NumericDate", raw)
	}
}
