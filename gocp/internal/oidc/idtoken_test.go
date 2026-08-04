package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// Port of IdTokenValidatorTest.kt — 8 cases — plus the two REPRODUCE + PIN suites this increment owes:
// F24 (malformed groups shape) and F43 (multi-audience rejection).
//
// ORACLE: control-plane/src/test/kotlin/.../IdTokenValidatorTest.kt, read this session. Its `claims()`
// helper's defaults are reproduced in [fakeIdP.defaultClaims], so each case below changes exactly the
// one field its Kotlin counterpart changes.

const testClientID = "test-client"

func newValidatorFixture(t *testing.T) (*fakeIdP, *IDTokenValidator) {
	t.Helper()
	idp := newFakeIdP(t, "test-kid")
	return idp, idp.validatorFor(testClientID)
}

// --- Case 1 · `a correctly signed, matching id_token validates and surfaces claims`
// KT: IdTokenValidatorTest.kt#a correctly signed, matching id_token validates and surfaces claims
func TestValidate_CorrectlySignedTokenSurfacesClaims(t *testing.T) {
	idp, v := newValidatorFixture(t)
	tok := idp.sign(idp.defaultClaims(testClientID), nil)

	got := v.Validate(context.Background(), tok, types.Ptr("the-nonce"))
	if got == nil {
		t.Fatal("Validate returned nil for a correctly signed token")
	}
	if got.Subject != "user-123" {
		t.Errorf("Subject = %q", got.Subject)
	}
	if got.Email == nil || *got.Email != "alice@example.com" {
		t.Errorf("Email = %v", got.Email)
	}
	if want := []string{"engineering", "eng-leads"}; !reflect.DeepEqual(got.Groups, want) {
		t.Errorf("Groups = %v, want %v", got.Groups, want)
	}
	// F28's dead field, asserted because the Kotlin case asserts it.
	if got.Nonce == nil || *got.Nonce != "the-nonce" {
		t.Errorf("Nonce = %v", got.Nonce)
	}
}

// --- Case 2 🔒 · `a nonce mismatch fails closed`
// KT: IdTokenValidatorTest.kt#a nonce mismatch fails closed
func TestValidate_NonceMismatchFailsClosed(t *testing.T) {
	idp, v := newValidatorFixture(t)
	tok := idp.sign(idp.defaultClaims(testClientID), nil)

	if got := v.Validate(context.Background(), tok, types.Ptr("a-different-nonce")); got != nil {
		t.Fatalf("Validate = %+v, want nil", got)
	}
}

// --- Case 3 · `the nonce check is skipped when the caller expects none (device flow)`
//
// 🔒 INV-A14-31 — this is what makes `revalidateSession`'s `expectedNonce = null` legitimate: a
// refresh-grant id_token legitimately carries no nonce. Making the check unconditional breaks daemon
// liveness, which is why the parameter stays a pointer.
// KT: IdTokenValidatorTest.kt#the nonce check is skipped when the caller expects none (device flow)
func TestValidate_NonceCheckSkippedWhenCallerExpectsNone(t *testing.T) {
	idp, v := newValidatorFixture(t)
	opts := idp.defaultClaims(testClientID)
	opts.nonce = nil
	tok := idp.sign(opts, nil)

	got := v.Validate(context.Background(), tok, nil)
	if got == nil {
		t.Fatal("Validate returned nil with expectedNonce = nil")
	}
	if got.Subject != "user-123" {
		t.Errorf("Subject = %q", got.Subject)
	}
	if got.Nonce != nil {
		t.Errorf("Nonce = %q, want nil", *got.Nonce)
	}
}

// --- Case 4 🔒 · `a wrong audience fails closed`
// KT: IdTokenValidatorTest.kt#a wrong audience fails closed
func TestValidate_WrongAudienceFailsClosed(t *testing.T) {
	idp, v := newValidatorFixture(t)
	opts := idp.defaultClaims(testClientID)
	opts.audience = "some-other-client"
	tok := idp.sign(opts, nil)

	if got := v.Validate(context.Background(), tok, types.Ptr("the-nonce")); got != nil {
		t.Fatalf("Validate = %+v, want nil", got)
	}
}

// --- Case 5 🔒 · `a wrong issuer fails closed`
//
// 🔒 The `iss` comparison is EXACT — no trailing-slash normalisation, unlike Discovery.Document. This
// case pins the rejection; the sub-test below pins that the normalisation really is absent, which is
// the half a port is most likely to "helpfully" add.
// KT: IdTokenValidatorTest.kt#a wrong issuer fails closed
func TestValidate_WrongIssuerFailsClosed(t *testing.T) {
	idp, v := newValidatorFixture(t)
	opts := idp.defaultClaims(testClientID)
	opts.issuer = "http://not-the-real-issuer"
	if got := v.Validate(context.Background(), idp.sign(opts, nil), types.Ptr("the-nonce")); got != nil {
		t.Fatalf("Validate = %+v, want nil", got)
	}

	t.Run("a trailing slash on the iss claim is NOT normalised away", func(t *testing.T) {
		opts := idp.defaultClaims(testClientID)
		opts.issuer = idp.issuer() + "/"
		if got := v.Validate(context.Background(), idp.sign(opts, nil), types.Ptr("the-nonce")); got != nil {
			t.Fatalf("Validate = %+v, want nil — iss is exact-match, only discovery normalises", got)
		}
	})
}

// --- Case 6 🔒 · `an expired token fails closed`
//
// expiresInSeconds = -60 is exactly on the assumed 60-second skew boundary, and the comparison is
// STRICT (`exp > now - skew`), so it must fail. See [MaxClockSkew] on why this test is the constraint
// that fixes the constant.
// KT: IdTokenValidatorTest.kt#an expired token fails closed
func TestValidate_ExpiredTokenFailsClosed(t *testing.T) {
	idp, v := newValidatorFixture(t)
	opts := idp.defaultClaims(testClientID)
	opts.expiresInSeconds = -60
	if got := v.Validate(context.Background(), idp.sign(opts, nil), types.Ptr("the-nonce")); got != nil {
		t.Fatalf("Validate = %+v, want nil", got)
	}

	t.Run("a token still inside the skew window is accepted", func(t *testing.T) {
		opts := idp.defaultClaims(testClientID)
		opts.expiresInSeconds = -30
		if got := v.Validate(context.Background(), idp.sign(opts, nil), types.Ptr("the-nonce")); got == nil {
			t.Fatal("a token expired 30s ago must still pass a 60s skew — otherwise the skew is 0 and clocks must be perfect")
		}
	})
}

// --- Case 7 🔒 · `a token signed by an untrusted key fails closed (bad signature)`
//
// The other key carries the SAME kid, so selection succeeds and only the signature check can reject
// it. A port that trusted the kid without verifying would pass every other case and fail this one.
// KT: IdTokenValidatorTest.kt#a token signed by an untrusted key fails closed (bad signature)
func TestValidate_UntrustedKeyFailsClosed(t *testing.T) {
	idp, v := newValidatorFixture(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tok := idp.sign(idp.defaultClaims(testClientID), other)

	if got := v.Validate(context.Background(), tok, types.Ptr("the-nonce")); got != nil {
		t.Fatalf("Validate = %+v, want nil", got)
	}
}

// --- Case 8 · `a missing groups claim resolves to an empty list, not a failure`
// KT: IdTokenValidatorTest.kt#a missing groups claim resolves to an empty list, not a failure
func TestValidate_MissingGroupsClaimIsAnEmptyList(t *testing.T) {
	idp, v := newValidatorFixture(t)
	opts := idp.defaultClaims(testClientID)
	opts.groups = nil
	got := v.Validate(context.Background(), idp.sign(opts, nil), types.Ptr("the-nonce"))
	if got == nil {
		t.Fatal("a missing groups claim must not fail validation")
	}
	if len(got.Groups) != 0 {
		t.Errorf("Groups = %v, want empty", got.Groups)
	}
	if got.Groups == nil {
		t.Error("Groups is nil — INV-A1-4 needs [] on the wire, and the provisioner iterates it")
	}
}

// ============================================================================================
// 🔒 REPRODUCE + PIN — F24 / INV-A14-32 (00-INDEX.md:214, disposition table :36)
//
//	"A `groups` claim of the wrong SHAPE (bare string, or comma-joined — both shipped by real IdPs)
//	 fails `as? List<*>` → `emptyList()`. Because provisioning RECONCILES membership to exactly the
//	 claim, an IdP claim-shape change strips every group from every user on next login, including
//	 `system:admin`."
//
// This test asserts the BUGGY behaviour ON PURPOSE. A later fix has to change it deliberately and
// visibly instead of silently passing. The DESTRUCTIVE half — that the empty list then strips
// system:admin — is pinned end-to-end in TestProvision_F24_MalformedShapeStripsSystemAdmin
// (provisioner_db_test.go); this half pins where the emptiness is manufactured.
// ============================================================================================

func TestValidate_F24_MalformedGroupsClaimSilentlyBecomesEmpty(t *testing.T) {
	idp, v := newValidatorFixture(t)

	cases := []struct {
		name   string
		groups any
		want   []string
	}{
		// The two shapes 00-INDEX.md names as shipped by real IdPs.
		{"a bare string", "engineering", []string{}},
		{"a comma-joined string", "engineering,eng-leads", []string{}},
		// Two more that take the identical path.
		{"an object", map[string]any{"values": []any{"engineering"}}, []string{}},
		{"a number", 7, []string{}},
		{"an explicit null", nil, []string{}},
		// Element granularity: mapNotNull drops non-strings INDIVIDUALLY rather than failing.
		{"a mixed list", []any{"engineering", 7, nil, "eng-leads"}, []string{"engineering", "eng-leads"}},
		{"a list of numbers", []any{1, 2, 3}, []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := idp.defaultClaims(testClientID)
			opts.groups = tc.groups
			// A nil `groups` in claimsOpts means OMIT, so the explicit-null case is built by hand.
			var tok string
			if tc.name == "an explicit null" {
				claims := map[string]any{
					"iss": idp.issuer(), "sub": "user-123", "aud": testClientID,
					"exp": nowPlus(300), "nonce": "the-nonce", "groups": nil,
				}
				tok = signClaims(t, idp.key, idp.kid, claims)
			} else {
				tok = idp.sign(opts, nil)
			}

			got := v.Validate(context.Background(), tok, types.Ptr("the-nonce"))
			if got == nil {
				t.Fatal("F24: a malformed groups claim must NOT fail validation — it silently empties. " +
					"If this now fails closed, the defect was fixed; update the finding, not the test.")
			}
			if !reflect.DeepEqual(got.Groups, tc.want) {
				t.Fatalf("F24: Groups = %v, want %v", got.Groups, tc.want)
			}
		})
	}
}

// ============================================================================================
// 🔒 REPRODUCE + PIN — F43 / 14-auth.md Q11: audience is EXACT-MATCH, not "contains".
//
// INVESTIGATED against the Kotlin source this session (auth/Oidc.kt:73-76): the TWO-argument
// `DefaultJWTClaimsVerifier(exactMatchClaims, requiredClaims)` is used, with
// `JWTClaimsSet.Builder().audience(clientId)` — a ONE-element list — as an exact-match claim. The
// three-argument overload, which takes an acceptedAudience and does a contains-check, is NOT used.
//
// So a multi-audience id_token — which Okta and Entra DO emit when a second resource is requested —
// is REJECTED. A Go port written with `slices.Contains(aud, clientID)` would ACCEPT it: a WIDENING
// divergence on an authentication path. This test is the port's own oracle for that, because the
// Kotlin suite does not decide it (its `claims()` helper defaults `audience: String = clientId` and
// case 4 only tries a wrong SINGLE audience — coverage gap 13).
//
// ⚠️ If the product decides multi-audience must be accepted, that is a deliberate behaviour change to
// make on BOTH sides at once — not a Go-side "fix".
// ============================================================================================

func TestValidate_F43_MultiAudienceTokenIsRejected(t *testing.T) {
	idp, v := newValidatorFixture(t)

	t.Run("aud with the client id PLUS another resource is rejected", func(t *testing.T) {
		opts := idp.defaultClaims(testClientID)
		opts.audience = []any{testClientID, "https://api.example/resource"}
		if got := v.Validate(context.Background(), idp.sign(opts, nil), types.Ptr("the-nonce")); got != nil {
			t.Fatalf("F43: Validate = %+v, want nil — aud is EXACT-MATCH against a one-element list", got)
		}
	})
	t.Run("aud with the client id FIRST is still rejected", func(t *testing.T) {
		opts := idp.defaultClaims(testClientID)
		opts.audience = []any{"https://api.example/resource", testClientID}
		if got := v.Validate(context.Background(), idp.sign(opts, nil), types.Ptr("the-nonce")); got != nil {
			t.Fatalf("F43: Validate = %+v, want nil", got)
		}
	})
	t.Run("a single-element aud ARRAY is accepted", func(t *testing.T) {
		opts := idp.defaultClaims(testClientID)
		opts.audience = []any{testClientID}
		if got := v.Validate(context.Background(), idp.sign(opts, nil), types.Ptr("the-nonce")); got == nil {
			t.Fatal("a one-element aud array must be accepted — every JWT parser normalises a bare string to one")
		}
	})
	t.Run("an absent aud is rejected", func(t *testing.T) {
		opts := idp.defaultClaims(testClientID)
		opts.audience = nil
		if got := v.Validate(context.Background(), idp.sign(opts, nil), types.Ptr("the-nonce")); got != nil {
			t.Fatalf("Validate = %+v, want nil", got)
		}
	})
}

// --- Extra 🔒 INV-A14-30 · the signature algorithm is PINNED to RS256.
//
// The three attacks the pin closes, each asserted directly: `alg: none`, an HMAC-signed token whose
// secret is the IdP's PUBLIC key (algorithm confusion), and a well-formed token in a different
// asymmetric family. None is covered by the Kotlin suite.
func TestValidate_AlgorithmIsPinnedToRS256(t *testing.T) {
	idp, v := newValidatorFixture(t)
	claims := map[string]any{
		"iss": idp.issuer(), "sub": "user-123", "aud": testClientID,
		"exp": nowPlus(300), "nonce": "the-nonce",
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

	t.Run("alg none is rejected", func(t *testing.T) {
		header := b64([]byte(`{"alg":"none","typ":"JWT"}`))
		unsecured := header + "." + b64(payload) + "."
		if got := v.Validate(context.Background(), unsecured, types.Ptr("the-nonce")); got != nil {
			t.Fatalf("Validate = %+v, want nil for an unsecured JWT", got)
		}
	})

	t.Run("an HMAC-signed token is rejected (algorithm confusion)", func(t *testing.T) {
		// The classic attack: the attacker reads the RSA public key from jwks_uri and uses its
		// bytes as an HS256 secret. If the verifier accepted "whatever alg the header says", this
		// would authenticate.
		pub, err := json.Marshal(idp.publicJWKS().Keys[0])
		if err != nil {
			t.Fatal(err)
		}
		hs := hs256(t, pub, payload)
		if got := v.Validate(context.Background(), hs, types.Ptr("the-nonce")); got != nil {
			t.Fatalf("Validate = %+v, want nil for an HS256 token", got)
		}
	})

	t.Run("a garbage token is rejected without ever fetching the JWKS", func(t *testing.T) {
		// The property OidcCallbackTest relies on: an unparseable id_token returns nil WITHOUT
		// touching jwks_uri, which is what lets that suite run with an unreachable JWKS URL.
		before := idp.jwksHits.Load()
		if got := v.Validate(context.Background(), "not-a-real-jwt", types.Ptr("the-nonce")); got != nil {
			t.Fatalf("Validate = %+v, want nil", got)
		}
		if after := idp.jwksHits.Load(); after != before {
			t.Errorf("jwks fetched %d time(s) for an unparseable token; parse must fail first", after-before)
		}
	})
}

// --- Extra 🔒 · a token with no `sub` is rejected by the APP-level check.
//
// `sub` is not in the Kotlin's requiredClaims, so the claims verifier lets it through and
// `claims.subject ?: return null` is the only thing that catches it. Deleting that line would pass
// every other case here.
func TestValidate_TokenWithoutSubjectIsRejected(t *testing.T) {
	idp, v := newValidatorFixture(t)
	opts := idp.defaultClaims(testClientID)
	opts.omitSubject = true
	if got := v.Validate(context.Background(), idp.sign(opts, nil), types.Ptr("the-nonce")); got != nil {
		t.Fatalf("Validate = %+v, want nil", got)
	}
}

// --- Extra 🔒 · a NON-STRING nonce or email claim takes the safe-cast path.
//
// `as? String` yields null, so a numeric nonce MISMATCHES (rejected) while a numeric email silently
// becomes nil (accepted, and then the principal falls back to `sub`). Two different outcomes from one
// idiom; both reproduced.
func TestValidate_NonStringNonceAndEmailTakeTheSafeCastPath(t *testing.T) {
	idp, v := newValidatorFixture(t)

	t.Run("a numeric nonce mismatches and is rejected", func(t *testing.T) {
		opts := idp.defaultClaims(testClientID)
		opts.nonce = 42
		if got := v.Validate(context.Background(), idp.sign(opts, nil), types.Ptr("the-nonce")); got != nil {
			t.Fatalf("Validate = %+v, want nil", got)
		}
	})
	t.Run("a numeric email silently becomes nil", func(t *testing.T) {
		opts := idp.defaultClaims(testClientID)
		opts.email = 42
		got := v.Validate(context.Background(), idp.sign(opts, nil), types.Ptr("the-nonce"))
		if got == nil {
			t.Fatal("a non-string email must not fail validation")
		}
		if got.Email != nil {
			t.Errorf("Email = %q, want nil", *got.Email)
		}
	})
}

// --- Extra ⚠️ F36 · the JWKS is re-fetched on EVERY validation.
//
// The Kotlin constructs `RemoteJWKSet(URL(...))` per call and throws Nimbus's cache away with it. The
// observable consequence to preserve: a rotated key takes effect IMMEDIATELY, where a caching port
// would lag by its TTL. Adding a cache here is the change this test exists to notice.
func TestValidate_F36_JWKSIsRefetchedEveryCall(t *testing.T) {
	idp, v := newValidatorFixture(t)
	tok := idp.sign(idp.defaultClaims(testClientID), nil)

	for i := 0; i < 3; i++ {
		if got := v.Validate(context.Background(), tok, types.Ptr("the-nonce")); got == nil {
			t.Fatalf("Validate #%d returned nil", i)
		}
	}
	if got := idp.jwksHits.Load(); got != 3 {
		t.Errorf("jwks_uri fetched %d times over 3 validations, want 3 (F36 — no cache)", got)
	}
	// …while the DISCOVERY document is fetched exactly once (F35). The two caching behaviours are
	// deliberately opposite, and asserting both together is what keeps them from being unified.
	if got := idp.discoveryHits.Load(); got != 1 {
		t.Errorf("discovery fetched %d times, want 1 (F35 — cached forever)", got)
	}
}
