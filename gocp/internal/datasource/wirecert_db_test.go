package datasource_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
)

// ---------------------------------------------------------------------------------------------
// WireCertRouteDbTest — 05-datasources-catalog.md §9, five cases, ported whole.
//
// From the Kotlin suite's class KDoc, which is the statement of why this route needs a TEST rather
// than an inspection (WireCertRouteDbTest.kt:42-47):
//
//	"This route hands out trust material, so its gate is load-bearing in a way the happy path cannot
//	show: the bytes are useless to an attacker on their own, but the route also reveals WHICH
//	datasources exist and which address they answer on, and it previously resolved its principal as
//	`userSession()?.principal ?: \"debug-user\"` — an unauthenticated caller silently became
//	`debug-user` and got whatever that identity could connect to. Nothing in the response
//	distinguishes the two cases, which is exactly why it needs a test rather than an inspection."
//
// Every case below runs with PM_AUTH_DEBUG OFF and against REAL Cedar over the `policy` table —
// "with it on, every gate short-circuits and this test proves nothing" — and every datasource is
// created through `DatasourceStore.Register`, "the same path the proxy's gRPC Register drives, so
// the presence/clear semantics of the chain are exercised rather than bypassed by a direct INSERT."
// ---------------------------------------------------------------------------------------------

const (
	wireConnector = "connector@example.com"
	wireStranger  = "stranger@example.com"
)

// connectPermit is the Kotlin fixture's policy: only members of Role::"connector" may connect, to
// any datasource.
const connectPermit = `permit(
    principal in Role::"connector",
    action == Action::"datasource.connect",
    resource
);`

type wireCertFixture struct {
	*fixture
	withChain datasource.Datasource
	noChain   datasource.Datasource
	chainPEM  string
}

func newWireCertFixture(t *testing.T) *wireCertFixture {
	t.Helper()
	f := newFixture(t, withRealCedar())

	chain := selfSignedPEM(t, "pm-test-ca")
	withChain := f.registerDatasource("cert-ds", datasource.EngineMySQL, "app",
		"proxy.example.com:6033", &chain, true)
	// A proxy serving TLS that publishes NOTHING (PM_TLS_NO_ADVERTISE): there is no file to hand out,
	// but this is emphatically not "no TLS" and not "no such datasource".
	noChain := f.registerDatasource("public-ds", datasource.EngineMySQL, "app",
		"public.example.com:6033", nil, true)

	roleID := f.seed.Role("connector")
	f.seed.User(wireConnector)
	f.seed.User(wireStranger)
	f.seed.AssignRole(wireConnector, roleID)
	f.addPolicy("wire-cert-connect", connectPermit)

	return &wireCertFixture{fixture: f, withChain: withChain, noChain: noChain, chainPEM: chain}
}

// TestAnUnauthenticatedCallerGets401NeverADebugUserFallback is 🔒 WireCertRouteDbTest case 1 /
// INV-A5-3 — the regression this suite exists for.
// KT: WireCertRouteDbTest.kt#an unauthenticated caller gets 401, never a debug-user fallback
func TestAnUnauthenticatedCallerGets401NeverADebugUserFallback(t *testing.T) {
	f := newWireCertFixture(t)

	rec := f.anon("GET", "/api/datasources/"+strconv.FormatInt(f.withChain.ID, 10)+"/wire-cert", "")
	assertStatus(t, rec, http.StatusUnauthorized,
		"no session and no bearer must be 401; resolving the principal as \"debug-user\" would hand the "+
			"advertised trust material and datasource inventory to an anonymous caller")
	assertAPIError(t, rec, "common.unauthenticated", "unauthenticated wire-cert")
	if strings.Contains(rec.Body.String(), "BEGIN CERTIFICATE") {
		t.Error("an unauthenticated response must not carry the certificate")
	}
	// The literal the Kotlin's earlier draft fell through to. Asserting its ABSENCE is the whole point:
	// nothing in a 401 body distinguishes the two cases, so the test has to name the failure mode.
	if strings.Contains(rec.Body.String(), datasource.DebugPrincipal) {
		t.Errorf("the 401 mentions %q: %s", datasource.DebugPrincipal, rec.Body.String())
	}
}

// TestAnAuthenticatedCallerWithoutDatasourceConnectGets403 is 🔒 WireCertRouteDbTest case 2 /
// INV-A5-2 — "a session alone is not authorization".
// KT: WireCertRouteDbTest.kt#an authenticated caller without datasource-connect gets 403
func TestAnAuthenticatedCallerWithoutDatasourceConnectGets403(t *testing.T) {
	f := newWireCertFixture(t)

	rec := f.as(wireStranger, "GET", "/api/datasources/"+strconv.FormatInt(f.withChain.ID, 10)+"/wire-cert", "")
	assertStatus(t, rec, http.StatusForbidden,
		"a session alone is not authorization — the route must run the same datasource.connect decision "+
			"the console's list runs, or it advertises a connection the caller may not make")
	assertAPIError(t, rec, "datasource.not_connectable", "wire-cert without a connect grant")
	if strings.Contains(rec.Body.String(), "BEGIN CERTIFICATE") {
		t.Error("a forbidden response must not carry the certificate")
	}
	// ⚠️ 403 `datasource.not_connectable`, NOT the admin gate's `common.forbidden`: the two are
	// different i18n keys and the console renders different sentences. A port that reused the generic
	// code would tell an unprivileged user their session was rejected rather than that they lack
	// connect authority on this datasource.
	if strings.Contains(rec.Body.String(), "common.forbidden") {
		t.Errorf("wire-cert answered the ADMIN gate's code: %s", rec.Body.String())
	}
}

// TestAGrantedCallerDownloadsTheAdvertisedChainAsAPemAttachment is WireCertRouteDbTest case 3.
//
// 🔒 The filename is built FROM THE NUMERIC ID, NOT THE NAME — "a datasource name is barely
// constrained, and a quote or CRLF in one would be header injection here."
// KT: WireCertRouteDbTest.kt#a granted caller downloads the advertised chain as a PEM attachment
func TestAGrantedCallerDownloadsTheAdvertisedChainAsAPemAttachment(t *testing.T) {
	f := newWireCertFixture(t)
	id := strconv.FormatInt(f.withChain.ID, 10)

	rec := f.as(wireConnector, "GET", "/api/datasources/"+id+"/wire-cert", "")
	assertStatus(t, rec, http.StatusOK, "a granted caller")
	if !strings.Contains(rec.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("the granted caller must receive the chain, got: %s", rec.Body.String())
	}
	if rec.Body.String() != f.chainPEM {
		t.Errorf("the body is not the stored chain byte for byte")
	}
	want := `attachment; filename="datasource-` + id + `-wire-cert.pem"`
	if got := rec.Header().Get("Content-Disposition"); got != want {
		t.Errorf("Content-Disposition = %q, want %q", got, want)
	}
	// ⚠️ `ContentType.parse("application/x-pem-file")` — NOT a text/* type, so Ktor appends no charset.
	if got := rec.Header().Get("Content-Type"); got != "application/x-pem-file" {
		t.Errorf("Content-Type = %q, want a bare application/x-pem-file", got)
	}
}

// TestADatasourceWhoseProxyPublishedNoChainIs404WithItsOwnCode is WireCertRouteDbTest case 4.
//
// 🔒 Distinct from `common.not_found` "so the console can say 'this proxy publishes no certificate'
// instead of 'no such datasource' — the two are different operator problems, and this datasource
// DOES serve TLS."
// KT: WireCertRouteDbTest.kt#a datasource whose proxy published no chain is 404 with its own code
func TestADatasourceWhoseProxyPublishedNoChainIs404WithItsOwnCode(t *testing.T) {
	f := newWireCertFixture(t)

	rec := f.as(wireConnector, "GET", "/api/datasources/"+strconv.FormatInt(f.noChain.ID, 10)+"/wire-cert", "")
	assertStatus(t, rec, http.StatusNotFound, "a datasource with no published chain")
	assertAPIError(t, rec, "datasource.no_wire_cert", "a datasource with no published chain")
	// It really is a TLS-serving datasource — the row says so, and that is what makes the distinct
	// code necessary rather than cosmetic.
	if !f.mustGet(f.noChain.ID).AdvertiseWireTls {
		t.Error("the fixture's no-chain datasource is not advertising TLS; the case is vacuous")
	}
}

// TestAnUnknownDatasourceIdIs404AndIsNotConfusedWithAMissingChain is 🔒 WireCertRouteDbTest case 5 —
// the other direction, and the security-relevant one.
//
// "a nonexistent datasource must not report the no-chain code: that would tell a caller the id
// exists."
// KT: WireCertRouteDbTest.kt#an unknown datasource id is 404 and is not confused with a missing chain
func TestAnUnknownDatasourceIdIs404AndIsNotConfusedWithAMissingChain(t *testing.T) {
	f := newWireCertFixture(t)

	rec := f.as(wireConnector, "GET", "/api/datasources/999999/wire-cert", "")
	assertStatus(t, rec, http.StatusNotFound, "an unknown datasource id")
	body := assertAPIError(t, rec, "common.not_found", "an unknown datasource id")
	assertParam(t, body, "resource", "datasource", "an unknown datasource id")
	if strings.Contains(rec.Body.String(), "no_wire_cert") {
		t.Errorf("a nonexistent datasource reported the no-chain code, confirming the id exists: %s",
			rec.Body.String())
	}
}

// TestTrustMaterialIsInspectedAndServedNeverWithheld is 🔒 INV-A5-22, and the reason the Kotlin
// route's own kdoc is NOT ported (§10 Q7).
//
// Quoted: "Served whatever it looks like. The client verifies, and it is the only party that can
// report a meaningful error about its own trust store — withholding the file just leaves the operator
// with nothing to install and no way to see why." `TrustChainInspectionTest.kt:9` says it flatly:
// "inspectTrustChain REPORTS on trust material; it never gates."
//
// 🔴 The route kdoc at Datasources.kt:888-891 describes a re-validation answering 409 that DOES NOT
// EXIST, on a premise ("Registration already refuses a chain that does not chain") that is also
// false. This test is what stops a reader porting the comment instead of the code.
func TestTrustMaterialIsInspectedAndServedNeverWithheld(t *testing.T) {
	f := newWireCertFixture(t)
	f.inspectBad = true
	id := strconv.FormatInt(f.withChain.ID, 10)

	rec := f.as(wireConnector, "GET", "/api/datasources/"+id+"/wire-cert", "")
	assertStatus(t, rec, http.StatusOK,
		"a chain the inspector reports on is still SERVED — inspectTrustChain never gates")
	if !strings.Contains(rec.Body.String(), "BEGIN CERTIFICATE") {
		t.Error("the reported-on chain was withheld")
	}
	if len(f.inspected) != 1 || f.inspected[0] != f.chainPEM {
		t.Errorf("the inspector saw %d chains, want exactly the served one", len(f.inspected))
	}
}

// TestTheChainAlsoRidesOnTheDatasourceList is INV-A5-10's reproduced self-contradiction (§10 Q5).
//
// ⚠️ `wireCertChain`'s kdoc says the chain is read separately "so a certificate body never rides
// along in the datasource poll every client makes" — but the 15-column projection DOES include
// `advertise_cert_chain` and `Datasources.kt:59-63` argues for that. The BEHAVIOUR ported is "the
// chain rides on the list", which makes `wireCertChain` a redundant query, and it is kept redundant.
// Pinned here so the contradiction is a decision rather than an accident.
func TestTheChainAlsoRidesOnTheDatasourceList(t *testing.T) {
	f := newWireCertFixture(t)

	rec := f.as(wireStranger, "GET", "/api/datasources", "")
	assertStatus(t, rec, http.StatusOK, "the datasource list")
	if !strings.Contains(rec.Body.String(), "BEGIN CERTIFICATE") {
		t.Errorf("the chain does NOT ride on the list; INV-A5-10's ported behaviour says it does: %s",
			rec.Body.String())
	}
	// ⚠️ And it rides there for a caller with NO connect grant — `wireStranger` is 403 on the
	// certificate route and gets the same bytes off the list. That is the contradiction, on the wire.
}

// ---------------------------------------------------------------------------------------------
// GET {id}/catalog — the same gate, over real Cedar (ElevationContextRouteAuthzDbTest case 7)
// ---------------------------------------------------------------------------------------------

// TestCatalogBrowseIsGatedByDatasourceConnect is 🔒 INV-A5-2, over the production Cedar path.
//
// "Browsing the catalog needs the same datasource.connect authority as opening a session." Two
// directions, because a gate that always denies passes half of this test.
// KT: ElevationContextRouteAuthzDbTest.kt#catalog browse is gated by datasource-connect
func TestCatalogBrowseIsGatedByDatasourceConnect(t *testing.T) {
	f := newWireCertFixture(t)
	id := strconv.FormatInt(f.withChain.ID, 10)
	f.seed.CatalogColumns(f.withChain.ID, dbtest.CatalogColumn{
		Schema: "app", Table: "users", Column: "id", DataType: "int", Ordinal: 1, Nullable: true,
	})

	denied := f.as(wireStranger, "GET", "/api/datasources/"+id+"/catalog", "")
	assertStatus(t, denied, http.StatusForbidden, "no datasource.connect -> catalog browse forbidden")
	assertAPIError(t, denied, "datasource.not_connectable", "catalog without a connect grant")

	allowed := f.as(wireConnector, "GET", "/api/datasources/"+id+"/catalog", "")
	assertStatus(t, allowed, http.StatusOK, "with datasource.connect -> catalog browse allowed")
	var columns []datasource.CatalogColumn
	decodeJSON(t, allowed, &columns)
	if len(columns) != 1 || columns[0].Column != "id" {
		t.Fatalf("catalog = %+v, want the one seeded column", columns)
	}
	// 🔒 INV-A5-1 — isTemp is NEVER set by A5. A base-catalog column carrying it true would be read
	// UNMASKED by A6's temp path, with no Cedar grant.
	if columns[0].IsTemp {
		t.Error("a base-catalog column came back with isTemp=true (INV-A5-1)")
	}
	// The `catalog` segment is computed in SQL: MySQL pins "def".
	if columns[0].Catalog != "def" {
		t.Errorf("catalog segment = %q, want \"def\" for a MySQL datasource", columns[0].Catalog)
	}
}

// TestAnEmptyCatalogIsAnArrayNotNull — a datasource whose proxy has never pushed answers `[]`, and
// the console renders `.length` on it.
func TestAnEmptyCatalogIsAnArrayNotNull(t *testing.T) {
	f := newWireCertFixture(t)
	rec := f.as(wireConnector, "GET", "/api/datasources/"+strconv.FormatInt(f.withChain.ID, 10)+"/catalog", "")
	assertStatus(t, rec, http.StatusOK, "an unsynced catalog")
	if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
		t.Errorf("an empty catalog is %q, want `[]`", got)
	}
}

// TestTheCatalogRouteOrdersItsFailuresTheKotlinsWay.
//
// 🔒 401 → 400 bad_id → 404 → 403. An UNAUTHENTICATED request to a nonexistent id is 401; an
// AUTHENTICATED one is 404 — so an authenticated caller learns the id does not exist BEFORE the
// connect check runs. Reproduced verbatim: reordering the 404 after the 403 would be a
// (defensible) hardening and is not this port's call.
func TestTheCatalogRouteOrdersItsFailuresTheKotlinsWay(t *testing.T) {
	f := newWireCertFixture(t)

	rec := f.anon("GET", "/api/datasources/999999/catalog", "")
	assertStatus(t, rec, http.StatusUnauthorized, "unauthenticated beats unknown-id")

	rec = f.as(wireStranger, "GET", "/api/datasources/abc/catalog", "")
	assertStatus(t, rec, http.StatusBadRequest, "bad id beats the connect check")
	assertAPIError(t, rec, "common.bad_id", "bad id beats the connect check")

	rec = f.as(wireStranger, "GET", "/api/datasources/999999/catalog", "")
	assertStatus(t, rec, http.StatusNotFound,
		"an unknown id is 404 even for a caller with no connect grant — the lookup precedes mayConnect")
	assertAPIError(t, rec, "common.not_found", "unknown id, no grant")
}

// TestTheListIsFilteredByConnectOnlyWhenConnectableIsRequested is the port of
// `ElevationContextRouteAuthzDbTest` case 8 — the only route-level coverage of `mayConnect` on
// `/api/datasources`, and it runs over real Cedar for the same reason the Kotlin does.
//
// Three steps, in the Kotlin's order:
//  1. Default (no param): the FULL list, "so JIT-request compose can show datasources the caller
//     cannot yet connect to".
//  2. `?connectable=true` with no grant: filtered OUT (the query picker).
//  3. Granting `datasource.connect` brings it back in.
//
// KT: ElevationContextRouteAuthzDbTest.kt#datasource list is filtered by connect only when connectable is requested
func TestTheListIsFilteredByConnectOnlyWhenConnectableIsRequested(t *testing.T) {
	f := newWireCertFixture(t)

	full := f.as(wireStranger, "GET", "/api/datasources", "")
	assertStatus(t, full, http.StatusOK, "the default list")
	if !strings.Contains(full.Body.String(), "cert-ds") {
		t.Error("the default list is filtered — compose needs it unfiltered")
	}

	filtered := f.as(wireStranger, "GET", "/api/datasources?connectable=true", "")
	assertStatus(t, filtered, http.StatusOK, "?connectable=true without a grant")
	if strings.Contains(filtered.Body.String(), "cert-ds") {
		t.Errorf("no datasource.connect -> must be excluded from ?connectable=true: %s", filtered.Body.String())
	}

	f.addPolicy("stranger-connect-list",
		`permit(principal == User::"`+wireStranger+`", action == Action::"datasource.connect", resource == Datasource::"cert-ds");`)
	allowed := f.as(wireStranger, "GET", "/api/datasources?connectable=true", "")
	assertStatus(t, allowed, http.StatusOK, "?connectable=true with a grant")
	if !strings.Contains(allowed.Body.String(), "cert-ds") {
		t.Errorf("with datasource.connect -> must be included in ?connectable=true: %s", allowed.Body.String())
	}
	// 🔒 The grant is NAME-scoped (INV-A2-2): `public-ds` is a different resource and stays out.
	if strings.Contains(allowed.Body.String(), "public-ds") {
		t.Errorf("a grant on cert-ds admitted public-ds — the decision is not name-keyed: %s",
			allowed.Body.String())
	}
}

// TestAuthDebugSeesEverythingWithoutASession is the bypass, stated once.
//
// 🔒 It is the ONLY way `"debug-user"` may appear, and mayConnect's step 1 returns true before any
// role or Cedar work — so a debug control plane serves the catalog and the certificate to a caller
// with no session at all. INV-A2-16: the bypass never SKIPS Cedar, it prevents Cedar from being
// REACHED.
func TestAuthDebugSeesEverythingWithoutASession(t *testing.T) {
	f := newFixture(t, withAuthDebug())
	chain := selfSignedPEM(t, "debug-ca")
	ds := f.registerDatasource("debug-ds", datasource.EngineMySQL, "app", "p:6033", &chain, true)
	id := strconv.FormatInt(ds.ID, 10)

	assertStatus(t, f.anon("GET", "/api/datasources", ""), http.StatusOK, "authDebug list")
	assertStatus(t, f.anon("GET", "/api/datasources?connectable=true", ""), http.StatusOK, "authDebug connectable")
	assertStatus(t, f.anon("GET", "/api/datasources/"+id+"/catalog", ""), http.StatusOK, "authDebug catalog")
	assertStatus(t, f.anon("GET", "/api/datasources/"+id+"/wire-cert", ""), http.StatusOK, "authDebug wire-cert")

	// mayConnect short-circuits BEFORE resolving roles, so the resolver is never asked.
	if len(f.connect.calls) != 0 {
		t.Errorf("authDebug reached Cedar %d times; step 1 must return before it", len(f.connect.calls))
	}
}

// ---------------------------------------------------------------------------------------------

// selfSignedPEM mints a real self-signed certificate — "the ordinary self-hosted case: the proxy's
// own certificate IS the anchor".
//
// ⚠️ It is a REAL certificate, not the Kotlin fixture's truncated literal. The Kotlin's constant is
// only ever compared for the `BEGIN CERTIFICATE` substring, but the Go route hands the bytes to
// grpcsvc.InspectTrustChain in production, and a fixture that could not parse would exercise the
// "unparseable" arm on every case instead of the intended one. [TestTrustMaterialIsInspectedAnd
// ServedNeverWithheld] drives the reporting arm explicitly instead.
func selfSignedPEM(t *testing.T, commonName string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
