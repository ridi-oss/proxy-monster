package pgproxy

import (
	"reflect"
	"strings"
	"testing"
)

func TestPostgresEmptyQuery(t *testing.T) {
	for _, sql := range []string{
		"",
		" \t\r\n\f",
		"-- empty\n",
		"/* outer /* nested */ comment */",
		";",
		" ; -- empty\n /* still empty */ ; ",
	} {
		if !isPostgresEmptyQuery(sql) {
			t.Errorf("isPostgresEmptyQuery(%q) = false, want true", sql)
		}
	}
	for _, sql := range []string{
		"SELECT 1",
		"-- empty\nSELECT 1",
		"/* empty */ SELECT 1",
		"/* unterminated",
		"-",
		"/",
		"';'",
	} {
		if isPostgresEmptyQuery(sql) {
			t.Errorf("isPostgresEmptyQuery(%q) = true, want false", sql)
		}
	}
}

func TestScramSHA256RFC7677Vector(t *testing.T) {
	const nonce = "rOprNGfwEbeRWgbNEkqO"
	const serverFirst = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
	const wantFinal = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
	const serverFinal = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="

	client := newScramClientWithNonceAndUser("pencil", nonce, "user")
	if got := string(client.clientFirstMessage()); got != "n,,n=user,r="+nonce {
		t.Fatalf("client first = %q", got)
	}
	if err := client.recvServerFirstMessage([]byte(serverFirst)); err != nil {
		t.Fatalf("server first: %v", err)
	}
	final, err := client.clientFinalMessage()
	if err != nil {
		t.Fatalf("client final: %v", err)
	}
	if got := string(final); got != wantFinal {
		t.Fatalf("client final = %q, want %q", got, wantFinal)
	}
	if err := client.verifyServerFinal([]byte(serverFinal)); err != nil {
		t.Fatalf("server final: %v", err)
	}
}

func TestScramRejectsIterationBoundsAndNonExtendingNonce(t *testing.T) {
	for _, serverFirst := range []string{
		"r=clientserver,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4095",
		"r=clientserver,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=1000001",
	} {
		client := newScramClientWithNonceAndUser("pencil", "client", "")
		client.clientFirstMessage()
		if err := client.recvServerFirstMessage([]byte(serverFirst)); err == nil || !strings.Contains(err.Error(), "out of allowed range") {
			t.Fatalf("server first %q error = %v, want iteration-bound rejection", serverFirst, err)
		}
	}

	client := newScramClientWithNonceAndUser("pencil", "client", "")
	client.clientFirstMessage()
	if err := client.recvServerFirstMessage([]byte("r=client,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")); err == nil || !strings.Contains(err.Error(), "strictly extend") {
		t.Fatalf("non-extending nonce error = %v", err)
	}
}

func TestMD5Password(t *testing.T) {
	salt := [4]byte{1, 2, 3, 4}
	if got, want := md5Password("user", "password", salt), "md5a3576f1ae039b8996bc4fc2720f9c71a"; got != want {
		t.Fatalf("md5Password = %q, want %q", got, want)
	}
}

func TestNamespaceProbeFromRows(t *testing.T) {
	str := func(value string) *string { return &value }

	for _, tc := range []struct {
		name             string
		json             string
		wantPath         []string
		wantNames        []string
		wantTypeObserved bool
		wantXIDVisible   bool
	}{
		{
			name:             "visible xid",
			json:             `{"search_path":["pg_catalog","public"],"shadowed_functions":[],"pg_catalog_xid_visible":true}`,
			wantPath:         []string{"pg_catalog", "public"},
			wantNames:        []string{},
			wantTypeObserved: true,
			wantXIDVisible:   true,
		},
		{
			name:             "shadowed xid",
			json:             `{"search_path":["pg_catalog","later"],"shadowed_functions":["unnest"],"pg_catalog_xid_visible":false}`,
			wantPath:         []string{"pg_catalog", "later"},
			wantNames:        []string{"unnest"},
			wantTypeObserved: true,
		},
		{
			name:      "visibility absent",
			json:      `{"search_path":["pg_catalog","public"],"shadowed_functions":[]}`,
			wantPath:  []string{"pg_catalog", "public"},
			wantNames: []string{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := namespaceProbeFromRows([][]*string{{str(tc.json)}})
			if err != nil {
				t.Fatalf("namespaceProbeFromRows: %v", err)
			}
			if !reflect.DeepEqual(got.Namespace, tc.wantPath) ||
				!reflect.DeepEqual(got.PostgresShadowedFunctions, tc.wantNames) ||
				!got.PostgresFunctionShadowingObserved ||
				got.PostgresTypeVisibilityObserved != tc.wantTypeObserved ||
				got.PostgresSystemXIDVisible != tc.wantXIDVisible {
				t.Fatalf("namespace probe = %+v, want path %v, shadows %v, type observed/visible %v/%v", got, tc.wantPath, tc.wantNames, tc.wantTypeObserved, tc.wantXIDVisible)
			}
		})
	}

	for _, tc := range []struct {
		name string
		rows [][]*string
	}{
		{name: "no rows"},
		{name: "extra row", rows: [][]*string{{str(`{}`)}, {str(`{}`)}}},
		{name: "wrong width", rows: [][]*string{{str(`{}`), str(`{}`)}}},
		{name: "null", rows: [][]*string{{nil}}},
		{name: "invalid json", rows: [][]*string{{str(`{`)}}},
		{name: "empty function", rows: [][]*string{{str(`{"search_path":[],"shadowed_functions":[""]}`)}}},
		{name: "uppercase function", rows: [][]*string{{str(`{"search_path":[],"shadowed_functions":["UNNEST"]}`)}}},
		{name: "duplicate function", rows: [][]*string{{str(`{"search_path":[],"shadowed_functions":["unnest","unnest"]}`)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := namespaceProbeFromRows(tc.rows); err == nil {
				t.Fatal("namespaceProbeFromRows succeeded, want strict error")
			}
		})
	}
}
