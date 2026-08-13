package pgproxy

import (
	"strings"
	"testing"
)

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
