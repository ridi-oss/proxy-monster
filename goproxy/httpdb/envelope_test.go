package httpdb

import (
	"bytes"
	"strings"
	"testing"
)

func TestEnvelopePreservesOriginalBytes(t *testing.T) {
	body := []byte(" {\n\t\"Unknown\": {\"integer\":900719925474099312345, \"decimal\":1.2300e+50, \"text\":\"<>&\\u0061\"},\n\t\"QueryString\" : \"SELECT \\u0031\"\n} \n")
	envelope, err := DecodeEnvelope(body)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := envelope.WithoutField("Absent")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unchanged.Bytes(), body) {
		t.Fatalf("unchanged bytes = %s, want %s", unchanged.Bytes(), body)
	}
	body[0] = '!'
	returned := envelope.Bytes()
	returned[0] = '!'
	field := envelope.Field("Unknown")
	field[0] = '!'
	if envelope.Bytes()[0] != ' ' || envelope.Field("Unknown")[0] != '{' {
		t.Fatal("caller mutated envelope storage")
	}
}

func TestEnvelopeReplacesOnlyTheNamedField(t *testing.T) {
	body := ` {"ClientRequestToken":"client-token","Query\u0053tring" : "SELECT old", "Unknown": { "n":900719925474099312345, "s":"\u0061<>&", "n":2 }, "NextToken":"native-next"} `
	envelope, err := DecodeEnvelope([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	rewritten, err := envelope.Replace("QueryString", "SELECT new")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(body, `"SELECT old"`, `"SELECT new"`, 1)
	if string(rewritten) != want {
		t.Fatalf("rewrite = %s, want %s", rewritten, want)
	}
	if string(envelope.Bytes()) != body {
		t.Fatal("rewrite changed original envelope")
	}
	if _, err := envelope.Replace("Missing", "x"); err == nil {
		t.Fatal("replace invented a field")
	}
}

func TestEnvelopeRejectsAmbiguousOrMalformedObjects(t *testing.T) {
	for _, body := range []string{
		``, `null`, `[]`, `1`, `{"QueryString":"a","QueryString":"b"}`,
		`{"QueryString":"a","Query\u0053tring":"b"}`, `{"a":1,"a":2}`,
		`{"a":1} {"b":2}`, `{"a":1} garbage`, `{"a":}`, `{"a":1`,
	} {
		t.Run(body, func(t *testing.T) {
			if _, err := DecodeEnvelope([]byte(body)); err == nil {
				t.Fatal("invalid envelope accepted")
			}
		})
	}
}
