package athena

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/goproxy/httpdb"
)

func TestEnvelopePreservesOriginalBytes(t *testing.T) {
	body := []byte(" {\n\t\"Unknown\": {\"integer\":900719925474099312345, \"decimal\":1.2300e+50, \"text\":\"<>&\\u0061\"},\n\t\"QueryString\" : \"SELECT \\u0031\", \"ExecutionParameters\": [\"'x'\", \"2\"]\n} \n")
	envelope, err := httpdb.DecodeEnvelope(body)
	if err != nil {
		t.Fatal(err)
	}
	query, present, err := queryString(envelope)
	if err != nil || !present || query != "SELECT 1" {
		t.Fatalf("QueryString = %q, %v, %v", query, present, err)
	}
	parameters, present, err := executionParameters(envelope)
	if err != nil || !present || !reflect.DeepEqual(parameters, []string{"'x'", "2"}) {
		t.Fatalf("ExecutionParameters = %v, %v, %v", parameters, present, err)
	}
	unchanged, err := withQueryString(envelope, query)
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

func TestEnvelopeReplacesOnlyQueryString(t *testing.T) {
	body := ` {"ClientRequestToken":"client-token","Query\u0053tring" : "SELECT old", "Unknown": { "n":900719925474099312345, "s":"\u0061<>&", "n":2 }, "QueryExecutionId":"native-id","NextToken":"native-next","ExecutionParameters":["42"]} `
	envelope, err := httpdb.DecodeEnvelope([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	rewritten, err := withQueryString(envelope, "SELECT new")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(body, `"SELECT old"`, `"SELECT new"`, 1)
	if string(rewritten.Bytes()) != want {
		t.Fatalf("rewrite = %s, want %s", rewritten.Bytes(), want)
	}
	if string(envelope.Bytes()) != body {
		t.Fatal("rewrite changed original envelope")
	}
}

func TestEnvelopeDecodesOnlyRequestedFields(t *testing.T) {
	for _, body := range []string{
		`{"QueryString":null,"ExecutionParameters":null}`,
		`{"QueryString":42,"ExecutionParameters":{}}`,
		`{"QueryString":[],"ExecutionParameters":[null]}`,
		`{"QueryString":{},"ExecutionParameters":[42]}`,
	} {
		envelope, err := httpdb.DecodeEnvelope([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		if _, present, err := queryString(envelope); !present || err == nil {
			t.Fatalf("invalid QueryString accepted: %s", body)
		}
		if _, present, err := executionParameters(envelope); !present || err == nil {
			t.Fatalf("invalid ExecutionParameters accepted: %s", body)
		}
		if _, err := withQueryString(envelope, "SELECT 1"); err == nil {
			t.Fatalf("invalid QueryString rewritten: %s", body)
		}
	}
	envelope, err := httpdb.DecodeEnvelope([]byte(`{"Unknown":[1,2,3]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, present, err := queryString(envelope); present || err != nil {
		t.Fatalf("missing QueryString = %v, %v", present, err)
	}
	if _, present, err := executionParameters(envelope); present || err != nil {
		t.Fatalf("missing ExecutionParameters = %v, %v", present, err)
	}
	if _, err := withQueryString(envelope, "SELECT 1"); err == nil {
		t.Fatal("rewrite invented QueryString")
	}
}
