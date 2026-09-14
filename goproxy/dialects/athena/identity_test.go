package athena

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestSTSIdentityVerifiedAtStartupAndCredentialRefresh(t *testing.T) {
	calls := 0
	account, session := "123456789012", "first"
	credentials := aws.Credentials{AccessKeyID: "first-key", SecretAccessKey: "secret", SessionToken: "first-token"}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls++
		body, _ := io.ReadAll(request.Body)
		if !strings.Contains(string(body), "Action=GetCallerIdentity") || !strings.Contains(request.Header.Get("Authorization"), "/us-east-1/sts/aws4_request") {
			t.Error("identity was not queried through signed STS API")
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = fmt.Fprintf(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:sts::%s:assumed-role/test-role/%s</Arn><UserId>AROATEST:%s</UserId><Account>%s</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`, account, session, session, account)
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL)
	client := &http.Client{Transport: endpointTransport{endpoint: endpoint, transport: server.Client().Transport}}
	identity, err := newCredentialIdentity(context.Background(), aws.Config{Region: "us-east-1", Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) { return credentials, nil })}, client)
	if err != nil {
		t.Fatal(err)
	}
	cfg := targetConfig{region: "us-east-1", workgroup: "primary", catalog: "AwsDataCatalog", database: "example"}
	binding := identity.targetBinding(cfg, "https://athena.us-east-1.amazonaws.com/")
	for range 5 {
		if _, err := identity.Retrieve(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("STS queried per request: %d calls", calls)
	}
	credentials.AccessKeyID, credentials.SessionToken = "second-key", "second-token"
	session = "second"
	if _, err := identity.Retrieve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || !bytes.Equal(binding, identity.targetBinding(cfg, "https://athena.us-east-1.amazonaws.com/")) {
		t.Fatal("session refresh changed stable target binding")
	}
	credentials.AccessKeyID = "third-key"
	account = "999999999999"
	if _, err := identity.Retrieve(context.Background()); !errors.Is(err, ErrAWSIdentityChanged) {
		t.Fatalf("changed AWS account accepted: %v", err)
	}
	if _, err := identity.Retrieve(context.Background()); !errors.Is(err, ErrAWSIdentityChanged) {
		t.Fatal("changed identity did not stay closed")
	}
	if calls != 3 {
		t.Fatalf("identity mismatch repeatedly queried STS: %d calls", calls)
	}
}
