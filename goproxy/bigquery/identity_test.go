package bigquery

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const awsAudience = "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/aws"

// awsFederationFile writes an AWS external_account file whose STS and IAM endpoints are google, and points
// the AWS SDK's default chain at an ECS container-credentials endpoint and nothing else.
func awsFederationFile(t *testing.T, google string, extra string) string {
	t.Helper()
	ecs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"AccessKeyId":"AKIDTASKROLE","SecretAccessKey":"secret","Token":"task-session","Expiration":"2099-01-01T00:00:00Z"}`))
	}))
	t.Cleanup(ecs.Close)
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_DEFAULT_REGION"} {
		t.Setenv(name, "")
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_REGION", "ap-northeast-2")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", ecs.URL+"/creds")
	path := filepath.Join(t.TempDir(), "wif.json")
	file := `{"type":"external_account","audience":"` + awsAudience + `","subject_token_type":"urn:ietf:params:aws:token-type:aws4_request",
		"token_url":"` + google + `/v1/token",` + extra + `"credential_source":{"environment_id":"aws1","region_url":"http://169.254.169.254/latest/meta-data/placement/availability-zone",
		"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials","regional_cred_verification_url":"https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15"}}`
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
	return path
}

func TestFindCredentialsFederatesECSTaskRoleThroughImpersonation(t *testing.T) {
	var exchange url.Values
	var subject map[string]any
	var impersonation struct {
		auth string
		body struct {
			Scope    []string `json:"scope"`
			Lifetime string   `json:"lifetime"`
		}
	}
	google := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/token":
			_ = r.ParseForm()
			exchange = r.PostForm
			token, _ := url.QueryUnescape(r.PostForm.Get("subject_token"))
			_ = json.Unmarshal([]byte(token), &subject)
			_, _ = w.Write([]byte(`{"access_token":"federated-token","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}`))
		case "/v1/projects/-/serviceAccounts/proxy@p.iam.gserviceaccount.com:generateAccessToken":
			impersonation.auth = r.Header.Get("Authorization")
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &impersonation.body)
			_, _ = w.Write([]byte(`{"accessToken":"sa-token","expireTime":"2099-01-01T00:00:00Z"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer google.Close()
	awsFederationFile(t, google.URL, `"service_account_impersonation_url":"`+google.URL+
		`/v1/projects/-/serviceAccounts/proxy@p.iam.gserviceaccount.com:generateAccessToken","service_account_impersonation":{"token_lifetime_seconds":600},`)

	credentials, token, err := findCredentials()
	if err != nil {
		t.Fatal(err)
	}
	access, err := token(context.Background())
	if err != nil || access != "sa-token" {
		t.Fatalf("token = %q, %v", access, err)
	}
	if exchange.Get("audience") != awsAudience || exchange.Get("scope") != "https://www.googleapis.com/auth/cloud-platform" {
		t.Fatalf("STS exchange = %v", exchange)
	}
	headers, _ := json.Marshal(subject["headers"])
	if !strings.Contains(string(headers), "Credential=AKIDTASKROLE/") || !strings.Contains(string(headers), "task-session") ||
		!strings.Contains(string(headers), awsAudience) || !strings.Contains(subject["url"].(string), "sts.ap-northeast-2.amazonaws.com") {
		t.Fatalf("subject token not signed with the task role for the audience in the region: %v", subject)
	}
	if impersonation.auth != "Bearer federated-token" || strings.Join(impersonation.body.Scope, " ") != bigqueryScope+" "+emailScope || impersonation.body.Lifetime != "600s" {
		t.Fatalf("impersonation = %+v", impersonation)
	}
	principal, err := credentialPrincipal(context.Background(), credentials.JSON, token, http.DefaultClient, "http://127.0.0.1:1/unused")
	if err != nil || principal != "proxy@p.iam.gserviceaccount.com" {
		t.Fatalf("principal = %q, %v", principal, err)
	}
}

func TestFindCredentialsRefusesAWSFederationWithoutARegion(t *testing.T) {
	awsFederationFile(t, "http://127.0.0.1:1", "")
	t.Setenv("AWS_REGION", "")
	if _, _, err := findCredentials(); err == nil || !strings.Contains(err.Error(), "workload identity federation") {
		t.Fatalf("err = %v", err)
	}
}

func TestAWSFederationLeavesOtherCredentialsToTheLibrary(t *testing.T) {
	for _, file := range []string{"", `{"type":"service_account","client_email":"a@p.iam.gserviceaccount.com"}`,
		`{"type":"external_account","credential_source":{"file":"/var/run/token"}}`,
		`{"type":"external_account","credential_source":{"environment_id":"aws2"}}`} {
		tokens, err := awsFederation(context.Background(), []byte(file), func(context.Context) (aws.Config, error) {
			t.Fatal("AWS config loaded for a credential the library handles")
			return aws.Config{}, nil
		})
		if tokens != nil || err != nil {
			t.Fatalf("%q: awsFederation = %v, %v", file, tokens, err)
		}
	}
}
