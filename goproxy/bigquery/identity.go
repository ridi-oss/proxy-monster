package bigquery

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/google/externalaccount"
)

const (
	bigqueryScope     = "https://www.googleapis.com/auth/bigquery"
	emailScope        = "https://www.googleapis.com/auth/userinfo.email"
	tokenInfoEndpoint = "https://oauth2.googleapis.com/tokeninfo"
)

// findCredentials reads Application Default Credentials: a service-account key, an impersonated or
// external_account (workload identity federation) file, gcloud user credentials, or the GCE/GKE metadata server.
func findCredentials() (*google.Credentials, TokenSource, error) {
	// The token source keeps this context for every refresh, so it must never be canceled.
	ctx := context.Background()
	credentials, err := google.FindDefaultCredentials(ctx, bigqueryScope, emailScope)
	if err != nil {
		return nil, nil, fmt.Errorf("bigquery: Google application default credentials: %w", err)
	}
	tokens, err := awsFederation(ctx, credentials.JSON, func(ctx context.Context) (aws.Config, error) {
		return awsconfig.LoadDefaultConfig(ctx, awsconfig.WithEC2IMDSRegion())
	})
	if err != nil {
		return nil, nil, err
	}
	if tokens != nil {
		credentials.TokenSource = tokens
	}
	source := oauth2.ReuseTokenSource(nil, credentials.TokenSource)
	return credentials, func(context.Context) (string, error) {
		token, err := source.Token()
		if err != nil {
			return "", err
		}
		return token.AccessToken, nil
	}, nil
}

// awsFederation is the token source for an external_account file federating AWS credentials, or nil for any
// other credential. The library's own AWS source reads only env vars and EC2 IMDS, never ECS task-role
// credentials, so the AWS SDK's default chain supplies them instead.
func awsFederation(ctx context.Context, credentialsJSON []byte, loadAWS func(context.Context) (aws.Config, error)) (oauth2.TokenSource, error) {
	var file struct {
		Type                           string `json:"type"`
		Audience                       string `json:"audience"`
		SubjectTokenType               string `json:"subject_token_type"`
		TokenURL                       string `json:"token_url"`
		TokenInfoURL                   string `json:"token_info_url"`
		ServiceAccountImpersonationURL string `json:"service_account_impersonation_url"`
		ServiceAccountImpersonation    struct {
			TokenLifetimeSeconds int `json:"token_lifetime_seconds"`
		} `json:"service_account_impersonation"`
		ClientID                 string                           `json:"client_id"`
		ClientSecret             string                           `json:"client_secret"`
		QuotaProjectID           string                           `json:"quota_project_id"`
		WorkforcePoolUserProject string                           `json:"workforce_pool_user_project"`
		UniverseDomain           string                           `json:"universe_domain"`
		CredentialSource         externalaccount.CredentialSource `json:"credential_source"`
	}
	if len(credentialsJSON) == 0 || json.Unmarshal(credentialsJSON, &file) != nil ||
		file.Type != "external_account" || file.CredentialSource.EnvironmentID != "aws1" {
		return nil, nil
	}
	awsConfig, err := loadAWS(ctx)
	if err != nil {
		return nil, fmt.Errorf("bigquery: AWS credentials for workload identity federation: %w", err)
	}
	if awsConfig.Region == "" {
		return nil, errors.New("bigquery: workload identity federation needs an AWS region (AWS_REGION)")
	}
	tokens, err := externalaccount.NewTokenSource(ctx, externalaccount.Config{
		Audience: file.Audience, SubjectTokenType: file.SubjectTokenType, TokenURL: file.TokenURL, TokenInfoURL: file.TokenInfoURL,
		ServiceAccountImpersonationURL:             file.ServiceAccountImpersonationURL,
		ServiceAccountImpersonationLifetimeSeconds: file.ServiceAccountImpersonation.TokenLifetimeSeconds,
		ClientID: file.ClientID, ClientSecret: file.ClientSecret, QuotaProjectID: file.QuotaProjectID,
		WorkforcePoolUserProject: file.WorkforcePoolUserProject, UniverseDomain: file.UniverseDomain, Scopes: []string{bigqueryScope, emailScope},
		AwsSecurityCredentialsSupplier: awsSupplier{awsConfig},
	})
	if err != nil {
		return nil, fmt.Errorf("bigquery: workload identity federation: %w", err)
	}
	return tokens, nil
}

type awsSupplier struct{ config aws.Config }

func (s awsSupplier) AwsRegion(context.Context, externalaccount.SupplierOptions) (string, error) {
	return s.config.Region, nil
}

func (s awsSupplier) AwsSecurityCredentials(ctx context.Context, _ externalaccount.SupplierOptions) (*externalaccount.AwsSecurityCredentials, error) {
	if s.config.Credentials == nil {
		return nil, errors.New("bigquery: no AWS credentials for workload identity federation")
	}
	creds, err := s.config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}
	if !creds.HasKeys() {
		return nil, errors.New("bigquery: empty AWS credentials for workload identity federation")
	}
	return &externalaccount.AwsSecurityCredentials{AccessKeyID: creds.AccessKeyID, SecretAccessKey: creds.SecretAccessKey, SessionToken: creds.SessionToken}, nil
}

// credentialPrincipal is the Google identity the proxy's credentials act as: the impersonated service
// account, the key's client_email, or else what tokeninfo says the access token belongs to.
func credentialPrincipal(ctx context.Context, credentialsJSON []byte, token TokenSource, client *http.Client, tokenInfo string) (string, error) {
	var file struct {
		ClientEmail   string `json:"client_email"`
		Impersonation string `json:"service_account_impersonation_url"`
	}
	if len(credentialsJSON) > 0 {
		if err := json.Unmarshal(credentialsJSON, &file); err != nil {
			return "", fmt.Errorf("bigquery: credentials file: %w", err)
		}
	}
	if file.Impersonation != "" {
		_, rest, _ := strings.Cut(file.Impersonation, "/serviceAccounts/")
		email, _, _ := strings.Cut(rest, ":generateAccessToken")
		if email == "" || strings.Contains(email, "/") {
			return "", errors.New("bigquery: cannot read the impersonated service account")
		}
		return email, nil
	}
	if file.ClientEmail != "" {
		return file.ClientEmail, nil
	}
	access, err := token(ctx)
	if err != nil {
		return "", fmt.Errorf("bigquery: access token: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenInfo, strings.NewReader(url.Values{"access_token": {access}}.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("bigquery: tokeninfo: %w", err)
	}
	defer response.Body.Close()
	var info struct{ Email, Sub string }
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil || response.StatusCode != http.StatusOK || json.Unmarshal(body, &info) != nil {
		return "", fmt.Errorf("bigquery: tokeninfo returned %d", response.StatusCode)
	}
	if info.Email != "" {
		return info.Email, nil
	}
	if info.Sub != "" {
		return info.Sub, nil
	}
	return "", errors.New("bigquery: cannot determine the credential's principal")
}

// targetBinding ties cached enforcement contexts to this exact target and credential identity.
func targetBinding(cfg settings, principal string) []byte {
	data, _ := json.Marshal([]string{principal, cfg.project, cfg.location, cfg.endpoint, cfg.dataset})
	hash := sha256.Sum256(data)
	return hash[:]
}
