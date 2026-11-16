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

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
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
	credentials, err := google.FindDefaultCredentials(context.Background(), bigqueryScope, emailScope)
	if err != nil {
		return nil, nil, fmt.Errorf("bigquery: Google application default credentials: %w", err)
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
