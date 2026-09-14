package athena

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithyendpoints "github.com/aws/smithy-go/endpoints"
)

var ErrAWSIdentityChanged = errors.New("athena: AWS credential identity changed")

type credentialIdentity struct {
	mu          sync.Mutex
	source      aws.CredentialsProvider
	config      aws.Config
	client      *http.Client
	endpoint    smithyendpoints.Endpoint
	credentials aws.Credentials
	principal   string
	account     string
	failure     error
}

type fixedSTSEndpoint struct{ endpoint smithyendpoints.Endpoint }

func (e fixedSTSEndpoint) ResolveEndpoint(context.Context, sts.EndpointParameters) (smithyendpoints.Endpoint, error) {
	return e.endpoint, nil
}

func newCredentialIdentity(ctx context.Context, cfg aws.Config, client *http.Client) (*credentialIdentity, error) {
	endpoint, err := sts.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, sts.EndpointParameters{
		Region: aws.String(cfg.Region), UseGlobalEndpoint: aws.Bool(false), UseDualStack: aws.Bool(false), UseFIPS: aws.Bool(false),
	})
	if err != nil {
		return nil, err
	}
	identity := &credentialIdentity{source: cfg.Credentials, config: cfg, client: client, endpoint: endpoint}
	if _, err := identity.Retrieve(ctx); err != nil {
		return nil, err
	}
	return identity, nil
}

func (i *credentialIdentity) Retrieve(ctx context.Context) (aws.Credentials, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.failure != nil {
		return aws.Credentials{}, i.failure
	}
	if i.source == nil {
		return aws.Credentials{}, ErrUnsigned
	}
	credentials, err := i.source.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}
	if credentials.AccessKeyID == i.credentials.AccessKeyID && credentials.SessionToken == i.credentials.SessionToken && i.principal != "" {
		return credentials, nil
	}
	cfg := i.config
	cfg.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) { return credentials, nil })
	client := sts.NewFromConfig(cfg, func(options *sts.Options) {
		options.HTTPClient = i.client
		options.EndpointResolver = nil
		options.BaseEndpoint = aws.String(i.endpoint.URI.String())
		options.EndpointResolverV2 = fixedSTSEndpoint{i.endpoint}
	})
	observed, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return aws.Credentials{}, err
	}
	account, principal, err := stableAWSPrincipal(observed)
	if err != nil {
		return aws.Credentials{}, err
	}
	if i.principal != "" && (i.principal != principal || i.account != account) {
		i.failure = ErrAWSIdentityChanged
		return aws.Credentials{}, i.failure
	}
	i.account, i.principal, i.credentials = account, principal, credentials
	return credentials, nil
}

func stableAWSPrincipal(identity *sts.GetCallerIdentityOutput) (string, string, error) {
	if identity == nil || aws.ToString(identity.Account) == "" || aws.ToString(identity.UserId) == "" {
		return "", "", errors.New("athena: STS returned incomplete identity")
	}
	parsed, err := arn.Parse(aws.ToString(identity.Arn))
	if err != nil || parsed.AccountID != aws.ToString(identity.Account) {
		return "", "", errors.New("athena: STS returned inconsistent identity")
	}
	userID := aws.ToString(identity.UserId)
	if parsed.Service == "sts" && strings.HasPrefix(parsed.Resource, "assumed-role/") {
		parts := strings.Split(parsed.Resource, "/")
		if len(parts) < 3 {
			return "", "", errors.New("athena: STS returned invalid assumed role")
		}
		parsed.Resource = strings.Join(parts[:len(parts)-1], "/")
		userID, _, _ = strings.Cut(userID, ":")
	}
	return parsed.AccountID, parsed.String() + "\x00" + userID, nil
}

func (i *credentialIdentity) targetBinding(cfg targetConfig, endpoint string) []byte {
	i.mu.Lock()
	defer i.mu.Unlock()
	data, _ := json.Marshal([]string{i.account, i.principal, cfg.region, endpoint, cfg.workgroup, cfg.catalog, cfg.database})
	hash := sha256.Sum256(data)
	return hash[:]
}
