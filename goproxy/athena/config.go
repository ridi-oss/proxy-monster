package athena

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsa "github.com/aws/aws-sdk-go-v2/service/athena"
	smithyendpoints "github.com/aws/smithy-go/endpoints"
)

const (
	defaultRequestLimit  = 2 << 20
	defaultResponseLimit = 16 << 20
)

// Flags is the Athena engine's kong grammar; credentials come from the SDK's default chain, never from PM_*.
type Flags struct {
	Region      string `env:"PM_ATHENA_REGION,AWS_REGION,AWS_DEFAULT_REGION"`
	Profile     string `env:"AWS_PROFILE"`
	Workgroup   string `env:"PM_ATHENA_WORKGROUP" default:"primary"`
	Catalog     string `env:"PM_ATHENA_DEFAULT_CATALOG" default:"AwsDataCatalog"`
	ContextPath string `env:"PM_ATHENA_CONTEXT_PATH" default:":memory:"`
	Database    string `env:"PM_TARGET_DB" default:"acme"`
}

// settings is the datasource scope the operator fixes: every submission is pinned to this workgroup,
// catalog, and database, and a request naming another is a scope violation.
type settings struct {
	region      string
	profile     string
	workgroup   string
	catalog     string
	database    string
	advertise   string
	contextPath string
}

func newSettings(flags Flags, advertise string) (settings, error) {
	cfg := settings{
		region:      strings.TrimSpace(flags.Region),
		profile:     strings.TrimSpace(flags.Profile),
		workgroup:   strings.TrimSpace(flags.Workgroup),
		catalog:     strings.TrimSpace(flags.Catalog),
		database:    strings.TrimSpace(flags.Database),
		advertise:   strings.TrimSpace(advertise),
		contextPath: strings.TrimSpace(flags.ContextPath),
	}
	if cfg.region != "" && !regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`).MatchString(cfg.region) {
		return settings{}, errors.New("athena: PM_ATHENA_REGION or AWS_REGION is required")
	}
	if cfg.workgroup == "" || cfg.catalog == "" || cfg.database == "" || cfg.contextPath == "" {
		return settings{}, errors.New("athena: workgroup, catalog, database, and context path must not be empty")
	}
	if cfg.advertise != "" {
		host, port, err := net.SplitHostPort(cfg.advertise)
		number, parseErr := strconv.Atoi(port)
		if err != nil || host == "" || strings.ContainsAny(host, "/?#@") || parseErr != nil || number < 1 || number > 65535 {
			return settings{}, errors.New("athena: PM_ADVERTISE_ADDR must be host:port")
		}
	}
	return cfg, nil
}

func loadAWSConfig(ctx context.Context, cfg settings) (aws.Config, error) {
	options := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(cfg.region)}
	if cfg.profile != "" {
		options = append(options, awsconfig.WithSharedConfigProfile(cfg.profile))
	}
	return awsconfig.LoadDefaultConfig(ctx, options...)
}

// athenaEndpoint is the region's Athena endpoint, or the SDK-configured base endpoint (AWS_ENDPOINT_URL) when
// one is set, so an operator can point the proxy at an Athena emulator.
func athenaEndpoint(ctx context.Context, region string, base *string) (string, error) {
	if base != nil {
		return upstreamEndpoint(*base)
	}
	endpoint, err := awsa.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, awsa.EndpointParameters{
		Region: aws.String(region), UseFIPS: aws.Bool(false), UseDualStack: aws.Bool(false),
	})
	if err != nil {
		return "", fmt.Errorf("athena: resolve regional endpoint: %w", err)
	}
	return endpoint.URI.String(), nil
}

type fixedEndpoint struct{ endpoint string }

func (e fixedEndpoint) ResolveEndpoint(context.Context, awsa.EndpointParameters) (smithyendpoints.Endpoint, error) {
	u, err := url.Parse(e.endpoint)
	if err != nil {
		return smithyendpoints.Endpoint{}, err
	}
	return smithyendpoints.Endpoint{URI: *u}, nil
}

func signAWS(credentials aws.CredentialsProvider, region string) SignRequest {
	signer := v4.NewSigner()
	return func(ctx context.Context, request *http.Request, body []byte) error {
		if credentials == nil {
			return ErrUnsigned
		}
		creds, err := credentials.Retrieve(ctx)
		if err != nil {
			return fmt.Errorf("athena: retrieve credentials: %w", err)
		}
		hash := sha256.Sum256(body)
		request.Host = request.URL.Host
		return signer.SignHTTP(ctx, creds, request, hex.EncodeToString(hash[:]), "athena", region, time.Now())
	}
}
