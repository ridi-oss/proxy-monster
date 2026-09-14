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
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const (
	defaultRequestLimit  = 2 << 20
	defaultResponseLimit = 16 << 20
)

type targetConfig struct {
	region      string
	profile     string
	workgroup   string
	catalog     string
	database    string
	advertise   string
	contextPath string
}

func configure(lookup spi.LookupEnv) (targetConfig, error) {
	get := func(key, fallback string) string {
		value, ok := lookup(key)
		if !ok {
			return fallback
		}
		return strings.TrimSpace(value)
	}
	cfg := targetConfig{
		region:      get("PM_ATHENA_REGION", get("AWS_REGION", get("AWS_DEFAULT_REGION", ""))),
		profile:     get("AWS_PROFILE", ""),
		workgroup:   get("PM_ATHENA_WORKGROUP", "primary"),
		catalog:     get("PM_ATHENA_CATALOG", "AwsDataCatalog"),
		database:    get("PM_ATHENA_DATABASE", "default"),
		advertise:   get("PM_ADVERTISE_ADDR", ""),
		contextPath: get("PM_ATHENA_CONTEXT_PATH", ":memory:"),
	}
	if cfg.region != "" && !regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`).MatchString(cfg.region) {
		return targetConfig{}, errors.New("athena: PM_ATHENA_REGION or AWS_REGION is required")
	}
	if cfg.workgroup == "" || cfg.catalog == "" || cfg.database == "" || cfg.contextPath == "" {
		return targetConfig{}, errors.New("athena: workgroup, catalog, database, and context path must not be empty")
	}
	if cfg.advertise != "" {
		host, port, err := net.SplitHostPort(cfg.advertise)
		number, parseErr := strconv.Atoi(port)
		if err != nil || host == "" || strings.ContainsAny(host, "/?#@") || parseErr != nil || number < 1 || number > 65535 {
			return targetConfig{}, errors.New("athena: PM_ADVERTISE_ADDR must be host:port")
		}
	}
	return cfg, nil
}

func loadAWSConfig(ctx context.Context, cfg targetConfig) (aws.Config, error) {
	options := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(cfg.region)}
	if cfg.profile != "" {
		options = append(options, awsconfig.WithSharedConfigProfile(cfg.profile))
	}
	return awsconfig.LoadDefaultConfig(ctx, options...)
}

func regionalEndpoint(ctx context.Context, region string) (string, error) {
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
