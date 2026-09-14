package athena

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsa "github.com/aws/aws-sdk-go-v2/service/athena"
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

var ErrOriginalContextUnavailable = errors.New("athena.original_context_unavailable")

type Provider struct{}

func (Provider) Definition() spi.Definition {
	return spi.Definition{Name: "athena", Engine: enginepb.Engine_ATHENA, DefaultProxyPort: 6443}
}

func (Provider) Configure(lookup spi.LookupEnv) (spi.Target, error) {
	cfg, err := configure(lookup)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	awsCfg, err := loadAWSConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	cfg.region = awsCfg.Region
	if cfg.region == "" {
		return nil, errors.New("athena: AWS region is required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	return newTarget(ctx, cfg, awsCfg, transport)
}

type target struct {
	config    targetConfig
	api       *awsa.Client
	endpoint  string
	sign      SignRequest
	transport http.RoundTripper
	identity  *credentialIdentity
	binding   []byte
	contexts  *EnforcementContextCache
}

func newTarget(ctx context.Context, cfg targetConfig, awsCfg aws.Config, transport http.RoundTripper) (*target, error) {
	endpoint, err := regionalEndpoint(ctx, cfg.region)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: metadataTransport{next: transport}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	awsCfg.Region = cfg.region
	identity, err := newCredentialIdentity(ctx, awsCfg, client)
	if err != nil {
		return nil, err
	}
	awsCfg.Credentials = identity
	api := awsa.NewFromConfig(awsCfg, func(options *awsa.Options) {
		options.Region = cfg.region
		options.BaseEndpoint = aws.String(endpoint)
		options.EndpointResolver = nil
		options.EndpointResolverV2 = fixedEndpoint{endpoint: endpoint}
		options.HTTPClient = client
	})
	contexts, err := OpenContextCache(cfg.contextPath, 10000)
	if err != nil {
		return nil, err
	}
	return &target{config: cfg, api: api, endpoint: endpoint, sign: signAWS(identity, cfg.region), transport: transport, identity: identity, binding: identity.targetBinding(cfg, endpoint), contexts: contexts}, nil
}

func (t *target) TargetInfo() spi.TargetInfo {
	u, _ := url.Parse(t.endpoint)
	return spi.TargetInfo{Host: u.Hostname(), Port: 443, Database: t.config.database}
}

func (t *target) ConnectionInfo() *pb.ConnectionInfo {
	endpoint := ""
	if t.config.advertise != "" {
		endpoint = "https://" + t.config.advertise
	}
	return &pb.ConnectionInfo{Endpoint: endpoint, Properties: map[string]string{
		"region": t.config.region, "workgroup": t.config.workgroup, "catalog": t.config.catalog, "database": t.config.database,
	}}
}

func (t *target) NewNativeServer(options spi.NativeServerOptions) spi.WireServer {
	return &nativeServer{target: t, options: options}
}

func (t *target) Close() error {
	if transport, ok := t.transport.(interface{ CloseIdleConnections() }); ok {
		transport.CloseIdleConnections()
	}
	if t.contexts != nil {
		return t.contexts.Close()
	}
	return nil
}

var _ spi.Provider = Provider{}
var _ spi.Target = (*target)(nil)
