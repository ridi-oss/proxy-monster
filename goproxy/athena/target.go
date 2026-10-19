package athena

import (
	"context"
	"net/http"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsa "github.com/aws/aws-sdk-go-v2/service/athena"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// target is one configured Athena datasource: the SDK client bound to the regional endpoint, the signer and
// transport the forwarder uses, the STS-verified credential identity, the binding that ties cached contexts
// to this exact target, and the context cache itself. Every AWS call the provider makes goes through it.
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
	endpoint, err := athenaEndpoint(ctx, cfg.region, awsCfg.BaseEndpoint)
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

func (t *target) TargetDb() spi.TargetDb {
	u, _ := url.Parse(t.endpoint)
	return spi.TargetDb{Host: u.Hostname(), Port: 443, Db: t.config.database}
}

// ConnectionInfo publishes what a client needs to reach this datasource: the HTTPS endpoint and the scope
// (region, workgroup, catalog, database). The AWS profile never leaves the proxy.
func (t *target) ConnectionInfo() *pb.ConnectionInfo {
	endpoint := ""
	if t.config.advertise != "" {
		endpoint = "https://" + t.config.advertise
	}
	return &pb.ConnectionInfo{Endpoint: endpoint, Properties: map[string]string{
		"region": t.config.region, "workgroup": t.config.workgroup, "catalog": t.config.catalog, "database": t.config.database,
	}}
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
