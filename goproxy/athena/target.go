package athena

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ridi-oss/proxy-monster/goproxy/nativeapi"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsa "github.com/aws/aws-sdk-go-v2/service/athena"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/wire"
)

// contextFormat names the enforcement-context file format, so a file from another engine or version is refused.
const contextFormat = "athena-enforcement-context-v1"

// target is one configured Athena datasource: the SDK client bound to the regional endpoint, the signer and
// transport the forwarder uses, the STS-verified credential identity, the binding that ties cached contexts
// to this exact target, and the context cache itself. Every AWS call the provider makes goes through it.
type target struct {
	settings    settings
	api         *awsa.Client
	endpoint    string
	sign        SignRequest
	transport   http.RoundTripper
	identity    *credentialIdentity
	binding     []byte
	generations wire.BackendGenerations
	contexts    *nativeapi.EnforcementContextCache
}

func newTarget(ctx context.Context, cfg settings, awsCfg aws.Config, transport http.RoundTripper) (*target, error) {
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
	contexts, err := nativeapi.OpenContextCache(cfg.contextPath, contextFormat, 10000)
	if err != nil {
		return nil, err
	}
	return &target{settings: cfg, api: api, endpoint: endpoint, sign: signAWS(identity, cfg.region), transport: transport, identity: identity, binding: identity.targetBinding(cfg, endpoint), contexts: contexts}, nil
}

func (t *target) TargetInfo() string {
	u, _ := url.Parse(t.endpoint)
	return fmt.Sprintf("%s workgroup %s, catalog %s", u.Host, t.settings.workgroup, t.settings.catalog)
}

// ConnectionInfo publishes what a client needs to reach this datasource: the HTTPS endpoint and the scope
// (region, workgroup, catalog, database). The AWS profile never leaves the proxy.
func (t *target) ConnectionInfo() *pb.ConnectionInfo {
	endpoint := ""
	if t.settings.advertise != "" {
		endpoint = "https://" + t.settings.advertise
	}
	return &pb.ConnectionInfo{Endpoint: endpoint, Properties: map[string]string{
		"region": t.settings.region, "workgroup": t.settings.workgroup, "catalog": t.settings.catalog, "database": t.settings.database,
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
