package athena

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// Provider registers the Athena engine under PM_ENGINE=athena. NewDb reads the target scope from the
// environment (PM_TARGET_DB is the default database) and pins the AWS identity; the Db then serves the
// Athena JSON API to clients and the editor run path.
type Provider struct{}

func (Provider) Dialect() engine.Dialect { return engine.Athena }

func (Provider) NewDb(target spi.TargetDb) (spi.Db, error) {
	cfg, err := configure(os.LookupEnv, target)
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
	if client, ok := awsCfg.HTTPClient.(*awshttp.BuildableClient); ok {
		transport = client.GetTransport()
	}
	transport.DisableCompression = true
	return newTarget(ctx, cfg, awsCfg, transport)
}

func (t *target) NewWireServer(port int, client spi.EnforcementClient, tlsProvider func() (*tls.Config, error)) spi.WireServer {
	return &nativeServer{target: t, port: port, client: client, tlsProvider: tlsProvider}
}

var _ spi.Provider = Provider{}
var _ spi.Db = (*target)(nil)
