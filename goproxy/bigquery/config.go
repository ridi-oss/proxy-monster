package bigquery

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	"github.com/ridi-oss/proxy-monster/goproxy/httpdb"
)

// Flags is the BigQuery engine's kong grammar; credentials come from Google Application Default
// Credentials, never from PM_*.
type Flags struct {
	Project     string `env:"PM_BIGQUERY_PROJECT"`
	Location    string `env:"PM_BIGQUERY_LOCATION"`
	Dataset     string `env:"PM_TARGET_DB"`
	ContextPath string `env:"PM_BIGQUERY_CONTEXT_PATH" default:":memory:"`
	Endpoint    string `env:"PM_BIGQUERY_ENDPOINT" default:"https://bigquery.googleapis.com"`
	// StorageEndpoint is the Storage Read API's gRPC host:port.
	StorageEndpoint string `env:"PM_BIGQUERY_STORAGE_ENDPOINT" default:"bigquerystorage.googleapis.com:443"`
	// CAFile is a PEM bundle trusted for both endpoints instead of the system roots, for an emulator.
	CAFile string `env:"PM_BIGQUERY_CA_FILE"`
}

const defaultStorageEndpoint = "bigquerystorage.googleapis.com:443"

// settings is the datasource scope the operator fixes: jobs run in project at location, and unqualified
// tables resolve in dataset.
type settings struct {
	project, location, dataset string
	endpoint                   string
	storageEndpoint            string
	advertise                  string
	contextPath                string
}

func newSettings(flags Flags, advertise string) (settings, error) {
	cfg := settings{
		project:         strings.TrimSpace(flags.Project),
		location:        strings.TrimSpace(flags.Location),
		dataset:         strings.TrimSpace(flags.Dataset),
		advertise:       strings.TrimSpace(advertise),
		contextPath:     strings.TrimSpace(flags.ContextPath),
		storageEndpoint: strings.TrimSpace(flags.StorageEndpoint),
	}
	if cfg.storageEndpoint == "" {
		cfg.storageEndpoint = defaultStorageEndpoint
	}
	if !validHostPort(cfg.storageEndpoint) {
		return settings{}, errors.New("bigquery: PM_BIGQUERY_STORAGE_ENDPOINT must be host:port")
	}
	if !engines.BigQuery.ValidConnectionProperty("project", cfg.project) {
		return settings{}, errors.New("bigquery: PM_BIGQUERY_PROJECT must be a project id")
	}
	if !engines.BigQuery.ValidConnectionProperty("location", cfg.location) {
		return settings{}, errors.New("bigquery: PM_BIGQUERY_LOCATION must be a location such as US or asia-northeast3")
	}
	if cfg.dataset == "" || cfg.contextPath == "" {
		return settings{}, errors.New("bigquery: PM_TARGET_DB and PM_BIGQUERY_CONTEXT_PATH must not be empty")
	}
	endpoint, err := httpdb.UpstreamEndpoint(strings.TrimSpace(flags.Endpoint))
	if u, _ := url.Parse(endpoint); err != nil || u.Path != "" && u.Path != "/" {
		return settings{}, errors.New("bigquery: PM_BIGQUERY_ENDPOINT must be an https origin")
	}
	cfg.endpoint = strings.TrimSuffix(endpoint, "/")
	if cfg.advertise != "" && !validHostPort(cfg.advertise) {
		return settings{}, errors.New("bigquery: PM_ADVERTISE_ADDR must be host:port")
	}
	return cfg, nil
}

func validHostPort(address string) bool {
	host, port, err := net.SplitHostPort(address)
	number, parseErr := strconv.Atoi(port)
	return err == nil && host != "" && !strings.ContainsAny(host, "/?#@") && parseErr == nil && number >= 1 && number <= 65535
}
