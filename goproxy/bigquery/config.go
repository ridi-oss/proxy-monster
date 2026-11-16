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
}

// settings is the datasource scope the operator fixes: jobs run in project at location, and unqualified
// tables resolve in dataset.
type settings struct {
	project, location, dataset string
	endpoint                   string
	advertise                  string
	contextPath                string
}

func newSettings(flags Flags, advertise string) (settings, error) {
	cfg := settings{
		project:     strings.TrimSpace(flags.Project),
		location:    strings.TrimSpace(flags.Location),
		dataset:     strings.TrimSpace(flags.Dataset),
		advertise:   strings.TrimSpace(advertise),
		contextPath: strings.TrimSpace(flags.ContextPath),
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
	if cfg.advertise != "" {
		host, port, err := net.SplitHostPort(cfg.advertise)
		number, parseErr := strconv.Atoi(port)
		if err != nil || host == "" || strings.ContainsAny(host, "/?#@") || parseErr != nil || number < 1 || number > 65535 {
			return settings{}, errors.New("bigquery: PM_ADVERTISE_ADDR must be host:port")
		}
	}
	return cfg, nil
}
