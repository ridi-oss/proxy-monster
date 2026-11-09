package edge

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/ridi-oss/proxy-monster/goproxy/config"
)

type Kind string

const (
	KindMySQL    Kind = "mysql"
	KindPostgres Kind = "postgres"
	KindHTTPS    Kind = "https"
)

type rawFlags struct {
	Listen         string `env:"PM_EDGE_LISTEN"`
	Routes         string `env:"PM_WIRE_ROUTES"`
	TrustedProxies string `env:"PM_TRUSTED_PROXIES"`
	HealthPort     string `env:"PM_EDGE_HEALTH_PORT"`
	MaxConnections string `env:"PM_EDGE_MAX_CONNECTIONS"`
}

const defaultMaxConnections = 1024

type Listener struct {
	Kind Kind
	Port int
}

type Route struct {
	Kind    Kind
	Backend string
}

type Config struct {
	Listeners      []Listener
	Routes         map[string]Route
	TrustedProxies []netip.Prefix
	HealthPort     int
	MaxConnections int
}

func Load() (*Config, error) {
	var raw rawFlags
	parser, err := kong.New(&raw)
	if err != nil {
		return nil, fmt.Errorf("edge config: building parser: %w", err)
	}
	if _, err := parser.Parse(nil); err != nil {
		return nil, fmt.Errorf("edge config: parsing environment: %w", err)
	}
	return parse(raw)
}

func parse(raw rawFlags) (*Config, error) {
	listeners, err := parseListeners(raw.Listen)
	if err != nil {
		return nil, err
	}
	routes, err := parseRoutes(raw.Routes)
	if err != nil {
		return nil, err
	}
	trusted, err := config.ParseTrustedProxies(raw.TrustedProxies)
	if err != nil {
		return nil, err
	}
	if len(trusted) == 0 {
		return nil, fmt.Errorf("PM_TRUSTED_PROXIES is required: every edge listener reads a PROXY protocol header")
	}
	healthPort := 0
	if s := strings.TrimSpace(raw.HealthPort); s != "" {
		healthPort, err = parsePort(s)
		if err != nil {
			return nil, fmt.Errorf("PM_EDGE_HEALTH_PORT=%q: %w", raw.HealthPort, err)
		}
		for _, l := range listeners {
			if l.Port == healthPort {
				return nil, fmt.Errorf("PM_EDGE_HEALTH_PORT=%d is also a PM_EDGE_LISTEN port", healthPort)
			}
		}
	}
	maxConnections := defaultMaxConnections
	if s := strings.TrimSpace(raw.MaxConnections); s != "" {
		n, err := strconv.ParseUint(s, 10, 31)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("PM_EDGE_MAX_CONNECTIONS=%q must be a positive integer", raw.MaxConnections)
		}
		maxConnections = int(n)
	}
	return &Config{
		Listeners:      listeners,
		Routes:         routes,
		TrustedProxies: trusted,
		HealthPort:     healthPort,
		MaxConnections: maxConnections,
	}, nil
}

func parseListeners(raw string) ([]Listener, error) {
	var listeners []Listener
	seen := map[int]bool{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		kindText, portText, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf("PM_EDGE_LISTEN entry %q must be kind:port", entry)
		}
		kind, err := parseKind(kindText)
		if err != nil {
			return nil, fmt.Errorf("PM_EDGE_LISTEN entry %q: %w", entry, err)
		}
		port, err := parsePort(strings.TrimSpace(portText))
		if err != nil {
			return nil, fmt.Errorf("PM_EDGE_LISTEN entry %q: %w", entry, err)
		}
		if seen[port] {
			return nil, fmt.Errorf("PM_EDGE_LISTEN lists port %d more than once", port)
		}
		seen[port] = true
		listeners = append(listeners, Listener{Kind: kind, Port: port})
	}
	if len(listeners) == 0 {
		return nil, fmt.Errorf("PM_EDGE_LISTEN is required, for example mysql:3306,postgres:5432")
	}
	return listeners, nil
}

func parseRoutes(raw string) (map[string]Route, error) {
	routes := map[string]Route{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		target, backend, ok := strings.Cut(entry, "=")
		kindText, hostText, hasKind := strings.Cut(target, ":")
		if !ok || !hasKind {
			return nil, fmt.Errorf("PM_WIRE_ROUTES entry %q must be kind:host=backend-host:port", entry)
		}
		kind, err := parseKind(kindText)
		if err != nil {
			return nil, fmt.Errorf("PM_WIRE_ROUTES entry %q: %w", entry, err)
		}
		host := normalizeHost(hostText)
		if host == "" || strings.ContainsAny(host, ":/* ") || strings.HasPrefix(host, ".") || strings.Contains(host, "..") {
			return nil, fmt.Errorf("PM_WIRE_ROUTES entry %q has an invalid host name %q", entry, hostText)
		}
		backend = strings.TrimSpace(backend)
		backendHost, backendPort, err := net.SplitHostPort(backend)
		if err != nil || backendHost == "" {
			return nil, fmt.Errorf("PM_WIRE_ROUTES entry %q: backend %q must be host:port", entry, backend)
		}
		if _, err := parsePort(backendPort); err != nil {
			return nil, fmt.Errorf("PM_WIRE_ROUTES entry %q: %w", entry, err)
		}
		if _, dup := routes[host]; dup {
			return nil, fmt.Errorf("PM_WIRE_ROUTES routes host %q more than once", host)
		}
		routes[host] = Route{Kind: kind, Backend: backend}
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("PM_WIRE_ROUTES is required, for example mysql:db1.example.com=10.0.1.5:16033")
	}
	return routes, nil
}

func parseKind(text string) (Kind, error) {
	kind := Kind(strings.ToLower(strings.TrimSpace(text)))
	switch kind {
	case KindMySQL, KindPostgres, KindHTTPS:
		return kind, nil
	default:
		return "", fmt.Errorf("unknown kind %q (want mysql, postgres, or https)", text)
	}
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func parsePort(s string) (int, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("port %q must be 1-65535", s)
	}
	return int(n), nil
}
