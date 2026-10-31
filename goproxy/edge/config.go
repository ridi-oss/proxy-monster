package edge

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/alecthomas/kong"
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
}

type Listener struct {
	Kind Kind
	Port int
}

type Config struct {
	Listeners      []Listener
	Routes         map[string]string
	TrustedProxies []netip.Prefix
	HealthPort     int
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
	trusted, err := parseTrustedProxies(raw.TrustedProxies)
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
	return &Config{Listeners: listeners, Routes: routes, TrustedProxies: trusted, HealthPort: healthPort}, nil
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
		kind := Kind(strings.ToLower(strings.TrimSpace(kindText)))
		switch kind {
		case KindMySQL, KindPostgres, KindHTTPS:
		default:
			return nil, fmt.Errorf("PM_EDGE_LISTEN entry %q has unknown kind %q (want mysql, postgres, or https)", entry, kindText)
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

func parseRoutes(raw string) (map[string]string, error) {
	routes := map[string]string{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		hostText, backend, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("PM_WIRE_ROUTES entry %q must be host=backend-host:port", entry)
		}
		host := strings.ToLower(strings.TrimSpace(hostText))
		if host == "" || strings.ContainsAny(host, ":/* ") {
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
		routes[host] = backend
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("PM_WIRE_ROUTES is required, for example db1.example.com=10.0.1.5:16033")
	}
	return routes, nil
}

func parseTrustedProxies(raw string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("PM_TRUSTED_PROXIES entry %q is neither an IP address nor a CIDR block", entry)
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, nil
}

func parsePort(s string) (int, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("port %q must be 1-65535", s)
	}
	return int(n), nil
}
