package mysql

import (
	"crypto/tls"

	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// New builds a wire server on a target that has no pool.
func New(listen spi.Listen, config spi.TargetConfig, client spi.ControlPlane, tlsProvider func() (*tls.Config, error)) *Server {
	return newServer(listen, &target{config: config}, client, tlsProvider)
}

// SchemaMessageEssnos lists the allowlisted essnos for the external e2e tests.
func SchemaMessageEssnos() []int {
	out := make([]int, 0, len(mysqlSchemaMessages))
	for essno := range mysqlSchemaMessages {
		out = append(out, essno)
	}
	return out
}

// MatchesSchemaTemplate reports whether msg matches one of essno's allowlisted templates.
func MatchesSchemaTemplate(essno int, msg string) bool {
	for _, re := range mysqlSchemaPatterns[essno] {
		if re.MatchString(msg) {
			return true
		}
	}
	return false
}
