package postgres

import (
	"crypto/tls"

	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// New builds a wire server on a target that has no pool.
func New(listen spi.Listen, config spi.TargetConfig, client spi.ControlPlane, tlsProvider func() (*tls.Config, error)) *Server {
	return newServer(listen, &target{config: config}, client, tlsProvider)
}

// SchemaMessageTemplates exposes the allowlist to the external e2e tests.
func SchemaMessageTemplates() map[string][]string { return pgSchemaMessages }

// MatchesSchemaTemplate reports whether message matches that exact allowlisted template of sqlState.
func MatchesSchemaTemplate(sqlState, template, message string) bool {
	for i, t := range pgSchemaMessages[sqlState] {
		if t == template {
			return pgSchemaPatterns[sqlState][i].MatchString(message)
		}
	}
	return false
}
