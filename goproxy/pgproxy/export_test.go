package pgproxy

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
