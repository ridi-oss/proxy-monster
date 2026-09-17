package probe

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ridi-oss/sqlglot-go"
	"github.com/ridi-oss/sqlglot-go/dialects"
	"github.com/ridi-oss/sqlglot-go/tokens"
)

// normalizeRules is the per-engine part of SqlNormalize: the dialect that tokenizes, the dialect that
// classifies a lexeme as a word, whether the lexer switches to Hive mid-stream (Athena DDL inside a Trino
// stream), whether unquoted identifiers fold, and whether executable comments are refused.
type normalizeRules struct {
	dialect *dialects.Dialect
	// wordDialect classifies raw lexemes as identifiers or keywords; usually dialect itself.
	wordDialect *dialects.Dialect
	// hiveDialect takes over on a HIVE_TOKEN_STREAM marker and wordDialect returns on ';'; nil = never.
	hiveDialect *dialects.Dialect
	// foldIdentifiers lowercases unquoted identifiers (PostgreSQL, Athena). MySQL keeps them byte-exact:
	// lower_case_table_names=0 makes `db.T` and `db.t` distinct tables.
	foldIdentifiers bool
	// rejectExecutableComments refuses `/*! */` and `/*+ */`, which MySQL runs as SQL.
	rejectExecutableComments bool
}

// normalizeRulesByWireName is the engine registry SqlNormalize consults; a name not here fails closed.
// Adding an engine means adding its row.
var normalizeRulesByWireName = map[string]func() normalizeRules{
	"mysql": func() normalizeRules {
		d := dialects.MySQL()
		return normalizeRules{dialect: d, wordDialect: d, rejectExecutableComments: true}
	},
	"postgres": func() normalizeRules {
		d := dialects.Postgres()
		return normalizeRules{dialect: d, wordDialect: d, foldIdentifiers: true}
	},
	"athena": func() normalizeRules {
		return normalizeRules{dialect: dialects.Athena(), wordDialect: dialects.Trino(), hiveDialect: dialects.Hive(), foldIdentifiers: true}
	},
}

// SqlNormalize produces a lexer-only canonical form suitable for exact approval matching.
// It is total and fail-closed so that no panic can cross the native binding boundary.
func SqlNormalize(sql, dialect string) (normalized string, ok bool) {
	defer func() {
		if recover() != nil {
			normalized = ""
			ok = false
		}
	}()

	if !utf8.ValidString(sql) || strings.IndexByte(sql, 0) >= 0 {
		return "", false
	}
	newRules, known := normalizeRulesByWireName[dialect]
	if !known {
		return "", false
	}
	rules := newRules()
	d := rules.dialect
	tokenStream, err := sqlglot.Tokenize(sql, d)
	if err != nil {
		return "", false
	}

	for len(tokenStream) > 0 && tokenStream[len(tokenStream)-1].TokenType == tokens.SEMICOLON {
		tokenStream = tokenStream[:len(tokenStream)-1]
	}
	runes := []rune(sql)
	previousEnd := -1
	previousWasDot := false
	lexemes := make([]string, 0, len(tokenStream))
	wordDialect := rules.wordDialect
	for _, token := range tokenStream {
		if rules.hiveDialect != nil && token.TokenType == tokens.HIVE_TOKEN_STREAM {
			wordDialect = rules.hiveDialect
			continue
		}
		if token.Start < 0 || token.End < token.Start || token.Start <= previousEnd || token.End >= len(runes) {
			return "", false
		}
		if rules.rejectExecutableComments && (containsUnsafeMySQLComment(runes[previousEnd+1:token.Start]) || token.TokenType == tokens.HINT) {
			return "", false
		}

		raw := string(runes[token.Start : token.End+1])
		if isWordToken(raw, token.TokenType, wordDialect) {
			if rules.foldIdentifiers {
				raw = d.FoldIdentifierName(raw, false)
			} else if d.IsReservedKeyword(raw) && !previousWasDot {
				// A reserved word immediately after `.` is an unquoted qualified identifier, not a
				// keyword: MySQL permits it there, and lower_case_table_names=0 makes qualified table
				// names case-sensitive, so `db.INTERSECT` and `db.intersect` are DISTINCT tables.
				// Folding it would collide two different tables onto one grant hash (an authorization
				// escalation), so keep it byte-exact — fail-safe over-denies case-variant column refs.
				raw = strings.ToLower(raw)
			}
		}
		lexemes = append(lexemes, raw)
		previousEnd = token.End
		previousWasDot = token.TokenType == tokens.DOT
		if rules.hiveDialect != nil && token.TokenType == tokens.SEMICOLON {
			wordDialect = rules.wordDialect
		}
	}
	if rules.rejectExecutableComments && containsUnsafeMySQLComment(runes[previousEnd+1:]) {
		return "", false
	}

	if len(lexemes) == 0 {
		return "", false
	}

	normalized = strings.Join(lexemes, " ")
	if normalized == "" {
		return "", false
	}
	return normalized, true
}

func containsUnsafeMySQLComment(gap []rune) bool {
	text := string(gap)
	return strings.Contains(text, "/*!") || strings.Contains(text, "/*+")
}

func isWordToken(raw string, tokenType tokens.TokenType, d *dialects.Dialect) bool {
	if tokenType == tokens.VAR {
		return true
	}
	first, _ := utf8.DecodeRuneInString(raw)
	if first != '_' && !unicode.IsLetter(first) {
		return false
	}
	configuredType, found := d.TokenizerConfig.Keywords[strings.ToUpper(raw)]
	return found && configuredType == tokenType
}
