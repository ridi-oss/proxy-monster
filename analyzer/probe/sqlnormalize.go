package probe

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ridi-oss/sqlglot-go"
	"github.com/ridi-oss/sqlglot-go/dialects"
	"github.com/ridi-oss/sqlglot-go/tokens"
)

// SqlNormalize produces a lexer-only canonical form suitable for exact approval matching.
// It is total and fail-closed so that no panic can cross the native binding boundary.
func SqlNormalize(sql, dialect string) (normalized string, ok bool) {
	defer func() {
		if recover() != nil {
			normalized = ""
			ok = false
		}
	}()

	if (dialect != "mysql" && dialect != "postgres" && dialect != "athena") || !utf8.ValidString(sql) || strings.IndexByte(sql, 0) >= 0 {
		return "", false
	}

	d, err := dialects.GetOrRaise(dialect)
	if err != nil {
		return "", false
	}
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
	wordDialect := d
	if dialect == "athena" {
		wordDialect = dialects.Trino()
	}
	for _, token := range tokenStream {
		if dialect == "athena" && token.TokenType == tokens.HIVE_TOKEN_STREAM {
			wordDialect = dialects.Hive()
			continue
		}
		if token.Start < 0 || token.End < token.Start || token.Start <= previousEnd || token.End >= len(runes) {
			return "", false
		}
		if dialect == "mysql" && containsUnsafeMySQLComment(runes[previousEnd+1:token.Start]) {
			return "", false
		}
		if dialect == "mysql" && token.TokenType == tokens.HINT {
			return "", false
		}

		raw := string(runes[token.Start : token.End+1])
		if isWordToken(raw, token.TokenType, wordDialect) {
			if dialect == "postgres" || dialect == "athena" {
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
		if dialect == "athena" && token.TokenType == tokens.SEMICOLON {
			wordDialect = dialects.Trino()
		}
	}
	if dialect == "mysql" && containsUnsafeMySQLComment(runes[previousEnd+1:]) {
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
