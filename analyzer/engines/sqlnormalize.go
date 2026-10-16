package engines

import (
	"strings"
	"unicode"
	"unicode/utf8"

	sqlglot "github.com/ridi-oss/sqlglot-go"
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

// lexeme is one token of a statement walked with its engine's rules: its raw text, the dialect that
// classifies it as a word, and the text between it and the previous token.
type lexeme struct {
	token       tokens.Token
	raw, gap    string
	wordDialect *dialects.Dialect
}

// lex walks sql's tokens in wireName's engine rules, without trailing semicolons. false means the engine is
// unknown, sql does not tokenize, a token falls outside it, or (MySQL) it holds an executable comment.
func lex(sql, wireName string) (normalizeRules, []lexeme, bool) {
	if !utf8.ValidString(sql) || strings.IndexByte(sql, 0) >= 0 {
		return normalizeRules{}, nil, false
	}
	e, err := Parse(wireName)
	if err != nil {
		return normalizeRules{}, nil, false
	}
	rules := e.normalizeRules()
	tokenStream, err := sqlglot.Tokenize(sql, rules.dialect)
	if err != nil {
		return rules, nil, false
	}
	for len(tokenStream) > 0 && tokenStream[len(tokenStream)-1].TokenType == tokens.SEMICOLON {
		tokenStream = tokenStream[:len(tokenStream)-1]
	}
	runes := []rune(sql)
	previousEnd := -1
	out := make([]lexeme, 0, len(tokenStream))
	wordDialect := rules.wordDialect
	for _, token := range tokenStream {
		if rules.hiveDialect != nil && token.TokenType == tokens.HIVE_TOKEN_STREAM {
			wordDialect = rules.hiveDialect
			continue
		}
		if token.Start < 0 || token.End < token.Start || token.Start <= previousEnd || token.End >= len(runes) {
			return rules, nil, false
		}
		gap := runes[previousEnd+1 : token.Start]
		if rules.rejectExecutableComments && (containsUnsafeMySQLComment(gap) || token.TokenType == tokens.HINT) {
			return rules, nil, false
		}
		out = append(out, lexeme{token: token, raw: string(runes[token.Start : token.End+1]), gap: string(gap), wordDialect: wordDialect})
		previousEnd = token.End
		if rules.hiveDialect != nil && token.TokenType == tokens.SEMICOLON {
			wordDialect = rules.wordDialect
		}
	}
	if rules.rejectExecutableComments && containsUnsafeMySQLComment(runes[previousEnd+1:]) {
		return rules, nil, false
	}
	return rules, out, true
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

	rules, lexed, ok := lex(sql, dialect)
	if !ok {
		return "", false
	}
	d := rules.dialect
	previousWasDot := false
	lexemes := make([]string, 0, len(lexed))
	for _, l := range lexed {
		raw := l.raw
		if isWordToken(raw, l.token.TokenType, l.wordDialect) {
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
		previousWasDot = l.token.TokenType == tokens.DOT
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
