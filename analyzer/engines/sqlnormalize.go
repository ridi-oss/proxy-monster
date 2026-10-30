package engines

import (
	"strings"
	"unicode/utf8"

	sqlglot "github.com/ridi-oss/sqlglot-go"
	"github.com/ridi-oss/sqlglot-go/dialects"
	"github.com/ridi-oss/sqlglot-go/tokens"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// normalizeRules is the per-engine part of SqlNormalize: whether unquoted identifiers fold, and whether
// executable comments are refused.
type normalizeRules struct {
	// foldIdentifiers lowercases unquoted identifiers (PostgreSQL, Athena). MySQL keeps them byte-exact:
	// lower_case_table_names=0 makes `db.T` and `db.t` distinct tables.
	foldIdentifiers bool
	// rejectExecutableComments refuses `/*! */` and `/*+ */`, which MySQL runs as SQL.
	rejectExecutableComments bool
}

// lexeme is one token of a statement and its raw text.
type lexeme struct {
	token tokens.Token
	raw   string
}

// lex walks sql's tokens in the dialect config's target is read by, without trailing semicolons. false means
// the engine or target is unusable, sql does not tokenize, a token falls outside it, or (MySQL) it holds an
// executable comment.
func lex(sql string, config *pb.EngineConfig) (normalizeRules, *dialects.Dialect, []lexeme, bool) {
	if !utf8.ValidString(sql) || strings.IndexByte(sql, 0) >= 0 {
		return normalizeRules{}, nil, nil, false
	}
	e, ok := ByProto(config.GetEngine())
	if !ok {
		return normalizeRules{}, nil, nil, false
	}
	d, _, err := e.Traits.targetDialect(config.GetTarget())
	if err != nil {
		return normalizeRules{}, nil, nil, false
	}
	rules := e.Traits.normalizeRules
	tokenStream, err := sqlglot.Tokenize(sql, d)
	if err != nil {
		return rules, d, nil, false
	}
	for len(tokenStream) > 0 && tokenStream[len(tokenStream)-1].TokenType == tokens.SEMICOLON {
		tokenStream = tokenStream[:len(tokenStream)-1]
	}
	runes := []rune(sql)
	previousEnd := -1
	out := make([]lexeme, 0, len(tokenStream))
	for _, token := range tokenStream {
		if token.Synthetic {
			continue
		}
		if token.Start < 0 || token.End < token.Start || token.Start <= previousEnd || token.End >= len(runes) {
			return rules, d, nil, false
		}
		gap := runes[previousEnd+1 : token.Start]
		if rules.rejectExecutableComments && (containsUnsafeMySQLComment(gap) || token.TokenType == tokens.HINT) {
			return rules, d, nil, false
		}
		out = append(out, lexeme{token: token, raw: string(runes[token.Start : token.End+1])})
		previousEnd = token.End
	}
	if rules.rejectExecutableComments && containsUnsafeMySQLComment(runes[previousEnd+1:]) {
		return rules, d, nil, false
	}
	return rules, d, out, true
}

// SqlNormalize produces a lexer-only canonical form suitable for exact approval matching.
// It reads sql in the dialect of config's engine and target; config's session is not read. It is total
// and fail-closed so that no panic can cross the native binding boundary.
func SqlNormalize(sql string, config *pb.EngineConfig) (normalized string, ok bool) {
	defer func() {
		if recover() != nil {
			normalized = ""
			ok = false
		}
	}()

	rules, d, lexed, ok := lex(sql, config)
	if !ok {
		return "", false
	}
	previousWasDot := false
	lexemes := make([]string, 0, len(lexed))
	for _, l := range lexed {
		raw := l.raw
		if isWordToken(l.token) {
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

// isWordToken reports a keyword or unquoted name; Keyword also marks operators, which lowercasing leaves alone.
func isWordToken(token tokens.Token) bool {
	return token.Keyword || token.TokenType == tokens.VAR
}
