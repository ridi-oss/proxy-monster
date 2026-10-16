package engines

import (
	"strings"

	"github.com/ridi-oss/sqlglot-go/tokens"
)

// literalTokens are every token that carries a value: strings in each quoting form, numbers, and bit, hex,
// byte, national, raw, dollar-quoted, and unicode strings.
var literalTokens = map[tokens.TokenType]bool{
	tokens.STRING: true, tokens.NUMBER: true, tokens.BIT_STRING: true, tokens.HEX_STRING: true,
	tokens.BYTE_STRING: true, tokens.NATIONAL_STRING: true, tokens.RAW_STRING: true,
	tokens.HEREDOC_STRING: true, tokens.UNICODE_STRING: true,
}

// RedactLiterals is sql with every literal value replaced by ?, so a statement can leave the system without
// its values: `SELECT * FROM users WHERE email = 'a@b.c'` becomes `SELECT * FROM users WHERE email = ?`. It
// works on tokens, read with SqlNormalize's engine rules, so a statement that does not parse is redacted too;
// comments, which sit between tokens, are dropped. The LIMIT row count keeps its number, which says how much a
// query reads; an offset does not (OFFSET n, or the n in MySQL's LIMIT n, count), so every page of one
// paginated read redacts to the same text. false means it cannot be redacted (see lex); send nothing then.
func RedactLiterals(sql, wireName string) (string, bool) {
	_, lexed, ok := lex(sql, wireName)
	if !ok || len(lexed) == 0 {
		return "", false
	}
	// The row count after LIMIT: the number that follows it, or in LIMIT offset, count the second one.
	keep := map[int]bool{}
	for j, l := range lexed {
		if l.token.TokenType != tokens.LIMIT || j+1 >= len(lexed) || lexed[j+1].token.TokenType != tokens.NUMBER {
			continue
		}
		if j+3 < len(lexed) && lexed[j+2].token.TokenType == tokens.COMMA && lexed[j+3].token.TokenType == tokens.NUMBER {
			keep[j+3] = true
		} else {
			keep[j+1] = true
		}
	}
	var out strings.Builder
	for i, l := range lexed {
		// Whitespace between tokens is kept; a gap holding a comment becomes one space.
		if strings.TrimSpace(l.gap) == "" {
			out.WriteString(l.gap)
		} else if i > 0 {
			out.WriteByte(' ')
		}
		if literalTokens[l.token.TokenType] && !keep[i] {
			out.WriteByte('?')
		} else {
			out.WriteString(l.raw)
		}
	}
	return strings.TrimSpace(out.String()), true
}
