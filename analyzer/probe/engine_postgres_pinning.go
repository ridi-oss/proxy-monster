// PostgreSQL statement-identity pinning: the target DB resolves object identities live
// (search_path, function/type visibility), so a statement the analyzer proved safe against one
// namespace could resolve DIFFERENTLY when executed. These passes pin analyzer-trusted
// resolutions (pg_catalog builtins, implicit table functions) into the relayed SQL, and fail
// closed on any identity that cannot be pinned.
package probe

import (
	"fmt"
	"sort"
	"strings"

	sqlglot "github.com/ridi-oss/sqlglot-go"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/generator"
	"github.com/ridi-oss/sqlglot-go/tokens"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

func hasUnsupportedPostgresUnnestOffset(root exp.Expression) bool {
	for _, unnest := range root.FindAll(exp.KindUnnest) {
		if offset := unnest.Arg("offset"); offset != nil {
			if _, ok := offset.(bool); !ok {
				return true
			}
		}
	}
	return false
}

var postgresDedicatedSafeFunctions = stringSet(
	"abs", "ceil", "ceiling", "char", "char_length", "character_length", "chr", "coalesce", "concat",
	"current_date", "date_part", "dateadd", "datediff", "exp", "extract", "floor", "greatest", "hex",
	"if", "ifnull", "initcap", "lcase", "least", "ln", "log", "md5", "mod", "nvl", "overlay",
	"position", "pow", "power", "replace", "round", "sqrt", "substr", "substring", "trim", "trunc",
	"truncate", "ucase",
)

var postgresRegenerationChangesFunctionCalls = stringSet(
	"ceiling", "char", "char_length", "character_length", "current_date", "date_part", "dateadd", "extract",
	"if", "ifnull", "lcase", "nvl", "overlay", "position", "pow", "substr", "substring", "truncate", "ucase",
)

type postgresFunctionCall struct {
	name        string
	position    int
	usesGrammar bool
}

func postgresFunctionUsesGrammar(stream []tokens.Token, index int, name string) bool {
	switch name {
	case "cast", "coalesce", "greatest", "least", "nullif", "trim":
		return true
	}
	markers := map[string]map[tokens.TokenType]bool{
		"convert":   {tokens.USING: true},
		"extract":   {tokens.FROM: true},
		"overlay":   {tokens.FROM: true},
		"position":  {tokens.IN: true},
		"substring": {tokens.ESCAPE: true, tokens.FOR: true, tokens.FROM: true, tokens.SIMILAR_TO: true},
	}
	wanted := markers[name]
	if len(wanted) == 0 {
		return false
	}
	depth := 0
	for i := index + 1; i < len(stream); i++ {
		token := stream[i]
		switch token.TokenType {
		case tokens.L_PAREN:
			depth++
		case tokens.R_PAREN:
			depth--
			if depth == 0 {
				return false
			}
		default:
			if depth != 1 {
				continue
			}
			if wanted[token.TokenType] {
				return true
			}
			if name == "overlay" && token.TokenType == tokens.VAR &&
				strings.EqualFold(token.Text, "placing") && i > index+1 &&
				stream[i-1].TokenType != tokens.COMMA {
				return true
			}
		}
	}
	return false
}

func (e *postgresEngine) functionFingerprint(function exp.Expression) (string, error) {
	return sqlglot.Generate(function, e.dialect, generator.Options{})
}

func postgresUnqualifiedFunctions(root exp.Expression) map[exp.Expression]bool {
	qualified := map[exp.Expression]bool{}
	for _, dot := range root.FindAll(exp.KindDot) {
		if function := dot.Right(); function != nil && function.Is(exp.TraitFunc) {
			qualified[function] = true
		}
	}
	for _, table := range root.FindAll(exp.KindTable) {
		function := table.This()
		if function == nil || !function.Is(exp.TraitFunc) {
			continue
		}
		if table.Arg("schema") != nil || table.Arg("catalog") != nil {
			qualified[function] = true
		}
	}
	unqualified := map[exp.Expression]bool{}
	for _, function := range root.FindAll(exp.TraitFunc) {
		if qualified[function] || function.FindAncestor(exp.KindTriggerExecute) != nil {
			continue
		}
		unqualified[function] = true
	}
	return unqualified
}

func (e *postgresEngine) functionCandidateFingerprint(
	sql []rune,
	stream []tokens.Token,
	index int,
) (string, bool, error) {
	depth := 0
	end := -1
	for i := index + 1; i < len(stream); i++ {
		switch stream[i].TokenType {
		case tokens.L_PAREN:
			depth++
		case tokens.R_PAREN:
			depth--
			if depth == 0 {
				end = stream[i].End + 1
				i = len(stream)
			}
		}
	}
	if end < 0 {
		return "", false, nil
	}
	candidate, err := sqlglot.ParseOne("SELECT "+string(sql[stream[index].Start:end]), e.dialect)
	if err != nil {
		return "", false, nil
	}
	selects := candidate.Selects()
	if len(selects) != 1 || !selects[0].Is(exp.TraitFunc) {
		return "", false, nil
	}
	fingerprint, err := e.functionFingerprint(selects[0])
	return fingerprint, true, err
}

func (e *postgresEngine) pinnableFunctionCalls(sql string) ([]postgresFunctionCall, error) {
	root, err := sqlglot.ParseOne(sql, e.dialect)
	if err != nil {
		return nil, err
	}
	stream, err := sqlglot.Tokenize(sql, e.dialect)
	if err != nil {
		return nil, err
	}
	actual := map[string]int{}
	for function := range postgresUnqualifiedFunctions(root) {
		fingerprint, err := e.functionFingerprint(function)
		if err != nil {
			return nil, err
		}
		actual[fingerprint]++
	}
	type candidate struct {
		call   postgresFunctionCall
		quoted bool
	}
	candidates := map[string][]candidate{}
	runes := []rune(sql)
	for i, token := range stream {
		if i+1 >= len(stream) || stream[i+1].TokenType != tokens.L_PAREN ||
			(i > 0 && stream[i-1].TokenType == tokens.DOT) {
			continue
		}
		name := strings.ToLower(token.Text)
		quoted := token.TokenType == tokens.IDENTIFIER
		if quoted {
			name = token.Text
		}
		if !e.IsSafeNoFromFunction(name) &&
			!(quoted && postgresDedicatedSafeFunctions[strings.ToLower(name)]) {
			continue
		}
		fingerprint, ok, err := e.functionCandidateFingerprint(runes, stream, i)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		candidates[fingerprint] = append(candidates[fingerprint], candidate{
			call: postgresFunctionCall{
				name:        name,
				position:    token.Start,
				usesGrammar: postgresFunctionUsesGrammar(stream, i, strings.ToLower(name)),
			},
			quoted: quoted,
		})
	}
	calls := []postgresFunctionCall{}
	for fingerprint, matches := range candidates {
		count := actual[fingerprint]
		if count == 0 {
			continue
		}
		if count != len(matches) {
			return nil, fmt.Errorf("ambiguous PostgreSQL function call location: %s", matches[0].call.name)
		}
		for _, match := range matches {
			if match.quoted && !e.IsSafeNoFromFunction(match.call.name) {
				return nil, fmt.Errorf(
					"quoted PostgreSQL function identity is not a system builtin: %s",
					match.call.name,
				)
			}
			if !match.call.usesGrammar {
				calls = append(calls, match.call)
			}
		}
	}
	sort.Slice(calls, func(i, j int) bool { return calls[i].position < calls[j].position })
	return calls, nil
}

func (e *postgresEngine) pinSafeFunctionSQL(sql string) (string, bool, error) {
	calls, err := e.pinnableFunctionCalls(sql)
	if err != nil {
		return "", false, err
	}
	if len(calls) == 0 {
		return sql, false, nil
	}
	rewritten := []rune(sql)
	prefix := []rune("pg_catalog.")
	for i := len(calls) - 1; i >= 0; i-- {
		position := calls[i].position
		rewritten = append(rewritten[:position], append(prefix, rewritten[position:]...)...)
	}
	return string(rewritten), true, nil
}

func (e *postgresEngine) functionChangedByRegeneration(sql string) (string, error) {
	calls, err := e.pinnableFunctionCalls(sql)
	if err != nil {
		return "", err
	}
	for _, call := range calls {
		if postgresRegenerationChangesFunctionCalls[call.name] {
			return call.name, nil
		}
	}
	return "", nil
}

func postgresLateralFunction(lateral exp.Expression) (exp.Expression, exp.Expression) {
	function := lateral.This()
	if function == nil {
		return nil, nil
	}
	if function.Kind() == exp.KindDot {
		if call := function.Right(); call != nil && call.Is(exp.TraitFunc) {
			return call, function.Left()
		}
		return nil, nil
	}
	if function.Is(exp.TraitFunc) {
		return function, nil
	}
	return nil, nil
}

func (e *postgresEngine) untrustedTableFunction(root exp.Expression, namespace NamespaceConfig) string {
	catalogFirst := postgresCatalogFirstAfterTempSchemas(namespace.SearchPath)
	for _, table := range root.FindAll(exp.KindTable) {
		function := table.This()
		if function == nil || !function.Is(exp.TraitFunc) {
			continue
		}
		name := normalizedFunctionName(function, e)
		implicit := len(e.ImplicitFunctionColumns(name)) != 0
		if !implicit && !e.IsSafeNoFromFunction(name) {
			continue
		}
		if table.Arg("catalog") != nil {
			return name
		}
		if schema, _ := table.Arg("schema").(exp.Expression); schema != nil {
			if !e.IsTrustedSystemQualifier(schema) {
				return name
			}
			continue
		}
		if implicit && (!catalogFirst || !e.ImplicitFunctionUnqualifiedTrusted(name)) {
			return name
		}
	}
	for _, lateral := range root.FindAll(exp.KindLateral) {
		function, qualifier := postgresLateralFunction(lateral)
		if function == nil {
			continue
		}
		name := normalizedFunctionName(function, e)
		implicit := len(e.ImplicitFunctionColumns(name)) != 0
		if !implicit && !e.IsSafeNoFromFunction(name) {
			continue
		}
		if qualifier != nil {
			if !e.IsTrustedSystemQualifier(qualifier) {
				return name
			}
			continue
		}
		if implicit && (!catalogFirst || !e.ImplicitFunctionUnqualifiedTrusted(name)) {
			return name
		}
	}
	for _, unnest := range root.FindAll(exp.KindUnnest) {
		if len(unnest.Expressions()) != 1 || !catalogFirst || !e.ImplicitFunctionUnqualifiedTrusted("unnest") {
			return "unnest"
		}
	}
	return ""
}

func (e *postgresEngine) pinTrustedImplicitFunctions(root exp.Expression, namespace NamespaceConfig) bool {
	if !postgresCatalogFirstAfterTempSchemas(namespace.SearchPath) {
		return false
	}
	pinned := false
	for _, table := range root.FindAll(exp.KindTable) {
		function := table.This()
		if function == nil || !function.Is(exp.TraitFunc) || table.Arg("catalog") != nil || table.Arg("schema") != nil {
			continue
		}
		name := function.Name()
		if identifier, ok := function.Arg("this").(exp.Expression); ok {
			identifier = identifier.Copy()
			e.dialect.NormalizeIdentifier(identifier)
			name = identifier.Name()
		} else {
			name = strings.ToLower(name)
		}
		if len(e.ImplicitFunctionColumns(name)) == 0 || !e.ImplicitFunctionUnqualifiedTrusted(name) ||
			(name == "unnest" && len(function.Expressions()) != 1) {
			continue
		}
		table.Set("schema", exp.ToIdentifier("pg_catalog"))
		pinned = true
	}
	for _, lateral := range root.FindAll(exp.KindLateral) {
		function, qualifier := postgresLateralFunction(lateral)
		if function == nil || qualifier != nil || function.Kind() == exp.KindUnnest {
			continue
		}
		name := normalizedFunctionName(function, e)
		if len(e.ImplicitFunctionColumns(name)) == 0 || !e.ImplicitFunctionUnqualifiedTrusted(name) {
			continue
		}
		lateral.Set("this", exp.Dot(exp.Args{
			"this":       exp.ToIdentifier("pg_catalog"),
			"expression": function.Copy(),
		}))
		pinned = true
	}
	if !e.ImplicitFunctionUnqualifiedTrusted("unnest") {
		return pinned
	}
	for _, unnest := range root.FindAll(exp.KindUnnest) {
		if len(unnest.Expressions()) != 1 {
			continue
		}
		ordinality, ok := unnest.Arg("offset").(bool)
		if !ok && unnest.Arg("offset") != nil {
			continue
		}
		arguments := make([]exp.Expression, 0, len(unnest.Expressions()))
		for _, argument := range unnest.Expressions() {
			arguments = append(arguments, argument.Copy())
		}
		tableArgs := exp.Args{
			"this": exp.Anonymous(exp.Args{
				"this":        "unnest",
				"expressions": arguments,
			}),
			"schema": exp.ToIdentifier("pg_catalog"),
		}
		if alias, ok := unnest.Arg("alias").(exp.Expression); ok && alias != nil {
			tableArgs["alias"] = alias.Copy()
		}
		if ordinality {
			tableArgs["ordinality"] = true
		}
		unnest.Replace(exp.Table(tableArgs))
		pinned = true
	}
	return pinned
}

func (e *postgresEngine) pinSafeFunctions(root exp.Expression, namespace NamespaceConfig) bool {
	return e.pinTrustedImplicitFunctions(root, namespace)
}

// EmitFacts parses one statement, classifies its relay behavior, and emits every Cedar requirement.
// Every return is a valid fail-closed StatementFacts; unresolved statements carry an explicit failure class.

// ValidateStatement vetoes forms the pinning passes cannot make safe: an UNNEST WITH ORDINALITY
// spelling the pin cannot rewrite, or a statement whose safe-function calls cannot be located
// unambiguously in the source text.
func (e *postgresEngine) ValidateStatement(root exp.Expression, sql string) error {
	if hasUnsupportedPostgresUnnestOffset(root) {
		return fmt.Errorf("unsupported PostgreSQL UNNEST offset")
	}
	if _, _, err := e.pinSafeFunctionSQL(sql); err != nil {
		return err
	}
	return nil
}

// FinalizeStatementIdentity runs the pinning passes over a resolved statement: verify every
// table-function resolution is trusted, pin implicit functions and safe builtins to pg_catalog,
// and refuse any statement whose function calls would change spelling under SQL regeneration.
func (e *postgresEngine) FinalizeStatementIdentity(root exp.Expression, sql string, facts *pb.StatementFacts, namespace NamespaceConfig) *pb.StatementFacts {
	pinned := false
	if facts.GetResolved() {
		if facts.RewrittenSql == nil {
			if name := e.untrustedTableFunction(root, namespace); name != "" {
				facts = unanalyzableFacts("VALIDATE", "untrusted PostgreSQL function resolution: "+name)
			} else {
				pinned = e.pinSafeFunctions(root, namespace)
			}
		} else {
			rewrittenRoot, err := sqlglot.ParseOne(facts.GetRewrittenSql(), e.dialect)
			if err != nil {
				facts = unanalyzableFacts("GENERATE", err.Error())
			} else if name := e.untrustedTableFunction(rewrittenRoot, namespace); name != "" {
				facts = unanalyzableFacts("VALIDATE", "untrusted PostgreSQL function resolution: "+name)
			} else if e.pinSafeFunctions(rewrittenRoot, namespace) {
				if rewrite, err := generateExecutableSQL(rewrittenRoot, e.dialect); err != nil {
					facts = unanalyzableFacts("GENERATE", err.Error())
				} else {
					facts.RewrittenSql = &rewrite
				}
			}
		}
	}
	if facts.GetResolved() && pinned && facts.RewrittenSql == nil {
		rewrite, err := generateExecutableSQL(root, e.dialect)
		if err != nil {
			facts = unanalyzableFacts("GENERATE", err.Error())
		} else {
			facts.RewrittenSql = &rewrite
		}
	}
	if facts.GetResolved() && facts.RewrittenSql != nil {
		name, err := e.functionChangedByRegeneration(sql)
		if err != nil {
			facts = unanalyzableFacts("VALIDATE", err.Error())
		} else if name != "" {
			facts = unanalyzableFacts("VALIDATE", "PostgreSQL function call changes during SQL regeneration: "+name)
		}
	}
	if facts.GetResolved() {
		effectiveSQL := sql
		if facts.RewrittenSql != nil {
			effectiveSQL = facts.GetRewrittenSql()
		}
		pinnedSQL, changed, err := e.pinSafeFunctionSQL(effectiveSQL)
		if err != nil {
			facts = unanalyzableFacts("VALIDATE", err.Error())
		} else if changed {
			if _, err := sqlglot.ParseOne(pinnedSQL, e.dialect); err != nil {
				facts = unanalyzableFacts("GENERATE", err.Error())
			} else {
				facts.RewrittenSql = &pinnedSQL
			}
		}
	}
	return facts
}
