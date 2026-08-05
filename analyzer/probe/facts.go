package probe

import (
	"fmt"
	"sort"
	"strings"

	sqlglot "github.com/ridi-oss/sqlglot-go"
	"github.com/ridi-oss/sqlglot-go/dialects"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/generator"
	"github.com/ridi-oss/sqlglot-go/schema"
	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

var safeNoFromFunctions = stringSet(
	"version", "current_schema", "current_schemas", "current_database", "current_catalog",
	"current_user", "session_user", "current_role", "user", "database", "schema", "connection_id",
	"pg_backend_pid", "pg_is_in_recovery", "pg_postmaster_start_time", "current_setting",
	"inet_server_addr", "inet_server_port", "inet_client_addr", "inet_client_port",
	"last_insert_id", "row_count", "found_rows", "charset", "collation", "coercibility",
	"now", "current_timestamp", "current_date", "current_time", "localtime", "localtimestamp",
	"clock_timestamp", "statement_timestamp", "transaction_timestamp", "timeofday", "sysdate",
	"curdate", "curtime", "utc_timestamp", "utc_date", "utc_time", "unix_timestamp", "from_unixtime",
	"extract", "date_part", "date_trunc", "datediff", "timestampdiff", "dateadd", "datepart",
	"to_char", "to_date", "to_timestamp", "to_number", "make_date", "make_timestamp",
	"abs", "ceil", "ceiling", "floor", "round", "trunc", "truncate", "mod", "power", "pow", "sqrt",
	"cbrt", "exp", "ln", "log", "log10", "log2", "sign", "pi", "degrees", "radians",
	"sin", "cos", "tan", "asin", "acos", "atan", "atan2", "rand", "random", "gen_random_uuid", "uuid",
	"length", "char_length", "character_length", "octet_length", "bit_length", "lower", "upper",
	"lcase", "ucase", "initcap", "trim", "ltrim", "rtrim", "btrim", "lpad", "rpad", "substr",
	"substring", "mid", "left", "right", "concat", "concat_ws", "replace", "translate", "reverse",
	"repeat", "ascii", "chr", "char", "ord", "instr", "locate", "position", "strpos", "split_part",
	"format", "quote_ident", "quote_literal", "quote_nullable", "regexp_replace", "regexp_substr",
	"md5", "sha1", "sha2", "encode", "decode", "hex", "unhex", "to_hex", "overlay",
	"cast", "convert", "coalesce", "nullif", "ifnull", "isnull", "nvl", "greatest", "least",
	"iif", "if", "typeof", "pg_typeof",
)

// userTypeCast returns the name of the first reference to a non-built-in (user) type anywhere in root, or
// "" if every type reference is a safe built-in. sqlglot resolves a built-in type to a concrete DType and
// a user type to DTypeUserDefined, so this is a single AST pass over DataType nodes. It covers every way a
// statement can name a type — the `::type` and `CAST(x AS type)` forms and the `type 'literal'` typed
// literal alike (they all parse to the same DataType node), in any position and whether or not the
// statement has a FROM (a `SELECT 1::public.evil_domain FROM users` runs the domain's code just the same).
// A `pg_catalog.<builtin>` reference needs no special-case here: sqlglot-go resolves it to the built-in
// node directly (`pg_catalog.int4` → INT DataType, `pg_catalog.oid`/reg* → ObjectIdentifier — not a
// DataType at all), so it never reaches the DTypeUserDefined branch. Only a non-catalog builtin ALIAS in
// pg_catalog (e.g. `pg_catalog.integer`, which PostgreSQL itself rejects as a nonexistent type) still
// lands here and is fail-closed — an accepted over-deny of invalid SQL.
func userTypeCast(root exp.Expression) string {
	for _, dt := range root.FindAll(exp.KindDataType) {
		if dt.Arg("this") != exp.DTypeUserDefined {
			continue
		}
		kind, _ := dt.Arg("kind").(exp.Expression)
		if kind != nil && kind.Kind() == exp.KindDot {
			qualifier := strings.ToLower(kind.Left().Name())
			leaf := strings.ToLower(kind.Right().Name())
			return qualifier + "." + leaf
		}
		if kind != nil {
			return strings.ToLower(kind.Name())
		}
		return "user-defined type"
	}
	return ""
}

// EmitFacts parses one statement, classifies its relay behavior, and emits every Cedar requirement.
// Every return is a valid fail-closed StatementFacts; unresolved statements carry an explicit failure class.
func EmitFacts(sql string, engineConfig *pb.EngineConfig, sch *schema.Mapping, namespace NamespaceConfig) *pb.StatementFacts {
	eng, err := createEngine(engineConfig)
	if err != nil {
		if utility := emitConfigFailureUtilityFacts(sql, engineConfig); utility != nil {
			return utility
		}
		return unanalyzableFacts("VALIDATE", err.Error())
	}
	validatedNamespace, err := validateNamespace(namespace)
	if err != nil {
		return unanalyzableFacts("VALIDATE", err.Error())
	}
	if err := detectRenderCollisions(sch); err != nil {
		return unanalyzableFacts("VALIDATE", err.Error())
	}
	qualifySchema, err := schema.NewMappingSchema(sch, eng.Dialect(), eng.NormalizeCatalogOnBuild())
	if err != nil {
		return unanalyzableFacts("VALIDATE", err.Error())
	}

	var parsed []exp.Expression
	if fail := runStage("PARSE", func() {
		var parseErr error
		parsed, parseErr = sqlglot.Parse(sql, eng.Dialect())
		if parseErr != nil {
			panic(parseErr)
		}
	}); fail != nil {
		return unanalyzableFacts("PARSE", fail.Detail)
	}
	stmts := nonNilStatements(parsed)
	if len(stmts) != 1 {
		return inadmissibleFacts("PARSE", fmt.Sprintf("expected 1 statement, got %d", len(stmts)))
	}
	// Peel a whole-statement parenthesized wrapper: `(SELECT 1)` parses to a Subquery whose `this` is the
	// real statement. Classification/lineage must run on the inner statement, not fail closed on the
	// wrapper (a wrapped SELECT is ordinary chatter, a wrapped write is still a write).
	root := stmts[0]
	for root != nil && root.Kind() == exp.KindSubquery && root.This() != nil {
		root = root.This()
	}
	candidates := schemaQualifierCandidates(root)

	var facts *pb.StatementFacts
	switch root.Kind() {
	case exp.KindDescribe:
		facts = emitDescribeFacts(root, eng, qualifySchema, validatedNamespace)
	case exp.KindShow:
		facts = emitShowFacts(root, eng)
	case exp.KindSet:
		facts = emitSetFacts(root, eng)
	case exp.KindCommand:
		facts = emitCommandFacts(root, eng)
	case exp.KindTransaction, exp.KindCommit, exp.KindRollback, exp.KindSavepoint, exp.KindUse, exp.KindAnalyze, exp.KindReset:
		// PostgreSQL `RESET <guc>` / `RESET ALL` (sqlglot-go v0.16 models it as a dedicated Reset node) only
		// restores a session variable to its default — a de-escalation, never a privilege gain — so it is a
		// benign session passthrough. (MySQL RESET MASTER/REPLICA is a privileged admin op that degrades to
		// Command and is denied there; it never reaches this Reset-node case.)
		facts = passthroughFacts(pb.StatementClass_STATEMENT_CLASS_SESSION)
		// Both arms end the transaction and so end the privacy of anything measured inside it. ROLLBACK
		// counts for the same reason COMMIT does: the schemas the connection read in the transaction now
		// describe a state that never became visible, and only a reading taken outside can say what the
		// backend actually holds. SAVEPOINT/RELEASE do not end the transaction and are excluded.
		facts.EndsTransaction = root.Kind() == exp.KindCommit || root.Kind() == exp.KindRollback
	case exp.KindAlter, exp.KindDrop, exp.KindTruncateTable:
		facts = unanalyzableFacts("LINEAGE", fmt.Sprintf("unsupported root %s", exp.ClassName(root.Kind())))
		facts.CatalogChanging = !isTemporaryDDL(root, eng)
		facts.RequiredGrants = append(facts.RequiredGrants, datasourceGrant(pb.GrantAction_GRANT_ACTION_SQL_DDL))
	default:
		if isKnownRoot(root) {
			facts = emitLineageFacts(root, eng, qualifySchema, validatedNamespace, false)
		} else {
			facts = unanalyzableFacts("PARSE", fmt.Sprintf("unsupported root %s", exp.ClassName(root.Kind())))
		}
	}
	facts.SchemaQualifierCandidates = candidates
	return facts
}

func emitConfigFailureUtilityFacts(sql string, engineConfig *pb.EngineConfig) *pb.StatementFacts {
	if engineConfig == nil || engineConfig.GetEngine() != pb.Engine_MYSQL {
		return nil
	}
	parsed, err := sqlglot.Parse(sql, dialects.MySQL())
	if err != nil {
		return nil
	}
	stmts := nonNilStatements(parsed)
	if len(stmts) != 1 || stmts[0].Kind() != exp.KindShow {
		return nil
	}
	command := showUtilityCommand(stmts[0])
	if command == "" {
		return nil
	}
	facts := passthroughFacts(pb.StatementClass_STATEMENT_CLASS_METADATA)
	facts.RequiredGrants = append(facts.RequiredGrants, utilityGrant(command))
	return facts
}

func emitLineageFacts(root exp.Expression, eng engine, qualifySchema schema.Schema, namespace NamespaceConfig, explain bool) *pb.StatementFacts {
	if userTypeCast(root) != "" {
		return criticalUtilityFacts(cmdUserTypeCast, pb.StatementClass_STATEMENT_CLASS_METADATA)
	}
	report := probeParsed(root, eng, qualifySchema, namespace)
	facts := factsFromProbe(report)
	facts.ExplainOfQuery = explain
	facts.StatementClass = pb.StatementClass_STATEMENT_CLASS_ANALYZED
	facts.RequiredGrants = append(facts.RequiredGrants, statementActionGrants(root, report)...)
	if !facts.Resolved {
		if len(facts.RequiredGrants) == 0 {
			facts.RequiredGrants = append(facts.RequiredGrants, syntacticStatementActionGrants(root)...)
		}
		return facts
	}

	for ordinal, origin := range report.Origins {
		for _, key := range origin.Origins {
			column, ok := columnResourceFromKey(key)
			if !ok {
				return unanalyzableFacts("LINEAGE", "invalid column identity emitted by analyzer")
			}
			disposition := pb.MaskedDisposition_MASKED_DISPOSITION_MASK_OUTPUT
			if origin.Derived {
				disposition = pb.MaskedDisposition_MASKED_DISPOSITION_REDACT_OUTPUT_NULL
			}
			facts.RequiredGrants = append(facts.RequiredGrants, columnGrant(column, disposition, int32(ordinal)))
		}
	}
	for _, refs := range report.References {
		for _, key := range refs {
			column, ok := columnResourceFromKey(key)
			if !ok {
				return unanalyzableFacts("LINEAGE", "invalid column identity emitted by analyzer")
			}
			facts.RequiredGrants = append(facts.RequiredGrants, columnGrant(column, pb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT))
		}
	}
	if report.IsWrite {
		seen := map[string]bool{}
		for _, grant := range facts.RequiredGrants {
			if column := grant.GetColumn(); column != nil {
				key := column.GetCatalog() + "." + column.GetIdentity().GetSchema() + "." + column.GetIdentity().GetTable() + "." + column.GetIdentity().GetColumn()
				if seen[key] {
					continue
				}
				seen[key] = true
				facts.RequiredGrants = append(facts.RequiredGrants, columnGrant(column, pb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT))
			}
		}
	}
	for _, source := range report.Sources {
		if source.Covered {
			continue
		}
		facts.RequiredGrants = append(facts.RequiredGrants, &pb.RequiredGrant{
			Action:            pb.GrantAction_GRANT_ACTION_RESULT_READ,
			Resource:          &pb.RequiredGrant_Table{Table: &pb.TableResource{Catalog: source.Catalog, Schema: source.Schema, Table: source.Table}},
			MaskedDisposition: pb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT,
		})
	}
	if len(report.Sources) == 0 {
		facts.RequiredGrants = append(facts.RequiredGrants, noFromFunctionGrants(root, eng)...)
		if len(facts.RequiredGrants) == 0 && !report.IsWrite {
			facts.StatementClass = pb.StatementClass_STATEMENT_CLASS_METADATA
		}
	}
	facts.OutputColumns = outputColumnNames(report)
	facts.CatalogChanging = root.Kind() == exp.KindCreate && !isTemporaryDDL(root, eng)
	if root.Kind() == exp.KindSelect && root.Arg("into") != nil {
		facts.CatalogChanging = true
	}
	if explain {
		facts.RewrittenSql = nil
	}
	return facts
}

// isTemporaryDDL reports whether a DDL root targets only session-local (temporary) objects, whose
// creation/drop must NOT set catalog_changing — the connection layer schedules datasource-global catalog
// refetches off that flag, and a session-local temp is invisible to other connections. The `TEMPORARY`
// keyword (a `temporary` arg on Drop / a TemporaryProperty on Create) is a structural, engine-agnostic
// signal; the temp-SCHEMA convention (PostgreSQL's pg_temp) is engine-specific and deferred to the engine.
func isTemporaryDDL(root exp.Expression, eng engine) bool {
	if truthy(root.Arg("temporary")) {
		return true
	}
	if len(root.FindAll(exp.KindTemporaryProperty)) > 0 {
		return true
	}
	for _, table := range root.FindAll(exp.KindTable) {
		schema, _ := table.Arg("schema").(exp.Expression)
		if eng.IsTempSchema(schema) {
			return true
		}
	}
	return false
}

func factsFromProbe(report ProbeResult) *pb.StatementFacts {
	facts := &pb.StatementFacts{
		Resolved:       report.Resolved,
		Detail:         report.Detail,
		StatementClass: pb.StatementClass_STATEMENT_CLASS_ANALYZED,
		IsWrite:        report.IsWrite,
		RewrittenSql:   report.RewrittenSQL,
		Functions:      append([]string(nil), report.Functions...),
	}
	if !report.Resolved {
		facts.FailureClass = pb.FailureClass_FAILURE_CLASS_UNANALYZABLE
		facts.FailedStage = report.FailedStage
	}
	for _, source := range report.Sources {
		facts.Sources = append(facts.Sources, &pb.SourceInfo{Catalog: source.Catalog, Schema: source.Schema, Table: source.Table, Covered: source.Covered})
	}
	return facts
}

func emitDescribeFacts(root exp.Expression, eng engine, qualifySchema schema.Schema, namespace NamespaceConfig) *pb.StatementFacts {
	this := root.This()
	kind := strings.ToUpper(fmt.Sprint(root.Arg("kind")))
	if kind == "TABLE" && this != nil && this.Kind() == exp.KindTable {
		selectRoot := exp.Select(exp.Args{"expressions": []exp.Expression{exp.Star(nil)}, "from_": exp.From(exp.Args{"this": this.Copy()})})
		return emitLineageFacts(selectRoot, eng, qualifySchema, namespace, true)
	}
	if this != nil && this.Kind() == exp.KindTable {
		return passthroughFacts(pb.StatementClass_STATEMENT_CLASS_METADATA)
	}
	if isKnownRoot(this) {
		return emitLineageFacts(this, eng, qualifySchema, namespace, true)
	}
	return unanalyzableFacts("PARSE", "DESCRIBE target is not a table or analyzable statement")
}

func emitShowFacts(root exp.Expression, eng engine) *pb.StatementFacts {
	if unsafeExpression(root.Arg("where"), eng) || unsafeExpression(root.Arg("query"), eng) {
		return criticalUtilityFacts(cmdShowSubquery, pb.StatementClass_STATEMENT_CLASS_METADATA)
	}
	if userTypeCast(root) != "" {
		return criticalUtilityFacts(cmdUserTypeCast, pb.StatementClass_STATEMENT_CLASS_METADATA)
	}
	facts := passthroughFacts(pb.StatementClass_STATEMENT_CLASS_METADATA)
	command := showUtilityCommand(root)
	if command != "" {
		facts.RequiredGrants = append(facts.RequiredGrants, utilityGrant(command))
	}
	return facts
}

// systemUtilityCommands: the manifest command ids for the session-config statements that carry a
// system: classification. They MUST match the ids in the bundled manifests
// (engine/src/main/resources/system-classification/**.json) exactly, so the control-plane classifier
// resolves each to its shipped tag (system:critical) and Cedar's floor forbid denies it — a policy
// decision, preset-relaxable like every other system:critical resource, not a Kotlin hard deny.
const (
	cmdSetRole                      = "SET_ROLE"
	cmdSetDefaultRole               = "SET_DEFAULT_ROLE"
	cmdSetSessionAuthorization      = "SET_SESSION_AUTHORIZATION"
	cmdSetSqlMode                   = "SET_SQL_MODE"
	cmdSetStandardConformingStrings = "SET_STANDARD_CONFORMING_STRINGS"
	cmdUserTypeCast                 = "USER_TYPE_CAST"
	cmdSetSubquery                  = "SET_SUBQUERY"
	cmdShowSubquery                 = "SHOW_SUBQUERY"
)

// criticalUtilityFacts emits a resolved statement of the given class carrying one system-classified
// Utility grant. The control-plane utility gate resolves the command's manifest tag (system:critical) and
// Cedar's unconditional floor forbid denies it — a policy decision on an existing resource kind (no new
// Cedar vocabulary).
//
// TODO(backlog): a data-reading SET/SHOW (subquery / unsafe-function RHS) is gated here as a whole-
// statement critical utility (the easy, fail-closed path). The precise model would trace the read's
// columns and mask/deny them individually — deferred until multi-position lineage over SET/SHOW lands.
func criticalUtilityFacts(command string, class pb.StatementClass) *pb.StatementFacts {
	facts := passthroughFacts(class)
	facts.RequiredGrants = append(facts.RequiredGrants, utilityGrant(command))
	return facts
}

// sessionUtilityFacts is criticalUtilityFacts for a SESSION-class statement (the SET … danger set).
func sessionUtilityFacts(command string) *pb.StatementFacts {
	return criticalUtilityFacts(command, pb.StatementClass_STATEMENT_CLASS_SESSION)
}

// sessionIdentitySetCommand returns the system-classified Utility command for a structured Set that
// changes, or persistently reconfigures, session/user identity on a shared backend session, or "" if it
// does not. It catches every spelling that means such an escalation — keying on only one leaves a
// privilege-escalation bypass:
//   - the keyword forms SET ROLE / SET DEFAULT ROLE / SET SESSION AUTHORIZATION, which sqlglot-go models as
//     a structured SetItem with kind "ROLE" / "DEFAULT ROLE" / "SESSION AUTHORIZATION" (its `this` is the
//     target role/user value, NOT a GUC named "role", so the name check below never sees it); and
//   - the GUC-alias assignment SET role = x / SET session_authorization = x, which parses as an EQ whose
//     LHS variable name is the session-identity GUC (case-insensitive; a quoted "role" folds to the same
//     unquoted .Name()).
//
// DEFAULT ROLE (MySQL) sets which roles activate on a user's next login — an admin mutation of a stored
// account, distinct from SET ROLE's live-session switch, but equally a privilege operation that must never
// run unauthorized on the pooled service-account connection. It gates as its own SET_DEFAULT_ROLE
// system:critical command (a distinct privileged statement, distinct resource; same deny outcome). Before
// sqlglot-go structured them, MySQL SET ROLE / SET DEFAULT ROLE degraded to Command and were denied there as
// a blanket MySQL-Command-SET INADMISSIBLE; now they gate precisely.
func sessionIdentitySetCommand(root exp.Expression) string {
	for _, item := range root.FindAll(exp.KindSetItem) {
		switch strings.ToUpper(strings.TrimSpace(item.Text("kind"))) {
		case "ROLE":
			return cmdSetRole
		case "DEFAULT ROLE":
			return cmdSetDefaultRole
		case "SESSION AUTHORIZATION":
			return cmdSetSessionAuthorization
		}
		target := item.This()
		if target == nil {
			continue
		}
		if target.Kind() == exp.KindEQ && target.Left() != nil {
			target = target.Left()
		}
		switch strings.ToLower(target.Name()) {
		case "role":
			return cmdSetRole
		case "session_authorization", "authorization":
			return cmdSetSessionAuthorization
		}
	}
	return ""
}

// lexerModeGucs name the session variables whose value changes how the SQL lexer parses SUBSEQUENT
// statements on the connection. The analyzer parses under a fixed per-engine dialect, so if the backend's
// effective mode diverges (ANSI_QUOTES makes "x" an identifier, NO_BACKSLASH_ESCAPES/standard_conforming_
// strings change string escaping) a later statement means something different on the wire than the
// analyzer saw. Their assignment is therefore only allowed with a value the analyzer can read at parse
// time — a literal or a bareword keyword — and never one that changes the lexer.
var lexerModeGucs = stringSet("sql_mode", "standard_conforming_strings")

func emitSetFacts(root exp.Expression, eng engine) *pb.StatementFacts {
	if command := sessionIdentitySetCommand(root); command != "" {
		return sessionUtilityFacts(command)
	}
	if unsafeExpression(root, eng) {
		return sessionUtilityFacts(cmdSetSubquery)
	}
	if userTypeCast(root) != "" {
		return sessionUtilityFacts(cmdUserTypeCast)
	}
	if command := lexerModeUtilityCommand(root); command != "" {
		return sessionUtilityFacts(command)
	}
	facts := passthroughFacts(pb.StatementClass_STATEMENT_CLASS_SESSION)
	for _, command := range setUtilityCommands(root) {
		facts.RequiredGrants = append(facts.RequiredGrants, utilityGrant(command))
	}
	return facts
}

// lexerModeUtilityCommand returns the system-classified Utility command for an assignment to sql_mode /
// standard_conforming_strings that the analyzer must gate — a value that changes the SQL lexer semantics,
// or one it cannot read at parse time — or "" for a benign lexer-mode SET (which stays SESSION
// passthrough). Substring-matching the rendered SQL is not enough: MySQL evaluates the RHS, so
// `SET sql_mode = @m`, `SET sql_mode = CONCAT('AN','SI_QUOTES')`, or any function/subquery can resolve to
// ANSI_QUOTES while the rendered text carries no such token — the analyzer would keep parsing the old
// dialect while the backend flips the lexer. So an unreadable RHS (and DEFAULT, a server value the
// analyzer cannot see) is gated too. Denial then lives in Cedar via the command's system:critical tag.
func lexerModeUtilityCommand(root exp.Expression) string {
	for _, item := range root.FindAll(exp.KindSetItem) {
		eq := item.This()
		if eq == nil || eq.Kind() != exp.KindEQ || eq.Left() == nil {
			continue
		}
		name := strings.ToLower(eq.Left().Name())
		if !lexerModeGucs[name] {
			continue
		}
		command := cmdSetSqlMode
		if name == "standard_conforming_strings" {
			command = cmdSetStandardConformingStrings
		}
		// Only the EQ's first value (eq.Right()) is inspected; a multi-value assignment's trailing values
		// (in the SetItem's `expressions`) are not. This is safe because both lexer GUCs are SCALAR: MySQL's
		// sql_mode never builds a value list (a comma there separates SetItems, each checked in its own loop
		// turn), and PostgreSQL rejects a multi-value assignment to the scalar standard_conforming_strings
		// ("SET takes only one argument"), so a trailing value can't flip the lexer on the wire. Revisit if
		// lexerModeGucs ever gains a genuinely list-typed GUC.
		value, ok := setModeLiteralValue(eq.Right(), name)
		if !ok || strings.EqualFold(value, "DEFAULT") {
			return command // unreadable at parse time → gate it
		}
		upper := strings.ToUpper(value)
		if name == "sql_mode" {
			for _, mode := range strings.Split(upper, ",") {
				switch strings.TrimSpace(mode) {
				case "ANSI_QUOTES", "NO_BACKSLASH_ESCAPES", "ANSI":
					return command
				}
			}
		} else if upper != "ON" && upper != "TRUE" && upper != "YES" && upper != "1" {
			return command
		}
	}
	return ""
}

// setModeLiteralValue returns the parse-time-visible text of a lexer-mode assignment's RHS and whether it
// is a value the analyzer can read: a string literal ('ANSI_QUOTES'), a bareword keyword (ANSI, off, on),
// or — only for standard_conforming_strings — a numeric literal (1). A session variable, function call,
// subquery, or any other expression is not readable and returns ok=false.
func setModeLiteralValue(rhs exp.Expression, variable string) (string, bool) {
	if rhs == nil {
		return "", false
	}
	switch rhs.Kind() {
	case exp.KindLiteral:
		if rhs.IsString() {
			return rhs.Name(), true
		}
		if variable == "standard_conforming_strings" {
			return rhs.Name(), true
		}
		return "", false
	case exp.KindVar:
		return rhs.Name(), true
	default:
		return "", false
	}
}

func emitCommandFacts(root exp.Expression, eng engine) *pb.StatementFacts {
	command := strings.ToUpper(strings.TrimSpace(fmt.Sprint(root.Arg("this"))))
	switch command {
	case "SET":
		// A SET that reaches Command — NOT a structured Set node — is one sqlglot-go did not structure. Every
		// benign session-config form on BOTH engines structures: single- and multi-value assignments incl.
		// LOCAL/SESSION scope and unquoted bareword value lists, SET NAMES, SET SESSION CHARACTERISTICS /
		// TRANSACTION / CONSTRAINTS / TIME ZONE, the identity forms (SET [SESSION|LOCAL] ROLE / DEFAULT ROLE /
		// SESSION AUTHORIZATION and the GUC-alias `SET role = x`), the lexer-mode gucs, and the credential.
		// What degrades to Command is a genuinely-unanalyzable spelling or a form the analyzer cannot vouch
		// for — a quoted-keyword laundering attempt (`SET "ROLE" admin`, which the backend also rejects), a
		// value the analyzer cannot read, or an engine construct not yet modeled. Fail closed UNIFORMLY on
		// both engines: an unstructured SET the analyzer never classified must never relay via an
		// engine-specific passthrough.
		return inadmissibleFacts("VALIDATE", "SET statement is not structurally analyzable")
	case "RESET":
		if eng.Type() == pb.Engine_POSTGRES {
			// A PostgreSQL RESET that degrades to Command (rather than the structured Reset node) is an
			// unusual/laundering spelling; RESET only ever restores defaults (de-escalation), so it stays a
			// benign session passthrough.
			return passthroughFacts(pb.StatementClass_STATEMENT_CLASS_SESSION)
		}
		return inadmissibleFacts("VALIDATE", "RESET is not allowed on MySQL")
	case "SHOW":
		// The data-bearing MySQL SHOWs (WARNINGS/PROCESSLIST/BINLOG/… and SHOW CREATE USER) and PostgreSQL
		// SHOW <guc> all parse as structured Show/Reset nodes and are handled in emitShowFacts, so they
		// never reach here. A SHOW that still degrades to Command is a form sqlglot-go did not model: on
		// PostgreSQL it can only be a read-only GUC/config read (no table data) → metadata passthrough; on
		// MySQL an unrecognized SHOW is one the proxy cannot vouch for → fail closed.
		if eng.Type() == pb.Engine_POSTGRES {
			return passthroughFacts(pb.StatementClass_STATEMENT_CLASS_METADATA)
		}
		return unanalyzableFacts("PARSE", "unsupported SHOW command")
	case "CALL":
		facts := unanalyzableFacts("PARSE", "CALL is not analyzable")
		facts.RequiredGrants = append(facts.RequiredGrants, datasourceGrant(pb.GrantAction_GRANT_ACTION_UNSPECIFIED))
		return facts
	default:
		return unanalyzableFacts("PARSE", fmt.Sprintf("unsupported command %s", command))
	}
}

func statementActionGrants(root exp.Expression, report ProbeResult) []*pb.RequiredGrant {
	var actions []pb.GrantAction
	if len(root.FindAll(exp.KindInto)) > 0 {
		return []*pb.RequiredGrant{datasourceGrant(pb.GrantAction_GRANT_ACTION_SQL_DDL)}
	}
	switch root.Kind() {
	case exp.KindSelect:
		if root.Arg("into") != nil {
			actions = []pb.GrantAction{pb.GrantAction_GRANT_ACTION_SQL_DDL}
		} else if len(report.Sources) > 0 || len(root.FindAll(exp.KindTable)) > 0 {
			actions = []pb.GrantAction{pb.GrantAction_GRANT_ACTION_SQL_SELECT}
		}
	case exp.KindInsert:
		if truthy(root.Arg("replace")) {
			actions = []pb.GrantAction{pb.GrantAction_GRANT_ACTION_UNSPECIFIED}
		} else {
			actions = []pb.GrantAction{pb.GrantAction_GRANT_ACTION_SQL_INSERT}
			if conflictDoesUpdate(root) {
				actions = append(actions, pb.GrantAction_GRANT_ACTION_SQL_UPDATE)
			}
		}
	case exp.KindUpdate:
		actions = []pb.GrantAction{pb.GrantAction_GRANT_ACTION_SQL_UPDATE}
	case exp.KindDelete:
		actions = []pb.GrantAction{pb.GrantAction_GRANT_ACTION_SQL_DELETE}
	case exp.KindCreate:
		actions = []pb.GrantAction{pb.GrantAction_GRANT_ACTION_SQL_DDL}
	case exp.KindMerge:
		actions = []pb.GrantAction{pb.GrantAction_GRANT_ACTION_UNSPECIFIED}
	default:
		if root.Is(exp.TraitSetOperation) {
			actions = []pb.GrantAction{pb.GrantAction_GRANT_ACTION_SQL_SELECT}
		} else {
			actions = []pb.GrantAction{pb.GrantAction_GRANT_ACTION_UNSPECIFIED}
		}
	}
	out := make([]*pb.RequiredGrant, 0, len(actions))
	for _, action := range actions {
		out = append(out, datasourceGrant(action))
	}
	return out
}

// conflictDoesUpdate reports whether an INSERT's conflict clause can UPDATE an existing row — PostgreSQL
// `ON CONFLICT ... DO UPDATE` (action Var `DO UPDATE`) or MySQL `ON DUPLICATE KEY UPDATE` (action Var
// `UPDATE`) — as opposed to `DO NOTHING`, which cannot. The structured `action` node is inspected rather
// than substring-matching the rendered clause, which mislabels `DO NOTHING` as an update and wrongly
// requires SQL_UPDATE of an insert-only principal.
func conflictDoesUpdate(root exp.Expression) bool {
	for _, oc := range root.FindAll(exp.KindOnConflict) {
		if action, ok := oc.Arg("action").(exp.Expression); ok && action != nil &&
			strings.Contains(strings.ToUpper(action.Name()), "UPDATE") {
			return true
		}
	}
	return false
}

func syntacticStatementActionGrants(root exp.Expression) []*pb.RequiredGrant {
	if len(root.FindAll(exp.KindInto)) > 0 {
		return []*pb.RequiredGrant{datasourceGrant(pb.GrantAction_GRANT_ACTION_SQL_DDL)}
	}
	var action pb.GrantAction
	switch root.Kind() {
	case exp.KindSelect:
		if root.Arg("into") != nil {
			action = pb.GrantAction_GRANT_ACTION_SQL_DDL
		} else {
			action = pb.GrantAction_GRANT_ACTION_SQL_SELECT
		}
	case exp.KindInsert:
		action = pb.GrantAction_GRANT_ACTION_SQL_INSERT
	case exp.KindUpdate:
		action = pb.GrantAction_GRANT_ACTION_SQL_UPDATE
	case exp.KindDelete:
		action = pb.GrantAction_GRANT_ACTION_SQL_DELETE
	case exp.KindCreate:
		action = pb.GrantAction_GRANT_ACTION_SQL_DDL
	default:
		if root.Is(exp.TraitSetOperation) {
			action = pb.GrantAction_GRANT_ACTION_SQL_SELECT
		} else {
			action = pb.GrantAction_GRANT_ACTION_UNSPECIFIED
		}
	}
	return []*pb.RequiredGrant{datasourceGrant(action)}
}

func noFromFunctionGrants(root exp.Expression, eng engine) []*pb.RequiredGrant {
	seen := map[string]bool{}
	out := []*pb.RequiredGrant{}
	emit := func(name string) {
		if name == "" || name == "*" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, &pb.RequiredGrant{
			Action:            pb.GrantAction_GRANT_ACTION_RESULT_READ,
			Resource:          &pb.RequiredGrant_Function{Function: &pb.FunctionResource{Name: name}},
			MaskedDisposition: pb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT,
		})
	}
	// Schema-qualified calls carry their qualifier in a wrapping Dot (left = qualifier, right = the
	// function), even though the function node's own Name() drops it. Only a bare `pg_catalog.<fn>` is a
	// trusted system builtin; any other qualifier — a user schema, or a multi-part/computed qualifier
	// whose leaf merely spells `pg_catalog` (`db.pg_catalog.fn`, `current_database().public.fn`) — is user
	// code and must NOT inherit a safe built-in's name. Emit its fully-qualified identity so it can never
	// classify to a trusted function and the control-plane hard-denies it (unclassified Function grant).
	qualified := map[exp.Expression]bool{}
	for _, dot := range root.FindAll(exp.KindDot) {
		fn := dot.Right()
		if fn == nil || !fn.Is(exp.TraitFunc) || dot.Left() == nil {
			continue
		}
		qualified[fn] = true
		leaf := strings.ToLower(fn.Name())
		if isTrustedSystemQualifier(dot.Left(), eng) {
			if !safeNoFromFunctions[leaf] {
				emit(leaf)
			}
			continue
		}
		emit(qualifiedCallName(dot.Left(), leaf, eng))
	}
	for _, fn := range root.FindAll(exp.TraitFunc) {
		if fn.Kind() != exp.KindAnonymous || qualified[fn] {
			continue
		}
		name := strings.ToLower(fn.Name())
		if safeNoFromFunctions[name] {
			continue
		}
		emit(name)
	}
	return out
}

// isTrustedSystemQualifier reports whether a call/type qualifier is the ONE trusted system-schema form:
// a single bare identifier that resolves to PostgreSQL's `pg_catalog`. Trust is decided on the qualifier
// folded through the dialect's quote-aware NormalizeIdentifier, NOT a raw EqualFold — an UNQUOTED
// `PG_CATALOG` folds to `pg_catalog` (trusted), but a QUOTED `"PG_CATALOG"` stays case-sensitive and is a
// DISTINCT user schema PostgreSQL's case-sensitive `pg_` reservation allows to exist, so it must NOT be
// trusted (a user function there would otherwise inherit a system builtin's pass). It is also engine-gated:
// `pg_catalog` is a PostgreSQL schema, so a MySQL database literally named `pg_catalog` is ordinary user
// code and never trusted. A multi-part qualifier (its left side is itself a Dot, i.e. `db.pg_catalog` /
// `current_database().public`) is never trusted either — its leaf spelling `pg_catalog` must not smuggle a
// call into the safe branch — so it fails this test and its call/type is emitted with a full qualified
// identity the control-plane cannot classify as safe.
func isTrustedSystemQualifier(qualifier exp.Expression, eng engine) bool {
	if qualifier == nil || eng.Type() != pb.Engine_POSTGRES || qualifier.Kind() != exp.KindIdentifier {
		return false
	}
	folded := qualifier.Copy()
	eng.Dialect().NormalizeIdentifier(folded)
	return folded.Name() == "pg_catalog"
}

// qualifiedCallName renders a user-code call's fully-qualified identity so it is always an unclassified
// Function grant. The single-identifier qualifier is folded through the dialect's quote-aware
// NormalizeIdentifier — matching how the analyzer resolves every other relation, so the emitted name keys
// identically to the control-plane's catalog (`"MySchema".fn` and `myschema.fn` stay DISTINCT rather than
// both collapsing to one lowercased name a classification could ride). A multi-part qualifier is rendered
// whole (`current_database().public.fn`) so the leaf never stands alone; that rendered form is always an
// unclassifiable identity, so its exact spelling is not load-bearing.
func qualifiedCallName(qualifier exp.Expression, leaf string, eng engine) string {
	if qualifier.Kind() == exp.KindDot {
		if rendered, err := sqlglot.Generate(qualifier, "", generator.Options{}); err == nil && rendered != "" {
			return strings.ToLower(rendered) + "." + leaf
		}
	}
	folded := qualifier.Copy()
	eng.Dialect().NormalizeIdentifier(folded)
	return folded.Name() + "." + leaf
}

func unsafeExpression(value any, eng engine) bool {
	var expressions []exp.Expression
	switch v := value.(type) {
	case exp.Expression:
		expressions = []exp.Expression{v}
	case []exp.Expression:
		expressions = v
	default:
		return false
	}
	for _, expression := range expressions {
		if expression == nil {
			continue
		}
		if len(expression.FindAll(exp.KindSelect)) > 0 || len(expression.FindAll(exp.TraitSetOperation)) > 0 {
			return true
		}
		if hasUnsafeCall(expression, eng) {
			return true
		}
	}
	return false
}

// hasUnsafeCall reports whether root contains any function call that is not provably a safe builtin,
// applying the SAME qualifier rule as noFromFunctionGrants: a qualified call is safe only when it is a
// bare `pg_catalog.<safe builtin>`; a user-schema or multi-part qualifier is user code regardless of the
// leaf's spelling. Without the qualifier check a call like `acme.version()` would fold onto the safe
// metadata `version()` and let session-state exfil (`SET @x = acme.leak()` then `SELECT @x`) slip through.
func hasUnsafeCall(root exp.Expression, eng engine) bool {
	qualified := map[exp.Expression]bool{}
	for _, dot := range root.FindAll(exp.KindDot) {
		fn := dot.Right()
		if fn == nil || !fn.Is(exp.TraitFunc) || dot.Left() == nil {
			continue
		}
		qualified[fn] = true
		if isTrustedSystemQualifier(dot.Left(), eng) {
			if !safeNoFromFunctions[strings.ToLower(fn.Name())] {
				return true
			}
			continue
		}
		return true
	}
	for _, fn := range root.FindAll(exp.TraitFunc) {
		// Only ANONYMOUS calls are candidates for user code — sqlglot resolves every recognized builtin to
		// a dedicated kind (Abs, Upper, …) whose Name() is its argument, not the function, so checking it
		// against the safe set is meaningless and would false-positive `abs(1)`. This mirrors
		// noFromFunctionGrants: dedicated builtins are inherently safe; an unrecognized Anonymous call is not.
		if qualified[fn] || fn.Kind() != exp.KindAnonymous {
			continue
		}
		name := strings.ToLower(fn.Name())
		if name != "" && name != "*" && !safeNoFromFunctions[name] {
			return true
		}
	}
	return false
}

func showUtilityCommand(root exp.Expression) string {
	name := strings.ToUpper(strings.TrimSpace(fmt.Sprint(root.Arg("this"))))
	switch name {
	case "WARNINGS":
		return "SHOW_WARNINGS"
	case "ERRORS":
		return "SHOW_ERRORS"
	case "PROCESSLIST":
		return "SHOW_PROCESSLIST"
	case "BINLOG EVENTS":
		return "SHOW_BINLOG_EVENTS"
	case "RELAYLOG EVENTS":
		return "SHOW_RELAYLOG_EVENTS"
	case "ENGINE":
		return "SHOW_ENGINE_STATUS"
	case "GRANTS":
		return "SHOW_GRANTS"
	case "REPLICA STATUS", "SLAVE STATUS":
		return "SHOW_REPLICA_STATUS"
	case "CREATE USER":
		// `SHOW CREATE USER u` exposes an account's stored password hash — system:critical. sqlglot-go
		// models it as a Show node (this="CREATE USER"), so it is read here structurally rather than off
		// the Command tail.
		return "SHOW_CREATE_USER"
	default:
		return ""
	}
}

// setUtilityCommands returns the privileged system-state utility commands a structured SET performs, by
// inspecting each SetItem's scope on the AST — NOT by substring-matching the rendered SQL. sqlglot-go
// renders a scope keyword inline per item, so `SET @a = 1, GLOBAL max_connections = 1` puts `GLOBAL` in
// the middle where a `SET GLOBAL` prefix scan never sees it; the mutation would then relay as an
// un-gated SESSION passthrough. Each item's scope keyword (`GLOBAL`/`PERSIST`/`PERSIST_ONLY`, whether
// carried on the SetItem or an `@@GLOBAL.x` SessionParameter target) and a `PASSWORD` target are the
// system:critical commands the control-plane utility gate must authorize regardless of item position.
func setUtilityCommands(root exp.Expression) []string {
	commands := []string{}
	seen := map[string]bool{}
	add := func(command string) {
		if !seen[command] {
			seen[command] = true
			commands = append(commands, command)
		}
	}
	scopeCommand := func(scope string) string {
		switch strings.ToUpper(scope) {
		case "GLOBAL":
			return "SET_GLOBAL"
		case "PERSIST":
			return "SET_PERSIST"
		case "PERSIST_ONLY":
			return "SET_PERSIST_ONLY"
		default:
			return ""
		}
	}
	for _, item := range root.FindAll(exp.KindSetItem) {
		itemKind := fmt.Sprint(item.Arg("kind"))
		if command := scopeCommand(itemKind); command != "" {
			add(command)
		}
		// `SET PASSWORD [FOR user] = …` / `… TO RANDOM` is a structured SetItem whose kind is PASSWORD
		// (the target is the optional FOR-user or absent, NOT a variable named "password"); it mutates a
		// stored account credential, so it carries the same system:critical SET_PASSWORD utility command.
		if strings.EqualFold(itemKind, "PASSWORD") {
			add("SET_PASSWORD")
		}
		target := setItemTarget(item)
		if target == nil {
			continue
		}
		if target.Kind() == exp.KindSessionParameter {
			if command := scopeCommand(fmt.Sprint(target.Arg("kind"))); command != "" {
				add(command)
			}
		}
	}
	return commands
}

// setItemTarget returns the variable a SetItem assigns — the LHS of its `EQ`, or the bare target when the
// item is not an assignment — so its scope (`@@GLOBAL.x`) and name (`PASSWORD`) can be inspected.
func setItemTarget(item exp.Expression) exp.Expression {
	this := item.This()
	if this == nil {
		return nil
	}
	if this.Kind() == exp.KindEQ && this.Left() != nil {
		return this.Left()
	}
	return this
}

func outputColumnNames(report ProbeResult) []string {
	out := make([]string, len(report.Origins))
	for i, origin := range report.Origins {
		out[i] = origin.Column
	}
	return out
}

func columnResourceFromKey(key string) (*pb.ColumnResource, bool) {
	parts := strings.Split(key, ".")
	if len(parts) != 4 {
		return nil, false
	}
	return &pb.ColumnResource{
		Catalog: parts[0],
		Identity: &pb.RelationIdentity{
			Schema: parts[1],
			Table:  parts[2],
			Column: parts[3],
		},
	}, true
}

func columnGrant(column *pb.ColumnResource, disposition pb.MaskedDisposition, ordinals ...int32) *pb.RequiredGrant {
	return &pb.RequiredGrant{
		Action:            pb.GrantAction_GRANT_ACTION_RESULT_READ,
		Resource:          &pb.RequiredGrant_Column{Column: column},
		MaskedDisposition: disposition,
		OutputOrdinals:    ordinals,
	}
}

func datasourceGrant(action pb.GrantAction) *pb.RequiredGrant {
	return &pb.RequiredGrant{
		Action:            action,
		Resource:          &pb.RequiredGrant_Datasource{Datasource: true},
		MaskedDisposition: pb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT,
	}
}

func utilityGrant(command string) *pb.RequiredGrant {
	return &pb.RequiredGrant{
		Action:            pb.GrantAction_GRANT_ACTION_RESULT_READ,
		Resource:          &pb.RequiredGrant_Utility{Utility: &pb.UtilityResource{Command: command}},
		MaskedDisposition: pb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT,
	}
}

func passthroughFacts(class pb.StatementClass) *pb.StatementFacts {
	return &pb.StatementFacts{Resolved: true, Detail: "ok", StatementClass: class}
}

func inadmissibleFacts(stage, detail string) *pb.StatementFacts {
	return &pb.StatementFacts{
		Resolved:       false,
		FailureClass:   pb.FailureClass_FAILURE_CLASS_INADMISSIBLE,
		FailedStage:    strPtr(stage),
		Detail:         truncateDetail(detail),
		StatementClass: pb.StatementClass_STATEMENT_CLASS_UNSPECIFIED,
	}
}

func unanalyzableFacts(stage, detail string) *pb.StatementFacts {
	return &pb.StatementFacts{
		Resolved:       false,
		FailureClass:   pb.FailureClass_FAILURE_CLASS_UNANALYZABLE,
		FailedStage:    strPtr(stage),
		Detail:         truncateDetail(detail),
		StatementClass: pb.StatementClass_STATEMENT_CLASS_UNSPECIFIED,
	}
}

func schemaQualifierCandidates(root exp.Expression) []string {
	set := map[string]bool{}
	for _, table := range root.FindAll(exp.KindTable) {
		if name := table.SchemaName(); name != "" {
			set[name] = true
		}
		if name := table.CatalogName(); name != "" {
			set[name] = true
		}
	}
	for _, column := range root.FindAll(exp.KindColumn) {
		if name := column.TableName(); name != "" {
			set[name] = true
		}
	}
	out := sortedSet(set)
	sort.Strings(out)
	return out
}
