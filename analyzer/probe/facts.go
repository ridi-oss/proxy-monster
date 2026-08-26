package probe

import (
	"fmt"
	"sort"
	"strings"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	sqlglot "github.com/ridi-oss/sqlglot-go"
	"github.com/ridi-oss/sqlglot-go/dialects"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/generator"
	"github.com/ridi-oss/sqlglot-go/optimizer"
	"github.com/ridi-oss/sqlglot-go/schema"
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

// mysqlOnlySafeFunctions are safe no-FROM function names that exist ONLY on MySQL. `values` is MySQL's
// INSERT … ON DUPLICATE KEY UPDATE pseudo-function — it names the value that would have been inserted, not a
// callable function, and its lineage is traced in probe.go. PostgreSQL has no `values` builtin, so keeping
// it out of the cross-engine set leaves a quoted PostgreSQL `"values"()` (a user function) gated.
var mysqlOnlySafeFunctions = stringSet("values")

// isSafeNoFromFunction reports whether a bare (unqualified) anonymous function name is a known-safe builtin
// that needs no no-FROM Function grant — the cross-engine set plus any engine-specific pseudo-functions.
func isSafeNoFromFunction(name string, eng engine) bool {
	return safeNoFromFunctions[name] || (eng.Type() == pb.Engine_MYSQL && mysqlOnlySafeFunctions[name])
}

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
	// Fold identifiers ONCE, here, so every consumer below reads canonical spellings. Qualify does this
	// as its own first step (optimizer.Qualify → NormalizeIdentifiers), but Qualify needs the catalog and
	// runs only in VALIDATE — so the paths that never reach it, or that reach it and fail, were each
	// left to fold by hand. Quote-aware, so a quoted identifier keeps its case: `"PG_CATALOG"` stays a
	// distinct user schema from `pg_catalog`, and `"MySchema".fn` from `myschema.fn`.
	root := optimizer.NormalizeIdentifiers(unwrapSubquery(stmts[0]), eng.Dialect())
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
	case exp.KindTransaction, exp.KindCommit, exp.KindRollback, exp.KindSavepoint, exp.KindUse, exp.KindReset:
		// PostgreSQL `RESET <guc>` / `RESET ALL` (sqlglot-go v0.16 models it as a dedicated Reset node) only
		// restores a session variable to its default — a de-escalation, never a privilege gain — so it is a
		// benign session passthrough. (MySQL RESET MASTER/REPLICA is a privileged admin op that degrades to
		// Command and is denied there; it never reaches this Reset-node case.)
		facts = passthroughFacts()
	case exp.KindAnalyze:
		facts = emitAnalyzeFacts(root, eng, qualifySchema, validatedNamespace)
	case exp.KindAlter, exp.KindDrop, exp.KindTruncateTable:
		facts = ddlFacts(root, eng)
	case exp.KindCreate:
		// A CREATE that reads columns (CREATE TABLE AS SELECT, CREATE VIEW) has lineage to trace and goes
		// down the lineage path. One that reads none — CREATE INDEX, a bare CREATE TABLE with a column
		// list — has no lineage, so it would fail there ("CREATE without analyzable query") and route a
		// plainly-classifiable DDL through the unmasked exception.unanalyzable relay.
		//
		// The test is "does the body contain a query", not "is the body a Select": both a parenthesis
		// wrapper (`AS (SELECT …)` is a Subquery) and a PostgreSQL `AS VALUES ((SELECT …))` hide one, and
		// either would otherwise be read as body-less and emit NO column grants — the same statement
		// enforced differently for a pair of parentheses, which is the copy-PII-into-a-new-table path.
		if createReadsColumns(root) {
			facts = emitLineageFacts(root, eng, qualifySchema, validatedNamespace, false)
		} else {
			facts = ddlFacts(root, eng)
		}
	default:
		if isKnownRoot(root) {
			facts = emitLineageFacts(root, eng, qualifySchema, validatedNamespace, false)
		} else {
			facts = unanalyzableFacts("PARSE", fmt.Sprintf("unsupported root %s", exp.ClassName(root.Kind())))
		}
	}
	// The engine may rewrite the statement into what the proxy relays to the target DB — MySQL pins
	// `character_set_results = NULL` to utf8mb4 so results stay UTF-8 for the wire masker. Emitted as
	// rewritten_sql: the data plane relays it while authorization and audit keep the client's original. A
	// lineage-driven rewrite (the `*`-expansion) already set on an analyzed statement takes precedence.
	if facts.RewrittenSql == nil {
		if rewrite := eng.RewriteStatement(root); rewrite != "" {
			facts.RewrittenSql = &rewrite
		}
	}
	facts.StatementExec = executeGrant(statementKind(root, eng))
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
	facts := passthroughFacts()
	facts.ResultReads = append(facts.ResultReads, utilityGrant(command))
	facts.StatementExec = executeGrant(statementKind(stmts[0], nil))
	return facts
}

func emitLineageFacts(root exp.Expression, eng engine, qualifySchema schema.Schema, namespace NamespaceConfig, explain bool) *pb.StatementFacts {
	if userTypeCast(root) != "" {
		return criticalUtilityFacts(cmdUserTypeCast)
	}
	report := probeParsed(root, eng, qualifySchema, namespace)
	facts := factsFromProbe(report)
	// The execute grant (the statement kind) is attached centrally in EmitFacts, for resolved and
	// unresolved statements alike; here we only add the column/table RESULT_READ grants below.
	if !facts.Resolved {
		return facts
	}

	// An EXPLAIN — of a read or a write — returns the query PLAN, not rows. So a projected column is READ to
	// build the plan but is NOT an output: emit it with no output ordinal, so it still needs a read grant
	// (masked read is enough) yet binds no mask, and output_columns is left empty below for the same reason.
	// A write EXPLAIN additionally keeps its DENY_STATEMENT payload protection via the IsWrite loop below, so
	// materializing a masked column still denies. Every EXPLAIN grant must have an empty ordinal to match the
	// empty output_columns — a stray ordinal would fail the mask-binding contract check (Query.kt).
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
			if explain {
				facts.ResultReads = append(facts.ResultReads, columnGrant(column, disposition))
			} else {
				facts.ResultReads = append(facts.ResultReads, columnGrant(column, disposition, int32(ordinal)))
			}
		}
	}
	// Flatten and sort the reference columns: report.References is a map, so iterating it directly emits the
	// DENY grants in a random order per run. The control-plane freezes these grants as a stored result's
	// fingerprint and compares them for equality at view, so a nondeterministic order would make an unchanged
	// query's fingerprint differ between execute and view and falsely deny the view.
	refCols := []string{}
	for _, refs := range report.References {
		refCols = append(refCols, refs...)
	}
	sort.Strings(refCols)
	for _, key := range refCols {
		column, ok := columnResourceFromKey(key)
		if !ok {
			return unanalyzableFacts("LINEAGE", "invalid column identity emitted by analyzer")
		}
		facts.ResultReads = append(facts.ResultReads, columnGrant(column, pb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT))
	}
	// Advisory, never authorization: this decides only whether the statement TEXT may be shown outside the
	// console. An unparseable identity is skipped rather than failing the statement — a fact that can only
	// hide text must not be able to deny a query.
	for _, lit := range report.PredicateLiterals {
		column, ok := columnResourceFromKey(lit.Column)
		if !ok {
			continue
		}
		facts.PredicateLiterals = append(facts.PredicateLiterals, &pb.PredicateLiteral{
			Column: column,
			Clause: lit.Clause,
		})
	}
	if report.IsWrite {
		seen := map[string]bool{}
		for _, grant := range facts.ResultReads {
			if column := grant.GetColumn(); column != nil {
				key := column.GetCatalog() + "." + column.GetIdentity().GetSchema() + "." + column.GetIdentity().GetTable() + "." + column.GetIdentity().GetColumn()
				if seen[key] {
					continue
				}
				seen[key] = true
				facts.ResultReads = append(facts.ResultReads, columnGrant(column, pb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT))
			}
		}
	}
	for _, source := range report.Sources {
		if source.Covered {
			continue
		}
		facts.ResultReads = append(facts.ResultReads, &pb.RequireResultReadGrant{
			Resource:          &pb.RequireResultReadGrant_Table{Table: &pb.TableResource{Catalog: source.Catalog, Schema: source.Schema, Table: source.Table}},
			MaskedDisposition: pb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT,
		})
	}
	if len(report.Sources) == 0 {
		facts.ResultReads = append(facts.ResultReads, noFromFunctionGrants(root, eng)...)
	}
	facts.CatalogChanging = root.Kind() == exp.KindCreate && !isTemporaryDDL(root, eng)
	if root.Kind() == exp.KindSelect && root.Arg("into") != nil {
		facts.CatalogChanging = true
	}
	if explain {
		// An EXPLAIN's output is the plan, not the query's columns: no output_columns (nothing to mask
		// against), and relay the client's original text rather than a `*`-expanded rewrite.
		facts.OutputColumns = nil
		facts.RewrittenSql = nil
	} else {
		facts.OutputColumns = outputColumnNames(report)
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
		Resolved:     report.Resolved,
		Detail:       report.Detail,
		RewrittenSql: report.RewrittenSQL,
		Functions:    append([]string(nil), report.Functions...),
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
		return passthroughFacts()
	}
	// `EXPLAIN (SELECT …)` wraps the query in a Subquery (parentheses are real syntax); peel it so a
	// parenthesized target is analyzed like a bare one. The kind (plan-only EXPLAIN, or the inner write for
	// an executing EXPLAIN ANALYZE) is decided centrally by describeKind; here we only trace the inner
	// query's lineage.
	if inner := unwrapSubquery(this); isKnownRoot(inner) {
		return emitLineageFacts(inner, eng, qualifySchema, namespace, true)
	}
	return unanalyzableFacts("PARSE", "DESCRIBE target is not a table or analyzable statement")
}

// explainInnerIsPlanOnlyRead reports whether an EXPLAIN's inner statement is a PROVABLE pure read — the
// only case that becomes the read-shaped plan-only EXPLAIN kind (its projected columns are read-required
// with no output ordinal, so a `context.stmt_kind == "explain"` policy can read them unmasked). A
// whitelist, deliberately, not a write blacklist: anything not provably a read — a write root, an
// as-yet-unmodeled root, a `SELECT … INTO`, or a data-modifying CTE — keeps its own kind, so it authorizes
// and denies (payload DENY_STATEMENT) as that statement. A newly modeled write shape therefore fails closed
// instead of silently reclassifying as a read.
func explainInnerIsPlanOnlyRead(inner exp.Expression) bool {
	if !inner.Is(exp.TraitSetOperation) && inner.Kind() != exp.KindSelect {
		return false
	}
	if len(inner.FindAll(exp.KindInto)) > 0 {
		return false // SELECT … INTO OUTFILE / a new table materializes
	}
	for _, k := range []exp.Kind{exp.KindInsert, exp.KindUpdate, exp.KindDelete, exp.KindMerge} {
		if len(inner.FindAll(k)) > 0 {
			return false // a data-modifying CTE writes
		}
	}
	return true
}

// emitAnalyzeFacts gates a table-targeted ANALYZE the same way DESCRIBE is: a table statistics command
// reveals the table's existence and touches its rows, so it must carry the same result-read grant a
// `SELECT * FROM <table>` would (routed through lineage with explain = true — read-required, not row
// masking). Without it the statement resolves connect-only and becomes an existence oracle that bypasses
// the result-read gate. The single-table target is exact: a multi-table `ANALYZE TABLE t1, t2` leaves the
// list tail unconsumed and the parser degrades the whole statement to Command, which never reaches here.
// The statement-kind exec grant is attached centrally in EmitFacts, so the kind gate applies regardless.
func emitAnalyzeFacts(root exp.Expression, eng engine, qualifySchema schema.Schema, namespace NamespaceConfig) *pb.StatementFacts {
	this := root.This()
	kind := ""
	if k := root.Arg("kind"); k != nil {
		kind = strings.ToUpper(fmt.Sprint(k))
	}
	// MySQL `ANALYZE TABLE t` (kind TABLE) and PostgreSQL/Presto `ANALYZE t` (no kind) both target one table
	// to read. INDEX / DATABASE / CLUSTER / bare all-table ANALYZE carry no single readable table target and
	// stay a benign passthrough — still exec-gated by the statement kind.
	if (kind == "TABLE" || kind == "") && this != nil && this.Kind() == exp.KindTable {
		selectRoot := exp.Select(exp.Args{"expressions": []exp.Expression{exp.Star(nil)}, "from_": exp.From(exp.Args{"this": this.Copy()})})
		return emitLineageFacts(selectRoot, eng, qualifySchema, namespace, true)
	}
	return passthroughFacts()
}

func emitShowFacts(root exp.Expression, eng engine) *pb.StatementFacts {
	if unsafeExpression(root.Arg("where"), eng) || unsafeExpression(root.Arg("query"), eng) {
		return criticalUtilityFacts(cmdShowSubquery)
	}
	if userTypeCast(root) != "" {
		return criticalUtilityFacts(cmdUserTypeCast)
	}
	facts := passthroughFacts()
	command := showUtilityCommand(root)
	if command != "" {
		facts.ResultReads = append(facts.ResultReads, utilityGrant(command))
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
func criticalUtilityFacts(command string) *pb.StatementFacts {
	facts := passthroughFacts()
	facts.ResultReads = append(facts.ResultReads, utilityGrant(command))
	return facts
}

// sessionUtilityFacts is criticalUtilityFacts for a SESSION-class statement (the SET … danger set).
func sessionUtilityFacts(command string) *pb.StatementFacts {
	return criticalUtilityFacts(command)
}

// sessionIdentitySetCommand returns the system-classified Utility command for a structured Set that
// changes, or persistently reconfigures, session/user identity on a shared target-DB session, or "" if it
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
// statements on the connection. The analyzer parses under a fixed per-engine dialect, so if the target DB's
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
	facts := passthroughFacts()
	for _, command := range setUtilityCommands(root) {
		facts.ResultReads = append(facts.ResultReads, utilityGrant(command))
	}
	return facts
}

// lexerModeUtilityCommand returns the system-classified Utility command for an assignment to sql_mode /
// standard_conforming_strings that the analyzer must gate — a value that changes the SQL lexer semantics,
// or one it cannot read at parse time — or "" for a benign lexer-mode SET (which stays SESSION
// passthrough). Substring-matching the rendered SQL is not enough: MySQL evaluates the RHS, so
// `SET sql_mode = @m`, `SET sql_mode = CONCAT('AN','SI_QUOTES')`, or any function/subquery can resolve to
// ANSI_QUOTES while the rendered text carries no such token — the analyzer would keep parsing the old
// dialect while the target DB flips the lexer. So an unreadable RHS (and DEFAULT, a server value the
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
		// for — a quoted-keyword laundering attempt (`SET "ROLE" admin`, which the target DB also rejects), a
		// value the analyzer cannot read, or an engine construct not yet modeled. Fail closed UNIFORMLY on
		// both engines: an unstructured SET the analyzer never classified must never relay via an
		// engine-specific passthrough.
		return inadmissibleFacts("VALIDATE", "SET statement is not structurally analyzable")
	case "RESET":
		if eng.Type() == pb.Engine_POSTGRES {
			// A PostgreSQL RESET that degrades to Command (rather than the structured Reset node) is an
			// unusual/laundering spelling; RESET only ever restores defaults (de-escalation), so it stays a
			// benign session passthrough.
			return passthroughFacts()
		}
		return inadmissibleFacts("VALIDATE", "RESET is not allowed on MySQL")
	case "SHOW":
		// The data-bearing MySQL SHOWs (WARNINGS/PROCESSLIST/BINLOG/… and SHOW CREATE USER) and PostgreSQL
		// SHOW <guc> all parse as structured Show/Reset nodes and are handled in emitShowFacts, so they
		// never reach here. A SHOW that still degrades to Command is a form sqlglot-go did not model: on
		// PostgreSQL it can only be a read-only GUC/config read (no table data) → metadata passthrough; on
		// MySQL an unrecognized SHOW is one the proxy cannot vouch for → fail closed.
		if eng.Type() == pb.Engine_POSTGRES {
			return passthroughFacts()
		}
		return unanalyzableFacts("PARSE", "unsupported SHOW command")
	case "CALL":
		return unanalyzableFacts("PARSE", "CALL is not analyzable")
	default:
		return unanalyzableFacts("PARSE", fmt.Sprintf("unsupported command %s", command))
	}
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

func noFromFunctionGrants(root exp.Expression, eng engine) []*pb.RequireResultReadGrant {
	seen := map[string]bool{}
	out := []*pb.RequireResultReadGrant{}
	emit := func(name string) {
		if name == "" || name == "*" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, &pb.RequireResultReadGrant{
			Resource:          &pb.RequireResultReadGrant_Function{Function: &pb.FunctionResource{Name: name}},
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
		if eng.IsTrustedSystemQualifier(dot.Left()) {
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
		if isSafeNoFromFunction(name, eng) {
			continue
		}
		emit(name)
	}
	return out
}

// qualifiedCallName renders a user-code call's fully-qualified identity so it is always an unclassified
// Function grant. The single-identifier qualifier arrives already folded (EmitFacts normalizes up front,
// quote-aware) — matching how the analyzer resolves every other relation, so the emitted name keys
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
	return qualifier.Name() + "." + leaf
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
		if eng.IsTrustedSystemQualifier(dot.Left()) {
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
		if name != "" && name != "*" && !isSafeNoFromFunction(name, eng) {
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

func columnGrant(column *pb.ColumnResource, disposition pb.MaskedDisposition, ordinals ...int32) *pb.RequireResultReadGrant {
	return &pb.RequireResultReadGrant{
		Resource:          &pb.RequireResultReadGrant_Column{Column: column},
		MaskedDisposition: disposition,
		OutputOrdinals:    ordinals,
	}
}

// executeGrant is the single per-statement authorization signal: run this statement, which the
// control-plane authorizes as stmt.kind.<kind>. The analyzer names only the kind — Cedar's schema maps
// it to a category. Every analyzable statement carries exactly one, added once at classification.
func executeGrant(kind pb.StatementKind) *pb.RequireStatementExecGrant {
	return &pb.RequireStatementExecGrant{StatementKind: kind}
}

func utilityGrant(command string) *pb.RequireResultReadGrant {
	return &pb.RequireResultReadGrant{
		Resource:          &pb.RequireResultReadGrant_Utility{Utility: &pb.UtilityResource{Command: command}},
		MaskedDisposition: pb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT,
	}
}

func passthroughFacts() *pb.StatementFacts {
	return &pb.StatementFacts{Resolved: true, Detail: "ok"}
}

// inadmissibleFacts and unanalyzableFacts carry no execute grant. A pre-root failure (parse error, batch)
// is genuinely unclassifiable, so the control-plane reads a missing execute grant as STMT_UNKNOWN — the
// deny-by-default-but-grantable unknown category. A statement that reaches EmitFacts's root classification
// gets its computed kind there instead (so an unanalyzable ALTER still reports ALTER_TABLE).
func inadmissibleFacts(stage, detail string) *pb.StatementFacts {
	return &pb.StatementFacts{
		Resolved:     false,
		FailureClass: pb.FailureClass_FAILURE_CLASS_INADMISSIBLE,
		FailedStage:  strPtr(stage),
		Detail:       truncateDetail(detail),
	}
}

func unanalyzableFacts(stage, detail string) *pb.StatementFacts {
	return &pb.StatementFacts{
		Resolved:     false,
		FailureClass: pb.FailureClass_FAILURE_CLASS_UNANALYZABLE,
		FailedStage:  strPtr(stage),
		Detail:       truncateDetail(detail),
	}
}

// A DDL statement (ALTER / DROP / TRUNCATE / a body-less CREATE) is RESOLVED: its meaning is fully
// determined and it reads no column values, so there is no lineage to trace — its whole authorization is
// the kind gate on its stmt.kind.* (which Cedar maps to stmt.cat.ddl). It resolves as ANALYZED with no
// column grants, carrying only the execute grant EmitFacts attaches. Reporting it unresolved instead
// would route it through the exception.unanalyzable gate — a grant that relays statements UNMASKED and ships
// scoped to system:development only — so a statement whose safety is trivially provable would be
// authorized only by the escape hatch built for statements nobody can prove safe, and denied elsewhere.
func ddlFacts(root exp.Expression, eng engine) *pb.StatementFacts {
	return &pb.StatementFacts{
		Resolved:     true,
		FailureClass: pb.FailureClass_FAILURE_CLASS_UNSPECIFIED,
		// A temp-scoped DDL target is session-local, so it changes no shared catalog and must not force
		// every other connection to re-measure. Account-object DDL (CREATE/ALTER/DROP USER|ROLE) changes
		// accounts/roles, not the column catalog the proxy re-measures for masking, so it is not
		// catalog-changing either — it relays as a no-column passthrough, which keeps a statement result
		// like CREATE USER … IDENTIFIED BY RANDOM PASSWORD viewable rather than dropped for column mismatch.
		CatalogChanging: !isTemporaryDDL(root, eng) && !isAccountObjectDDL(root),
	}
}

// isAccountObjectDDL is true for CREATE/ALTER/DROP of a USER or ROLE — account management that touches no
// table or column, so unlike schema DDL it changes no catalog the proxy re-measures.
func isAccountObjectDDL(root exp.Expression) bool {
	switch objectKindText(root) {
	case "USER", "ROLE":
		return true
	}
	return false
}

// schemaQualifierCandidates collects every schema the statement names, so a caller holding a partial
// catalog can fetch the ones it lacks. The names are the target DB's own spelling — EmitFacts folds the
// statement's identifiers before this runs — because a candidate is used to look that schema up: MySQL
// under lower_case_table_names=1 reports information_schema lowercase, so an unfolded `GOODS_STORE`
// would match nothing.
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
