package probe

import (
	"strings"

	exp "github.com/ridi-oss/sqlglot-go/expressions"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// statementKind classifies a parsed statement root into its StatementKind by inspecting the AST — the
// same nodes and helpers EmitFacts's classifiers already read. It is purely descriptive (the granular
// half of the classification model the control-plane maps to a category); it does not decide the relay
// class, the grants, or resolution, and never overrides them.
//
// It is only ever called with a real root (a single statement that parsed): a parse error or a batch
// returns before a root exists, and those carry STMT_UNKNOWN from the unanalyzable/inadmissible facts.
// A statement sqlglot-go does not structure arrives as a raw exp.Command; that IS the signal it is
// unmodeled, so it is classified by its normalized leading keyword alone (Keyword()) and, where the
// keyword cannot reach a kind on its own, STMT_UNKNOWN — fail-closed, matching the deny-by-default-but-
// grantable unknown category. The remainder of a Command is never parsed here. The zero value
// (UNSPECIFIED) is never returned.
func statementKind(root exp.Expression, eng engine) pb.StatementKind {
	if root == nil {
		return pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN
	}
	// A SELECT ... INTO writes data to a destination outside the result stream, so it is a gated write, not
	// the read its outer shape suggests. Classified recursively BEFORE the shape dispatch so a leading
	// wrapper or a union/subquery branch cannot hide the INTO (sqlglot hoists a set-op's INTO onto the root
	// but FindAll still reaches it): a file target (OUTFILE/DUMPFILE) is admin.file; any other target
	// (MySQL `INTO @var`, PostgreSQL `INTO <table>`) is the ddl-gated select_into.
	if into := firstInto(root); into != nil {
		switch into.Text("kind") {
		case exp.IntoOutfile:
			return pb.StatementKind_STATEMENT_KIND_SELECT_INTO_OUTFILE
		case exp.IntoDumpfile:
			return pb.StatementKind_STATEMENT_KIND_SELECT_INTO_DUMPFILE
		default:
			return pb.StatementKind_STATEMENT_KIND_SELECT_INTO
		}
	}
	// A set operation (UNION/INTERSECT/EXCEPT) is a distinct node family, not a Select — check the trait
	// before the Kind switch, mirroring isKnownRoot.
	if root.Is(exp.TraitSetOperation) {
		return pb.StatementKind_STATEMENT_KIND_SET_OP
	}
	switch root.Kind() {
	case exp.KindSelect:
		return selectKind(root)
	case exp.KindValues:
		return pb.StatementKind_STATEMENT_KIND_VALUES
	case exp.KindInsert:
		return insertKind(root)
	case exp.KindUpdate:
		return pb.StatementKind_STATEMENT_KIND_UPDATE
	case exp.KindDelete:
		return pb.StatementKind_STATEMENT_KIND_DELETE
	case exp.KindCopy:
		// PostgreSQL COPY TO/FROM a server file (both directions) — admin.file, like OUTFILE. The probe
		// cannot trace lineage through COPY, so it stays UNANALYZABLE: the kind gate (admin.file) applies
		// on top of the unanalyzable gate, not instead of it.
		return pb.StatementKind_STATEMENT_KIND_COPY
	case exp.KindCreate:
		return createKind(objectKindText(root))
	case exp.KindAlter:
		return alterKind(objectKindText(root))
	case exp.KindDrop:
		return dropKind(objectKindText(root))
	case exp.KindTruncateTable:
		return pb.StatementKind_STATEMENT_KIND_TRUNCATE_TABLE
	case exp.KindTransaction:
		// START TRANSACTION and BEGIN both parse to a Transaction node (COMMIT/ROLLBACK have their own).
		return pb.StatementKind_STATEMENT_KIND_START_TRANSACTION
	case exp.KindCommit:
		return pb.StatementKind_STATEMENT_KIND_COMMIT
	case exp.KindRollback:
		// ROLLBACK and ROLLBACK TO SAVEPOINT share the Rollback node; the savepoint variant is not distinguished.
		return pb.StatementKind_STATEMENT_KIND_ROLLBACK
	case exp.KindSavepoint:
		// SAVEPOINT and RELEASE SAVEPOINT share the Savepoint node.
		return pb.StatementKind_STATEMENT_KIND_SAVEPOINT
	case exp.KindUse:
		return pb.StatementKind_STATEMENT_KIND_USE
	case exp.KindAnalyze:
		return pb.StatementKind_STATEMENT_KIND_ANALYZE_TABLE
	case exp.KindReset:
		// PostgreSQL `RESET <guc>` / `RESET ALL` restores a session variable to its default — a benign
		// session form (MySQL RESET is a privileged Command, classified below). No dedicated kind; it is a
		// session variable operation.
		return pb.StatementKind_STATEMENT_KIND_SET_SESSION_VAR
	case exp.KindKill:
		return pb.StatementKind_STATEMENT_KIND_KILL
	case exp.KindShow:
		return showKind(root)
	case exp.KindSet:
		return setKind(root)
	case exp.KindDescribe:
		return describeKind(root, eng)
	case exp.KindCommand:
		return commandKind(root)
	default:
		return pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN
	}
}

// selectKind distinguishes the plain Select forms — a file/var/table INTO is already handled by the
// recursive INTO check in statementKind. A CTE is marked by the root's own `with_` arg. `TABLE t` (MySQL
// 8.0.19+) parses to a plain `SELECT * FROM t` with no distinguishing marker, so it is SELECT
// (STATEMENT_KIND_TABLE has no AST signal to key on).
func selectKind(root exp.Expression) pb.StatementKind {
	if root.Arg("with_") != nil {
		return pb.StatementKind_STATEMENT_KIND_WITH_SELECT
	}
	return pb.StatementKind_STATEMENT_KIND_SELECT
}

// firstInto returns the statement's SELECT ... INTO clause anywhere in the tree, or nil. FindAll recurses,
// so an INTO hidden in a union branch or subquery is still found; INSERT/REPLACE's own `INTO t` target is
// part of the Insert node, not a KindInto, so a plain write is never matched.
func firstInto(root exp.Expression) exp.Expression {
	if intos := root.FindAll(exp.KindInto); len(intos) > 0 {
		return intos[0]
	}
	return nil
}

// insertKind distinguishes the write forms of an Insert. `replace` marks REPLACE; a conflict clause that
// can update marks the upsert — checked BEFORE the query-body form so an INSERT ... SELECT ... ON
// DUPLICATE KEY UPDATE is still an upsert (it can modify existing rows), not a plain INSERT ... SELECT.
func insertKind(root exp.Expression) pb.StatementKind {
	if truthy(root.Arg("replace")) {
		return pb.StatementKind_STATEMENT_KIND_REPLACE
	}
	if conflictDoesUpdate(root) {
		return pb.StatementKind_STATEMENT_KIND_INSERT_ON_DUP
	}
	if body, ok := root.Arg("expression").(exp.Expression); ok && body != nil &&
		(body.Kind() == exp.KindSelect || body.Is(exp.TraitSetOperation)) {
		return pb.StatementKind_STATEMENT_KIND_INSERT_SELECT
	}
	return pb.StatementKind_STATEMENT_KIND_INSERT
}

// describeKind classifies DESCRIBE / EXPLAIN. `EXPLAIN <query>` (its `this` is an analyzable statement)
// returns the plan, not rows: a READ is the read-shaped STATEMENT_KIND_EXPLAIN (the body), a WRITE keeps
// its own kind. `DESCRIBE <table>`, `DESC <table>`, and `EXPLAIN <table>` are all table introspection and
// parse to an identical Describe{this:Table} node — indistinguishable, so all three are DESCRIBE.
// `EXPLAIN TABLE t` is distinct: its Describe carries kind=TABLE (`TABLE t` is `SELECT * FROM t`
// shorthand), so it plans a scan of t — the same plan-only read EXPLAIN of that SELECT is, and the same
// signal emitDescribeFacts routes through lineage.
func describeKind(root exp.Expression, eng engine) pb.StatementKind {
	if isTableShorthandDescribe(root) {
		return pb.StatementKind_STATEMENT_KIND_EXPLAIN
	}
	// `EXPLAIN (SELECT …)` wraps the query in a Subquery (parentheses are real syntax); peel it so a
	// parenthesized target classifies like a bare one — matching emitDescribeFacts.
	inner := unwrapSubquery(root.This())
	if !isKnownRoot(inner) {
		return pb.StatementKind_STATEMENT_KIND_DESCRIBE
	}
	// An EXPLAIN of a READ returns the plan, not rows → one read-shaped kind (MySQL EXPLAIN and EXPLAIN
	// ANALYZE, PostgreSQL EXPLAIN, and PostgreSQL EXPLAIN ANALYZE of a read all land here). Everything else —
	// a write, an as-yet-unmodeled root — keeps its own kind, so it authorizes and denies (payload
	// DENY_STATEMENT) as that statement rather than as a mask-dropping plan-only EXPLAIN.
	if explainInnerIsPlanOnlyRead(inner) {
		return pb.StatementKind_STATEMENT_KIND_EXPLAIN
	}
	return statementKind(inner, eng)
}

// showKind maps a structured Show to its kind off the SHOW target (Show.this). That value is a canonical
// uppercase label for MySQL (sqlglot-go folds every alias to one spelling — SHOW SLAVE STATUS ->
// exp.ShowReplicaStatus, SHOW SLAVE HOSTS -> exp.ShowReplicas), so it is compared directly against the
// exported constants with no re-normalization. A PostgreSQL `SHOW <guc>` carries the verbatim
// (lower-case) parameter name, which never collides with a MySQL label and so falls through to
// SHOW_METADATA — every benign schema-introspecting SHOW shares that kind.
func showKind(root exp.Expression) pb.StatementKind {
	switch root.Text("this") {
	case exp.ShowWarnings:
		return pb.StatementKind_STATEMENT_KIND_SHOW_WARNINGS
	case exp.ShowErrors:
		return pb.StatementKind_STATEMENT_KIND_SHOW_ERRORS
	case exp.ShowGrants:
		return pb.StatementKind_STATEMENT_KIND_SHOW_GRANTS
	case exp.ShowCreateUser:
		return pb.StatementKind_STATEMENT_KIND_SHOW_CREATE_USER
	case exp.ShowProcesslist:
		return pb.StatementKind_STATEMENT_KIND_SHOW_PROCESSLIST
	case exp.ShowEngine:
		return pb.StatementKind_STATEMENT_KIND_SHOW_ENGINE_STATUS
	case exp.ShowBinlogEvents:
		return pb.StatementKind_STATEMENT_KIND_SHOW_BINLOG_EVENTS
	case exp.ShowRelaylogEvents:
		return pb.StatementKind_STATEMENT_KIND_SHOW_RELAYLOG_EVENTS
	case exp.ShowMasterStatus:
		return pb.StatementKind_STATEMENT_KIND_SHOW_MASTER_STATUS
	case exp.ShowBinaryLogs:
		return pb.StatementKind_STATEMENT_KIND_SHOW_BINARY_LOGS
	case exp.ShowReplicaStatus:
		return pb.StatementKind_STATEMENT_KIND_SHOW_REPLICA_STATUS
	case exp.ShowReplicas:
		return pb.StatementKind_STATEMENT_KIND_SHOW_REPLICAS
	default:
		return pb.StatementKind_STATEMENT_KIND_SHOW_METADATA
	}
}

// setKind maps a structured Set to its kind by reusing EmitFacts's SET classifiers, in the same order:
// an identity change, a privileged scope / credential, a lexer-mode GUC, then the two distinguished
// session forms (SET TRANSACTION, sql_log_bin). Everything else benign — SET NAMES, SET @var,
// SET autocommit, SET CHARACTER SET — is SET_SESSION_VAR (they are not separately distinguished).
func setKind(root exp.Expression) pb.StatementKind {
	switch sessionIdentitySetCommand(root) {
	case cmdSetRole:
		return pb.StatementKind_STATEMENT_KIND_SET_ROLE
	case cmdSetDefaultRole:
		return pb.StatementKind_STATEMENT_KIND_SET_DEFAULT_ROLE
	case cmdSetSessionAuthorization:
		return pb.StatementKind_STATEMENT_KIND_SET_SESSION_AUTHORIZATION
	}
	for _, command := range setUtilityCommands(root) {
		switch command {
		case "SET_PASSWORD":
			return pb.StatementKind_STATEMENT_KIND_SET_PASSWORD
		case "SET_GLOBAL":
			return pb.StatementKind_STATEMENT_KIND_SET_GLOBAL
		case "SET_PERSIST":
			return pb.StatementKind_STATEMENT_KIND_SET_PERSIST
		case "SET_PERSIST_ONLY":
			return pb.StatementKind_STATEMENT_KIND_SET_PERSIST_ONLY
		}
	}
	switch lexerModeUtilityCommand(root) {
	case cmdSetSqlMode:
		return pb.StatementKind_STATEMENT_KIND_SET_SQL_MODE
	case cmdSetStandardConformingStrings:
		return pb.StatementKind_STATEMENT_KIND_SET_STANDARD_CONFORMING_STRINGS
	}
	for _, item := range root.FindAll(exp.KindSetItem) {
		// SetItem.kind is canonical uppercase — compare directly to the exported constant.
		if item.Text("kind") == exp.SetItemTransaction {
			return pb.StatementKind_STATEMENT_KIND_SET_TRANSACTION
		}
		// sql_log_bin is a variable name (not a discriminator arg), so case is not contract-guaranteed.
		if target := setItemTarget(item); target != nil && strings.EqualFold(target.Name(), "sql_log_bin") {
			return pb.StatementKind_STATEMENT_KIND_SET_SQL_LOG_BIN
		}
	}
	return pb.StatementKind_STATEMENT_KIND_SET_SESSION_VAR
}

// commandKind classifies a Command — a statement sqlglot-go did not structure. It reads ONLY the
// normalized leading keyword (Keyword()); a Command's untokenized remainder is not a reliable
// discriminator and is never parsed. A keyword that maps to a single kind on its own is classified here;
// every other keyword — one that would need the remainder to tell replication apart from server (RESET),
// a rename target apart (RENAME), or a CREATE/ALTER/DROP object type apart — is STMT_UNKNOWN,
// deny-by-default. As sqlglot-go structures more of these into real nodes, they move up to the Kind
// switch and out of this fallback.
func commandKind(root exp.Expression) pb.StatementKind {
	switch root.Keyword() {
	case "CALL":
		return pb.StatementKind_STATEMENT_KIND_CALL
	case "DO":
		// MySQL `DO expr` parse-errors; PostgreSQL `DO $$ … $$` (anonymous code block) parses to a Command
		// with keyword DO — admin.exec, alongside CALL. Unanalyzable, so the kind gate stacks on the
		// unanalyzable gate.
		return pb.StatementKind_STATEMENT_KIND_DO
	case "PREPARE":
		return pb.StatementKind_STATEMENT_KIND_PREPARE
	case "EXECUTE":
		return pb.StatementKind_STATEMENT_KIND_EXECUTE
	case "HELP":
		return pb.StatementKind_STATEMENT_KIND_HELP
	case "OPTIMIZE":
		return pb.StatementKind_STATEMENT_KIND_OPTIMIZE_TABLE
	case "FLUSH":
		return pb.StatementKind_STATEMENT_KIND_FLUSH
	case "BINLOG":
		return pb.StatementKind_STATEMENT_KIND_BINLOG
	case "RESTART":
		return pb.StatementKind_STATEMENT_KIND_RESTART
	case "SHUTDOWN":
		return pb.StatementKind_STATEMENT_KIND_SHUTDOWN
	case "XA":
		return pb.StatementKind_STATEMENT_KIND_XA
	case "KILL":
		return pb.StatementKind_STATEMENT_KIND_KILL
	case "LOCK TABLES":
		return pb.StatementKind_STATEMENT_KIND_LOCK_TABLES
	case "UNLOCK TABLES":
		return pb.StatementKind_STATEMENT_KIND_UNLOCK_TABLES
	case "GRANT":
		// GRANT and REVOKE both gate as admin.account; a privilege grant vs a role grant is the same
		// subcategory and telling them apart would need the remainder, so it is not distinguished.
		return pb.StatementKind_STATEMENT_KIND_GRANT_PRIV
	case "REVOKE":
		return pb.StatementKind_STATEMENT_KIND_REVOKE_PRIV
	}
	return pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN
}

// createKind / alterKind / dropKind map a STRUCTURED Create/Alter/Drop's object-type keyword (its
// canonical-uppercase `kind` arg) to the matching CREATE_*/ALTER_*/DROP_* kind. Which object types the
// parser structures is verb- and dialect-dependent (DROP TRIGGER is a structured Drop, CREATE TRIGGER is
// a Command); an object type that arrives unstructured never reaches here — it is a Command, classified
// by commandKind. An object the enum does not name is STMT_UNKNOWN.
func createKind(object string) pb.StatementKind {
	switch object {
	case "TABLE":
		return pb.StatementKind_STATEMENT_KIND_CREATE_TABLE
	case "VIEW":
		return pb.StatementKind_STATEMENT_KIND_CREATE_VIEW
	case "INDEX":
		return pb.StatementKind_STATEMENT_KIND_CREATE_INDEX
	case "DATABASE", "SCHEMA":
		return pb.StatementKind_STATEMENT_KIND_CREATE_DATABASE
	case "FUNCTION":
		return pb.StatementKind_STATEMENT_KIND_CREATE_FUNCTION
	case "PROCEDURE":
		return pb.StatementKind_STATEMENT_KIND_CREATE_PROCEDURE
	case "TRIGGER":
		return pb.StatementKind_STATEMENT_KIND_CREATE_TRIGGER
	case "EVENT":
		return pb.StatementKind_STATEMENT_KIND_CREATE_EVENT
	case "SERVER":
		return pb.StatementKind_STATEMENT_KIND_CREATE_SERVER
	case "TABLESPACE":
		return pb.StatementKind_STATEMENT_KIND_CREATE_TABLESPACE
	case "SPATIAL":
		return pb.StatementKind_STATEMENT_KIND_CREATE_SRS
	case "USER":
		return pb.StatementKind_STATEMENT_KIND_CREATE_USER
	case "ROLE":
		return pb.StatementKind_STATEMENT_KIND_CREATE_ROLE
	case "RESOURCE":
		return pb.StatementKind_STATEMENT_KIND_CREATE_RESOURCE_GROUP
	}
	return pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN
}

func alterKind(object string) pb.StatementKind {
	switch object {
	case "TABLE":
		return pb.StatementKind_STATEMENT_KIND_ALTER_TABLE
	case "VIEW":
		return pb.StatementKind_STATEMENT_KIND_ALTER_VIEW
	case "DATABASE", "SCHEMA":
		return pb.StatementKind_STATEMENT_KIND_ALTER_DATABASE
	case "FUNCTION":
		return pb.StatementKind_STATEMENT_KIND_ALTER_FUNCTION
	case "PROCEDURE":
		return pb.StatementKind_STATEMENT_KIND_ALTER_PROCEDURE
	case "EVENT":
		return pb.StatementKind_STATEMENT_KIND_ALTER_EVENT
	case "SERVER":
		return pb.StatementKind_STATEMENT_KIND_ALTER_SERVER
	case "TABLESPACE":
		return pb.StatementKind_STATEMENT_KIND_ALTER_TABLESPACE
	case "INSTANCE":
		return pb.StatementKind_STATEMENT_KIND_ALTER_INSTANCE
	case "USER":
		return pb.StatementKind_STATEMENT_KIND_ALTER_USER
	case "RESOURCE":
		return pb.StatementKind_STATEMENT_KIND_ALTER_RESOURCE_GROUP
	}
	return pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN
}

func dropKind(object string) pb.StatementKind {
	switch object {
	case "TABLE":
		return pb.StatementKind_STATEMENT_KIND_DROP_TABLE
	case "INDEX":
		return pb.StatementKind_STATEMENT_KIND_DROP_INDEX
	case "VIEW":
		return pb.StatementKind_STATEMENT_KIND_DROP_VIEW
	case "DATABASE", "SCHEMA":
		return pb.StatementKind_STATEMENT_KIND_DROP_DATABASE
	case "FUNCTION":
		return pb.StatementKind_STATEMENT_KIND_DROP_FUNCTION
	case "PROCEDURE":
		return pb.StatementKind_STATEMENT_KIND_DROP_PROCEDURE
	case "TRIGGER":
		return pb.StatementKind_STATEMENT_KIND_DROP_TRIGGER
	case "EVENT":
		return pb.StatementKind_STATEMENT_KIND_DROP_EVENT
	case "SERVER":
		return pb.StatementKind_STATEMENT_KIND_DROP_SERVER
	case "TABLESPACE":
		return pb.StatementKind_STATEMENT_KIND_DROP_TABLESPACE
	case "SPATIAL":
		return pb.StatementKind_STATEMENT_KIND_DROP_SRS
	case "USER":
		return pb.StatementKind_STATEMENT_KIND_DROP_USER
	case "ROLE":
		return pb.StatementKind_STATEMENT_KIND_DROP_ROLE
	case "RESOURCE":
		return pb.StatementKind_STATEMENT_KIND_DROP_RESOURCE_GROUP
	}
	return pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN
}

// objectKindText returns a structured Create/Alter/Drop's object-type keyword — its canonical-uppercase
// `kind` arg, read directly (the sqlglot-go contract guarantees the value is upper-cased and trimmed).
func objectKindText(root exp.Expression) string {
	return root.Text("kind")
}
