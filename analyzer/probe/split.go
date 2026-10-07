package probe

import (
	"strings"
	"unicode/utf8"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/sqlglot-go"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
)

// SplitStatements cuts a batch into its statements, each a VERBATIM slice of sql — the text is stored,
// hashed, and authorized, so Generate() would rewrite what the caller wrote. ok=false denies the batch.
//
//	SELECT 'a;b' FROM t; SELECT 2                  ->  ["SELECT 'a;b' FROM t", "SELECT 2"]
//	CREATE PROCEDURE p() BEGIN a; b; END; SELECT 2  ->  ["CREATE PROCEDURE p() BEGIN a; b; END", "SELECT 2"]
func SplitStatements(sql string, config *pb.EngineConfig) (statements []string, ok bool) {
	batch, ok := SplitBatch(sql, config)
	for _, statement := range batch {
		statements = append(statements, statement.SQL)
	}
	return statements, ok
}

// BatchStatement is one statement of a split batch.
type BatchStatement struct {
	SQL  string
	Kind pb.StatementKind
	// BEGIN/START TRANSACTION, COMMIT/END, ROLLBACK, SAVEPOINT/RELEASE, SET TRANSACTION, or a statement
	// sqlglot-go did not parse as one (PostgreSQL `ABORT` reads as a column), which could be any of them.
	MayControlTransaction bool
	// An empty statement (`;;`, or a comment alone) comes before it, which MySQL stops at.
	AfterEmpty bool
}

// SplitBatch is SplitStatements that also marks each statement that may control the transaction.
func SplitBatch(sql string, config *pb.EngineConfig) (statements []BatchStatement, ok bool) {
	defer func() {
		if recover() != nil {
			statements = nil
			ok = false
		}
	}()

	if !utf8.ValidString(sql) || strings.IndexByte(sql, 0) >= 0 {
		return nil, false
	}

	// The dialect decides where a statement ends: under ANSI_QUOTES `SELECT "a;b"` is two statements,
	// and one otherwise — so split with exactly the config the target and the analyzer use.
	eng, err := createEngine(config)
	if err != nil {
		return nil, false
	}
	d := eng.Dialect()
	// Parsed, not scanned for `;` — a `;` inside `'a;b'` or a BEGIN…END body ends nothing.
	parsed, err := sqlglot.Parse(sql, d)
	if err != nil {
		return nil, false
	}

	out := make([]BatchStatement, 0, len(parsed))
	afterEmpty := false
	for _, statement := range parsed {
		// `;;` leaves a nil slot and a bare `;` a Semicolon node — nothing to run, nothing to authorize.
		if statement == nil || statement.Kind() == exp.KindSemicolon {
			afterEmpty = true
			continue
		}
		text, spanned := statement.SpanText()
		// No span means no slice of sql carries this statement, so nothing verbatim to authorize.
		if !spanned {
			return nil, false
		}
		if trimmed := strings.TrimSpace(text); trimmed != "" {
			out = append(out, BatchStatement{SQL: trimmed, Kind: statementKind(statement, eng), MayControlTransaction: mayControlTransaction(statement, eng), AfterEmpty: afterEmpty})
			afterEmpty = false
		}
	}
	// TODO: PG runs a bare `;` and the wire path relays EmptyQueryResponse; here it denies, since a
	// batch of nothing would mean a task with zero children.
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

func mayControlTransaction(root exp.Expression, eng engine) bool {
	kind := statementKind(root, eng)
	if kind != pb.StatementKind_STATEMENT_KIND_STMT_UNKNOWN {
		return transactionControlKinds[kind]
	}
	switch root.Kind() {
	case exp.KindCommand, exp.KindCreate, exp.KindAlter, exp.KindDrop:
		return false
	}
	return true
}

var transactionControlKinds = map[pb.StatementKind]bool{
	pb.StatementKind_STATEMENT_KIND_START_TRANSACTION: true,
	pb.StatementKind_STATEMENT_KIND_COMMIT:            true,
	pb.StatementKind_STATEMENT_KIND_ROLLBACK:          true,
	pb.StatementKind_STATEMENT_KIND_SAVEPOINT:         true,
	pb.StatementKind_STATEMENT_KIND_SET_TRANSACTION:   true,
}
