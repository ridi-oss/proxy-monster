package engines

import (
	"reflect"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

func TestSetAutocommitIsTransactionControlInEverySpelling(t *testing.T) {
	for _, sql := range []string{
		"SET autocommit = 0", "set autocommit=1", "SET AUTOCOMMIT = ON",
		"SET SESSION autocommit = 0", "SET LOCAL autocommit = 0",
		"SET @@autocommit = 0", "SET @@session.autocommit = 0", "SET @@local.autocommit = 0",
		"SET @a = 1, autocommit = 0",
	} {
		parityKind(t, sql, "mysql", pb.StatementKind_STATEMENT_KIND_SET_TRANSACTION)
		parityNoUtility(t, sql, "mysql")
	}
	parityKind(t, "set autocommit=0", "postgres", pb.StatementKind_STATEMENT_KIND_SET_TRANSACTION)
}

func TestSetAutocommitAuthorizesAsSetTransaction(t *testing.T) {
	if got := resolve(t, "SET autocommit = 0"); got != "stmt.kind.set_transaction" {
		t.Fatalf("classification = %q, want stmt.kind.set_transaction", got)
	}
}

func TestUserVariableNamedAutocommitStaysASessionVariable(t *testing.T) {
	parityKind(t, "SET @autocommit = 0", "mysql", pb.StatementKind_STATEMENT_KIND_SET_SESSION_VAR)
}

func TestSqlLogBinOutranksAutocommitInOneSet(t *testing.T) {
	for _, sql := range []string{"SET autocommit = 0, sql_log_bin = 0", "SET sql_log_bin = 0, autocommit = 0"} {
		parityKind(t, sql, "mysql", pb.StatementKind_STATEMENT_KIND_SET_SQL_LOG_BIN)
	}
}

func TestGlobalAutocommitStaysSetGlobal(t *testing.T) {
	parityKind(t, "SET @@global.autocommit = 0", "mysql", pb.StatementKind_STATEMENT_KIND_SET_GLOBAL)
}

func TestSplitBatchMarksSetAutocommitAsTransactionControl(t *testing.T) {
	batch, ok := SplitBatch("SET autocommit = 0; UPDATE t SET a = 1; SET @autocommit = 1", mysqlSplitConfig())
	if !ok {
		t.Fatal("split failed")
	}
	var got []bool
	for _, statement := range batch {
		got = append(got, statement.MayControlTransaction)
	}
	if want := []bool{true, false, false}; !reflect.DeepEqual(got, want) {
		t.Fatalf("transaction control = %v, want %v", got, want)
	}
}
