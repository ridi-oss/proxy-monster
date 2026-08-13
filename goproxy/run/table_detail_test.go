package run_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/ridi-oss/proxy-monster/goproxy/cp"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/run"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const tableDetailTestTimeout = 10 * time.Second

type tableDetailObserved struct {
	sessionID string
	message   *pb.ProxyTableDetailMsg
	err       error
}

type tableDetailFakeCP struct {
	pb.UnimplementedControlPlaneServer

	mu              sync.Mutex
	expectedSession string
	observed        chan tableDetailObserved
}

func (tableDetailFake *tableDetailFakeCP) tableDetailExpect(sessionID string) {
	tableDetailFake.mu.Lock()
	tableDetailFake.expectedSession = sessionID
	tableDetailFake.mu.Unlock()
}

func (tableDetailFake *tableDetailFakeCP) TableDetailExec(stream grpc.BidiStreamingServer[pb.ProxyTableDetailMsg, pb.ControlTableDetailMsg]) error {
	tableDetailReady, err := stream.Recv()
	if err != nil {
		tableDetailFake.observed <- tableDetailObserved{err: fmt.Errorf("receive session ready: %w", err)}
		return err
	}
	tableDetailSessionID := tableDetailReady.GetSessionReady().GetSessionId()
	tableDetailFake.mu.Lock()
	tableDetailExpectedSession := tableDetailFake.expectedSession
	tableDetailFake.mu.Unlock()
	if tableDetailReady.GetSessionReady() == nil || tableDetailSessionID != tableDetailExpectedSession {
		tableDetailErr := fmt.Errorf("session ready id = %q, want %q", tableDetailSessionID, tableDetailExpectedSession)
		tableDetailFake.observed <- tableDetailObserved{sessionID: tableDetailSessionID, err: tableDetailErr}
		return tableDetailErr
	}

	tableDetailMessage, err := stream.Recv()
	if err != nil {
		tableDetailFake.observed <- tableDetailObserved{sessionID: tableDetailSessionID, err: fmt.Errorf("receive result: %w", err)}
		return err
	}
	if (tableDetailMessage.GetResult() == nil) == (tableDetailMessage.GetError() == nil) {
		tableDetailErr := fmt.Errorf("terminal message must contain exactly one result or error: %v", tableDetailMessage)
		tableDetailFake.observed <- tableDetailObserved{sessionID: tableDetailSessionID, err: tableDetailErr}
		return tableDetailErr
	}
	tableDetailClone := proto.Clone(tableDetailMessage).(*pb.ProxyTableDetailMsg)
	tableDetailFake.observed <- tableDetailObserved{sessionID: tableDetailSessionID, message: tableDetailClone}
	return stream.Send(&pb.ControlTableDetailMsg{
		Kind: &pb.ControlTableDetailMsg_Close{Close: &pb.TableDetailClose{}},
	})
}

func tableDetailStartFakeCP(t *testing.T) (*cp.Client, *tableDetailFakeCP) {
	t.Helper()
	tableDetailListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tableDetailServer := grpc.NewServer()
	tableDetailFake := &tableDetailFakeCP{observed: make(chan tableDetailObserved, 1)}
	pb.RegisterControlPlaneServer(tableDetailServer, tableDetailFake)
	go func() { _ = tableDetailServer.Serve(tableDetailListener) }()
	t.Cleanup(tableDetailServer.Stop)

	tableDetailClient, err := cp.New(tableDetailListener.Addr().String(), "table-detail-secret", "pm_tdetail_ds")
	if err != nil {
		t.Fatalf("cp.New: %v", err)
	}
	t.Cleanup(func() { _ = tableDetailClient.Close() })
	return tableDetailClient, tableDetailFake
}

func tableDetailRun(
	t *testing.T,
	tableDetailClient *cp.Client,
	tableDetailFake *tableDetailFakeCP,
	provider spi.Provider,
	tableDetailTargetDb spi.TargetDb,
	tableDetailSessionID, schema, table string,
) *pb.ProxyTableDetailMsg {
	t.Helper()
	tableDetailFake.tableDetailExpect(tableDetailSessionID)
	run.NewTableDetailRunner(tableDetailClient, tableDetailTargetDb, provider).Run(tableDetailSessionID, schema, table)
	select {
	case tableDetailObservation := <-tableDetailFake.observed:
		if tableDetailObservation.err != nil {
			t.Fatalf("table-detail stream: %v", tableDetailObservation.err)
		}
		if tableDetailObservation.sessionID != tableDetailSessionID {
			t.Fatalf("observed session id = %q, want %q", tableDetailObservation.sessionID, tableDetailSessionID)
		}
		return tableDetailObservation.message
	case <-time.After(tableDetailTestTimeout):
		t.Fatal("timed out waiting for table-detail result")
		return nil
	}
}

func tableDetailTargetDb(tableDetailDBTargetDb dbtest.TargetDb) spi.TargetDb {
	return spi.TargetDb{
		Host:     tableDetailDBTargetDb.Host,
		Port:     tableDetailDBTargetDb.Port,
		Db:       tableDetailDBTargetDb.DB,
		User:     tableDetailDBTargetDb.User,
		Password: tableDetailDBTargetDb.Password,
	}
}

func tableDetailExec(t *testing.T, tableDetailSQLDB *sql.DB, statement string) {
	t.Helper()
	if _, err := tableDetailSQLDB.ExecContext(context.Background(), statement); err != nil {
		t.Fatalf("execute fixture SQL: %v\n%s", err, statement)
	}
}

func tableDetailRequireResult(t *testing.T, tableDetailMessage *pb.ProxyTableDetailMsg) string {
	t.Helper()
	if tableDetailMessage.GetError() != nil {
		t.Fatalf("table-detail error: %s", tableDetailMessage.GetError().GetMessage())
	}
	if tableDetailMessage.GetResult() == nil {
		t.Fatalf("table-detail message has no result: %v", tableDetailMessage)
	}
	return tableDetailMessage.GetResult().GetJson()
}

func tableDetailRequireNull(t *testing.T, tableDetailMessage *pb.ProxyTableDetailMsg) {
	t.Helper()
	if tableDetailPayload := tableDetailRequireResult(t, tableDetailMessage); tableDetailPayload != "null" {
		t.Fatalf("table-detail payload = %q, want literal null", tableDetailPayload)
	}
}

func tableDetailDecode(t *testing.T, tableDetailPayload string) (spi.TableDetail, map[string]json.RawMessage) {
	t.Helper()
	for _, tableDetailForbidden := range []string{`"rows"`, `"data"`, `"preview"`} {
		if strings.Contains(tableDetailPayload, tableDetailForbidden) {
			t.Fatalf("metadata-only JSON contains forbidden key %s: %s", tableDetailForbidden, tableDetailPayload)
		}
	}
	var tableDetailTop map[string]json.RawMessage
	if err := json.Unmarshal([]byte(tableDetailPayload), &tableDetailTop); err != nil {
		t.Fatalf("decode top-level JSON: %v\n%s", err, tableDetailPayload)
	}
	tableDetailWantKeys := map[string]struct{}{
		"schema": {}, "table": {}, "columns": {}, "indexes": {},
		"foreignKeys": {}, "referencedBy": {}, "metadata": {},
	}
	tableDetailGotKeys := make(map[string]struct{}, len(tableDetailTop))
	for tableDetailKey := range tableDetailTop {
		tableDetailGotKeys[tableDetailKey] = struct{}{}
	}
	if !reflect.DeepEqual(tableDetailGotKeys, tableDetailWantKeys) {
		t.Fatalf("top-level keys = %v, want %v", tableDetailGotKeys, tableDetailWantKeys)
	}
	var tableDetailDecoded spi.TableDetail
	if err := json.Unmarshal([]byte(tableDetailPayload), &tableDetailDecoded); err != nil {
		t.Fatalf("decode TableDetail: %v", err)
	}
	if tableDetailDecoded.Columns == nil || tableDetailDecoded.Indexes == nil || tableDetailDecoded.ForeignKeys == nil || tableDetailDecoded.ReferencedBy == nil {
		t.Fatalf("list fields must decode from [] rather than null: %+v", tableDetailDecoded)
	}
	return tableDetailDecoded, tableDetailTop
}

func tableDetailAssertColumns(
	t *testing.T,
	tableDetailDecoded spi.TableDetail,
	tableDetailTop map[string]json.RawMessage,
	tableDetailExpected map[string]struct {
		dataType string
		ordinal  int
		nullable bool
	},
) {
	t.Helper()
	tableDetailByName := make(map[string]spi.TableDetailColumn, len(tableDetailDecoded.Columns))
	for _, tableDetailColumn := range tableDetailDecoded.Columns {
		tableDetailByName[tableDetailColumn.Name] = tableDetailColumn
	}
	for tableDetailName, tableDetailWant := range tableDetailExpected {
		tableDetailColumn, ok := tableDetailByName[tableDetailName]
		if !ok {
			t.Fatalf("missing seeded column %q in %+v", tableDetailName, tableDetailDecoded.Columns)
		}
		if tableDetailColumn.DataType != tableDetailWant.dataType || tableDetailColumn.Ordinal != tableDetailWant.ordinal || tableDetailColumn.Nullable != tableDetailWant.nullable {
			t.Fatalf("column %q = {dataType:%q ordinal:%d nullable:%v}, want %+v", tableDetailName, tableDetailColumn.DataType, tableDetailColumn.Ordinal, tableDetailColumn.Nullable, tableDetailWant)
		}
	}

	var tableDetailRawColumns []map[string]any
	if err := json.Unmarshal(tableDetailTop["columns"], &tableDetailRawColumns); err != nil {
		t.Fatalf("decode raw columns: %v", err)
	}
	for _, tableDetailRawColumn := range tableDetailRawColumns {
		tableDetailClassification, ok := tableDetailRawColumn["classification"]
		if !ok {
			t.Fatalf("column object is missing classification key: %v", tableDetailRawColumn)
		}
		if tableDetailClassification != nil {
			t.Fatalf("proxy-owned classification = %v, want null", tableDetailClassification)
		}
	}
}

func tableDetailAssertRelation(t *testing.T, tableDetailRelations []spi.TableRelation, tableDetailName, tableDetailSource, tableDetailTarget string) {
	t.Helper()
	for _, tableDetailRelation := range tableDetailRelations {
		if tableDetailRelation.Name == tableDetailName && tableDetailRelation.SourceTable == tableDetailSource && tableDetailRelation.TargetTable == tableDetailTarget {
			return
		}
	}
	t.Fatalf("missing relation %q (%s -> %s) in %+v", tableDetailName, tableDetailSource, tableDetailTarget, tableDetailRelations)
}

func tableDetailAssertSeededTablesExist(t *testing.T, tableDetailSQLDB *sql.DB, tableDetailQuery string, tableDetailArgs ...any) {
	t.Helper()
	var tableDetailCount int
	if err := tableDetailSQLDB.QueryRowContext(context.Background(), tableDetailQuery, tableDetailArgs...).Scan(&tableDetailCount); err != nil {
		t.Fatalf("verify seeded tables: %v", err)
	}
	if tableDetailCount != 3 {
		t.Fatalf("seeded table count = %d, want 3", tableDetailCount)
	}
}

func TestTableDetailMySQL(t *testing.T) {
	tableDetailDBTargetDb := dbtest.MySQL(t)
	tableDetailSQLDB := dbtest.OpenMySQL(t, tableDetailDBTargetDb.DB)
	tableDetailExec(t, tableDetailSQLDB, `
DROP TABLE IF EXISTS pm_tdetail_orders;
DROP TABLE IF EXISTS pm_tdetail_users;
DROP TABLE IF EXISTS pm_tdetail_plain;
CREATE TABLE pm_tdetail_users (
    id BIGINT NOT NULL AUTO_INCREMENT,
    email VARCHAR(255) NULL COMMENT 'user email',
    score DECIMAL(10,2) NULL,
    PRIMARY KEY (id),
    KEY pm_tdetail_users_email_idx (email DESC)
) ENGINE=InnoDB COMMENT='users table';
CREATE TABLE pm_tdetail_orders (
    id BIGINT NOT NULL AUTO_INCREMENT,
    user_id BIGINT NULL,
    note VARCHAR(100) NULL COMMENT 'order note',
    PRIMARY KEY (id),
    KEY pm_tdetail_orders_user_idx (user_id),
    CONSTRAINT pm_tdetail_orders_user_fk FOREIGN KEY (user_id)
        REFERENCES pm_tdetail_users (id) ON UPDATE CASCADE ON DELETE SET NULL
) ENGINE=InnoDB COMMENT='orders table';
CREATE TABLE pm_tdetail_plain (
    id BIGINT NOT NULL,
    note VARCHAR(64) NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB;`)

	tableDetailClient, tableDetailFake := tableDetailStartFakeCP(t)
	tableDetailTarget := tableDetailTargetDb(tableDetailDBTargetDb)

	tableDetailUsersPayload := tableDetailRequireResult(t, tableDetailRun(
		t, tableDetailClient, tableDetailFake, mustProvider(t, engine.MySQL), tableDetailTarget,
		"pm_tdetail_mysql_users", "public", "pm_tdetail_users",
	))
	tableDetailUsers, tableDetailUsersTop := tableDetailDecode(t, tableDetailUsersPayload)
	if tableDetailUsers.Schema != tableDetailDBTargetDb.DB || tableDetailUsers.Table != "pm_tdetail_users" {
		t.Fatalf("MySQL public selector resolved to %s.%s, want %s.pm_tdetail_users", tableDetailUsers.Schema, tableDetailUsers.Table, tableDetailDBTargetDb.DB)
	}
	tableDetailAssertColumns(t, tableDetailUsers, tableDetailUsersTop, map[string]struct {
		dataType string
		ordinal  int
		nullable bool
	}{
		"id":    {dataType: "bigint", ordinal: 1, nullable: false},
		"email": {dataType: "varchar", ordinal: 2, nullable: true},
		"score": {dataType: "decimal", ordinal: 3, nullable: true},
	})
	tableDetailAssertRelation(t, tableDetailUsers.ReferencedBy, "pm_tdetail_orders_user_fk", "pm_tdetail_orders", "pm_tdetail_users")

	tableDetailOrdersPayload := tableDetailRequireResult(t, tableDetailRun(
		t, tableDetailClient, tableDetailFake, mustProvider(t, engine.MySQL), tableDetailTarget,
		"pm_tdetail_mysql_orders", tableDetailDBTargetDb.DB, "pm_tdetail_orders",
	))
	tableDetailOrders, _ := tableDetailDecode(t, tableDetailOrdersPayload)
	tableDetailAssertRelation(t, tableDetailOrders.ForeignKeys, "pm_tdetail_orders_user_fk", "pm_tdetail_orders", "pm_tdetail_users")

	tableDetailPlainPayload := tableDetailRequireResult(t, tableDetailRun(
		t, tableDetailClient, tableDetailFake, mustProvider(t, engine.MySQL), tableDetailTarget,
		"pm_tdetail_mysql_plain", "public", "pm_tdetail_plain",
	))
	tableDetailPlain, _ := tableDetailDecode(t, tableDetailPlainPayload)
	if len(tableDetailPlain.ForeignKeys) != 0 || len(tableDetailPlain.ReferencedBy) != 0 {
		t.Fatalf("plain table relations = foreignKeys:%+v referencedBy:%+v, want [] and []", tableDetailPlain.ForeignKeys, tableDetailPlain.ReferencedBy)
	}

	tableDetailRequireNull(t, tableDetailRun(
		t, tableDetailClient, tableDetailFake, mustProvider(t, engine.MySQL), tableDetailTarget,
		"pm_tdetail_mysql_other_schema", "other", "pm_tdetail_users",
	))
	for tableDetailIndex, tableDetailSelector := range []struct{ schema, table string }{
		{schema: "public", table: "pm_tdetail_missing"},
		{schema: "public", table: `x"; DROP TABLE pm_tdetail_users; --`},
		{schema: "public", table: "pm_tdetail_users` WHERE 1=1 --"},
	} {
		tableDetailRequireNull(t, tableDetailRun(
			t, tableDetailClient, tableDetailFake, mustProvider(t, engine.MySQL), tableDetailTarget,
			fmt.Sprintf("pm_tdetail_mysql_hostile_%d", tableDetailIndex), tableDetailSelector.schema, tableDetailSelector.table,
		))
	}
	tableDetailAssertSeededTablesExist(t, tableDetailSQLDB,
		"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = ? AND table_name IN (?, ?, ?)",
		tableDetailDBTargetDb.DB, "pm_tdetail_users", "pm_tdetail_orders", "pm_tdetail_plain",
	)
}

func TestTableDetailPostgres(t *testing.T) {
	tableDetailDBTargetDb := dbtest.Postgres(t)
	tableDetailSQLDB := dbtest.OpenPostgres(t, tableDetailDBTargetDb.DB)
	tableDetailExec(t, tableDetailSQLDB, `
DROP SCHEMA IF EXISTS pm_tdetail_it CASCADE;
CREATE SCHEMA pm_tdetail_it;
CREATE TABLE pm_tdetail_it.pm_tdetail_users (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    email VARCHAR(255) NULL,
    score NUMERIC(10,2) NULL
);
COMMENT ON TABLE pm_tdetail_it.pm_tdetail_users IS 'users table';
COMMENT ON COLUMN pm_tdetail_it.pm_tdetail_users.email IS 'user email';
CREATE INDEX pm_tdetail_users_email_idx ON pm_tdetail_it.pm_tdetail_users (email DESC);
CREATE TABLE pm_tdetail_it.pm_tdetail_orders (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    user_id BIGINT NULL,
    note VARCHAR(100) NULL,
    CONSTRAINT pm_tdetail_orders_user_fk FOREIGN KEY (user_id)
        REFERENCES pm_tdetail_it.pm_tdetail_users (id) ON UPDATE CASCADE ON DELETE SET NULL
);
COMMENT ON COLUMN pm_tdetail_it.pm_tdetail_orders.note IS 'order note';
CREATE INDEX pm_tdetail_orders_user_idx ON pm_tdetail_it.pm_tdetail_orders (user_id);
CREATE TABLE pm_tdetail_it.pm_tdetail_plain (
    id BIGINT PRIMARY KEY,
    note VARCHAR(64) NULL
);`)

	tableDetailClient, tableDetailFake := tableDetailStartFakeCP(t)
	tableDetailTarget := tableDetailTargetDb(tableDetailDBTargetDb)

	tableDetailUsersPayload := tableDetailRequireResult(t, tableDetailRun(
		t, tableDetailClient, tableDetailFake, mustProvider(t, engine.Postgres), tableDetailTarget,
		"pm_tdetail_pg_users", "pm_tdetail_it", "pm_tdetail_users",
	))
	tableDetailUsers, tableDetailUsersTop := tableDetailDecode(t, tableDetailUsersPayload)
	if tableDetailUsers.Schema != "pm_tdetail_it" || tableDetailUsers.Table != "pm_tdetail_users" {
		t.Fatalf("Postgres selector resolved to %s.%s, want pm_tdetail_it.pm_tdetail_users", tableDetailUsers.Schema, tableDetailUsers.Table)
	}
	tableDetailAssertColumns(t, tableDetailUsers, tableDetailUsersTop, map[string]struct {
		dataType string
		ordinal  int
		nullable bool
	}{
		"id":    {dataType: "bigint", ordinal: 1, nullable: false},
		"email": {dataType: "character varying", ordinal: 2, nullable: true},
		"score": {dataType: "numeric", ordinal: 3, nullable: true},
	})
	tableDetailAssertRelation(t, tableDetailUsers.ReferencedBy, "pm_tdetail_orders_user_fk", "pm_tdetail_orders", "pm_tdetail_users")

	tableDetailOrdersPayload := tableDetailRequireResult(t, tableDetailRun(
		t, tableDetailClient, tableDetailFake, mustProvider(t, engine.Postgres), tableDetailTarget,
		"pm_tdetail_pg_orders", "pm_tdetail_it", "pm_tdetail_orders",
	))
	tableDetailOrders, _ := tableDetailDecode(t, tableDetailOrdersPayload)
	tableDetailAssertRelation(t, tableDetailOrders.ForeignKeys, "pm_tdetail_orders_user_fk", "pm_tdetail_orders", "pm_tdetail_users")

	tableDetailPlainPayload := tableDetailRequireResult(t, tableDetailRun(
		t, tableDetailClient, tableDetailFake, mustProvider(t, engine.Postgres), tableDetailTarget,
		"pm_tdetail_pg_plain", "pm_tdetail_it", "pm_tdetail_plain",
	))
	tableDetailPlain, _ := tableDetailDecode(t, tableDetailPlainPayload)
	if len(tableDetailPlain.ForeignKeys) != 0 || len(tableDetailPlain.ReferencedBy) != 0 {
		t.Fatalf("plain table relations = foreignKeys:%+v referencedBy:%+v, want [] and []", tableDetailPlain.ForeignKeys, tableDetailPlain.ReferencedBy)
	}

	for tableDetailIndex, tableDetailSelector := range []struct{ schema, table string }{
		{schema: "pm_tdetail_it", table: "pm_tdetail_missing"},
		{schema: `x"; DROP SCHEMA pm_tdetail_it CASCADE; --`, table: "pm_tdetail_users"},
		{schema: "pm_tdetail_it", table: `x"; DROP TABLE pm_tdetail_it.pm_tdetail_users; --`},
		{schema: "pm_tdetail_it`", table: "pm_tdetail_users`"},
	} {
		tableDetailRequireNull(t, tableDetailRun(
			t, tableDetailClient, tableDetailFake, mustProvider(t, engine.Postgres), tableDetailTarget,
			fmt.Sprintf("pm_tdetail_pg_hostile_%d", tableDetailIndex), tableDetailSelector.schema, tableDetailSelector.table,
		))
	}
	tableDetailAssertSeededTablesExist(t, tableDetailSQLDB,
		"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = $1 AND table_name = ANY($2)",
		"pm_tdetail_it", []string{"pm_tdetail_users", "pm_tdetail_orders", "pm_tdetail_plain"},
	)
}
