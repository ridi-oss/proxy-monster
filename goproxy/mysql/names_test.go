package mysql_test

import (
	"context"
	"database/sql"
	"reflect"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/mysql"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const namesSchema = "PmNamesMixed"

func startNamesBroker(t *testing.T, targetConfig dbtest.TargetDb, seed *sql.DB, extraSchemas ...string) *brokerHarness {
	t.Helper()
	for _, schema := range append([]string{namesSchema}, extraSchemas...) {
		for _, statement := range []string{
			"CREATE DATABASE IF NOT EXISTS `" + schema + "`",
			"CREATE TABLE IF NOT EXISTS `" + schema + "`.`Users` (id INT PRIMARY KEY)",
			"DELETE FROM `" + schema + "`.`Users`",
			"INSERT INTO `" + schema + "`.`Users` VALUES (7)",
		} {
			if _, err := seed.Exec(statement); err != nil {
				t.Fatalf("seed %q: %v", statement, err)
			}
		}
	}
	fake, cpClient := startFakeCP(t)
	config := spi.TargetConfig{Host: targetConfig.Host, Port: targetConfig.Port, Db: targetConfig.DB, User: targetConfig.User, Password: targetConfig.Password}
	server := mysql.New(spi.Listen{}, config, cpClient, nil)
	if err := server.Listen(); err != nil {
		t.Fatalf("mysql.Listen: %v", err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve() }()
	t.Cleanup(func() {
		server.Shutdown()
		if err := <-serveDone; err != nil {
			t.Errorf("mysql.Serve: %v", err)
		}
	})
	return &brokerHarness{fake: fake, server: server, addr: server.Addr().String()}
}

func TestSessionNamespaceIsCanonical(t *testing.T) {
	for _, tc := range []struct {
		name  string
		start func(*testing.T) *brokerHarness
		uses  []string
		want  string
	}{
		{
			name: "lower_case_table_names=0",
			start: func(t *testing.T) *brokerHarness {
				return startNamesBroker(t, dbtest.MySQL(t), dbtest.OpenMySQL(t, ""), strings.ToLower(namesSchema))
			},
			uses: []string{namesSchema},
			want: namesSchema,
		},
		{
			name: "lower_case_table_names=1",
			start: func(t *testing.T) *brokerHarness {
				return startNamesBroker(t, dbtest.MySQLLowerCase1(t), dbtest.OpenMySQLLowerCase1(t, ""))
			},
			uses: []string{namesSchema, strings.ToUpper(namesSchema), strings.ToLower(namesSchema)},
			want: strings.ToLower(namesSchema),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.start(t)
			client := openRawClient(t, h.addr, validToken)
			for _, use := range tc.uses {
				client.query(t, "USE `"+use+"`")
				client.query(t, "SELECT id FROM Users")
				client.initDB(t, use)
				client.query(t, "SELECT id FROM Users")
			}
			var selects [][]string
			for _, req := range h.fake.requests() {
				if strings.HasPrefix(req.GetSql(), "SELECT") {
					selects = append(selects, req.GetSearchPath())
				}
			}
			if len(selects) != 2*len(tc.uses) {
				t.Fatalf("decided %d SELECTs, want %d", len(selects), 2*len(tc.uses))
			}
			for i, got := range selects {
				if !reflect.DeepEqual(got, []string{tc.want}) {
					t.Errorf("SELECT %d SearchPath = %v, want [%s]", i, got, tc.want)
				}
			}
		})
	}
	t.Run("lower_case_table_names=0 keeps differently-cased databases apart", func(t *testing.T) {
		h := startNamesBroker(t, dbtest.MySQL(t), dbtest.OpenMySQL(t, ""), strings.ToLower(namesSchema))
		client := openRawClient(t, h.addr, validToken)
		client.initDB(t, strings.ToLower(namesSchema))
		client.query(t, "SELECT id FROM Users")
		requests := h.fake.requests()
		if len(requests) != 1 || !reflect.DeepEqual(requests[0].GetSearchPath(), []string{strings.ToLower(namesSchema)}) {
			t.Fatalf("requests = %v, want one SELECT under [%s]", requests, strings.ToLower(namesSchema))
		}
	})
}

func TestBatchSplitsUnderLowerCaseTableNames1(t *testing.T) {
	h := startNamesBroker(t, dbtest.MySQLLowerCase1(t), dbtest.OpenMySQLLowerCase1(t, ""))
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	conn := h.openMultiStatementConn(t)
	statements := []string{
		"USE `" + namesSchema + "`",
		"SELECT id FROM Users",
		"SELECT id FROM `" + strings.ToUpper(namesSchema) + "`.users",
	}
	rows, err := conn.QueryContext(context.Background(), strings.Join(statements, ";\n"))
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	defer rows.Close()
	if sets := readResultSets(t, rows); !reflect.DeepEqual(sets[len(sets)-2:], [][]string{{"7"}, {"7"}}) {
		t.Fatalf("result sets = %v, want two sets of [7] last", sets)
	}
	requests := h.fake.requests()
	if got := mysqlDecidedSQL(h); !reflect.DeepEqual(got, statements) {
		t.Fatalf("decided = %q, want each statement once, in order", got)
	}
	for _, req := range requests[1:] {
		if !reflect.DeepEqual(req.GetSearchPath(), []string{strings.ToLower(namesSchema)}) {
			t.Errorf("%q SearchPath = %v, want [%s]", req.GetSql(), req.GetSearchPath(), strings.ToLower(namesSchema))
		}
	}
}
