package run_test

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"google.golang.org/protobuf/proto"
)

func TestRunnerCatalogIdentity(t *testing.T) {
	for _, test := range []struct {
		name string
		seed func(*testing.T) runEngineFixture
	}{
		{"mysql", runSeedMySQL}, {"postgres", runSeedPostgres},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := test.seed(t)
			catalog := "def"
			if test.name == "postgres" {
				catalog = fixture.runTarget.Db
			}
			fake, client := runStartFakeCP(t, runSessionID)
			open := runOpen(fixture)
			for _, command := range open.OnOpen {
				command.Catalog = proto.String(catalog)
			}
			done := runLaunchOpen(t, fake, client, fixture, open)
			runSendQuery(fake, "SELECT 1", 20)
			runExpectDecision(t, runRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
			if message := runRecv(t, fake); message.GetResultRows() == nil {
				t.Fatalf("result = %v", message)
			}
			runExpectDone(t, runRecv(t, fake), -1)
			requests := fake.runRecordedRequests()
			if len(requests) != 1 || requests[0].CurrentCatalog == nil || requests[0].GetCurrentCatalog() != catalog {
				t.Fatalf("decision requests = %v", requests)
			}
			fragments := fake.runRecordedFragments()
			if len(fragments) == 0 {
				t.Fatal("no on-open fragment was pushed")
			}
			columns := 0
			for _, fragment := range fragments {
				if fragment.Catalog == nil || fragment.GetCatalog() != catalog {
					t.Fatalf("fragment = %v", fragment)
				}
				for _, column := range fragment.Columns {
					columns++
					if column.GetCatalog() != catalog {
						t.Fatalf("column = %v", column)
					}
				}
			}
			if columns == 0 {
				t.Fatal("on-open fragments contained no columns")
			}
			runSendClose(fake)
			done()
		})
	}
}
