package editor_test

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

func TestServerCatalogIdentity(t *testing.T) {
	for _, test := range []struct {
		name string
		seed func(*testing.T) editorEngineFixture
	}{
		{"mysql", editorSeedMySQL}, {"postgres", editorSeedPostgres},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := test.seed(t)
			catalog := "def"
			if test.name == "postgres" {
				catalog = fixture.editorConfig.Db
			}
			fake, client := editorStartFakeCP(t, editorSessionID)
			open := editorOpenOn(fake, fixture)
			for _, command := range fake.identity.OnOpen {
				command.GetRefetch().Catalog = catalog
			}
			done := editorLaunchOpen(t, fake, client, fixture, open)
			editorSendQuery(fake, "SELECT 1", 20)
			editorExpectDecision(t, editorRecv(t, fake), pb.EnfAction_ALLOW, nil, "")
			if message := editorRecv(t, fake); message.GetResultRows() == nil {
				t.Fatalf("result = %v", message)
			}
			editorExpectDone(t, editorRecv(t, fake), -1)
			requests := fake.editorRecordedRequests()
			if len(requests) != 1 || requests[0].GetCurrentCatalog() != catalog {
				t.Fatalf("decision requests = %v", requests)
			}
			fragments := fake.editorRecordedFragments()
			if len(fragments) == 0 {
				t.Fatal("no on-open fragment was pushed")
			}
			columns := 0
			for _, fragment := range fragments {
				if fragment.GetCatalog() != catalog {
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
			editorSendClose(fake)
			done()
		})
	}
}
