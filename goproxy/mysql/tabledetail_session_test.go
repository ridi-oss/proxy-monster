package mysql

import (
	"context"
	"sync/atomic"
	"testing"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"
)

func TestTableDetailProbesItsConnectionSessionOnce(t *testing.T) {
	targetConfig := dbtest.MySQL(t)
	seed := dbtest.OpenMySQL(t, "")
	if _, err := seed.Exec("CREATE TABLE IF NOT EXISTS pm_detail_probe (id INT PRIMARY KEY, name VARCHAR(8), INDEX by_name (name))"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = seed.Exec("DROP TABLE IF EXISTS pm_detail_probe") })

	var probes atomic.Int32
	queries := Queries
	queries.TargetSettings = func(row []*string) (*enginepb.TargetSettings, error) {
		probes.Add(1)
		return Queries.TargetSettings(row)
	}
	pool, _, err := sqldb.OpenPool(OpenPool, spi.TargetConfig{Host: targetConfig.Host, Port: targetConfig.Port, Db: targetConfig.DB, User: targetConfig.User, Password: targetConfig.Password})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })

	for read := int32(1); read <= 2; read++ {
		detail, err := sqldb.ReadTableDetail(context.Background(), pool, queries, readCatalog, readMySQLTableDetail, &enginepb.ObjectRef{Catalog: "def", Schema: targetConfig.DB, Table: "pm_detail_probe"})
		if err != nil || detail == nil || len(detail.Columns) != 2 {
			t.Fatalf("ReadTableDetail = %+v, %v", detail, err)
		}
		if got := probes.Load(); got != read {
			t.Fatalf("after %d reads the session was probed %d times, want once per read", read, got)
		}
	}
}
