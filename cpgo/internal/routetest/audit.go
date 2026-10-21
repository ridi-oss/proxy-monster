package routetest

import (
	"context"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/auditmon/canon"
	"github.com/ridi-oss/proxy-monster/auditmon/store"
	"github.com/ridi-oss/proxy-monster/auditmon/verify"
)

func AuditRows(t *testing.T, e *Env) []string {
	t.Helper()
	rows, err := e.St.Pool.Query(context.Background(), `SELECT kind || '|' || principal || '|' || action || '|' || resource || '|' || statement || '|' || coalesce(client_addr, '') || '|' || channel
		FROM audit_event ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		out = append(out, s)
	}
	return out
}

func VerifyChain(t *testing.T, e *Env) {
	t.Helper()
	ctx := context.Background()
	dsn := strings.Replace(strings.TrimPrefix(e.St.JDBCURL, "jdbc:"), "postgresql://", "postgresql://"+e.St.User+":"+e.St.Password+"@", 1)
	reader, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if finding, err := verify.VerifyFromGenesis(ctx, reader, canon.GenesisHash(), nil); err != nil || finding != nil {
		t.Fatalf("chain: %+v %v", finding, err)
	}
}
