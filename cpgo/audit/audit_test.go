package audit

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/auditmon/canon"
	"github.com/ridi-oss/proxy-monster/auditmon/store"
	"github.com/ridi-oss/proxy-monster/auditmon/verify"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/dbtest"
)

func TestGoWrittenRowsVerifyFromGenesis(t *testing.T) {
	st := dbtest.Open(t)
	ctx := context.Background()
	write := func(f func(pgx.Tx) error) {
		t.Helper()
		if err := pgx.BeginFunc(ctx, st.Pool, f); err != nil {
			t.Fatal(err)
		}
	}
	write(func(tx pgx.Tx) error {
		return Admin(ctx, tx, Actor{Principal: "admin@example.com", ClientAddr: "203.0.113.9", Channel: "console"},
			"admin.policies", Entity("Role", "analyst"), "create role 'analyst'")
	})
	addr := "10.0.0.1"
	rows := int64(3)
	write(func(tx pgx.Tx) error {
		_, err := Insert(ctx, tx, canon.AuditEvent{
			Kind: "decision", Principal: "alice@example.com", Roles: []string{"b", "a"}, Datasource: "acme",
			ClientAddr: &addr, Statement: "select 1", Decision: "MASK", EffectiveNamespace: []string{"app", "public"},
			MaskedColumns: []string{"users.email"}, PIITouched: []string{"users.email"}, LatencyMs: 12,
			ContextTags: []string{"trusted-network"}, RowsReturned: &rows,
		})
		return err
	})
	// A rolled-back change leaves no row and does not move the head.
	_ = pgx.BeginFunc(ctx, st.Pool, func(tx pgx.Tx) error {
		if err := Admin(ctx, tx, Actor{Principal: "admin@example.com", Channel: "console"}, "admin.policies", Entity("Role", "x"), "never"); err != nil {
			return err
		}
		return context.Canceled
	})
	write(func(tx pgx.Tx) error {
		return Admin(ctx, tx, Actor{Principal: "admin@example.com", Channel: "mcp"}, "admin.identity", Entity("Role", "analyst"), "assign")
	})

	dsn := strings.Replace(strings.TrimPrefix(st.JDBCURL, "jdbc:"), "postgresql://", "postgresql://"+st.User+":"+st.Password+"@", 1)
	reader, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	finding, err := verify.VerifyFromGenesis(ctx, reader, canon.GenesisHash(), nil)
	if err != nil || finding != nil {
		t.Fatalf("finding %+v err %v", finding, err)
	}
	var n int
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_event`).Scan(&n)
	if n != 3 {
		t.Fatalf("%d rows, want 3 (the rolled-back one is gone)", n)
	}

	// Tampering with a Go-written row is caught, so the check above is not vacuous.
	if _, err := st.Pool.Exec(ctx, `UPDATE audit_event SET statement = 'edited' WHERE id = (SELECT min(id) FROM audit_event)`); err != nil {
		t.Fatal(err)
	}
	if finding, err := verify.VerifyFromGenesis(ctx, reader, canon.GenesisHash(), nil); err != nil || finding == nil {
		t.Fatalf("an edited row must fail verification: %+v %v", finding, err)
	}
}
