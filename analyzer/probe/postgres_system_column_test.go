package probe

import (
	"strings"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	sqlglot "github.com/ridi-oss/sqlglot-go"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
)

func TestPostgresCTIDSupportsDataGripTableQuery(t *testing.T) {
	catalog := []*pb.ColumnSpec{
		columnSpec("acme", "public", "users", "id", "BIGINT"),
		columnSpec("acme", "public", "users", "email", "VARCHAR"),
		columnSpec("acme", "public", "users", "phone", "VARCHAR"),
		columnSpec("acme", "public", "users", "name", "VARCHAR"),
		columnSpec("acme", "public", "users", "ssn", "VARCHAR"),
		columnSpec("acme", "public", "users", "region", "VARCHAR"),
		columnSpec("acme", "public", "users", "created_at", "TIMESTAMP"),
	}
	req := &pb.AnalyzeRequest{
		Sql:          "SELECT t.*, CTID FROM public.users t LIMIT 501",
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
		Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
		Catalog:      catalog,
	}
	result := analyzeProbe(t, req)
	if !result.Resolved {
		t.Fatalf("DataGrip query must resolve: stage=%v detail=%q", result.FailedStage, result.Detail)
	}
	if result.OutputColumns != 8 {
		t.Fatalf("output columns = %d, want 8: %+v", result.OutputColumns, result.Origins)
	}
	if result.RewrittenSQL == nil {
		t.Fatal("DataGrip query with t.* must carry a rewritten SQL statement")
	}

	rewritten, err := sqlglot.ParseOne(*result.RewrittenSQL, "postgres")
	if err != nil {
		t.Fatalf("parse rewritten SQL: %v; sql=%q", err, *result.RewrittenSQL)
	}
	ctidCount := 0
	for _, projection := range rewritten.Selects() {
		if projection.Kind() == exp.KindStar || (projection.Kind() == exp.KindColumn && projection.This().Kind() == exp.KindStar) {
			t.Fatalf("rewritten SQL still contains a star: %q", *result.RewrittenSQL)
		}
		if strings.EqualFold(projection.AliasOrName(), "ctid") {
			ctidCount++
		}
	}
	if ctidCount != 1 {
		t.Fatalf("rewritten SQL contains %d CTID outputs, want 1: %q", ctidCount, *result.RewrittenSQL)
	}

	expectedOrigins := []string{
		"acme.public.users.id",
		"acme.public.users.email",
		"acme.public.users.phone",
		"acme.public.users.name",
		"acme.public.users.ssn",
		"acme.public.users.region",
		"acme.public.users.created_at",
	}
	for i, expected := range expectedOrigins {
		origin := result.Origins[i]
		if len(origin.Origins) != 1 || origin.Origins[0] != expected {
			t.Fatalf("output %d origin = %+v, want %q", i, origin, expected)
		}
	}
	ctidOrigin := result.Origins[len(result.Origins)-1]
	if !strings.EqualFold(ctidOrigin.Column, "ctid") || len(ctidOrigin.Origins) != 0 {
		t.Fatalf("CTID origin = %+v, want an unclassified system-column output", ctidOrigin)
	}

	facts := analyzeProto(t, req)
	if !facts.GetResolved() {
		t.Fatalf("FFM statement facts must resolve: stage=%s detail=%q", stageString(facts.FailedStage), facts.GetDetail())
	}
	if got := facts.GetOutputColumns(); len(got) != 8 || !strings.EqualFold(got[7], "ctid") {
		t.Fatalf("statement-facts outputs = %v, want seven visible columns followed by CTID", got)
	}
	ordinals := map[string]int32{}
	tableGrant := false
	for _, grant := range facts.GetResultReads() {
		if table := grant.GetTable(); table != nil {
			if table.GetCatalog() == "acme" && table.GetSchema() == "public" && table.GetTable() == "users" {
				tableGrant = true
			}
			continue
		}
		column := grant.GetColumn()
		if column == nil {
			continue
		}
		positions := grant.GetOutputOrdinals()
		if len(positions) != 1 {
			t.Fatalf("column %s has output ordinals %v, want one", column.GetIdentity().GetColumn(), positions)
		}
		ordinals[column.GetIdentity().GetColumn()] = positions[0]
	}
	if !tableGrant {
		t.Fatalf("virtual CTID must emit a table grant even when visible columns cover the same source: %+v", result.Sources)
	}
	if len(ordinals) != len(expectedOrigins) {
		t.Fatalf("statement facts emitted %d column grants, want %d: %v", len(ordinals), len(expectedOrigins), ordinals)
	}
	for i, spec := range catalog {
		column := spec.GetIdentity().GetColumn()
		if ordinal, ok := ordinals[column]; !ok || ordinal != int32(i) {
			t.Fatalf("column %s output ordinal = %d, %t; want %d", column, ordinal, ok, i)
		}
	}
	if _, ok := ordinals["ctid"]; ok {
		t.Fatalf("virtual CTID must not emit a catalog-column grant: %v", ordinals)
	}
}

func TestPostgresSystemColumnsResolveExplicitly(t *testing.T) {
	catalog := []*pb.ColumnSpec{
		columnSpec("acme", "public", "users", "id", "BIGINT"),
		columnSpec("acme", "public", "users", "email", "VARCHAR"),
	}

	t.Run("all system columns", func(t *testing.T) {
		facts := analyzeProto(t, &pb.AnalyzeRequest{
			Sql:          "SELECT tableoid, xmin, cmin, xmax, cmax, ctid FROM public.users",
			EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
			Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
			Catalog:      catalog,
		})
		if !facts.GetResolved() {
			t.Fatalf("PostgreSQL system columns must resolve: stage=%s detail=%q", stageString(facts.FailedStage), facts.GetDetail())
		}
		if len(facts.GetResultReads()) != 1 {
			t.Fatalf("system columns emitted unexpected grants: %+v", facts.GetResultReads())
		}
		table := facts.GetResultReads()[0].GetTable()
		if table == nil || table.GetCatalog() != "acme" || table.GetSchema() != "public" || table.GetTable() != "users" {
			t.Fatalf("system columns must emit the physical table grant: %+v", facts.GetResultReads())
		}
	})
}

func TestPostgresSystemColumnsSupportDataGripIntrospection(t *testing.T) {
	cases := []struct {
		name    string
		sql     string
		catalog []*pb.ColumnSpec
		table   string
	}{
		{
			name: "namespaces",
			sql: `select N.oid::bigint as id,
       N.xmin as state_number,
       nspname as name,
       D.description,
       pg_catalog.pg_get_userbyid(N.nspowner) as "owner"
from pg_catalog.pg_namespace N
  left join pg_catalog.pg_description D on N.oid = D.objoid
order by case when nspname = pg_catalog.current_schema() then -1::bigint else N.oid::bigint end`,
			catalog: []*pb.ColumnSpec{
				columnSpec("acme", "pg_catalog", "pg_namespace", "oid", "OID"),
				columnSpec("acme", "pg_catalog", "pg_namespace", "nspname", "NAME"),
				columnSpec("acme", "pg_catalog", "pg_namespace", "nspowner", "OID"),
				columnSpec("acme", "pg_catalog", "pg_description", "objoid", "OID"),
				columnSpec("acme", "pg_catalog", "pg_description", "description", "TEXT"),
			},
			table: "pg_namespace",
		},
		{
			name: "tablespaces",
			sql: `select T.oid::bigint as id, T.spcname as name,
       T.xmin as state_number, pg_catalog.pg_get_userbyid(T.spcowner) as owner,
       pg_catalog.pg_tablespace_location(T.oid) /* null */ as location,
       T.spcoptions /* null */ as options,
       D.description as comment
from pg_catalog.pg_tablespace T
  left join pg_catalog.pg_shdescription D on D.objoid = T.oid
--  where pg_catalog.age(T.xmin) <= #TXAGE`,
			catalog: []*pb.ColumnSpec{
				columnSpec("acme", "pg_catalog", "pg_tablespace", "oid", "OID"),
				columnSpec("acme", "pg_catalog", "pg_tablespace", "spcname", "NAME"),
				columnSpec("acme", "pg_catalog", "pg_tablespace", "spcowner", "OID"),
				columnSpec("acme", "pg_catalog", "pg_tablespace", "spcoptions", "TEXT[]"),
				columnSpec("acme", "pg_catalog", "pg_shdescription", "objoid", "OID"),
				columnSpec("acme", "pg_catalog", "pg_shdescription", "description", "TEXT"),
			},
			table: "pg_tablespace",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := analyzeProto(t, &pb.AnalyzeRequest{
				Sql:          tc.sql,
				EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
				Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
				Catalog:      tc.catalog,
			})
			if !facts.GetResolved() {
				t.Fatalf("DataGrip introspection must resolve: stage=%s detail=%q", stageString(facts.FailedStage), facts.GetDetail())
			}
			tableGrant := false
			for _, grant := range facts.GetResultReads() {
				if column := grant.GetColumn(); column != nil && strings.EqualFold(column.GetIdentity().GetColumn(), "xmin") {
					t.Fatalf("virtual xmin emitted a catalog-column grant: %+v", grant)
				}
				if table := grant.GetTable(); table != nil && table.GetCatalog() == "acme" && table.GetSchema() == "pg_catalog" && table.GetTable() == tc.table {
					tableGrant = true
				}
			}
			if !tableGrant {
				t.Fatalf("virtual xmin emitted no %s table grant: %+v", tc.table, facts.GetResultReads())
			}
		})
	}
}

func TestPostgresCTIDResolutionBoundaries(t *testing.T) {
	baseCatalog := []*pb.ColumnSpec{
		columnSpec("acme", "public", "users", "id", "BIGINT"),
		columnSpec("acme", "public", "orders", "id", "BIGINT"),
	}
	analyze := func(t *testing.T, sql string, catalog []*pb.ColumnSpec) ProbeResult {
		t.Helper()
		return *analyzeProbe(t, &pb.AnalyzeRequest{
			Sql:          sql,
			EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
			Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
			Catalog:      catalog,
		})
	}

	t.Run("qualified physical table", func(t *testing.T) {
		result := analyze(t, "SELECT u.ctid FROM users u", baseCatalog)
		if !result.Resolved || len(result.Origins) != 1 || len(result.Origins[0].Origins) != 0 {
			t.Fatalf("qualified CTID must resolve without a catalog-column origin: %+v", result)
		}
		if len(result.Sources) != 1 || result.Sources[0].Catalog != "acme" || result.Sources[0].Schema != "public" || result.Sources[0].Table != "users" || result.Sources[0].Covered {
			t.Fatalf("CTID-only read must require the physical table grant: %+v", result.Sources)
		}
	})

	t.Run("composite virtual CTID emits only a table grant", func(t *testing.T) {
		catalog := append([]*pb.ColumnSpec{}, baseCatalog...)
		catalog = append(catalog, columnSpec("acme", "public", "users", "email", "VARCHAR"))
		cases := []string{
			"SELECT (u).ctid FROM users u",
			"SELECT 1 FROM users u WHERE (u).ctid = '(0,1)'",
			"UPDATE users u SET email = 'x' WHERE (u).ctid = '(0,1)'",
			"UPDATE users u SET email = 'x' RETURNING (u).ctid",
		}
		for _, sql := range cases {
			t.Run(sql, func(t *testing.T) {
				facts := analyzeProto(t, &pb.AnalyzeRequest{
					Sql:          sql,
					EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
					Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
					Catalog:      catalog,
				})
				if !facts.GetResolved() {
					t.Fatalf("composite virtual CTID must resolve: stage=%s detail=%q", stageString(facts.FailedStage), facts.GetDetail())
				}
				reads := facts.GetResultReads()
				if len(reads) != 1 {
					result := analyze(t, sql, catalog)
					t.Fatalf("composite virtual CTID emitted unexpected result reads: %+v; references=%v", reads, result.References)
				}
				table := reads[0].GetTable()
				if table == nil || table.GetCatalog() != "acme" || table.GetSchema() != "public" || table.GetTable() != "users" {
					t.Fatalf("composite virtual CTID grant = %+v, want acme.public.users table", reads[0])
				}
			})
		}
	})

	t.Run("mixed virtual CTID use requires table grant", func(t *testing.T) {
		cases := []string{
			"SELECT id, ctid FROM users",
			"SELECT id FROM users WHERE ctid = '(0,1)'",
			"SELECT id FROM users ORDER BY ctid",
			"SELECT (u).ctid FROM users u",
			"SELECT ((u)).ctid, u.id FROM users u",
		}
		for _, sql := range cases {
			t.Run(sql, func(t *testing.T) {
				result := analyze(t, sql, baseCatalog)
				if !result.Resolved || len(result.Sources) != 1 || result.Sources[0].Covered {
					t.Fatalf("virtual CTID must leave its physical source table-gated: %+v", result)
				}
				facts := analyzeProto(t, &pb.AnalyzeRequest{
					Sql:          sql,
					EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
					Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
					Catalog:      baseCatalog,
				})
				tableGrant := false
				for _, grant := range facts.GetResultReads() {
					if table := grant.GetTable(); table != nil && table.GetCatalog() == "acme" && table.GetSchema() == "public" && table.GetTable() == "users" {
						tableGrant = true
					}
				}
				if !tableGrant {
					t.Fatalf("virtual CTID use emitted no users table grant: %+v", facts.GetResultReads())
				}
			})
		}
	})

	t.Run("write CTID reads require table grant", func(t *testing.T) {
		catalog := append([]*pb.ColumnSpec{}, baseCatalog...)
		catalog = append(catalog, columnSpec("acme", "public", "users", "email", "VARCHAR"))
		cases := []string{
			"UPDATE users SET email = 'x' WHERE ctid = '(0,1)'",
			"UPDATE users u SET email = 'x' WHERE u.ctid = '(0,1)' RETURNING u.ctid",
			"UPDATE users SET email = 'x' WHERE id = 1 RETURNING ctid",
			"DELETE FROM users WHERE ctid = '(0,1)'",
			"DELETE FROM users WHERE ctid = '(0,1)' RETURNING ctid",
			"INSERT INTO users (id, email) VALUES (3, 'x') RETURNING ctid",
		}
		for _, sql := range cases {
			t.Run(sql, func(t *testing.T) {
				result := analyze(t, sql, catalog)
				if !result.Resolved || len(result.Sources) != 1 || result.Sources[0].Catalog != "acme" || result.Sources[0].Schema != "public" || result.Sources[0].Table != "users" || result.Sources[0].Covered {
					t.Fatalf("virtual CTID write read must leave its target table-gated: %+v", result)
				}
				facts := analyzeProto(t, &pb.AnalyzeRequest{
					Sql:          sql,
					EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
					Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
					Catalog:      catalog,
				})
				if !facts.GetResolved() {
					t.Fatalf("virtual CTID write facts must resolve: stage=%s detail=%q", stageString(facts.FailedStage), facts.GetDetail())
				}
				tableGrant := false
				for _, grant := range facts.GetResultReads() {
					if table := grant.GetTable(); table != nil && table.GetCatalog() == "acme" && table.GetSchema() == "public" && table.GetTable() == "users" {
						tableGrant = true
						if grant.GetMaskedDisposition() != pb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT {
							t.Fatalf("virtual CTID write table grant disposition = %s, want DENY_STATEMENT", grant.GetMaskedDisposition())
						}
					}
					if column := grant.GetColumn(); column != nil && strings.EqualFold(column.GetIdentity().GetColumn(), "ctid") {
						t.Fatalf("virtual CTID write emitted a catalog-column grant: %+v", grant)
					}
				}
				if !tableGrant {
					t.Fatalf("virtual CTID write emitted no users table grant: %+v", facts.GetResultReads())
				}
			})
		}
	})

	t.Run("qualified multi-source write CTID resolves exact source", func(t *testing.T) {
		catalog := append([]*pb.ColumnSpec{}, baseCatalog...)
		catalog = append(catalog, columnSpec("acme", "public", "users", "email", "VARCHAR"))
		cases := []struct {
			sql     string
			covered map[string]bool
		}{
			{
				sql:     "UPDATE users u SET email = 'x' FROM orders o WHERE u.ctid = '(0,1)' AND o.id = 1",
				covered: map[string]bool{"users": false, "orders": true},
			},
			{
				sql:     "UPDATE users u SET email = 'x' FROM orders o WHERE o.ctid = '(0,1)'",
				covered: map[string]bool{"orders": false},
			},
			{
				sql:     "UPDATE users AS u SET email = 'x' FROM orders AS users WHERE users.ctid = '(0,1)'",
				covered: map[string]bool{"orders": false},
			},
			{
				sql:     "MERGE INTO users AS u USING orders AS o ON u.id = o.id WHEN MATCHED AND u.ctid = '(0,1)' THEN UPDATE SET email = 'x'",
				covered: map[string]bool{"users": false, "orders": true},
			},
			{
				sql:     "MERGE INTO users AS u USING orders AS o ON u.id = o.id WHEN NOT MATCHED AND o.ctid = '(0,1)' THEN INSERT (id, email) VALUES (o.id, 'x')",
				covered: map[string]bool{"orders": false},
			},
		}
		for _, tc := range cases {
			t.Run(tc.sql, func(t *testing.T) {
				result := analyze(t, tc.sql, catalog)
				if !result.Resolved || len(result.Sources) != len(tc.covered) {
					t.Fatalf("qualified virtual CTID write must resolve exact sources: %+v", result)
				}
				for _, source := range result.Sources {
					covered, ok := tc.covered[source.Table]
					if !ok || source.Covered != covered {
						t.Fatalf("qualified virtual CTID write source = %+v, want %v", source, tc.covered)
					}
				}
			})
		}
	})

	t.Run("nested write CTID resolves from its own scope", func(t *testing.T) {
		catalog := append([]*pb.ColumnSpec{}, baseCatalog...)
		catalog = append(
			catalog,
			columnSpec("acme", "public", "users", "email", "VARCHAR"),
			columnSpec("acme", "public", "orders", "email", "VARCHAR"),
		)
		cases := []string{
			"UPDATE users u SET email = (SELECT o.email FROM orders o WHERE ctid = '(0,1)') WHERE u.id = 1",
			"INSERT INTO users (id, email) SELECT o.id, o.email FROM orders o WHERE ctid = '(0,1)'",
		}
		for _, sql := range cases {
			t.Run(sql, func(t *testing.T) {
				result := analyze(t, sql, catalog)
				if !result.Resolved || len(result.Sources) != 1 || result.Sources[0].Table != "orders" || result.Sources[0].Covered {
					t.Fatalf("nested virtual CTID must gate its inner physical source: %+v", result)
				}
				facts := analyzeProto(t, &pb.AnalyzeRequest{
					Sql:          sql,
					EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
					Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
					Catalog:      catalog,
				})
				ordersTableGrant := false
				for _, grant := range facts.GetResultReads() {
					if table := grant.GetTable(); table != nil {
						if table.GetTable() == "users" {
							t.Fatalf("nested virtual CTID gated the outer write target: %+v", grant)
						}
						if table.GetTable() == "orders" {
							ordersTableGrant = true
							if grant.GetMaskedDisposition() != pb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT {
								t.Fatalf("nested virtual CTID table disposition = %s, want DENY_STATEMENT", grant.GetMaskedDisposition())
							}
						}
					}
					if column := grant.GetColumn(); column != nil && strings.EqualFold(column.GetIdentity().GetColumn(), "ctid") {
						t.Fatalf("nested virtual CTID emitted a catalog-column grant: %+v", grant)
					}
				}
				if !ordersTableGrant {
					t.Fatalf("nested virtual CTID emitted no orders table grant: %+v", facts.GetResultReads())
				}
			})
		}
	})

	t.Run("derived CTID output remains ordinary in write", func(t *testing.T) {
		catalog := append([]*pb.ColumnSpec{}, baseCatalog...)
		catalog = append(catalog, columnSpec("acme", "public", "users", "email", "VARCHAR"))
		cases := []string{
			"UPDATE users u SET email = (SELECT d.ctid::text FROM (SELECT '(9,9)'::tid AS ctid) d) WHERE u.id = 1",
			"UPDATE users u SET email = (SELECT ctid::text FROM (SELECT '(9,9)'::tid AS ctid) d) WHERE u.id = 1",
			"UPDATE users u SET email = (SELECT u.ctid::text FROM (SELECT '(9,9)'::tid AS ctid) u) WHERE u.id = 1",
		}
		for _, sql := range cases {
			t.Run(sql, func(t *testing.T) {
				result := analyze(t, sql, catalog)
				if !result.Resolved {
					t.Fatalf("derived CTID output must remain an ordinary scalar: %+v", result)
				}
				facts := analyzeProto(t, &pb.AnalyzeRequest{
					Sql:          sql,
					EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
					Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
					Catalog:      catalog,
				})
				for _, grant := range facts.GetResultReads() {
					if table := grant.GetTable(); table != nil {
						t.Fatalf("derived CTID output emitted a physical table grant: %+v", table)
					}
					if column := grant.GetColumn(); column != nil && strings.EqualFold(column.GetIdentity().GetColumn(), "ctid") {
						t.Fatalf("derived CTID output emitted a CTID column grant: %+v", column)
					}
				}
			})
		}
	})

	t.Run("derived physical CTID keeps its table provenance", func(t *testing.T) {
		catalog := append([]*pb.ColumnSpec{}, baseCatalog...)
		catalog = append(catalog, columnSpec("acme", "public", "users", "email", "VARCHAR"))
		cases := []string{
			"SELECT d.ctid FROM (SELECT ctid, id FROM orders) d",
			"SELECT d.row_id FROM (SELECT ctid AS row_id, id FROM orders) d",
			"SELECT (d).ctid FROM (SELECT ctid, id FROM orders) d",
			"SELECT (d).row_id FROM (SELECT ctid AS row_id, id FROM orders) d",
			"WITH d AS (SELECT ctid, id FROM orders) UPDATE users u SET email = d.ctid::text FROM d WHERE d.id = u.id",
			"UPDATE users u SET email = d.row_id::text FROM (SELECT ctid AS row_id, id FROM orders) d WHERE d.id = u.id",
		}
		for _, sql := range cases {
			t.Run(sql, func(t *testing.T) {
				result := analyze(t, sql, catalog)
				if !result.Resolved {
					t.Fatalf("derived physical CTID must resolve: %+v", result)
				}
				ordersTableGrant := false
				for _, source := range result.Sources {
					if source.Table == "orders" && !source.Covered {
						ordersTableGrant = true
					}
				}
				if !ordersTableGrant {
					t.Fatalf("derived physical CTID lost its orders table grant: %+v", result.Sources)
				}
				facts := analyzeProto(t, &pb.AnalyzeRequest{
					Sql:          sql,
					EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
					Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
					Catalog:      catalog,
				})
				for _, grant := range facts.GetResultReads() {
					if column := grant.GetColumn(); column != nil {
						if strings.EqualFold(column.GetIdentity().GetColumn(), "ctid") {
							t.Fatalf("derived virtual CTID emitted a catalog-column grant: %+v", grant)
						}
						if strings.HasPrefix(sql, "SELECT ") {
							t.Fatalf("derived virtual CTID SELECT emitted an unrelated column grant: %+v", grant)
						}
					}
				}
			})
		}
	})

	t.Run("composite derived CTID expression keeps ordinary column provenance", func(t *testing.T) {
		sql := "SELECT (d).mixed FROM (SELECT ctid::text || id::text AS mixed FROM orders) d"
		facts := analyzeProto(t, &pb.AnalyzeRequest{
			Sql:          sql,
			EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
			Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
			Catalog:      baseCatalog,
		})
		if !facts.GetResolved() {
			t.Fatalf("composite mixed CTID expression must resolve: stage=%s detail=%q", stageString(facts.FailedStage), facts.GetDetail())
		}
		ordersTableGrant := false
		ordersIDGrant := false
		for _, grant := range facts.GetResultReads() {
			if table := grant.GetTable(); table != nil {
				if table.GetCatalog() != "acme" || table.GetSchema() != "public" || table.GetTable() != "orders" {
					t.Fatalf("composite mixed CTID expression emitted an unexpected table grant: %+v", grant)
				}
				ordersTableGrant = true
			}
			if column := grant.GetColumn(); column != nil {
				identity := column.GetIdentity()
				if identity.GetSchema() != "public" || identity.GetTable() != "orders" || identity.GetColumn() != "id" {
					t.Fatalf("composite mixed CTID expression emitted an unexpected column grant: %+v", grant)
				}
				ordersIDGrant = true
			}
		}
		if !ordersTableGrant || !ordersIDGrant {
			t.Fatalf("composite mixed CTID grants = %+v, want orders table and orders.id column", facts.GetResultReads())
		}
	})

	t.Run("dead derived CTID output emits no table grant", func(t *testing.T) {
		cases := []string{
			"SELECT d.id FROM (SELECT ctid, id FROM orders) d",
			"SELECT d.id FROM (SELECT ctid AS row_id, id FROM orders) d",
			"WITH d AS (SELECT ctid, id FROM orders) SELECT d.id FROM d",
		}
		for _, sql := range cases {
			t.Run(sql, func(t *testing.T) {
				facts := analyzeProto(t, &pb.AnalyzeRequest{
					Sql:          sql,
					EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
					Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
					Catalog:      baseCatalog,
				})
				if !facts.GetResolved() {
					t.Fatalf("dead derived CTID output must not affect resolution: stage=%s detail=%q", stageString(facts.FailedStage), facts.GetDetail())
				}
				for _, grant := range facts.GetResultReads() {
					if table := grant.GetTable(); table != nil && table.GetTable() == "orders" {
						t.Fatalf("dead derived CTID output emitted an orders table grant: %+v", grant)
					}
				}
			})
		}
	})

	t.Run("unqualified write CTID ignores nonmatching derived sources", func(t *testing.T) {
		catalog := append([]*pb.ColumnSpec{}, baseCatalog...)
		catalog = append(catalog, columnSpec("acme", "public", "users", "email", "VARCHAR"))
		cases := []string{
			"UPDATE users u SET email = 'x' FROM (SELECT 1) d WHERE ctid = '(0,1)'",
			"WITH d AS (SELECT id FROM orders) UPDATE users u SET email = 'x' WHERE ctid = '(0,1)' AND EXISTS (SELECT 1 FROM d WHERE d.id = u.id)",
		}
		for _, sql := range cases {
			t.Run(sql, func(t *testing.T) {
				result := analyze(t, sql, catalog)
				if !result.Resolved {
					t.Fatalf("unique target CTID must ignore nonmatching derived sources: %+v", result)
				}
				usersTableGrant := false
				for _, source := range result.Sources {
					if source.Table == "users" && !source.Covered {
						usersTableGrant = true
					}
				}
				if !usersTableGrant {
					t.Fatalf("unique target CTID emitted no users table grant: %+v", result.Sources)
				}
			})
		}
	})

	t.Run("write payload cannot read target CTID", func(t *testing.T) {
		catalog := append([]*pb.ColumnSpec{}, baseCatalog...)
		catalog = append(catalog, columnSpec("acme", "public", "users", "email", "VARCHAR"))
		cases := []string{
			"INSERT INTO users (id, email) SELECT 4, ctid::text FROM (SELECT 1) d",
			"MERGE INTO users AS u USING orders AS o ON u.id = o.id WHEN NOT MATCHED THEN INSERT (id, email) VALUES (o.id, u.ctid::text)",
		}
		for _, sql := range cases {
			t.Run(sql, func(t *testing.T) {
				result := analyze(t, sql, catalog)
				if result.Resolved {
					t.Fatalf("write payload must not resolve CTID against its target: %+v", result)
				}
			})
		}
	})

	t.Run("write target alias hides base name", func(t *testing.T) {
		catalog := append([]*pb.ColumnSpec{}, baseCatalog...)
		catalog = append(catalog, columnSpec("acme", "public", "users", "email", "VARCHAR"))
		result := analyze(t, "UPDATE users AS u SET email = 'x' WHERE users.ctid = '(0,1)'", catalog)
		if result.Resolved {
			t.Fatalf("aliased write target must reject its hidden base name: %+v", result)
		}
	})

	t.Run("ambiguous write CTID remains unresolved", func(t *testing.T) {
		catalog := append([]*pb.ColumnSpec{}, baseCatalog...)
		catalog = append(
			catalog,
			columnSpec("acme", "public", "users", "email", "VARCHAR"),
			columnSpec("acme", "public", "orders", "email", "VARCHAR"),
		)
		cases := []string{
			"UPDATE users u SET email = 'x' FROM orders o WHERE ctid = '(0,1)'",
			"UPDATE users u SET email = 'x' FROM (SELECT id AS ctid FROM orders) o WHERE ctid = 1",
			"UPDATE users u SET email = (SELECT o.email FROM orders o, orders p WHERE ctid = '(0,1)') WHERE u.id = 1",
			"INSERT INTO users (id, email) SELECT o.id, o.email FROM orders o, orders p WHERE ctid = '(0,1)'",
		}
		for _, sql := range cases {
			t.Run(sql, func(t *testing.T) {
				result := analyze(t, sql, catalog)
				if result.Resolved {
					t.Fatalf("ambiguous write CTID must fail closed: %+v", result)
				}
			})
		}
	})

	t.Run("output alias named CTID remains ordinary", func(t *testing.T) {
		cases := []string{
			"SELECT id AS ctid FROM users ORDER BY ctid",
			"SELECT DISTINCT ON (ctid) id AS ctid FROM users",
			"SELECT id AS ctid FROM users ORDER BY 1",
			"SELECT u.id AS ctid, o.id FROM users u JOIN orders o ON u.id = o.id ORDER BY 1",
			"SELECT id AS ctid FROM users UNION ALL SELECT id FROM users ORDER BY ctid",
		}
		for _, sql := range cases {
			t.Run(sql, func(t *testing.T) {
				result := analyze(t, sql, baseCatalog)
				if !result.Resolved {
					t.Fatalf("ordinary CTID output alias must resolve: %+v", result)
				}
				for _, source := range result.Sources {
					if !source.Covered {
						t.Fatalf("ordinary CTID output alias left a source table-gated: %+v", result.Sources)
					}
				}
				facts := analyzeProto(t, &pb.AnalyzeRequest{
					Sql:          sql,
					EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
					Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
					Catalog:      baseCatalog,
				})
				for _, grant := range facts.GetResultReads() {
					if table := grant.GetTable(); table != nil {
						t.Fatalf("ordinary CTID output alias emitted a table grant: %+v", table)
					}
				}
			})
		}
	})

	t.Run("unqualified join is ambiguous", func(t *testing.T) {
		result := analyze(t, "SELECT ctid FROM users u CROSS JOIN orders o", baseCatalog)
		if result.Resolved {
			t.Fatalf("ambiguous CTID must fail closed: %+v", result)
		}
	})

	t.Run("derived table has no implicit CTID", func(t *testing.T) {
		result := analyze(t, "SELECT ctid FROM (SELECT id FROM users) u", baseCatalog)
		if result.Resolved {
			t.Fatalf("derived-table CTID must fail closed: %+v", result)
		}
	})

	t.Run("unknown column remains unresolved", func(t *testing.T) {
		result := analyze(t, "SELECT bogus FROM users", baseCatalog)
		if result.Resolved {
			t.Fatalf("unknown column must fail closed: %+v", result)
		}
	})

	t.Run("real CTID column remains catalog-backed", func(t *testing.T) {
		catalog := append([]*pb.ColumnSpec{}, baseCatalog...)
		catalog = append(catalog, columnSpec("acme", "public", "users", "ctid", "TEXT"))
		result := analyze(t, "SELECT ctid FROM users", catalog)
		if !result.Resolved || len(result.Origins) != 1 || len(result.Origins[0].Origins) != 1 || result.Origins[0].Origins[0] != "acme.public.users.ctid" {
			t.Fatalf("real CTID column must retain ordinary lineage: %+v", result)
		}
		if len(result.Sources) != 1 || !result.Sources[0].Covered {
			t.Fatalf("real CTID column must cover its source through the column grant: %+v", result.Sources)
		}
	})
}
