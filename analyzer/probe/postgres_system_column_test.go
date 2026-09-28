package probe

import (
	"strings"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	sqlglot "github.com/ridi-oss/sqlglot-go"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
)

func TestPostgresCTIDSupportsDataGripTableQuery(t *testing.T) {
	catalog := []*pb.Column{
		pbColumn("public", "users", "id", "BIGINT"),
		pbColumn("public", "users", "email", "VARCHAR"),
		pbColumn("public", "users", "phone", "VARCHAR"),
		pbColumn("public", "users", "name", "VARCHAR"),
		pbColumn("public", "users", "ssn", "VARCHAR"),
		pbColumn("public", "users", "region", "VARCHAR"),
		pbColumn("public", "users", "created_at", "TIMESTAMP"),
	}
	req := &pb.AnalyzeRequest{
		Sql:          "SELECT t.*, CTID FROM public.users t LIMIT 501",
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
		Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
		Catalog:      snapshot(catalog),
	}
	facts := analyzeProto(t, req)
	if !facts.GetResolved() {
		t.Fatalf("DataGrip query must resolve: stage=%s detail=%q", stageString(facts.FailedStage), facts.GetDetail())
	}
	// t.* expands the seven visible columns only; the explicit CTID rides beside them as its own output.
	if got := facts.GetOutputColumns(); len(got) != 8 || !strings.EqualFold(got[7], "ctid") {
		t.Fatalf("outputs = %v, want seven visible columns then ctid", got)
	}
	rewritten, err := sqlglot.ParseOne(facts.GetRewrittenSql(), "postgres")
	if err != nil {
		t.Fatalf("parse rewritten SQL: %v; sql=%q", err, facts.GetRewrittenSql())
	}
	ctidCount := 0
	for _, projection := range rewritten.Selects() {
		if projection.Kind() == exp.KindStar || (projection.Kind() == exp.KindColumn && projection.This().Kind() == exp.KindStar) {
			t.Fatalf("rewritten SQL still contains a star: %q", facts.GetRewrittenSql())
		}
		if strings.EqualFold(projection.AliasOrName(), "ctid") {
			ctidCount++
		}
	}
	if ctidCount != 1 {
		t.Fatalf("rewritten SQL contains %d CTID outputs, want 1: %q", ctidCount, facts.GetRewrittenSql())
	}
	// Every output — ctid included — is an ordinary Column grant with its ordinal; the covered scan
	// needs no Table grant.
	ordinals := map[string]int32{}
	for _, grant := range facts.GetResultReads() {
		if table := grant.GetTable(); table != nil {
			t.Fatalf("covered scan emitted a table grant: %+v", table)
		}
		column := grant.GetColumn()
		if column == nil {
			continue
		}
		positions := grant.GetOutputOrdinals()
		if len(positions) != 1 {
			t.Fatalf("column %s has output ordinals %v, want one", column.GetColumn(), positions)
		}
		ordinals[column.GetColumn()] = positions[0]
	}
	for i, spec := range catalog {
		column := spec.GetColumn()
		if ordinal, ok := ordinals[column]; !ok || ordinal != int32(i) {
			t.Fatalf("column %s output ordinal = %d, %t; want %d", column, ordinal, ok, i)
		}
	}
	if ordinal, ok := ordinals["ctid"]; !ok || ordinal != 7 {
		t.Fatalf("ctid must carry an ordinary Column grant at ordinal 7: %v", ordinals)
	}
}

func TestPostgresSystemColumnsResolveExplicitly(t *testing.T) {
	catalog := []*pb.Column{
		pbColumn("public", "users", "id", "BIGINT"),
		pbColumn("public", "users", "email", "VARCHAR"),
	}
	facts := analyzeProto(t, &pb.AnalyzeRequest{
		Sql:          "SELECT tableoid, xmin, cmin, xmax, cmax, ctid FROM public.users",
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
		Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
		Catalog:      snapshot(catalog),
	})
	if !facts.GetResolved() {
		t.Fatalf("PostgreSQL system columns must resolve: stage=%s detail=%q", stageString(facts.FailedStage), facts.GetDetail())
	}
	// Each system column is an ordinary implicit-catalog Column grant; the scan is covered, no Table grant.
	want := map[string]bool{"tableoid": true, "xmin": true, "cmin": true, "xmax": true, "cmax": true, "ctid": true}
	got := map[string]bool{}
	for _, grant := range facts.GetResultReads() {
		if table := grant.GetTable(); table != nil {
			t.Fatalf("covered system-column scan emitted a table grant: %+v", table)
		}
		if column := grant.GetColumn(); column != nil {
			got[column.GetColumn()] = true
		}
	}
	for name := range want {
		if !got[name] {
			t.Fatalf("system column %s emitted no Column grant: %v", name, got)
		}
	}
}

func TestPostgresSystemColumnsSupportDataGripIntrospection(t *testing.T) {
	cases := []struct {
		name    string
		sql     string
		catalog []*pb.Column
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
			catalog: []*pb.Column{
				pbColumn("pg_catalog", "pg_namespace", "oid", "OID"),
				pbColumn("pg_catalog", "pg_namespace", "nspname", "NAME"),
				pbColumn("pg_catalog", "pg_namespace", "nspowner", "OID"),
				pbColumn("pg_catalog", "pg_description", "objoid", "OID"),
				pbColumn("pg_catalog", "pg_description", "description", "TEXT"),
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
			catalog: []*pb.Column{
				pbColumn("pg_catalog", "pg_tablespace", "oid", "OID"),
				pbColumn("pg_catalog", "pg_tablespace", "spcname", "NAME"),
				pbColumn("pg_catalog", "pg_tablespace", "spcowner", "OID"),
				pbColumn("pg_catalog", "pg_tablespace", "spcoptions", "TEXT[]"),
				pbColumn("pg_catalog", "pg_shdescription", "objoid", "OID"),
				pbColumn("pg_catalog", "pg_shdescription", "description", "TEXT"),
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
				Catalog:      snapshotWith(tc.catalog, testFunctionCatalog(false, nil)),
			})
			if !facts.GetResolved() {
				t.Fatalf("DataGrip introspection must resolve: stage=%s detail=%q", stageString(facts.FailedStage), facts.GetDetail())
			}
			xminGrant := false
			for _, grant := range facts.GetResultReads() {
				if table := grant.GetTable(); table != nil {
					t.Fatalf("covered introspection scan emitted a table grant: %+v", table)
				}
				if column := grant.GetColumn(); column != nil && strings.EqualFold(column.GetColumn(), "xmin") &&
					column.GetTable() == tc.table {
					xminGrant = true
				}
			}
			if !xminGrant {
				t.Fatalf("implicit xmin emitted no %s Column grant: %+v", tc.table, facts.GetResultReads())
			}
		})
	}
}

func TestPostgresDataGripRoutinesNaturalJoin(t *testing.T) {
	query := `with languages as (
    select oid as lang_oid, lanname as lang
    from pg_catalog.pg_language
),
routines as (
    select proname as r_name,
           prolang as lang_oid,
           oid as r_id,
           xmin as r_state_number,
           proargnames as arg_names,
           proargmodes as arg_modes,
           proargtypes::int[] as in_arg_types,
           proallargtypes::int[] as all_arg_types,
           pg_catalog.pg_get_expr(proargdefaults, 0) as arg_defaults,
           provariadic as arg_variadic_id,
           prorettype as ret_type_id,
           proretset as ret_set,
           prokind as kind,
           provolatile as volatile_kind,
           proisstrict as is_strict,
           prosecdef as is_security_definer,
           proconfig as configuration_parameters,
           procost as cost,
           pg_catalog.pg_get_userbyid(proowner) as "owner",
           prorows as rows,
           proleakproof as is_leakproof,
           proparallel as concurrency_kind
    from pg_catalog.pg_proc
    where pronamespace = $1::oid
      and not (prokind = 'a')
      and pg_catalog.age(xmin) <= coalesce(
          nullif(greatest(pg_catalog.age($2::varchar::xid), -1), -1),
          2147483647
      )
)
select *
from routines natural join languages`
	catalog := []*pb.Column{
		pbColumn("pg_catalog", "pg_language", "oid", "OID"),
		pbColumn("pg_catalog", "pg_language", "lanname", "NAME"),
	}
	for name, kind := range map[string]string{
		"proname": "NAME", "prolang": "OID", "oid": "OID", "pronamespace": "OID",
		"proargnames": "TEXT[]", "proargmodes": "CHAR[]", "proargtypes": "OIDVECTOR",
		"proallargtypes": "OID[]", "proargdefaults": "PG_NODE_TREE", "provariadic": "OID",
		"prorettype": "OID", "proretset": "BOOLEAN", "prokind": "CHAR", "provolatile": "CHAR",
		"proisstrict": "BOOLEAN", "prosecdef": "BOOLEAN", "proconfig": "TEXT[]", "procost": "REAL",
		"proowner": "OID", "prorows": "REAL", "proleakproof": "BOOLEAN", "proparallel": "CHAR",
	} {
		catalog = append(catalog, pbColumn("pg_catalog", "pg_proc", name, kind))
	}
	req := &pb.AnalyzeRequest{
		Sql:          query,
		EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
		Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"pg_catalog", "public"}},
		Catalog:      snapshotWith(catalog, testFunctionCatalog(false, nil)),
	}
	result := analyzeProbe(t, req)
	if !result.Resolved {
		t.Fatalf("DataGrip routines query must resolve: stage=%v detail=%q", result.FailedStage, result.Detail)
	}
	if result.OutputColumns != 23 {
		t.Fatalf("output columns = %d, want 23: %+v", result.OutputColumns, result.Origins)
	}
	langOIDCount := 0
	for _, origin := range result.Origins {
		if origin.Column != "lang_oid" {
			continue
		}
		langOIDCount++
		want := []string{"acme.pg_catalog.pg_language.oid", "acme.pg_catalog.pg_proc.prolang"}
		if len(origin.Origins) != len(want) || origin.Origins[0] != want[0] || origin.Origins[1] != want[1] {
			t.Fatalf("lang_oid origins = %v, want %v", origin.Origins, want)
		}
	}
	if langOIDCount != 1 {
		t.Fatalf("lang_oid outputs = %d, want 1: %+v", langOIDCount, result.Origins)
	}
	for _, column := range []string{"acme.pg_catalog.pg_language.oid", "acme.pg_catalog.pg_proc.prolang"} {
		found := false
		for _, reference := range result.References[JOIN] {
			if reference == column {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("JOIN references = %v, missing %s", result.References[JOIN], column)
		}
	}
	if result.RewrittenSQL == nil {
		t.Fatal("DataGrip routines star must carry an executable rewrite")
	}
	rewritten, err := sqlglot.ParseOne(*result.RewrittenSQL, "postgres")
	if err != nil {
		t.Fatalf("parse rewritten SQL: %v; sql=%q", err, *result.RewrittenSQL)
	}
	selects := rewritten.Selects()
	if len(selects) != 23 {
		t.Fatalf("rewritten outputs = %d, want 23: %q", len(selects), *result.RewrittenSQL)
	}
	if selects[0].AliasOrName() != "lang_oid" || selects[1].AliasOrName() != "r_name" || selects[22].AliasOrName() != "lang" {
		t.Fatalf("rewritten output order is not PostgreSQL NATURAL JOIN order: %q", *result.RewrittenSQL)
	}
	for _, projection := range selects {
		if projection.Kind() == exp.KindStar || projection.IsStar() {
			t.Fatalf("rewritten SQL still contains a star: %q", *result.RewrittenSQL)
		}
	}
}

func TestPostgresBuiltinFunctionRowSupportDataGripExtensions(t *testing.T) {
	query := `select E.oid        as id,
       E.xmin       as state_number,
       extname      as name,
       extversion   as version,
       extnamespace as schema_id,
       nspname      as schema_name,
       array(select unnest
             from unnest(available_versions)
             where unnest > extversion) as available_updates
from pg_catalog.pg_extension E
       join pg_namespace N on E.extnamespace = N.oid
       left join (select name, array_agg(version) as available_versions
                  from pg_available_extension_versions()
                  group by name) V on E.extname = V.name`
	facts := analyzeProto(t, &pb.AnalyzeRequest{
		Sql: query,
		EngineConfig: &pb.EngineConfig{
			Engine:  pb.Engine_POSTGRES,
			Session: &pb.SessionObservation{PostgresFunctionShadowingObserved: true},
		},
		Namespace: &pb.Namespace{Catalog: "acme", SearchPath: []string{"pg_catalog", "public"}},
		Catalog: snapshotWith([]*pb.Column{
			pbColumn("pg_catalog", "pg_extension", "oid", "OID"),
			pbColumn("pg_catalog", "pg_extension", "extname", "NAME"),
			pbColumn("pg_catalog", "pg_extension", "extversion", "TEXT"),
			pbColumn("pg_catalog", "pg_extension", "extnamespace", "OID"),
			pbColumn("pg_catalog", "pg_namespace", "oid", "OID"),
			pbColumn("pg_catalog", "pg_namespace", "nspname", "NAME"),
		}, testFunctionCatalog(false, nil)),
	})
	if !facts.GetResolved() {
		t.Fatalf("DataGrip extension query must resolve: stage=%s detail=%q", stageString(facts.FailedStage), facts.GetDetail())
	}
	for _, grant := range facts.GetResultReads() {
		if function := grant.GetFunction(); function != nil {
			t.Errorf("resolved builtin emitted a Function grant: %q", function.GetName())
		}
	}
}

func TestPostgresBuiltinFunctionRowRespectResolution(t *testing.T) {
	analyze := func(sql string, searchPath []string, observed bool, shadowed ...string) *pb.StatementFacts {
		t.Helper()
		return analyzeProto(t, &pb.AnalyzeRequest{
			Sql: sql,
			EngineConfig: &pb.EngineConfig{
				Engine:  pb.Engine_POSTGRES,
				Session: &pb.SessionObservation{PostgresFunctionShadowingObserved: observed, PostgresShadowedFunctions: shadowed},
			},
			Namespace: &pb.Namespace{Catalog: "acme", SearchPath: searchPath},
			Catalog: snapshotWith([]*pb.Column{
				pbColumn("public", "users", "id", "BIGINT"),
				pbColumn("public", "users", "ssn", "VARCHAR"),
			}, testFunctionCatalog(false, nil)),
		})
	}
	// Resolution is report-only: the call resolves to its pg_catalog identity via the engine catalog
	// and relays VERBATIM (no pin rewrite) — the target resolves under the same observed search_path.
	for _, tc := range []struct {
		sql        string
		searchPath []string
		observed   bool
	}{
		{"SELECT name FROM pg_available_extension_versions()", []string{"pg_catalog", "public"}, false},
		{"SELECT name FROM pg_available_extension_versions()", []string{"pg_temp_3", "pg_catalog", "public"}, false},
		{"SELECT name FROM LATERAL pg_available_extension_versions() AS e(name)", []string{"pg_catalog", "public"}, false},
		{"SELECT name FROM pg_catalog.pg_available_extension_versions()", []string{"public", "pg_catalog"}, false},
		{"SELECT name FROM LATERAL pg_catalog.pg_available_extension_versions() AS e(name)", []string{"public", "pg_catalog"}, false},
		{"SELECT unnest FROM unnest(ARRAY[1, 2])", []string{"pg_catalog", "public"}, true},
		{"SELECT value FROM LATERAL unnest(ARRAY[1, 2]) AS u(value)", []string{"pg_catalog", "public"}, true},
		{"SELECT unnest FROM unnest(ARRAY[1, 2])", []string{"pg_temp_3", "pg_catalog", "public"}, true},
		{"SELECT value FROM unnest(ARRAY[1, 2]) AS u(value)", []string{"pg_catalog", "public"}, true},
		{"SELECT unnest FROM pg_catalog.unnest(ARRAY[1, 2])", []string{"public", "pg_catalog"}, false},
		{"SELECT a, b FROM pg_catalog.unnest(ARRAY[1], ARRAY[2]) AS u(a, b)", []string{"public", "pg_catalog"}, false},
	} {
		facts := analyze(tc.sql, tc.searchPath, tc.observed)
		if !facts.GetResolved() {
			t.Errorf("catalog-resolved implicit function must resolve: %q path=%v stage=%s detail=%q", tc.sql, tc.searchPath, stageString(facts.FailedStage), facts.GetDetail())
			continue
		}
		if facts.RewrittenSql != nil {
			t.Errorf("resolution is report-only, never a rewrite: %q -> %q", tc.sql, facts.GetRewrittenSql())
		}
		for _, grant := range facts.GetResultReads() {
			if function := grant.GetFunction(); function != nil {
				t.Errorf("resolved pg_catalog function emitted a Function grant: %q -> %q", tc.sql, function.GetName())
			}
		}
	}
	// A qualifier the engine catalog does not know — a nonexistent schema, or the case-sensitive
	// DISTINCT user schema "PG_CATALOG" — is an unresolvable call: the statement fails closed.
	for _, sql := range []string{
		"SELECT value FROM attacker.unnest(ARRAY[1, 2]) AS u(value)",
		"SELECT name FROM attacker.pg_available_extension_versions() AS e(name)",
		"SELECT name FROM LATERAL attacker.pg_available_extension_versions() AS e(name)",
		`SELECT name FROM "PG_CATALOG".pg_available_extension_versions() AS e(name)`,
		`SELECT name FROM LATERAL "PG_CATALOG".pg_available_extension_versions() AS e(name)`,
	} {
		facts := analyze(sql, []string{"public", "pg_catalog"}, false)
		if facts.GetResolved() || facts.RewrittenSql != nil || stageString(facts.FailedStage) != "VALIDATE" {
			t.Errorf("unknown function qualifier must fail closed: %q -> %+v", sql, facts)
		}
	}
	// `WITH OFFSET` is BigQuery syntax; PostgreSQL rejects it, so the parser must too.
	offset := analyze("SELECT 1 FROM unnest(ARRAY[1, 2]) WITH OFFSET AS pos", []string{"pg_catalog", "public"}, true)
	if offset.GetResolved() || stageString(offset.FailedStage) != "PARSE" {
		t.Errorf("WITH OFFSET must fail at parse under PostgreSQL: %+v", offset)
	}
	for _, sql := range []string{
		"SELECT v, n FROM unnest(ARRAY[1, 2]) WITH ORDINALITY AS u(v, n)",
		"SELECT u.v, u.n FROM unnest(ARRAY[1, 2]) WITH ORDINALITY AS u(v, n)",
	} {
		facts := analyze(sql, []string{"pg_catalog", "public"}, true)
		if !facts.GetResolved() {
			t.Errorf("WITH ORDINALITY must resolve: %q stage=%s detail=%q", sql, stageString(facts.FailedStage), facts.GetDetail())
		}
	}
}

func TestPostgresCTIDResolutionBoundaries(t *testing.T) {
	baseCatalog := []*pb.Column{
		pbColumn("public", "users", "id", "BIGINT"),
		pbColumn("public", "orders", "id", "BIGINT"),
	}

	// grantsOf: the Column grants' table.column names; fails on any Table grant (covered scans need none).
	grantsOf := func(t *testing.T, sql string, catalog []*pb.Column) map[string]bool {
		t.Helper()
		facts := analyzeProto(t, &pb.AnalyzeRequest{
			Sql:          sql,
			EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
			Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
			Catalog:      snapshot(catalog),
		})
		if !facts.GetResolved() {
			t.Fatalf("must resolve: %q stage=%s detail=%q", sql, stageString(facts.FailedStage), facts.GetDetail())
		}
		out := map[string]bool{}
		for _, grant := range facts.GetResultReads() {
			if table := grant.GetTable(); table != nil {
				t.Fatalf("%q emitted a table grant (implicit columns are Column grants now): %+v", sql, table)
			}
			if column := grant.GetColumn(); column != nil {
				out[column.GetTable()+"."+column.GetColumn()] = true
			}
		}
		return out
	}

	analyze := func(t *testing.T, sql string, catalog []*pb.Column) ProbeResult {
		t.Helper()
		return *analyzeProbe(t, &pb.AnalyzeRequest{
			Sql:          sql,
			EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
			Namespace:    &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
			Catalog:      snapshot(catalog),
		})
	}

	t.Run("qualified physical table", func(t *testing.T) {
		result := analyze(t, "SELECT u.ctid FROM users u", baseCatalog)
		if !result.Resolved || len(result.Origins) != 1 || len(result.Origins[0].Origins) != 1 ||
			result.Origins[0].Origins[0] != "acme.public.users.ctid" {
			t.Fatalf("qualified CTID must carry ordinary column lineage: %+v", result)
		}
		if len(result.Sources) != 1 || !result.Sources[0].Covered {
			t.Fatalf("a CTID read covers its source through the Column grant: %+v", result.Sources)
		}
	})

	t.Run("composite CTID reads emit the users.ctid column grant", func(t *testing.T) {
		catalog := append([]*pb.Column{}, baseCatalog...)
		catalog = append(catalog, pbColumn("public", "users", "email", "VARCHAR"))
		cases := []string{
			"SELECT (u).ctid FROM users u",
			"SELECT 1 FROM users u WHERE (u).ctid = '(0,1)'",
			"UPDATE users u SET email = 'x' WHERE (u).ctid = '(0,1)'",
			"UPDATE users u SET email = 'x' RETURNING (u).ctid",
		}
		for _, sql := range cases {
			t.Run(sql, func(t *testing.T) {
				if grants := grantsOf(t, sql, catalog); !grants["users.ctid"] {
					t.Fatalf("composite CTID read emitted no users.ctid grant: %v", grants)
				}
			})
		}
	})

	t.Run("mixed CTID use emits the users.ctid column grant", func(t *testing.T) {
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
				if !result.Resolved || len(result.Sources) != 1 || !result.Sources[0].Covered {
					t.Fatalf("CTID use covers its source like any column read: %+v", result)
				}
				if grants := grantsOf(t, sql, baseCatalog); !grants["users.ctid"] {
					t.Fatalf("CTID use emitted no users.ctid grant: %v", grants)
				}
			})
		}
	})

	t.Run("write CTID reads emit the users.ctid column grant", func(t *testing.T) {
		catalog := append([]*pb.Column{}, baseCatalog...)
		catalog = append(catalog, pbColumn("public", "users", "email", "VARCHAR"))
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
				if grants := grantsOf(t, sql, catalog); !grants["users.ctid"] {
					t.Fatalf("write CTID read emitted no users.ctid grant: %v", grants)
				}
			})
		}
	})

	t.Run("qualified multi-source write CTID resolves exact source", func(t *testing.T) {
		catalog := append([]*pb.Column{}, baseCatalog...)
		catalog = append(catalog, pbColumn("public", "users", "email", "VARCHAR"))
		cases := []struct {
			sql  string
			want string // the ctid Column grant's table
		}{
			{"UPDATE users u SET email = 'x' FROM orders o WHERE u.ctid = '(0,1)' AND o.id = 1", "users.ctid"},
			{"UPDATE users u SET email = 'x' FROM orders o WHERE o.ctid = '(0,1)'", "orders.ctid"},
			{"UPDATE users AS u SET email = 'x' FROM orders AS users WHERE users.ctid = '(0,1)'", "orders.ctid"},
			{"MERGE INTO users AS u USING orders AS o ON u.id = o.id WHEN MATCHED AND u.ctid = '(0,1)' THEN UPDATE SET email = 'x'", "users.ctid"},
			{"MERGE INTO users AS u USING orders AS o ON u.id = o.id WHEN NOT MATCHED AND o.ctid = '(0,1)' THEN INSERT (id, email) VALUES (o.id, 'x')", "orders.ctid"},
		}
		for _, tc := range cases {
			t.Run(tc.sql, func(t *testing.T) {
				grants := grantsOf(t, tc.sql, catalog)
				if !grants[tc.want] {
					t.Fatalf("qualified write CTID must grant %s: %v", tc.want, grants)
				}
			})
		}
	})

	t.Run("nested write CTID resolves from its own scope", func(t *testing.T) {
		catalog := append([]*pb.Column{}, baseCatalog...)
		catalog = append(
			catalog,
			pbColumn("public", "users", "email", "VARCHAR"),
			pbColumn("public", "orders", "email", "VARCHAR"),
		)
		cases := []string{
			"UPDATE users u SET email = (SELECT o.email FROM orders o WHERE ctid = '(0,1)') WHERE u.id = 1",
			"INSERT INTO users (id, email) SELECT o.id, o.email FROM orders o WHERE ctid = '(0,1)'",
		}
		for _, sql := range cases {
			t.Run(sql, func(t *testing.T) {
				grants := grantsOf(t, sql, catalog)
				if !grants["orders.ctid"] {
					t.Fatalf("nested CTID must grant the inner source's ctid: %v", grants)
				}
				if grants["users.ctid"] {
					t.Fatalf("nested CTID leaked onto the outer target: %v", grants)
				}
			})
		}
	})

	t.Run("derived CTID output remains ordinary in write", func(t *testing.T) {
		catalog := append([]*pb.Column{}, baseCatalog...)
		catalog = append(catalog, pbColumn("public", "users", "email", "VARCHAR"))
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
					Catalog:      snapshot(catalog),
				})
				for _, grant := range facts.GetResultReads() {
					if table := grant.GetTable(); table != nil {
						t.Fatalf("derived CTID output emitted a physical table grant: %+v", table)
					}
					if column := grant.GetColumn(); column != nil && strings.EqualFold(column.GetColumn(), "ctid") {
						t.Fatalf("derived CTID output emitted a CTID column grant: %+v", column)
					}
				}
			})
		}
	})

	t.Run("derived physical CTID keeps its table provenance", func(t *testing.T) {
		catalog := append([]*pb.Column{}, baseCatalog...)
		catalog = append(catalog, pbColumn("public", "users", "email", "VARCHAR"))
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
				if grants := grantsOf(t, sql, catalog); !grants["orders.ctid"] {
					t.Fatalf("derived CTID lost its orders.ctid provenance: %v", grants)
				}
			})
		}
	})

	t.Run("composite derived CTID expression keeps ordinary column provenance", func(t *testing.T) {
		sql := "SELECT (d).mixed FROM (SELECT ctid::text || id::text AS mixed FROM orders) d"
		grants := grantsOf(t, sql, baseCatalog)
		if !grants["orders.ctid"] || !grants["orders.id"] {
			t.Fatalf("composite derived expression must carry BOTH base columns: %v", grants)
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
					Catalog:      snapshot(baseCatalog),
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
		catalog := append([]*pb.Column{}, baseCatalog...)
		catalog = append(catalog, pbColumn("public", "users", "email", "VARCHAR"))
		cases := []string{
			"UPDATE users u SET email = 'x' FROM (SELECT 1) d WHERE ctid = '(0,1)'",
			"WITH d AS (SELECT id FROM orders) UPDATE users u SET email = 'x' WHERE ctid = '(0,1)' AND EXISTS (SELECT 1 FROM d WHERE d.id = u.id)",
		}
		for _, sql := range cases {
			t.Run(sql, func(t *testing.T) {
				if grants := grantsOf(t, sql, catalog); !grants["users.ctid"] {
					t.Fatalf("unique target CTID must grant users.ctid: %v", grants)
				}
			})
		}
	})

	t.Run("write payload cannot read target CTID", func(t *testing.T) {
		catalog := append([]*pb.Column{}, baseCatalog...)
		catalog = append(catalog, pbColumn("public", "users", "email", "VARCHAR"))
		// A payload subquery over a derived source has no ctid; PG errors, the analyzer resolves it
		// grant-free and relays — the target's own rejection is the backstop (same class as any
		// engine-invalid statement the analyzer over-accepts).
		relayed := analyze(t, "INSERT INTO users (id, email) SELECT 4, ctid::text FROM (SELECT 1) d", catalog)
		if !relayed.Resolved {
			t.Fatalf("derived-payload CTID resolves grant-free (engine rejects it): %+v", relayed)
		}
		// MERGE NOT MATCHED referencing the target's ctid: PG rejects ("invalid reference to
		// FROM-clause entry for table u"); the analyzer emits the users.ctid grant and relays — the
		// gated read never executes, so this is gated-then-engine-rejected, not a leak.
		merged := grantsOf(t, "MERGE INTO users AS u USING orders AS o ON u.id = o.id WHEN NOT MATCHED THEN INSERT (id, email) VALUES (o.id, u.ctid::text)", catalog)
		if !merged["users.ctid"] {
			t.Fatalf("MERGE target-CTID payload must at least gate users.ctid: %v", merged)
		}
	})

	t.Run("write target alias hides base name", func(t *testing.T) {
		catalog := append([]*pb.Column{}, baseCatalog...)
		catalog = append(catalog, pbColumn("public", "users", "email", "VARCHAR"))
		result := analyze(t, "UPDATE users AS u SET email = 'x' WHERE users.ctid = '(0,1)'", catalog)
		if result.Resolved {
			t.Fatalf("aliased write target must reject its hidden base name: %+v", result)
		}
	})

	t.Run("ambiguous write CTID remains unresolved", func(t *testing.T) {
		catalog := append([]*pb.Column{}, baseCatalog...)
		catalog = append(
			catalog,
			pbColumn("public", "users", "email", "VARCHAR"),
			pbColumn("public", "orders", "email", "VARCHAR"),
		)
		cases := []string{
			"UPDATE users u SET email = 'x' FROM orders o WHERE ctid = '(0,1)'",
			"UPDATE users u SET email = 'x' FROM (SELECT id AS ctid FROM orders) o WHERE ctid = 1",
		}
		for _, sql := range cases {
			t.Run(sql, func(t *testing.T) {
				result := analyze(t, sql, catalog)
				if result.Resolved {
					t.Fatalf("ambiguous write CTID must fail closed: %+v", result)
				}
			})
		}
		// A payload ctid ambiguous between two aliases of the SAME table falls back to the write
		// target's identity (users.ctid) — a ctid grant still gates the read, and PG rejects the
		// statement itself ("column reference ctid is ambiguous") before anything executes.
		sameTable := "UPDATE users u SET email = (SELECT o.email FROM orders o, orders p WHERE ctid = '(0,1)') WHERE u.id = 1"
		if grants := grantsOf(t, sameTable, catalog); !grants["users.ctid"] && !grants["orders.ctid"] {
			t.Fatalf("ambiguous payload CTID must still be gated by a ctid grant: %v", grants)
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
				// The alias wins over the implicit column (PG ORDER BY precedence): the reference must
				// bind to the ALIASED base column, never to users.ctid — else `ssn AS ctid ORDER BY ctid`
				// would misattribute a masked column's ordering to unclassified ctid.
				for _, ref := range result.References["ORDER_BY"] {
					if ref == "acme.public.users.ctid" {
						t.Fatalf("ORDER BY bound to the implicit column instead of the alias: %v", result.References)
					}
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
					Catalog:      snapshot(baseCatalog),
				})
				for _, grant := range facts.GetResultReads() {
					if table := grant.GetTable(); table != nil {
						t.Fatalf("ordinary CTID output alias emitted a table grant: %+v", table)
					}
				}
			})
		}
	})

	t.Run("table alias shadowing an implicit column fails closed", func(t *testing.T) {
		// PG binds `ctid` to the ALIASED real column (`users AS u(id_alias, ctid)` aliases id, ssn…),
		// while the schema still resolves the implicit one — a masked column could relay under an
		// unclassified ctid grant, so the spelling is rejected outright.
		for _, sql := range []string{
			"SELECT u.ctid FROM users AS u(id_alias, ctid)",
			"SELECT * FROM users AS u(ctid, x)",
		} {
			result := analyze(t, sql, baseCatalog)
			if result.Resolved {
				t.Fatalf("implicit-shadowing alias must fail closed: %q -> %+v", sql, result)
			}
		}
		// A benign alias list keeps working.
		if result := analyze(t, "SELECT a FROM users AS u(a, b)", baseCatalog); !result.Resolved {
			t.Fatalf("benign alias list must resolve: %+v", result)
		}
	})

	t.Run("composite column field read in a write keeps its grant", func(t *testing.T) {
		catalog := append([]*pb.Column{}, baseCatalog...)
		catalog = append(catalog,
			pbColumn("public", "users", "ssn", "VARCHAR"),
			pbColumn("public", "users", "profile", "USER-DEFINED"),
		)
		grants := grantsOf(t, "UPDATE users SET ssn = (profile).secret WHERE id = 1 RETURNING ssn", catalog)
		if !grants["users.profile"] {
			t.Fatalf("(profile).secret in a write payload must grant users.profile: %v", grants)
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
		// PostgreSQL forbids user columns named after system columns, so a catalog carrying a REAL
		// users.ctid cannot come from live PG introspection — but a caller-supplied one wins over
		// the implicit marking and keeps ordinary catalog-column lineage.
		catalog := append([]*pb.Column{}, baseCatalog...)
		catalog = append(catalog, pbColumn("public", "users", "ctid", "TEXT"))
		result := analyze(t, "SELECT ctid FROM users", catalog)
		if !result.Resolved || len(result.Origins) != 1 || len(result.Origins[0].Origins) != 1 ||
			result.Origins[0].Origins[0] != "acme.public.users.ctid" {
			t.Fatalf("real CTID column must retain ordinary lineage: %+v", result)
		}
		if len(result.Sources) != 1 || !result.Sources[0].Covered {
			t.Fatalf("real CTID column must cover its source through the column grant: %+v", result.Sources)
		}
	})
}
