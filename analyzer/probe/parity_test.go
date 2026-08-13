package probe

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	sqlglot "github.com/ridi-oss/sqlglot-go"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/generator"
	"github.com/ridi-oss/sqlglot-go/schema"
)

type probeParityCase struct {
	name           string
	dialect        string
	sql            string
	deferredReason string
	category       string
	schema         *schema.Mapping
}

func defaultProbeSchema() *schema.Mapping {
	return schema.M(
		"users", schema.M("id", "BIGINT", "email", "VARCHAR", "ssn", "VARCHAR", "region", "VARCHAR", "name", "VARCHAR"),
		"orders", schema.M("id", "BIGINT", "user_id", "BIGINT", "amount", "DECIMAL"),
		"sink", schema.M("id", "BIGINT", "data", "VARCHAR", "data2", "VARCHAR"),
	)
}

func probeParityCases() []probeParityCase {
	return []probeParityCase{
		{name: "simple lineage", sql: "SELECT id, ssn FROM users", category: "simple lineage"},
		{name: "bare star", sql: "SELECT * FROM users", category: "star"},
		{name: "qualified star", sql: "SELECT u.* FROM users u", category: "star"},
		{name: "bare star plus explicit", sql: "SELECT *, amount FROM orders", category: "star"},
		{name: "join and join on refs", sql: "SELECT u.ssn, o.amount FROM users u JOIN orders o ON u.id = o.user_id", category: "join"},
		{name: "derived table", sql: "SELECT t.r FROM (SELECT ssn AS r FROM users) t", category: "derived"},
		{name: "nested derived", sql: "SELECT x.r FROM (SELECT t.r FROM (SELECT ssn AS r FROM users) t) x", category: "derived"},
		{name: "cte", sql: "WITH c AS (SELECT ssn FROM users) SELECT ssn FROM c", category: "cte"},
		{name: "recursive cte", sql: "WITH RECURSIVE r(id, ssn) AS (SELECT id, ssn FROM users UNION ALL SELECT id, ssn FROM users) SELECT ssn FROM r", category: "cte"},
		{name: "union all transparent", sql: "SELECT ssn FROM users UNION ALL SELECT region FROM users", category: "set-op"},
		{name: "union distinct", sql: "SELECT ssn FROM users UNION SELECT region FROM users", category: "set-op"},
		{name: "intersect", sql: "SELECT ssn FROM users INTERSECT SELECT region FROM users", category: "set-op"},
		{name: "except", sql: "SELECT ssn FROM users EXCEPT SELECT region FROM users", category: "set-op"},
		{name: "parenthesized set branch", sql: "(SELECT ssn FROM users UNION ALL SELECT region FROM users) UNION ALL SELECT email FROM users", category: "set-op"},
		{name: "set op order by", sql: "SELECT ssn AS x FROM users UNION ALL SELECT region AS x FROM users ORDER BY x", category: "set-op"},
		{name: "in subquery", sql: "SELECT id FROM orders WHERE user_id IN (SELECT id FROM users WHERE ssn = 'x')", category: "subquery"},
		{name: "exists subquery", sql: "SELECT id FROM orders WHERE EXISTS (SELECT 1 FROM users WHERE users.id = orders.user_id AND ssn = 'x')", category: "subquery"},
		{name: "scalar projection", sql: "SELECT (SELECT ssn FROM users) AS r FROM orders", category: "subquery"},
		{name: "group by alias", sql: "SELECT region AS r, count(*) AS c FROM users GROUP BY r", category: "clause refs"},
		{name: "group by ordinal", sql: "SELECT region, count(*) AS c FROM users GROUP BY 1", category: "clause refs"},
		{name: "having", sql: "SELECT region, count(*) AS c FROM users GROUP BY region HAVING max(ssn) > 'x'", category: "clause refs"},
		{name: "order by alias", sql: "SELECT ssn AS r FROM users ORDER BY r", category: "clause refs"},
		{name: "order by ordinal", sql: "SELECT ssn FROM users ORDER BY 1", category: "clause refs"},
		{name: "qualify", sql: "SELECT ssn, row_number() OVER (PARTITION BY region ORDER BY id) AS rn FROM users QUALIFY rn = 1", category: "clause refs"},
		{name: "distinct", sql: "SELECT DISTINCT ssn FROM users", category: "clause refs"},
		{name: "distinct on", dialect: "postgres", sql: "SELECT DISTINCT ON (region) ssn FROM users ORDER BY region", category: "clause refs"},
		{name: "window", sql: "SELECT row_number() OVER (PARTITION BY region ORDER BY ssn) FROM users", category: "window"},
		{name: "aggregate filter", dialect: "postgres", sql: "SELECT count(*) FILTER (WHERE ssn IS NOT NULL) FROM users", category: "aggregate"},
		{name: "insert values", sql: "INSERT INTO sink (id, data) VALUES (1, 'x')", category: "insert"},
		{name: "insert values scalar subquery", sql: "INSERT INTO sink (id, data) VALUES ((SELECT id FROM users WHERE ssn = 'x'), 'x')", category: "insert"},
		{name: "insert select", sql: "INSERT INTO sink (id, data) SELECT id, ssn FROM users", category: "insert"},
		{name: "insert on conflict update", dialect: "postgres", sql: "INSERT INTO sink (id, data) SELECT id, ssn FROM users ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data", category: "insert"},
		{name: "update from", dialect: "postgres", sql: "UPDATE sink SET data = users.ssn FROM users WHERE sink.id = users.id", category: "update"},
		{name: "update where subquery", sql: "UPDATE sink SET data = 'x' WHERE id IN (SELECT id FROM users WHERE ssn = 'x')", category: "update"},
		{name: "delete using", dialect: "postgres", sql: "DELETE FROM sink USING users WHERE sink.id = users.id AND users.ssn = 'x'", category: "delete"},
		{name: "delete where", sql: "DELETE FROM sink WHERE id IN (SELECT id FROM users WHERE ssn = 'x')", category: "delete"},
		{name: "merge", dialect: "postgres", sql: "MERGE INTO sink USING users ON sink.id = users.id WHEN MATCHED THEN UPDATE SET data = users.ssn WHEN NOT MATCHED THEN INSERT (id, data) VALUES (users.id, users.ssn)", category: "merge"},
		{name: "cte in update from", dialect: "postgres", sql: "WITH c AS (SELECT id, ssn FROM users) UPDATE sink SET data = c.ssn FROM c WHERE sink.id = c.id", category: "cte write"},
		{name: "cte in delete using", dialect: "postgres", sql: "WITH c AS (SELECT id, ssn FROM users) DELETE FROM sink USING c WHERE sink.id = c.id AND c.ssn = 'x'", category: "cte write"},
		{name: "cte in merge using", dialect: "postgres", sql: "WITH c AS (SELECT id, ssn FROM users) MERGE INTO sink USING c ON sink.id = c.id WHEN MATCHED THEN UPDATE SET data = c.ssn", category: "cte write"},
		{name: "shadow cte in update from", dialect: "postgres", sql: "WITH orders AS (SELECT ssn AS amount, id FROM users) UPDATE sink SET data = orders.amount FROM orders WHERE sink.id = orders.id", category: "cte write"},
		{name: "ctas", sql: "CREATE TABLE sink AS SELECT id, ssn FROM users", category: "create"},
		{name: "create view", sql: "CREATE VIEW sink AS SELECT id, ssn FROM users", category: "create"},
		{name: "select into", sql: "SELECT id, ssn INTO sink FROM users", category: "select into"},
		{name: "pivot", sql: "SELECT * FROM users PIVOT (SUM(id) FOR region IN ('x')) AS p", category: "fail closed"},
		{name: "natural join", sql: "SELECT * FROM users NATURAL JOIN orders", category: "fail closed"},
		{name: "unknown table", sql: "SELECT id FROM nope", category: "fail closed"},
		{name: "unknown column", sql: "SELECT nope FROM users", category: "fail closed"},
		{name: "multiple statements", sql: "SELECT 1; SELECT 2", category: "fail closed"},
		{name: "unsupported root", sql: "SET x = 1", category: "fail closed"},
		{name: "plain create", sql: "CREATE TABLE sink (id BIGINT)", category: "fail closed"},
		{name: "data modifying cte", dialect: "postgres", sql: "WITH a AS (UPDATE users SET name = 'x' RETURNING ssn) SELECT ssn FROM a", category: "fail closed"},
		{name: "on conflict constraint", dialect: "postgres", sql: "INSERT INTO sink (id, data) VALUES (1, 'x') ON CONFLICT ON CONSTRAINT sink_pkey DO NOTHING", category: "fail closed"},
		// Deferred: pre-existing parser gaps. All are fail-closed-safe (Go returns
		// PARSE/VALIDATE=DENY where Python resolves), so they are documented non-matches,
		// not leaks. Listed explicitly rather than silently absent; skipped by the harness
		// deferred branch.
		{name: "table valued function source", dialect: "postgres", sql: "SELECT g FROM generate_series(1, 10) g", category: "parser gap", deferredReason: "TVF as standalone FROM source not parsed by the Go parser; Go PARSE-fails=DENY vs Python resolves"},
		{name: "mysql on duplicate key update", dialect: "mysql", sql: "INSERT INTO sink (id, data) VALUES (1, 'x') ON DUPLICATE KEY UPDATE data = VALUES(data)", category: "parser gap", deferredReason: "MySQL ON DUPLICATE KEY UPDATE ... VALUES(col) not parsed; Go PARSE-fails=DENY vs Python resolves"},
		{name: "similar to operator", dialect: "postgres", sql: "SELECT ssn FROM users WHERE ssn SIMILAR TO 'x%'", category: "parser gap", deferredReason: "SIMILAR TO operator not parsed by the Go parser; Go PARSE-fails=DENY vs Python resolves"},
	}
}

func TestProbeParity(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	pkgDir := filepath.Dir(file)
	repoRoot := filepath.Dir(pkgDir)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skipf("python3 not found: %v", err)
	}
	refPath := filepath.Join(repoRoot, ".reference", "sqlglot-v30.12.0")
	if st, err := os.Stat(refPath); err != nil || !st.IsDir() {
		t.Skipf("pinned sqlglot reference not found at %s", refPath)
	}

	type wireCase struct {
		SQL     string          `json:"sql"`
		Dialect string          `json:"dialect"`
		Schema  json.RawMessage `json:"schema"`
	}
	type expandedCase struct {
		probeParityCase
		dialect string
		schema  *schema.Mapping
	}

	var expanded []expandedCase
	var wire []wireCase
	for _, tc := range probeParityCases() {
		if tc.deferredReason != "" {
			t.Logf("deferred parity case %q (%s): %s", tc.name, tc.category, tc.deferredReason)
			continue
		}
		dialects := []string{"mysql", "postgres"}
		if tc.dialect != "" {
			dialects = []string{tc.dialect}
		}
		sch := tc.schema
		if sch == nil {
			sch = defaultProbeSchema()
		}
		for _, dialect := range dialects {
			expanded = append(expanded, expandedCase{probeParityCase: tc, dialect: dialect, schema: sch})
			wire = append(wire, wireCase{SQL: tc.sql, Dialect: dialect, Schema: mappingToJSON(sch)})
		}
	}

	payload, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal oracle input: %v", err)
	}
	driver := filepath.Join(pkgDir, "testdata", "oracle", "driver.py")
	cmd := exec.Command("python3", driver)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+refPath, "PYTHONDONTWRITEBYTECODE=1")
	cmd.Stdin = bytes.NewReader(payload)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("python oracle failed: %v\nstderr:\n%s", err, stderr.String())
	}
	var pyJSONResults []string
	if err := json.Unmarshal(out, &pyJSONResults); err != nil {
		t.Fatalf("unmarshal oracle output: %v\noutput: %s", err, string(out))
	}
	if len(pyJSONResults) != len(expanded) {
		t.Fatalf("oracle returned %d results for %d cases", len(pyJSONResults), len(expanded))
	}

	exactMatches := 0
	detailExact := 0
	mismatches := []string{}
	for i, tc := range expanded {
		var py ProbeResult
		if err := json.Unmarshal([]byte(pyJSONResults[i]), &py); err != nil {
			t.Fatalf("unmarshal oracle result %s/%s: %v\n%s", tc.dialect, tc.name, err, pyJSONResults[i])
		}
		goResult := Probe(tc.sql, parityEngineConfig(t, tc.dialect), qualifyParitySchema(tc.schema, tc.dialect), parityNamespace(tc.dialect))
		ok, detailOK, diffs := compareProbeResults(py, goResult, tc.dialect)
		if detailOK {
			detailExact++
		}
		if ok {
			exactMatches++
			continue
		}
		for _, diff := range diffs {
			mismatches = append(mismatches, fmt.Sprintf("%s | %s | %s | %s", tc.dialect, tc.sql, diff, tc.category))
		}
	}

	t.Logf("parity = %d/%d cases exact-match", exactMatches, len(expanded))
	t.Logf("detail exact-match = %d/%d cases", detailExact, len(expanded))
	if len(mismatches) > 0 {
		t.Logf("non-matching cases:\n%s", strings.Join(mismatches, "\n"))
	}
	// Regenerate the committed golden file (the Python ground truth) that TestProbeGolden
	// checks Go against hermetically. Run: PROBE_REGEN=1 go test ./probe/ -run TestProbeParity
	if os.Getenv("PROBE_REGEN") == "1" {
		golden := map[string]json.RawMessage{}
		for i, tc := range expanded {
			golden[goldenKey(tc.dialect, tc.name)] = json.RawMessage(pyJSONResults[i])
		}
		blob, err := json.MarshalIndent(golden, "", "  ")
		if err != nil {
			t.Fatalf("marshal golden: %v", err)
		}
		goldenPath := filepath.Join(pkgDir, "testdata", "golden.json")
		if err := os.WriteFile(goldenPath, append(blob, '\n'), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("regenerated %s (%d entries)", goldenPath, len(golden))
	}

	const minParity = 94 // Ratchet: set to the achieved count and never lower to mask a regression.
	if exactMatches < minParity {
		t.Fatalf("probe parity regressed: got %d/%d exact matches, min %d", exactMatches, len(expanded), minParity)
	}
}

func legacyLineageKey(key string) string {
	parts := strings.Split(key, ".")
	if len(parts) < 4 {
		return key
	}
	return strings.Join(parts[2:], ".")
}

func projectLegacyProbeResult(result ProbeResult) ProbeResult {
	projected := result
	projected.Origins = make([]OriginInfo, len(result.Origins))
	for i, origin := range result.Origins {
		projected.Origins[i] = origin
		projected.Origins[i].Origins = make([]string, len(origin.Origins))
		for j, key := range origin.Origins {
			projected.Origins[i].Origins[j] = legacyLineageKey(key)
		}
	}
	projected.References = make(map[string][]string, len(result.References))
	for bucket, keys := range result.References {
		projected.References[bucket] = make([]string, len(keys))
		for i, key := range keys {
			projected.References[bucket][i] = legacyLineageKey(key)
		}
	}
	return projected
}

func projectLegacyRewrittenSQL(sql, dialect string) string {
	expressions, err := sqlglot.Parse(sql, dialect)
	if err != nil || len(expressions) != 1 || expressions[0] == nil {
		return sql
	}
	for _, table := range expressions[0].FindAll(exp.KindTable) {
		table.Set("catalog", nil)
		table.Set("schema", nil)
	}
	projected, err := sqlglot.Generate(expressions[0], dialect, generator.Options{})
	if err != nil {
		return sql
	}
	return projected
}

func compareProbeResults(py, goResult ProbeResult, dialect string) (bool, bool, []string) {
	goResult = projectLegacyProbeResult(goResult)
	if goResult.RewrittenSQL != nil {
		projected := projectLegacyRewrittenSQL(*goResult.RewrittenSQL, dialect)
		goResult.RewrittenSQL = &projected
	}
	diffs := []string{}
	compare := func(field string, pyValue, goValue any) {
		if !reflect.DeepEqual(pyValue, goValue) {
			diffs = append(diffs, fmt.Sprintf("%s mismatch: py=%#v go=%#v", field, pyValue, goValue))
		}
	}
	compare("resolved", py.Resolved, goResult.Resolved)
	compare("failedStage", py.FailedStage, goResult.FailedStage)
	compare("isWrite", py.IsWrite, goResult.IsWrite)
	compare("outputColumns", py.OutputColumns, goResult.OutputColumns)
	compare("tracedColumns", py.TracedColumns, goResult.TracedColumns)
	compare("origins", py.Origins, goResult.Origins)
	compare("references", py.References, goResult.References)
	if !reflect.DeepEqual(py.RewrittenSQL, goResult.RewrittenSQL) {
		if py.RewrittenSQL != nil && goResult.RewrittenSQL != nil && semanticallySameSQL(*py.RewrittenSQL, *goResult.RewrittenSQL, dialect) {
			diffs = append(diffs, fmt.Sprintf("rewrittenSql mismatch (semantic round-trip equal; generator-cosmetic only): py=%#v go=%#v", py.RewrittenSQL, goResult.RewrittenSQL))
		} else {
			diffs = append(diffs, fmt.Sprintf("rewrittenSql mismatch: py=%#v go=%#v", py.RewrittenSQL, goResult.RewrittenSQL))
		}
	}
	detailExact := py.Detail == goResult.Detail
	if py.Resolved && goResult.Resolved {
		if py.Detail != "ok" || goResult.Detail != "ok" {
			diffs = append(diffs, fmt.Sprintf("detail mismatch on resolved result: py=%#v go=%#v", py.Detail, goResult.Detail))
		}
	} else if py.Detail == "" || goResult.Detail == "" {
		diffs = append(diffs, fmt.Sprintf("detail empty on unresolved result: py=%#v go=%#v", py.Detail, goResult.Detail))
	}
	return len(diffs) == 0, detailExact, diffs
}

func semanticallySameSQL(left, right, dialect string) bool {
	lnorm, ok := normalizeSQL(left, dialect)
	if !ok {
		return false
	}
	rnorm, ok := normalizeSQL(right, dialect)
	if !ok {
		return false
	}
	return lnorm == rnorm
}

func normalizeSQL(sql, dialect string) (string, bool) {
	exprs, err := sqlglot.Parse(sql, dialect)
	if err != nil || len(exprs) != 1 || exprs[0] == nil {
		return "", false
	}
	out, err := sqlglot.Generate(exprs[0], dialect, generator.Options{})
	if err != nil {
		return "", false
	}
	return out, true
}
