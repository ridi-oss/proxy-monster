package query_test

import (
	"sort"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/engine"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
)

// ManifestCommandCoverageDbTest.kt — 220 LOC, 2 cases. Both were unmapped and neither was covered:
// nothing in the Go suite enumerated the manifests' command ids, and nothing asserted the masked-column
// INTO OUTFILE case for a sql.ddl-GRANTED principal (enforcement_db_test.go:587 asserts the no-FROM
// variant for the analyst, which is the kind gate, not the write-payload rule).
//
// The Kotlin header, quoted, because it is the whole point of the file:
//
//	FAIL-CLOSED completeness guard for the utility/command gate (the emission-completeness leak class).
//	`Admission.utilityFacts` hand-recognizes the statements that perform a manifest command id; the
//	shipped `system:` policy then gates them. Three consecutive access-model audits each found a
//	DIFFERENT dangerous command that `utilityFacts` failed to emit — so it relayed verbatim as a
//	passthrough (SET PERSIST; SHOW CREATE USER, which leaks the service account's password hash; SHOW
//	GRANTS; SHOW REPLICA STATUS). The hand-maintained subset kept leaking. This test closes the CLASS.
//
// A NEW manifest command id with no sample and no passthrough entry FAILS this test, which is the
// structural property being ported — not any one of the statements below.

type manifestCmdEngine int

const (
	cmdEnginePG manifestCmdEngine = iota
	cmdEngineMySQL
)

type manifestCmdSample struct {
	engine manifestCmdEngine
	sql    string
}

// One representative statement per dangerous command id + the engine to decide it on. The completeness
// assertion proves this map ∪ intentionalPassthrough covers every manifest dangerous command, so a
// missing entry is a test failure, not a silent relay. Statements need only ADMIT + decide — they are
// never executed, because a dangerous command denies before it reaches the backend.
var manifestCommandSamples = map[string]manifestCmdSample{
	// MySQL — account / privilege administration.
	"SET_PASSWORD":     {cmdEngineMySQL, "SET PASSWORD = 'x'"},
	"CREATE_USER":      {cmdEngineMySQL, "CREATE USER u IDENTIFIED BY 'p'"},
	"ALTER_USER":       {cmdEngineMySQL, "ALTER USER u IDENTIFIED BY 'p'"},
	"DROP_USER":        {cmdEngineMySQL, "DROP USER u"},
	"GRANT":            {cmdEngineMySQL, "GRANT ALL ON *.* TO u"},
	"REVOKE":           {cmdEngineMySQL, "REVOKE ALL ON *.* FROM u"},
	"RENAME_USER":      {cmdEngineMySQL, "RENAME USER a TO b"},
	"SET_DEFAULT_ROLE": {cmdEngineMySQL, "SET DEFAULT ROLE r TO u"},
	// MySQL — server-state mutation.
	"SET_GLOBAL":       {cmdEngineMySQL, "SET GLOBAL max_connections = 1"},
	"SET_PERSIST":      {cmdEngineMySQL, "SET PERSIST max_connections = 5000"},
	"SET_PERSIST_ONLY": {cmdEngineMySQL, "SET PERSIST_ONLY max_connections = 5000"},
	"RESET_PERSIST":    {cmdEngineMySQL, "RESET PERSIST"},
	"ALTER_INSTANCE":   {cmdEngineMySQL, "ALTER INSTANCE ROTATE INNODB MASTER KEY"},
	"CLONE_INSTANCE":   {cmdEngineMySQL, "CLONE INSTANCE FROM 'u'@'h':3306 IDENTIFIED BY 'p'"},
	"RESTART":          {cmdEngineMySQL, "RESTART"},
	"SHUTDOWN":         {cmdEngineMySQL, "SHUTDOWN"},
	// MySQL — replication / binlog.
	"CHANGE_REPLICATION_SOURCE": {cmdEngineMySQL, "CHANGE REPLICATION SOURCE TO SOURCE_HOST = 'h'"},
	"RESET_REPLICA":             {cmdEngineMySQL, "RESET REPLICA"},
	"PURGE_BINARY_LOGS":         {cmdEngineMySQL, "PURGE BINARY LOGS TO 'mysql-bin.000001'"},
	// MySQL — code loading.
	"INSTALL_PLUGIN":         {cmdEngineMySQL, "INSTALL PLUGIN x SONAME 'y.so'"},
	"UNINSTALL_PLUGIN":       {cmdEngineMySQL, "UNINSTALL PLUGIN x"},
	"INSTALL_COMPONENT":      {cmdEngineMySQL, "INSTALL COMPONENT 'file://x'"},
	"UNINSTALL_COMPONENT":    {cmdEngineMySQL, "UNINSTALL COMPONENT 'file://x'"},
	"CREATE_FUNCTION_SONAME": {cmdEngineMySQL, "CREATE FUNCTION x RETURNS INTEGER SONAME 'y.so'"},
	"DROP_FUNCTION_SONAME":   {cmdEngineMySQL, "DROP FUNCTION x"},
	// MySQL — file IO (server-side read/write, an exfil surface).
	"INTO_OUTFILE":  {cmdEngineMySQL, "SELECT rrn FROM users INTO OUTFILE '/tmp/x'"},
	"INTO_DUMPFILE": {cmdEngineMySQL, "SELECT rrn FROM users INTO DUMPFILE '/tmp/x'"},
	"LOAD_DATA":     {cmdEngineMySQL, "LOAD DATA INFILE '/tmp/x' INTO TABLE t"},
	"LOAD_XML":      {cmdEngineMySQL, "LOAD XML INFILE '/tmp/x' INTO TABLE t"},
	// MySQL — data-bearing SHOW (the emission-leak class this guard protects).
	"SHOW_CREATE_USER":     {cmdEngineMySQL, "SHOW CREATE USER CURRENT_USER()"},
	"SHOW_GRANTS":          {cmdEngineMySQL, "SHOW GRANTS"},
	"SHOW_BINLOG_EVENTS":   {cmdEngineMySQL, "SHOW BINLOG EVENTS"},
	"SHOW_RELAYLOG_EVENTS": {cmdEngineMySQL, "SHOW RELAYLOG EVENTS"},
	"SHOW_ENGINE_STATUS":   {cmdEngineMySQL, "SHOW ENGINE INNODB STATUS"},
	"SHOW_WARNINGS":        {cmdEngineMySQL, "SHOW WARNINGS"},
	"SHOW_ERRORS":          {cmdEngineMySQL, "SHOW ERRORS"},
	"SHOW_PROCESSLIST":     {cmdEngineMySQL, "SHOW PROCESSLIST"},
	"SHOW_REPLICA_STATUS":  {cmdEngineMySQL, "SHOW REPLICA STATUS"},
	// PostgreSQL.
	"PG_ALTER_SYSTEM":        {cmdEnginePG, "ALTER SYSTEM SET work_mem = '1MB'"},
	"PG_ALTER_ROLE_PASSWORD": {cmdEnginePG, "ALTER ROLE r PASSWORD 'x'"},
	"PG_CREATE_USER_MAPPING": {cmdEnginePG, "CREATE USER MAPPING FOR u SERVER s OPTIONS (user 'x')"},
	"PG_ALTER_SERVER":        {cmdEnginePG, "ALTER SERVER s OPTIONS (SET host 'h')"},
	"PG_COPY_PROGRAM":        {cmdEnginePG, "COPY users TO PROGRAM 'cat > /tmp/x'"},
	// Session-identity / lexer-mode SETs — the "engine-safety" danger set. The analyzer resolves these
	// carrying a system-classified Utility grant (not a hard admission deny), so the system:critical
	// floor forbids them through the same gate as SET_GLOBAL/SET_PASSWORD.
	"SET_ROLE":                        {cmdEnginePG, "SET ROLE analyst"},
	"SET_SESSION_AUTHORIZATION":       {cmdEnginePG, "SET SESSION AUTHORIZATION bob"},
	"SET_STANDARD_CONFORMING_STRINGS": {cmdEnginePG, "SET standard_conforming_strings = off"},
	"SET_SQL_MODE":                    {cmdEngineMySQL, "SET sql_mode = 'ANSI_QUOTES'"},
	// Code-executing / data-reading danger set: a user-type/DOMAIN cast runs the type's coercion
	// function; a subquery / unsafe-function RHS in a SET / SHOW reads data outside a plain query. Each
	// resolves carrying a system:critical Utility grant (the whole-statement gate; column-level masking
	// of the read is backlogged).
	"USER_TYPE_CAST": {cmdEnginePG, "SELECT 'x'::public.evil_domain"},
	"SET_SUBQUERY":   {cmdEngineMySQL, "SET @x = (SELECT rrn FROM users)"},
	"SHOW_SUBQUERY":  {cmdEngineMySQL, "SHOW TABLES WHERE Tables_in_db IN (SELECT rrn FROM users)"},
}

// Manifest command ids DELIBERATELY kept passthrough: their statements are needed by ordinary clients
// (psql/mysql issue them at connect), and they expose server config/counters rather than
// data/credentials. The manifest tag is over-broad relative to the intended enforcement here —
// documented, not a leak.
var intentionalPassthrough = map[string]string{
	"SHOW_VARIABLES": "server config; clients issue SHOW [SESSION] VARIABLES at connect — gating breaks them",
	"SHOW_STATUS":    "server counters (Uptime/Threads_connected); clients poll it — low sensitivity",
	"PG_SHOW_GUC":    "psql issues SHOW <guc> (e.g. SHOW search_path) routinely — gating breaks the client",
}

func TestManifestCommandCoverageDb(t *testing.T) {
	fixtures := map[manifestCmdEngine]*dbtest.EnforcementFixture{
		cmdEnginePG:    newEnforcementFixture(t, dbtest.EnginePostgres),
		cmdEngineMySQL: newEnforcementFixture(t, dbtest.EngineMySQL),
	}
	classifier := shippedClassifier(t)

	decide := func(eng manifestCmdEngine, sql, who string) pb.EnfAction {
		return gateDecide(fixtures[eng], who, sql, classifier).Action
	}
	setVersion := func(eng manifestCmdEngine, version *string) {
		fixtures[eng].SetEngineVersion(version)
	}
	version := func(v string) *string { return &v }

	// KT: ManifestCommandCoverageDbTest.kt#every manifest dangerous command is gated (or documented passthrough) — fail-closed emission guard
	t.Run("every manifest dangerous command is gated (or documented passthrough)", func(t *testing.T) {
		store, err := engine.LoadSystemClassificationStore()
		if err != nil {
			t.Fatalf("the bundled manifests must load: %v", err)
		}
		gated := map[engine.SystemTag]bool{
			engine.TagCritical: true, engine.TagDataLeak: true, engine.TagActivity: true,
		}
		// Completeness: every dangerous command id across every shipped manifest MUST have a coverage
		// sample or an explicit passthrough entry. A new manifest command with neither fails HERE.
		var uncovered []string
		for _, engineName := range []string{dbtest.EnginePostgres, dbtest.EngineMySQL} {
			for _, c := range store.ClassifiersForEngine(engineName) {
				for _, cmd := range c.Manifest().Commands {
					tag, ok := engine.SystemTagFromID(cmd.Tag)
					if !ok || !gated[tag] {
						continue
					}
					_, sampled := manifestCommandSamples[cmd.ID]
					_, allowed := intentionalPassthrough[cmd.ID]
					if !sampled && !allowed {
						uncovered = append(uncovered, engineName+":"+cmd.ID+" ("+cmd.Tag+")")
					}
				}
			}
		}
		sort.Strings(uncovered)
		if len(uncovered) > 0 {
			t.Fatalf("manifest dangerous command(s) with NO decideQuery coverage sample and NO documented "+
				"passthrough — add a sample (must DENY) or an intentionalPassthrough entry, else it relays "+
				"un-gated: %v", uncovered)
		}

		// Enforcement, exercised on BOTH datasource states so the DENY is proven via the real gate on
		// each:
		//   - CERTIFIED (a shipped engine_version) → a utility-emitted command denies via its manifest
		//     `system:` tag forbid (critical unconditional; data-leak/activity floor-denied), and the
		//     non-utility ones via the sql.<kind>/OTHER/admission gates; and
		//   - NO-MANIFEST (nil engine_version) → a utility-emitted command denies via the unclassified
		//     hard-deny, the non-utility ones unchanged.
		// Running both means a typo'd/wrong emitted command id is caught (it would pass ONLY the
		// no-manifest branch, not the certified tag-forbid), and it proves no dangerous command relays on
		// either state.
		ids := make([]string, 0, len(manifestCommandSamples))
		for id := range manifestCommandSamples {
			ids = append(ids, id)
		}
		sort.Strings(ids) // Go map order is randomised; the Kotlin's is insertion order. Sorted = stable.

		for _, state := range []struct {
			name string
			pg   *string
			my   *string
		}{
			{"certified", version("PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc"), version("8.0.44")},
			{"no-manifest", nil, nil},
		} {
			setVersion(cmdEnginePG, state.pg)
			setVersion(cmdEngineMySQL, state.my)
			for _, id := range ids {
				spec := manifestCommandSamples[id]
				if got := decide(spec.engine, spec.sql, dbtest.FixturePrincipal); got != pb.EnfAction_DENY {
					t.Errorf("[%s] %s must DENY on the production floor: %q got %v",
						state.name, id, spec.sql, got)
				}
			}
		}

		// The activity/critical distinction is real: on a CERTIFIED datasource with the system:development
		// relaxation, SHOW REPLICA STATUS (system:activity) is relaxed to ALLOW, but SHOW CREATE USER /
		// SHOW GRANTS (system:critical) are NEVER relaxed — proving the emitted commands carry the right
		// tag, not just "some deny". (No-manifest cannot distinguish these — both hard-deny unclassified.)
		setVersion(cmdEngineMySQL, version("8.0.44"))
		fixtures[cmdEngineMySQL].SetTags("system:development")
		if got := decide(cmdEngineMySQL, "SHOW REPLICA STATUS", dbtest.FixturePrincipal); got != pb.EnfAction_ALLOW {
			t.Errorf("SHOW REPLICA STATUS (activity) must relax on a dev datasource, got %v", got)
		}
		if got := decide(cmdEngineMySQL, "SHOW CREATE USER CURRENT_USER()", dbtest.FixturePrincipal); got != pb.EnfAction_DENY {
			t.Errorf("SHOW CREATE USER (critical) is NEVER relaxed, even on dev, got %v", got)
		}
		if got := decide(cmdEngineMySQL, "SHOW GRANTS", dbtest.FixturePrincipal); got != pb.EnfAction_DENY {
			t.Errorf("SHOW GRANTS (critical) is NEVER relaxed, even on dev, got %v", got)
		}
		fixtures[cmdEngineMySQL].SetTags("system:production")
	})

	// KT: ManifestCommandCoverageDbTest.kt#SELECT INTO OUTFILE cannot exfil a masked column even with sql-ddl granted
	t.Run("SELECT INTO OUTFILE cannot exfil a masked column even with sql-ddl granted", func(t *testing.T) {
		// INTO_OUTFILE/DUMPFILE classify as DDL (a write), so an analyst (no sql.ddl) is denied by the kind
		// gate above. The real exfil concern is a sql.ddl-granted principal: writer@example.com has sql.ddl
		// + the same users grants analyst has, so `SELECT rrn INTO OUTFILE` reads MASKED rrn into a file.
		// The write-references-a-masked-column rule must DENY it regardless of the granted sql.ddl.
		setVersion(cmdEngineMySQL, version("8.0.44"))
		got := decide(cmdEngineMySQL, "SELECT rrn FROM users INTO OUTFILE '/tmp/x'", dbtest.FixtureDDLPrincipal)
		if got != pb.EnfAction_DENY {
			t.Errorf("INTO OUTFILE of a masked column must DENY even with sql.ddl (write-payload rule), "+
				"not exfil cleartext; got %v", got)
		}
	})
}
