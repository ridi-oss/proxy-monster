package detect_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/auditmon/alert"
	"github.com/ridi-oss/proxy-monster/auditmon/canon"
	"github.com/ridi-oss/proxy-monster/auditmon/config"
	"github.com/ridi-oss/proxy-monster/auditmon/detect"
	"github.com/ridi-oss/proxy-monster/auditmon/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/auditmon/store"
)

// captureSink records every delivered alert. It does not dedup — the detector fires per condition and the
// real sink dedups, so a test sees exactly what the rules fired.
type captureSink struct {
	mu     sync.Mutex
	alerts []alert.Alert
}

func (c *captureSink) Deliver(a alert.Alert) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.alerts = append(c.alerts, a)
}

func (c *captureSink) byRule(rule string) []alert.Alert {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []alert.Alert
	for _, a := range c.alerts {
		if a.Rule == rule {
			out = append(out, a)
		}
	}
	return out
}

// seedAndInspect applies the schema, seeds the events as a valid chain, then runs one detector poll with the
// whole seeded trail as the fresh batch. It returns the sink so the caller can assert what fired.
func seedAndInspect(t *testing.T, rules config.RulesConfig, events []canon.AuditEvent) *captureSink {
	t.Helper()
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	dbtest.SeedChain(t, ctx, pool, canon.GenesisHash(), events)

	reader, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	t.Cleanup(reader.Close)

	fresh, err := reader.TailEvents(ctx, 0, 10000)
	if err != nil {
		t.Fatalf("read fresh: %v", err)
	}

	sink := &captureSink{}
	det, err := detect.New(reader, sink, rules)
	if err != nil {
		t.Fatalf("new detector: %v", err)
	}
	if err := det.Inspect(fresh); err != nil {
		t.Fatalf("inspect: %v", err)
	}
	return sink
}

func decision(principal, datasource, statement, decisionVal string, pii []string, ts time.Time) canon.AuditEvent {
	return canon.AuditEvent{
		Kind:       "decision",
		TSMicros:   canon.EpochMicros(ts),
		Principal:  principal,
		Roles:      []string{"analyst"},
		Datasource: datasource,
		Statement:  statement,
		Decision:   decisionVal,
		PIITouched: pii,
	}
}

func completion(principal, datasource string, decisionID, rows, bytes int64, ts time.Time) canon.AuditEvent {
	return canon.AuditEvent{
		Kind:          "completion",
		TSMicros:      canon.EpochMicros(ts),
		Principal:     principal,
		Roles:         []string{"analyst"},
		Datasource:    datasource,
		Statement:     "",
		Decision:      "ALLOW",
		DecisionID:    &decisionID,
		RowsReturned:  &rows,
		BytesReturned: &bytes,
	}
}

func authEvent(principal, outcome, channel, action string, ts time.Time) canon.AuditEvent {
	return canon.AuditEvent{
		Kind:        "auth",
		TSMicros:    canon.EpochMicros(ts),
		Principal:   principal,
		Channel:     &channel,
		AuthzAction: &action,
		Outcome:     &outcome,
	}
}

func adminEvent(principal, action string, ts time.Time) canon.AuditEvent {
	outcome, channel := "ALLOW", "console"
	return canon.AuditEvent{
		Kind:        "admin",
		TSMicros:    canon.EpochMicros(ts),
		Principal:   principal,
		Channel:     &channel,
		AuthzAction: &action,
		Outcome:     &outcome,
	}
}

func repeat(n int, mk func(i int) canon.AuditEvent) []canon.AuditEvent {
	out := make([]canon.AuditEvent, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, mk(i))
	}
	return out
}

// --- repeated_deny ---

func TestRepeatedDeny(t *testing.T) {
	rules := config.RulesConfig{RepeatedDeny: config.RepeatedDenyRule{Window: 10 * time.Minute, MaxDeny: 3}}
	now := time.Now()
	deny := func(int) canon.AuditEvent {
		return decision("mallory", "example-mysql", "SELECT ssn FROM users", "DENY", nil, now)
	}

	// At the threshold (== max) it must NOT fire.
	sink := seedAndInspect(t, rules, repeat(3, deny))
	if got := sink.byRule(config.RuleRepeatedDeny); len(got) != 0 {
		t.Fatalf("3 denies (== max 3) fired %d repeated_deny alerts, want 0", len(got))
	}

	// One over the threshold fires.
	sink = seedAndInspect(t, rules, repeat(4, deny))
	got := sink.byRule(config.RuleRepeatedDeny)
	if len(got) != 1 || got[0].Principal != "mallory" {
		t.Fatalf("4 denies (> max 3) = %+v, want one alert for mallory", got)
	}
}

// --- auth_failure_burst ---

func TestAuthFailureBurst(t *testing.T) {
	rules := config.RulesConfig{AuthFailureBurst: config.AuthFailureBurstRule{Window: 10 * time.Minute, MaxFailures: 3}}
	now := time.Now()
	fail := func(int) canon.AuditEvent {
		return authEvent("mallory", "FAILURE", "wire", "login", now)
	}

	// At the threshold (== max) it must NOT fire.
	sink := seedAndInspect(t, rules, repeat(3, fail))
	if got := sink.byRule(config.RuleAuthFailureBurst); len(got) != 0 {
		t.Fatalf("3 auth failures (== max 3) fired %d auth_failure_burst alerts, want 0", len(got))
	}

	// One over the threshold fires, at warn, for the right principal.
	sink = seedAndInspect(t, rules, repeat(4, fail))
	got := sink.byRule(config.RuleAuthFailureBurst)
	if len(got) != 1 || got[0].Principal != "mallory" || got[0].Severity != config.SeverityWarn {
		t.Fatalf("4 auth failures (> max 3) = %+v, want one warn alert for mallory", got)
	}

	// Successful auth events never count toward the burst, even well past the threshold.
	success := func(int) canon.AuditEvent {
		return authEvent("mallory", "SUCCESS", "wire", "login", now)
	}
	sink = seedAndInspect(t, rules, repeat(10, success))
	if got := sink.byRule(config.RuleAuthFailureBurst); len(got) != 0 {
		t.Fatalf("10 auth successes fired %d auth_failure_burst alerts, want 0", len(got))
	}
}

// TestAuthFailureBurstUnknownPrincipal confirms that unattributed failures — rejected wire tokens that carry
// the principal "unknown" — still burst: "unknown" is keyed like any other principal.
func TestAuthFailureBurstUnknownPrincipal(t *testing.T) {
	rules := config.RulesConfig{AuthFailureBurst: config.AuthFailureBurstRule{Window: 10 * time.Minute, MaxFailures: 3}}
	now := time.Now()
	fail := func(int) canon.AuditEvent {
		return authEvent("unknown", "FAILURE", "wire", "token_validate", now)
	}
	sink := seedAndInspect(t, rules, repeat(4, fail))
	got := sink.byRule(config.RuleAuthFailureBurst)
	if len(got) != 1 || got[0].Principal != "unknown" {
		t.Fatalf("4 unknown-principal auth failures = %+v, want one alert for unknown", got)
	}
}

// --- off_hours_admin ---

func TestOffHoursAdmin(t *testing.T) {
	rules := config.RulesConfig{
		OffHours:      config.OffHoursRule{BusinessHours: "09:00-19:00 Asia/Seoul", AppliesTo: []string{"pii_read", "write"}},
		OffHoursAdmin: config.OffHoursAdminRule{Enabled: true},
	}
	seoul, err := time.LoadLocation("Asia/Seoul")
	if err != nil {
		t.Fatalf("load location: %v", err)
	}
	mon0300 := time.Date(2026, 1, 5, 3, 0, 0, 0, seoul)  // Monday, before business hours
	mon1200 := time.Date(2026, 1, 5, 12, 0, 0, 0, seoul) // Monday, business hours

	// An admin change inside business hours does NOT fire.
	sink := seedAndInspect(t, rules, []canon.AuditEvent{adminEvent("root", "policy.update", mon1200)})
	if got := sink.byRule(config.RuleOffHoursAdmin); len(got) != 0 {
		t.Fatalf("business-hours admin change fired %d off_hours_admin alerts, want 0", len(got))
	}

	// The same change outside business hours fires, at warn, for the right principal.
	sink = seedAndInspect(t, rules, []canon.AuditEvent{adminEvent("root", "policy.update", mon0300)})
	got := sink.byRule(config.RuleOffHoursAdmin)
	if len(got) != 1 || got[0].Principal != "root" || got[0].Severity != config.SeverityWarn {
		t.Fatalf("off-hours admin change = %+v, want one warn alert for root", got)
	}
}

// TestOffHoursAdminNoCrossKind confirms the admin rule keys strictly on kind "admin": an off-hours decision
// or auth event does not trigger it, and an off-hours admin change does not leak into the pii off_hours rule.
func TestOffHoursAdminNoCrossKind(t *testing.T) {
	rules := config.RulesConfig{
		OffHours:      config.OffHoursRule{BusinessHours: "09:00-19:00 Asia/Seoul", AppliesTo: []string{"pii_read", "write"}},
		OffHoursAdmin: config.OffHoursAdminRule{Enabled: true},
	}
	seoul, _ := time.LoadLocation("Asia/Seoul")
	mon0300 := time.Date(2026, 1, 5, 3, 0, 0, 0, seoul) // off-hours

	events := []canon.AuditEvent{
		decision("alice", "example-mysql", "SELECT email FROM users", "ALLOW", []string{"pii:email"}, mon0300),
		authEvent("mallory", "FAILURE", "wire", "login", mon0300),
		adminEvent("root", "policy.update", mon0300),
	}
	sink := seedAndInspect(t, rules, events)

	// Exactly the admin change triggers off_hours_admin — not the decision, not the auth event.
	if got := sink.byRule(config.RuleOffHoursAdmin); len(got) != 1 || got[0].Principal != "root" {
		t.Fatalf("off_hours_admin = %+v, want exactly the admin change (root)", got)
	}
	// The admin change is neither a PII read nor a write, so it must not appear under the pii off_hours rule.
	for _, a := range sink.byRule(config.RuleOffHours) {
		if a.Principal == "root" {
			t.Fatalf("admin change leaked into the pii off_hours rule: %+v", a)
		}
	}
}

// New fails closed when off_hours_admin is enabled without a business-hours window, rather than
// constructing a detector whose enabled rule can never fire (Config.Validate rejects it too).
func TestNewRejectsEnabledOffHoursAdminWithoutBusinessHours(t *testing.T) {
	if _, err := detect.New(nil, nil, config.RulesConfig{
		OffHoursAdmin: config.OffHoursAdminRule{Enabled: true},
	}); err == nil {
		t.Fatal("New should reject off_hours_admin enabled with no business_hours window")
	}
}

// --- bulk_pii ---

func TestBulkPIIDecisionCount(t *testing.T) {
	rules := config.RulesConfig{BulkPII: config.BulkPIIRule{Window: 5 * time.Minute, MaxPIIDecisions: 3}}
	now := time.Now()
	read := func(i int) canon.AuditEvent {
		return decision("alice", "example-mysql", "SELECT email FROM users", "ALLOW", []string{"pii:email"}, now)
	}

	sink := seedAndInspect(t, rules, repeat(3, read))
	if got := sink.byRule(config.RuleBulkPII); len(got) != 0 {
		t.Fatalf("3 pii decisions (== max 3) fired %d, want 0", len(got))
	}

	sink = seedAndInspect(t, rules, repeat(4, read))
	if got := sink.byRule(config.RuleBulkPII); len(got) != 1 {
		t.Fatalf("4 pii decisions (> max 3) fired %d, want 1", len(got))
	}
}

func TestBulkPIIDistinctColumns(t *testing.T) {
	// Only the distinct-columns dimension is enabled (decision count disabled with 0).
	rules := config.RulesConfig{BulkPII: config.BulkPIIRule{Window: 5 * time.Minute, MaxDistinctPIIColumns: 2}}
	now := time.Now()

	// Two decisions touching two distinct columns total: at the boundary, no fire.
	twoCols := []canon.AuditEvent{
		decision("alice", "example-mysql", "SELECT email FROM users", "ALLOW", []string{"pii:email"}, now),
		decision("alice", "example-mysql", "SELECT phone FROM users", "ALLOW", []string{"pii:phone"}, now),
	}
	sink := seedAndInspect(t, rules, twoCols)
	if got := sink.byRule(config.RuleBulkPII); len(got) != 0 {
		t.Fatalf("2 distinct pii columns (== max 2) fired %d, want 0", len(got))
	}

	// A third distinct column crosses the threshold.
	threeCols := append(twoCols, decision("alice", "example-mysql", "SELECT ssn FROM users", "MASK", []string{"pii:ssn"}, now))
	sink = seedAndInspect(t, rules, threeCols)
	if got := sink.byRule(config.RuleBulkPII); len(got) != 1 {
		t.Fatalf("3 distinct pii columns (> max 2) fired %d, want 1", len(got))
	}
}

// --- mass_export (completion-volume) ---

func TestMassExportVolume(t *testing.T) {
	rules := config.RulesConfig{MassExport: config.MassExportRule{
		Window:        10 * time.Minute,
		PerDatasource: map[string]config.VolumeThreshold{"example-mysql": {Rows: 50000}},
	}}
	now := time.Now()

	// A decision plus a completion whose rows exactly equal the ceiling: at the boundary, no fire.
	atCeiling := []canon.AuditEvent{
		decision("bob", "example-mysql", "SELECT * FROM users", "ALLOW", nil, now),
		completion("bob", "example-mysql", 1, 50000, 0, now),
	}
	sink := seedAndInspect(t, rules, atCeiling)
	if got := sink.byRule(config.RuleMassExport); len(got) != 0 {
		t.Fatalf("50000 rows (== ceiling) fired %d mass_export alerts, want 0", len(got))
	}

	// One row over the ceiling fires, at critical severity, attributed to the decision's principal+datasource.
	overCeiling := []canon.AuditEvent{
		decision("bob", "example-mysql", "SELECT * FROM users", "ALLOW", nil, now),
		completion("bob", "example-mysql", 1, 50001, 0, now),
	}
	sink = seedAndInspect(t, rules, overCeiling)
	got := sink.byRule(config.RuleMassExport)
	if len(got) != 1 {
		t.Fatalf("50001 rows (> ceiling) fired %d, want 1", len(got))
	}
	if got[0].Severity != config.SeverityCritical || got[0].Principal != "bob" || got[0].Datasource != "example-mysql" {
		t.Fatalf("mass_export alert = %+v, want critical bob/example-mysql", got[0])
	}
}

// TestMassExportBytesDimension confirms the bytes ceiling catches a few wide rows even when the row count is
// small.
func TestMassExportBytesDimension(t *testing.T) {
	rules := config.RulesConfig{MassExport: config.MassExportRule{
		Window:        10 * time.Minute,
		PerDatasource: map[string]config.VolumeThreshold{"example-mysql": {Bytes: 1000}},
	}}
	now := time.Now()
	events := []canon.AuditEvent{
		decision("bob", "example-mysql", "SELECT blob FROM docs", "ALLOW", nil, now),
		completion("bob", "example-mysql", 1, 3, 1500, now), // only 3 rows, but 1500 bytes > 1000
	}
	sink := seedAndInspect(t, rules, events)
	if got := sink.byRule(config.RuleMassExport); len(got) != 1 {
		t.Fatalf("1500 bytes (> 1000) fired %d, want 1", len(got))
	}
}

// --- mass_export (statement-shape heuristic degradation) ---

func TestMassExportHeuristicDegradation(t *testing.T) {
	rules := config.RulesConfig{MassExport: config.MassExportRule{
		Window:                 10 * time.Minute,
		HeuristicMaxBroadReads: 2,
	}}
	now := time.Now()
	broad := func(int) canon.AuditEvent {
		// A SELECT with no LIMIT is a broad (unbounded) read — the heuristic's stand-in for volume.
		return decision("bob", "example-mysql", "SELECT * FROM users", "ALLOW", nil, now)
	}

	// No completion events in the window, so mass_export degrades to counting broad reads. At the heuristic
	// boundary, no fire.
	sink := seedAndInspect(t, rules, repeat(2, broad))
	if got := sink.byRule(config.RuleMassExport); len(got) != 0 {
		t.Fatalf("2 broad reads (== heuristic max) fired %d, want 0", len(got))
	}

	// A third broad read crosses the heuristic threshold and fires at warn (weaker signal than volume).
	sink = seedAndInspect(t, rules, repeat(3, broad))
	got := sink.byRule(config.RuleMassExport)
	if len(got) != 1 {
		t.Fatalf("3 broad reads (> heuristic max) fired %d, want 1", len(got))
	}
	if got[0].Severity != config.SeverityWarn {
		t.Fatalf("heuristic mass_export severity = %q, want warn", got[0].Severity)
	}
}

// TestMassExportVolumeSuppressesHeuristic confirms that when completion events are present, volume mode wins:
// broad reads over the heuristic threshold do NOT fire while the summed volume is under the ceiling.
func TestMassExportVolumeSuppressesHeuristic(t *testing.T) {
	rules := config.RulesConfig{MassExport: config.MassExportRule{
		Window:                 10 * time.Minute,
		HeuristicMaxBroadReads: 1,
		PerDatasource:          map[string]config.VolumeThreshold{"example-mysql": {Rows: 50000}},
	}}
	now := time.Now()
	events := []canon.AuditEvent{
		decision("bob", "example-mysql", "SELECT * FROM users", "ALLOW", nil, now),  // broad read #1 (id 1)
		decision("bob", "example-mysql", "SELECT * FROM orders", "ALLOW", nil, now), // broad read #2 (id 2)
		completion("bob", "example-mysql", 1, 10, 0, now),                           // a completion exists → volume mode
	}
	sink := seedAndInspect(t, rules, events)
	if got := sink.byRule(config.RuleMassExport); len(got) != 0 {
		t.Fatalf("volume under ceiling fired %d despite 2 broad reads > heuristic max 1, want 0 (volume mode wins)", len(got))
	}
}

// TestMassExportUnprotectedDatasourceStillAlerts is the regression for the fail-closed fall-through: a
// datasource whose resolved threshold is {0,0} (no per_datasource entry and a zero default) has completion
// volume that no ceiling can judge. Rather than pass it silently, the detector must fall through to the
// broad-read heuristic so a genuine mass export still alerts.
func TestMassExportUnprotectedDatasourceStillAlerts(t *testing.T) {
	// Window enabled, a heuristic ceiling set, but NO rows/bytes threshold for any datasource.
	rules := config.RulesConfig{MassExport: config.MassExportRule{
		Window:                 10 * time.Minute,
		HeuristicMaxBroadReads: 2,
	}}
	now := time.Now()
	events := []canon.AuditEvent{
		decision("bob", "example-mysql", "SELECT * FROM users", "ALLOW", nil, now), // broad read (id 1)
		decision("bob", "example-mysql", "SELECT * FROM users", "ALLOW", nil, now), // broad read (id 2)
		decision("bob", "example-mysql", "SELECT * FROM users", "ALLOW", nil, now), // broad read (id 3)
		completion("bob", "example-mysql", 1, 1_000_000, 0, now),                   // huge volume (id 4)
	}
	sink := seedAndInspect(t, rules, events)
	got := sink.byRule(config.RuleMassExport)
	if len(got) != 1 {
		t.Fatalf("unprotected datasource with high volume fired %d mass_export alerts, want 1 (heuristic fall-through)", len(got))
	}
	if got[0].Severity != config.SeverityWarn || got[0].Principal != "bob" || got[0].Datasource != "example-mysql" {
		t.Fatalf("mass_export alert = %+v, want warn bob/example-mysql", got[0])
	}
}

// --- off_hours ---

func TestOffHours(t *testing.T) {
	rules := config.RulesConfig{OffHours: config.OffHoursRule{
		BusinessHours: "09:00-19:00 Asia/Seoul",
		AppliesTo:     []string{"pii_read", "write"},
	}}
	seoul, err := time.LoadLocation("Asia/Seoul")
	if err != nil {
		t.Fatalf("load location: %v", err)
	}
	mon0300 := time.Date(2026, 1, 5, 3, 0, 0, 0, seoul)  // Monday, before business hours
	mon1200 := time.Date(2026, 1, 5, 12, 0, 0, 0, seoul) // Monday, business hours
	sat1200 := time.Date(2026, 1, 3, 12, 0, 0, 0, seoul) // Saturday, weekend

	events := []canon.AuditEvent{
		decision("alice", "example-mysql", "SELECT email FROM users", "ALLOW", []string{"pii:email"}, mon0300), // off → fire
		decision("alice", "example-mysql", "SELECT email FROM users", "ALLOW", []string{"pii:email"}, mon1200), // business → no fire
		decision("carol", "example-mysql", "UPDATE users SET x=1", "ALLOW", nil, mon0300),                      // off write → fire
		decision("dave", "example-mysql", "SELECT email FROM users", "ALLOW", []string{"pii:email"}, sat1200),  // weekend → fire
	}
	sink := seedAndInspect(t, rules, events)
	got := sink.byRule(config.RuleOffHours)
	if len(got) != 3 {
		t.Fatalf("off_hours fired %d alerts, want 3 (the two off-hours reads/writes + the weekend read): %+v", len(got), got)
	}
}

func TestOffHoursAppliesToFilter(t *testing.T) {
	// Only writes are watched: an off-hours PII read must be ignored, an off-hours write must fire.
	rules := config.RulesConfig{OffHours: config.OffHoursRule{
		BusinessHours: "09:00-19:00 Asia/Seoul",
		AppliesTo:     []string{"write"},
	}}
	seoul, _ := time.LoadLocation("Asia/Seoul")
	mon0300 := time.Date(2026, 1, 5, 3, 0, 0, 0, seoul)

	events := []canon.AuditEvent{
		decision("alice", "example-mysql", "SELECT email FROM users", "ALLOW", []string{"pii:email"}, mon0300), // pii_read off → ignored
		decision("carol", "example-mysql", "DELETE FROM users", "ALLOW", nil, mon0300),                         // write off → fire
	}
	sink := seedAndInspect(t, rules, events)
	got := sink.byRule(config.RuleOffHours)
	if len(got) != 1 || got[0].Principal != "carol" {
		t.Fatalf("off_hours with applies_to=[write] = %+v, want one alert for carol's write", got)
	}
}

// TestDisabledRulesReadNothing confirms a detector with no enabled rate rules performs no window read and
// fires nothing on a batch of ordinary reads.
func TestDisabledRulesFireNothing(t *testing.T) {
	now := time.Now()
	events := repeat(5, func(int) canon.AuditEvent {
		return decision("alice", "example-mysql", "SELECT id FROM users LIMIT 10", "ALLOW", nil, now)
	})
	sink := seedAndInspect(t, config.RulesConfig{}, events)
	if len(sink.alerts) != 0 {
		t.Fatalf("disabled rules fired %d alerts, want 0", len(sink.alerts))
	}
}
