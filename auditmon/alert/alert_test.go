package alert

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/auditmon/config"
	"github.com/ridi-oss/proxy-monster/auditmon/verify"
	"github.com/ridi-oss/proxy-monster/auditmon/worm"
)

// capture is an httptest handler that records every request body and can be told to fail a number of leading
// requests (to exercise retry).
type capture struct {
	mu        sync.Mutex
	bodies    [][]byte
	failFirst int
}

func (c *capture) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.bodies = append(c.bodies, body)
		n := len(c.bodies)
		fail := n <= c.failFirst
		c.mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func (c *capture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.bodies)
}

func (c *capture) last() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.bodies) == 0 {
		return nil
	}
	return c.bodies[len(c.bodies)-1]
}

// wormAlerts returns every alerts/ object body in the store.
func wormAlerts(t *testing.T, os worm.ObjectStore) [][]byte {
	t.Helper()
	keys, err := os.List("alerts/")
	if err != nil {
		t.Fatalf("list alerts: %v", err)
	}
	var out [][]byte
	for _, k := range keys {
		b, err := os.Get(k)
		if err != nil {
			t.Fatalf("get %s: %v", k, err)
		}
		out = append(out, b)
	}
	return out
}

func fastSink(t *testing.T, cfg config.AlertsConfig, store worm.ObjectStore) *Sink {
	t.Helper()
	s, err := New(cfg, store, WithBackoffBase(time.Millisecond))
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	return s
}

func TestDeliverWritesWormAndPostsWebhook(t *testing.T) {
	cap := &capture{}
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()
	t.Setenv("SECOPS_WEBHOOK_URL", srv.URL)

	store := worm.NewMemory()
	sink := fastSink(t, config.AlertsConfig{
		DedupWindow: time.Hour,
		Sinks:       []config.SinkConfig{{Type: "webhook", URLEnv: "SECOPS_WEBHOOK_URL", MinSeverity: "warn", Rules: []string{"*"}}},
	}, store)

	sink.Deliver(Alert{
		Severity:    config.SeverityWarn,
		Rule:        config.RuleBulkPII,
		Principal:   "alice",
		Datasource:  "example-mysql",
		DecisionIDs: []int64{7, 8, 9},
		TS:          time.Unix(1_700_000_000, 0),
	})

	if cap.count() != 1 {
		t.Fatalf("webhook posts = %d, want 1", cap.count())
	}
	var got payload
	if err := json.Unmarshal(cap.last(), &got); err != nil {
		t.Fatalf("decode webhook body: %v", err)
	}
	if got.Rule != config.RuleBulkPII || got.Principal != "alice" || got.Datasource != "example-mysql" {
		t.Errorf("webhook payload = %+v", got)
	}
	if len(got.DecisionIDs) != 3 || got.Anchor == "" {
		t.Errorf("webhook payload ids/anchor = %+v", got)
	}

	alerts := wormAlerts(t, store)
	if len(alerts) != 1 {
		t.Fatalf("worm alerts = %d, want 1", len(alerts))
	}
	var durable payload
	if err := json.Unmarshal(alerts[0], &durable); err != nil {
		t.Fatalf("decode worm alert: %v", err)
	}
	if durable.Anchor != got.Anchor {
		t.Errorf("worm anchor %q != webhook anchor %q", durable.Anchor, got.Anchor)
	}
}

func TestRoutingBySeverityAndRule(t *testing.T) {
	all := &capture{}
	crit := &capture{}
	allSrv := httptest.NewServer(all.handler())
	defer allSrv.Close()
	critSrv := httptest.NewServer(crit.handler())
	defer critSrv.Close()
	t.Setenv("ALL_URL", allSrv.URL)
	t.Setenv("CRIT_URL", critSrv.URL)

	sink := fastSink(t, config.AlertsConfig{
		DedupWindow: time.Hour,
		Sinks: []config.SinkConfig{
			{Type: "webhook", URLEnv: "ALL_URL", MinSeverity: "warn", Rules: []string{"*"}},
			{Type: "webhook", URLEnv: "CRIT_URL", MinSeverity: "critical", Rules: []string{config.RuleMassExport}},
		},
	}, worm.NewMemory())

	// A warn bulk_pii alert reaches only the catch-all sink.
	sink.Deliver(Alert{Severity: config.SeverityWarn, Rule: config.RuleBulkPII, Principal: "a", TS: time.Now()})
	if all.count() != 1 || crit.count() != 0 {
		t.Fatalf("after warn: all=%d crit=%d, want 1/0", all.count(), crit.count())
	}

	// A critical mass_export reaches both (severity >= floor and rule matches).
	sink.Deliver(Alert{Severity: config.SeverityCritical, Rule: config.RuleMassExport, Principal: "b", TS: time.Now()})
	if all.count() != 2 || crit.count() != 1 {
		t.Fatalf("after critical: all=%d crit=%d, want 2/1", all.count(), crit.count())
	}

	// A critical off_hours does NOT reach the mass_export-only sink (rule filter).
	sink.Deliver(Alert{Severity: config.SeverityCritical, Rule: config.RuleOffHours, Principal: "c", TS: time.Now()})
	if crit.count() != 1 {
		t.Fatalf("off_hours reached the mass_export-only sink: crit=%d, want still 1", crit.count())
	}
}

func TestRetryWithBackoffSucceeds(t *testing.T) {
	cap := &capture{failFirst: 2}
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()
	t.Setenv("SECOPS_WEBHOOK_URL", srv.URL)

	sink := fastSink(t, config.AlertsConfig{
		DedupWindow: time.Hour,
		Sinks:       []config.SinkConfig{{Type: "webhook", URLEnv: "SECOPS_WEBHOOK_URL", MinSeverity: "warn", Rules: []string{"*"}, MaxRetries: 3}},
	}, worm.NewMemory())

	sink.Deliver(Alert{Severity: config.SeverityWarn, Rule: config.RuleRepeatedDeny, Principal: "a", TS: time.Now()})

	// Two 500s then a 200: exactly three attempts.
	if cap.count() != 3 {
		t.Fatalf("attempts = %d, want 3 (2 failures + 1 success)", cap.count())
	}
}

func TestRetryExhaustionKeepsWormRecord(t *testing.T) {
	cap := &capture{failFirst: 1000} // always fails
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()
	t.Setenv("SECOPS_WEBHOOK_URL", srv.URL)

	store := worm.NewMemory()
	sink := fastSink(t, config.AlertsConfig{
		DedupWindow: time.Hour,
		Sinks:       []config.SinkConfig{{Type: "webhook", URLEnv: "SECOPS_WEBHOOK_URL", MinSeverity: "warn", Rules: []string{"*"}, MaxRetries: 2}},
	}, store)

	sink.Deliver(Alert{Severity: config.SeverityWarn, Rule: config.RuleRepeatedDeny, Principal: "a", TS: time.Now()})

	if cap.count() != 3 { // initial + 2 retries
		t.Fatalf("attempts = %d, want 3 (initial + 2 retries)", cap.count())
	}
	// A webhook that never succeeds must not lose the alert: it is still durable in WORM.
	if alerts := wormAlerts(t, store); len(alerts) != 1 {
		t.Fatalf("worm alerts = %d, want the alert durable despite webhook failure", len(alerts))
	}
}

func TestDedupSuppressesRepeat(t *testing.T) {
	cap := &capture{}
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()
	t.Setenv("SECOPS_WEBHOOK_URL", srv.URL)

	store := worm.NewMemory()
	sink := fastSink(t, config.AlertsConfig{
		DedupWindow: time.Hour,
		Sinks:       []config.SinkConfig{{Type: "webhook", URLEnv: "SECOPS_WEBHOOK_URL", MinSeverity: "warn", Rules: []string{"*"}}},
	}, store)

	a := Alert{Severity: config.SeverityWarn, Rule: config.RuleRepeatedDeny, Principal: "alice", Datasource: "example-mysql", TS: time.Now()}
	sink.Deliver(a)
	sink.Deliver(a) // same subject within the dedup window

	if cap.count() != 1 {
		t.Fatalf("webhook posts = %d, want 1 (duplicate suppressed)", cap.count())
	}
	if alerts := wormAlerts(t, store); len(alerts) != 1 {
		t.Fatalf("worm alerts = %d, want 1 (duplicate suppressed)", len(alerts))
	}

	// A different subject is not suppressed.
	sink.Deliver(Alert{Severity: config.SeverityWarn, Rule: config.RuleRepeatedDeny, Principal: "bob", Datasource: "example-mysql", TS: time.Now()})
	if cap.count() != 2 {
		t.Fatalf("webhook posts = %d, want 2 after a distinct subject", cap.count())
	}
}

func TestSlackFormatBody(t *testing.T) {
	cap := &capture{}
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()
	t.Setenv("SLACK_WEBHOOK_URL", srv.URL)

	sink := fastSink(t, config.AlertsConfig{
		DedupWindow: time.Hour,
		Sinks:       []config.SinkConfig{{Type: "webhook", URLEnv: "SLACK_WEBHOOK_URL", MinSeverity: "warn", Rules: []string{"*"}, Format: "slack"}},
	}, worm.NewMemory())

	sink.Deliver(Alert{Severity: config.SeverityCritical, Rule: config.RuleMassExport, Principal: "alice", TS: time.Now()})

	var body map[string]any
	if err := json.Unmarshal(cap.last(), &body); err != nil {
		t.Fatalf("decode slack body: %v", err)
	}
	text, ok := body["text"].(string)
	if !ok || text == "" {
		t.Fatalf("slack body = %v, want a non-empty text field", body)
	}
	if _, hasBlocks := body["blocks"]; !hasBlocks {
		t.Errorf("slack body should carry Block Kit blocks: %v", body)
	}
	if _, isCanonical := body["decision_ids"]; isCanonical {
		t.Errorf("slack body must not be the canonical payload shape: %v", body)
	}
}

func TestSlackLinksDecisionsToConsole(t *testing.T) {
	cap := &capture{}
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()
	t.Setenv("SLACK_WEBHOOK_URL", srv.URL)

	sink := fastSink(t, config.AlertsConfig{
		DedupWindow: time.Hour,
		ConsoleURL:  "https://console.example/", // trailing slash must be trimmed
		Sinks:       []config.SinkConfig{{Type: "webhook", URLEnv: "SLACK_WEBHOOK_URL", MinSeverity: "warn", Rules: []string{"*"}, Format: "slack"}},
	}, worm.NewMemory())

	sink.Deliver(Alert{Severity: config.SeverityWarn, Rule: config.RuleRepeatedDeny, Principal: "alice", DecisionIDs: []int64{7, 7, 9}, TS: time.Now()})

	body := string(cap.last())
	if !strings.Contains(body, "<https://console.example/audit/7|#7>") {
		t.Errorf("missing console link for decision 7 (or slash not trimmed): %s", body)
	}
	if !strings.Contains(body, "<https://console.example/audit/9|#9>") {
		t.Errorf("missing console link for decision 9: %s", body)
	}
	if n := strings.Count(body, "audit/7|"); n != 1 {
		t.Errorf("decision 7 should be linked once (deduplicated), got %d: %s", n, body)
	}
}

func TestIntegrityReporterDelivers(t *testing.T) {
	cap := &capture{}
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()
	t.Setenv("SECOPS_WEBHOOK_URL", srv.URL)

	store := worm.NewMemory()
	sink := fastSink(t, config.AlertsConfig{
		DedupWindow: time.Hour,
		Sinks:       []config.SinkConfig{{Type: "webhook", URLEnv: "SECOPS_WEBHOOK_URL", MinSeverity: "warn", Rules: []string{"*"}}},
	}, store)

	reporter := NewReporter(sink)
	reporter.Report(verify.Finding{DivergentID: 103, Reason: verify.ReasonRowHashMismatch})

	if cap.count() != 1 {
		t.Fatalf("webhook posts = %d, want 1", cap.count())
	}
	var got payload
	if err := json.Unmarshal(cap.last(), &got); err != nil {
		t.Fatalf("decode webhook body: %v", err)
	}
	if got.Rule != config.RuleIntegrity || got.Severity != config.SeverityCritical {
		t.Errorf("integrity alert = %+v, want critical integrity", got)
	}
	if len(got.DecisionIDs) != 1 || got.DecisionIDs[0] != 103 {
		t.Errorf("integrity alert ids = %v, want [103]", got.DecisionIDs)
	}
	if alerts := wormAlerts(t, store); len(alerts) != 1 {
		t.Fatalf("worm alerts = %d, want 1", len(alerts))
	}
}

func TestNewRejectsMissingURLEnv(t *testing.T) {
	// Env var intentionally unset: a configured sink with no URL is a loud, fail-closed error.
	_, err := New(config.AlertsConfig{
		Sinks: []config.SinkConfig{{Type: "webhook", URLEnv: "DEFINITELY_UNSET_WEBHOOK_URL", MinSeverity: "warn"}},
	}, worm.NewMemory())
	if err == nil {
		t.Fatal("expected New to reject a sink whose url_env is unset")
	}
}
