// Package alert delivers anomaly and integrity alerts out-of-band. Every alert is first written as an
// immutable alerts/<id>.json object to the WORM store — the durable system of record, tamper-evident and
// SIEM-ingestible — and then POSTed to any configured webhook sinks. Because the WORM write happens first, a
// webhook that ultimately fails never loses the alert. Delivery is deduplicated per subject over a window and
// is non-recursive: an alert is written only to the WORM alerts/ prefix, never back to the audit trail, so it
// can never itself trigger a rule.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ridi-oss/proxy-monster/auditmon/config"
	"github.com/ridi-oss/proxy-monster/auditmon/worm"
)

// Alert is one detected condition ready for delivery. The detector fills every field except Anchor; the sink
// assigns Anchor (the durable object id) at delivery so the webhook payload points back at the WORM record.
type Alert struct {
	Severity    string
	Rule        string
	Principal   string
	Datasource  string
	DecisionIDs []int64
	TS          time.Time
}

// payload is the canonical alert JSON — the exact shape written to WORM and POSTed to a default (non-slack)
// webhook. Anchor is the alerts/<anchor>.json object id a recipient uses to fetch the durable record.
type payload struct {
	Severity    string  `json:"severity"`
	Rule        string  `json:"rule"`
	Principal   string  `json:"principal"`
	Datasource  string  `json:"datasource"`
	DecisionIDs []int64 `json:"decision_ids"`
	TS          string  `json:"ts"`
	Anchor      string  `json:"anchor"`
}

// destination is one resolved webhook sink: the POST target plus its routing filters and delivery knobs.
type destination struct {
	url        string
	minRank    int
	matchAll   bool
	ruleSet    map[string]struct{}
	format     string
	timeout    time.Duration
	maxRetries int
}

// routes reports whether an alert should go to this destination: at or above its severity floor and matching
// its rule filter.
func (d destination) routes(a Alert) bool {
	if config.SeverityRank(a.Severity) < d.minRank {
		return false
	}
	if d.matchAll {
		return true
	}
	_, ok := d.ruleSet[a.Rule]
	return ok
}

// Sink is the alert delivery fan-out: it dedups, writes the WORM record, and POSTs to each routed webhook. It
// is safe for concurrent use.
type Sink struct {
	store       worm.ObjectStore
	dests       []destination
	dedupWindow time.Duration
	client      *http.Client
	backoffBase time.Duration
	consoleURL  string
	log         *slog.Logger

	mu       sync.Mutex
	lastSent map[string]time.Time
	seq      int64
}

// Option tunes a Sink at construction (test hooks for the HTTP client and retry backoff).
type Option func(*Sink)

// WithHTTPClient overrides the HTTP client used for webhook POSTs.
func WithHTTPClient(c *http.Client) Option { return func(s *Sink) { s.client = c } }

// WithBackoffBase overrides the initial retry backoff (doubling each retry).
func WithBackoffBase(d time.Duration) Option { return func(s *Sink) { s.backoffBase = d } }

// WithLogger overrides the logger.
func WithLogger(l *slog.Logger) Option { return func(s *Sink) { s.log = l } }

const (
	defaultTimeout    = 5 * time.Second
	defaultMaxRetries = 3
	defaultBackoff    = 250 * time.Millisecond
)

// New builds a Sink from the alerts config. Each sink's URL is resolved from its named env var (secrets never
// live in the file); a configured sink whose env var is unset is a loud, fail-closed error rather than a
// silently-dead notification path.
func New(cfg config.AlertsConfig, store worm.ObjectStore, opts ...Option) (*Sink, error) {
	s := &Sink{
		store:       store,
		dedupWindow: cfg.DedupWindow,
		client:      &http.Client{},
		backoffBase: defaultBackoff,
		log:         slog.Default(),
		lastSent:    make(map[string]time.Time),
	}
	for _, o := range opts {
		o(s)
	}
	s.consoleURL = strings.TrimRight(strings.TrimSpace(cfg.ConsoleURL), "/")
	for i, sc := range cfg.Sinks {
		url := strings.TrimSpace(os.Getenv(sc.URLEnv))
		if url == "" {
			return nil, fmt.Errorf("alert: sinks[%d] env var %s (url_env) is empty", i, sc.URLEnv)
		}
		d := destination{
			url:        url,
			minRank:    config.SeverityRank(sc.MinSeverity),
			format:     sc.Format,
			timeout:    sc.Timeout,
			maxRetries: sc.MaxRetries,
		}
		if d.timeout <= 0 {
			d.timeout = defaultTimeout
		}
		if d.maxRetries <= 0 {
			d.maxRetries = defaultMaxRetries
		}
		rules := sc.Rules
		if len(rules) == 0 {
			rules = []string{"*"}
		}
		d.ruleSet = make(map[string]struct{}, len(rules))
		for _, r := range rules {
			if r == "*" {
				d.matchAll = true
			}
			d.ruleSet[r] = struct{}{}
		}
		s.dests = append(s.dests, d)
	}
	return s, nil
}

// Deliver durably records the alert and notifies every routed webhook. Duplicate subjects (same
// rule+principal+datasource) inside the dedup window are suppressed. Errors are logged and swallowed so
// delivery can never block or slow the monitor.
func (s *Sink) Deliver(a Alert) {
	if a.Severity == "" {
		a.Severity = config.SeverityWarn
	}
	ts := a.TS
	if ts.IsZero() {
		ts = time.Now()
	}

	now := time.Now()
	key := a.Rule + "|" + a.Principal + "|" + a.Datasource
	s.mu.Lock()
	if last, ok := s.lastSent[key]; ok && s.dedupWindow > 0 && now.Sub(last) < s.dedupWindow {
		s.mu.Unlock()
		return
	}
	s.lastSent[key] = now
	s.seq++
	seq := s.seq
	s.mu.Unlock()

	id := fmt.Sprintf("%d-%s-%d", ts.UTC().UnixNano(), sanitizeID(a.Rule), seq)
	p := payload{
		Severity:    a.Severity,
		Rule:        a.Rule,
		Principal:   a.Principal,
		Datasource:  a.Datasource,
		DecisionIDs: a.DecisionIDs,
		TS:          ts.UTC().Format(time.RFC3339Nano),
		Anchor:      id,
	}
	if p.DecisionIDs == nil {
		p.DecisionIDs = []int64{}
	}

	// WORM first: the alert must be durable before any webhook is attempted, so a failed webhook never loses
	// it. A WORM write failure is itself logged but must not stop the webhook notification.
	body, err := json.Marshal(p)
	if err != nil {
		s.log.Error("alert: marshal payload", "err", err, "rule", a.Rule)
		return
	}
	if err := s.store.Put("alerts/"+id+".json", body); err != nil {
		s.log.Error("alert: worm write failed", "err", err, "id", id, "rule", a.Rule)
	}

	for _, d := range s.dests {
		if !d.routes(a) {
			continue
		}
		s.post(d, p)
	}
}

// post sends one webhook with a per-attempt timeout and exponential backoff, up to the destination's retry
// budget. On exhaustion it logs; the alert is already durable in WORM, so a lost webhook is a missed
// notification, not a lost record. The URL is never logged (it is a secret).
func (s *Sink) post(d destination, p payload) {
	body, err := renderBody(d.format, s.consoleURL, p)
	if err != nil {
		s.log.Error("alert: render webhook body", "err", err, "rule", p.Rule)
		return
	}
	backoff := s.backoffBase
	for attempt := 0; attempt <= d.maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2
		}
		if s.trySend(d, body) {
			return
		}
		s.log.Warn("alert: webhook attempt failed", "rule", p.Rule, "attempt", attempt)
	}
	s.log.Error("alert: webhook delivery exhausted retries; alert remains durable in WORM",
		"rule", p.Rule, "anchor", p.Anchor)
}

// trySend performs a single POST and reports success (a 2xx). Transport errors and non-2xx both fail.
func (s *Sink) trySend(d destination, body []byte) bool {
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// renderBody produces the wire body for a destination: the canonical alert JSON, or a Slack Block Kit
// message when the sink asked for the slack format.
func renderBody(format, consoleURL string, p payload) ([]byte, error) {
	if format == "slack" {
		// No HTML escaping: the mrkdwn link syntax <url|text> must stay literal rather than becoming
		// <url|text> (Slack decodes either, but the literal form keeps the payload readable).
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(slackMessage(consoleURL, p)); err != nil {
			return nil, err
		}
		return bytes.TrimRight(buf.Bytes(), "\n"), nil
	}
	return json.Marshal(p)
}

var severityEmoji = map[string]string{
	config.SeverityCritical: "🔴",
	config.SeverityWarn:     "🟡",
	config.SeverityInfo:     "🔵",
}

// slackMessage renders one alert as a Slack Block Kit message. There is no alert page in the console, so
// the message is the alert record: severity, principal, datasource, time, the alert id, and every decision
// linked into the console's audit view (consoleURL/audit/<id>) when a console URL is set. The top-level
// "text" is the notification fallback for clients that do not render blocks.
func slackMessage(consoleURL string, p payload) map[string]any {
	emoji := severityEmoji[p.Severity]
	if emoji == "" {
		emoji = "⚪"
	}
	datasource := p.Datasource
	if datasource == "" {
		datasource = "—"
	}

	blocks := []any{
		map[string]any{
			"type": "header",
			"text": map[string]any{
				"type":  "plain_text",
				"text":  fmt.Sprintf("%s %s — %s", emoji, strings.ToUpper(p.Severity), p.Rule),
				"emoji": true,
			},
		},
		map[string]any{
			"type": "section",
			"fields": []any{
				mrkdwnField("*Principal*\n" + p.Principal),
				mrkdwnField("*Datasource*\n" + datasource),
				mrkdwnField("*When*\n" + p.TS),
				mrkdwnField("*Alert*\n`" + p.Anchor + "`"),
			},
		},
	}

	links := decisionLinks(consoleURL, p.DecisionIDs)
	if len(links) == 0 {
		blocks = append(blocks, mrkdwnSection("*Decisions:* —"))
	} else {
		blocks = append(blocks, mrkdwnSection(fmt.Sprintf("*Decisions (%d):*", len(links))))
		// Chunk the links across sections: a full window (up to maxAlertIDs=100 ids) would overrun Slack's
		// ~3000-char per-section text limit in a single block.
		for _, chunk := range chunkJoin(links, "  ", 2800) {
			blocks = append(blocks, mrkdwnSection(chunk))
		}
	}

	return map[string]any{
		"text":   fmt.Sprintf("[%s] %s principal=%s datasource=%s (%d decisions)", strings.ToUpper(p.Severity), p.Rule, p.Principal, datasource, len(links)),
		"blocks": blocks,
	}
}

func mrkdwnField(text string) map[string]any { return map[string]any{"type": "mrkdwn", "text": text} }

func mrkdwnSection(text string) map[string]any {
	return map[string]any{"type": "section", "text": mrkdwnField(text)}
}

// decisionLinks turns decision ids into deduplicated Slack links to consoleURL/audit/<id> (bare #<id> when
// no console URL is configured), preserving first-seen order.
func decisionLinks(consoleURL string, ids []int64) []string {
	seen := make(map[int64]struct{}, len(ids))
	links := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if consoleURL != "" {
			links = append(links, fmt.Sprintf("<%s/audit/%d|#%d>", consoleURL, id, id))
		} else {
			links = append(links, fmt.Sprintf("#%d", id))
		}
	}
	return links
}

// chunkJoin joins items with sep into as few strings as possible, each at most maxLen bytes.
func chunkJoin(items []string, sep string, maxLen int) []string {
	var out []string
	var b strings.Builder
	for _, it := range items {
		if b.Len() > 0 && b.Len()+len(sep)+len(it) > maxLen {
			out = append(out, b.String())
			b.Reset()
		}
		if b.Len() > 0 {
			b.WriteString(sep)
		}
		b.WriteString(it)
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

// sanitizeID keeps object keys to a safe, filesystem/S3-friendly alphabet.
func sanitizeID(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			return r
		default:
			return '_'
		}
	}, s)
}
