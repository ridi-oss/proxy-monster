// Package detect evaluates the config-driven anomaly rules over the committed audit trail and fires alerts
// through an AlertSink. It plugs into the monitor as the Detector: Inspect is called each poll with the
// freshly verified, past-watermark rows. The rate rules (mass_export, bulk_pii, repeated_deny,
// auth_failure_burst) need more than that one batch, so the detector also reads a window of the durable trail
// on each poll and recomputes the windows from it — a restart loses no state and nothing is double-counted.
// off_hours and off_hours_admin are per-event rules and need only the fresh batch. Every rule is fail-safe: a
// bad row is skipped, never fatal.
package detect

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ridi-oss/proxy-monster/auditmon/alert"
	"github.com/ridi-oss/proxy-monster/auditmon/config"
	"github.com/ridi-oss/proxy-monster/auditmon/store"
)

// WindowReader reads a window of the durable trail for the rate rules. *store.Reader satisfies it.
type WindowReader interface {
	EventsSince(ctx context.Context, since time.Time) ([]store.StoredEvent, error)
}

// AlertSink receives a fired alert. *alert.Sink satisfies it.
type AlertSink interface {
	Deliver(alert.Alert)
}

// maxAlertIDs caps how many decision ids ride in a single alert so a huge window never produces an unbounded
// payload; the alert is a pointer into the trail, not a copy of it.
const maxAlertIDs = 100

// Detector holds the parsed rules and the two dependencies each poll needs: the durable-trail window reader
// and the alert sink.
type Detector struct {
	reader    WindowReader
	sink      AlertSink
	rules     config.RulesConfig
	maxWindow time.Duration

	offHoursOK bool
	business   config.BusinessWindow

	now func() time.Time
	log *slog.Logger
}

// New parses the off-hours window, computes the widest rate window to read each poll, and returns a Detector.
// A malformed off_hours business_hours is a construction error (config.Validate already catches it on load;
// this is the same fail-closed guard for programmatic construction).
func New(reader WindowReader, sink AlertSink, rules config.RulesConfig) (*Detector, error) {
	d := &Detector{
		reader: reader,
		sink:   sink,
		rules:  rules,
		now:    time.Now,
		log:    slog.Default(),
	}
	if rules.OffHours.BusinessHours != "" {
		bw, err := rules.OffHours.Parse()
		if err != nil {
			return nil, err
		}
		d.business = bw
		d.offHoursOK = true
	}
	// Fail closed at construction, not just in Config.Validate: an enabled off-hours-admin rule with no
	// window would silently never fire — a monitoring gap in a security tool.
	if rules.OffHoursAdmin.Enabled && rules.OffHours.BusinessHours == "" {
		return nil, fmt.Errorf("config: rules.off_hours_admin.enabled requires rules.off_hours.business_hours")
	}
	for _, w := range []time.Duration{rules.MassExport.Window, rules.BulkPII.Window, rules.RepeatedDeny.Window, rules.AuthFailureBurst.Window} {
		if w > d.maxWindow {
			d.maxWindow = w
		}
	}
	return d, nil
}

// needsWindow reports whether any rate rule is enabled (and so a window read is worthwhile this poll).
func (d *Detector) needsWindow() bool { return d.maxWindow > 0 }

// Inspect evaluates every enabled rule for the poll. off_hours runs on the fresh batch alone; the rate rules
// read one window of the durable trail (widest rule window) and each re-floors it to its own window. A window
// read failure is returned for the monitor to log and retry; it never blocks the loop.
func (d *Detector) Inspect(fresh []store.StoredEvent) error {
	d.evalOffHours(fresh)
	d.evalOffHoursAdmin(fresh)

	if !d.needsWindow() {
		return nil
	}
	since := d.now().Add(-d.maxWindow)
	window, err := d.reader.EventsSince(context.Background(), since)
	if err != nil {
		return fmt.Errorf("detect: read window: %w", err)
	}
	d.evalMassExport(fresh, window)
	d.evalBulkPII(fresh, window)
	d.evalRepeatedDeny(fresh, window)
	d.evalAuthFailureBurst(fresh, window)
	return nil
}

// evalOffHours fires on each fresh PII read or write whose timestamp falls outside business hours. Dedup in
// the sink collapses a burst from one principal into a single alert per dedup window.
func (d *Detector) evalOffHours(fresh []store.StoredEvent) {
	if !d.offHoursOK {
		return
	}
	rule := d.rules.OffHours
	for _, ev := range fresh {
		if !isDecision(ev) {
			continue
		}
		kind := accessKind(ev)
		if kind == "" {
			continue
		}
		if kind == "write" && !rule.AppliesToWrite() {
			continue
		}
		if kind == "pii_read" && !rule.AppliesToPIIRead() {
			continue
		}
		ts := time.UnixMicro(ev.Event.TSMicros).In(d.business.Location)
		if !d.isOffHours(ts) {
			continue
		}
		d.sink.Deliver(alert.Alert{
			Severity:    config.SeverityWarn,
			Rule:        config.RuleOffHours,
			Principal:   ev.Event.Principal,
			Datasource:  ev.Event.Datasource,
			DecisionIDs: []int64{ev.ID},
			TS:          ts,
		})
	}
}

// evalOffHoursAdmin fires on each fresh admin event — a privileged config/authorization change — whose
// timestamp falls outside business hours, reusing the same business window off_hours parses.
func (d *Detector) evalOffHoursAdmin(fresh []store.StoredEvent) {
	if !d.offHoursOK || !d.rules.OffHoursAdmin.Enabled {
		return
	}
	for _, ev := range fresh {
		if !isAdmin(ev) {
			continue
		}
		ts := time.UnixMicro(ev.Event.TSMicros).In(d.business.Location)
		if !d.isOffHours(ts) {
			continue
		}
		d.sink.Deliver(alert.Alert{
			Severity:    config.SeverityWarn,
			Rule:        config.RuleOffHoursAdmin,
			Principal:   ev.Event.Principal,
			Datasource:  ev.Event.Datasource,
			DecisionIDs: []int64{ev.ID},
			TS:          ts,
		})
	}
}

// isOffHours reports whether t falls on a weekend or outside the daily [start, end) business span.
func (d *Detector) isOffHours(t time.Time) bool {
	if t.Weekday() == time.Saturday || t.Weekday() == time.Sunday {
		return true
	}
	minute := t.Hour()*60 + t.Minute()
	return minute < d.business.StartMinute || minute >= d.business.EndMinute
}

// evalRepeatedDeny fires when a principal accumulates more than max_deny DENY/ERROR decisions in the window.
func (d *Detector) evalRepeatedDeny(fresh, window []store.StoredEvent) {
	rule := d.rules.RepeatedDeny
	if rule.Window <= 0 {
		return
	}
	cutoff := d.now().Add(-rule.Window)

	touched := map[string]struct{}{}
	for _, ev := range fresh {
		if isDenyOrError(ev) {
			touched[ev.Event.Principal] = struct{}{}
		}
	}
	if len(touched) == 0 {
		return
	}

	counts := map[string]int{}
	ids := map[string][]int64{}
	for _, ev := range window {
		if !withinWindow(ev, cutoff) || !isDenyOrError(ev) {
			continue
		}
		p := ev.Event.Principal
		if _, ok := touched[p]; !ok {
			continue
		}
		counts[p]++
		ids[p] = appendCapped(ids[p], ev.ID)
	}
	for p := range touched {
		if counts[p] > rule.MaxDeny {
			d.sink.Deliver(alert.Alert{
				Severity:    config.SeverityWarn,
				Rule:        config.RuleRepeatedDeny,
				Principal:   p,
				DecisionIDs: ids[p],
				TS:          d.now(),
			})
		}
	}
}

// evalAuthFailureBurst fires when a principal accumulates more than max_failures failed authentication events
// in the window (a brute-force / credential-stuffing signal). Unattributed failures carry the principal
// "unknown"; a burst on "unknown" is itself worth surfacing, so it is keyed like any other principal.
func (d *Detector) evalAuthFailureBurst(fresh, window []store.StoredEvent) {
	rule := d.rules.AuthFailureBurst
	if rule.Window <= 0 {
		return
	}
	cutoff := d.now().Add(-rule.Window)

	touched := map[string]struct{}{}
	for _, ev := range fresh {
		if isAuthFailure(ev) {
			touched[ev.Event.Principal] = struct{}{}
		}
	}
	if len(touched) == 0 {
		return
	}

	counts := map[string]int{}
	ids := map[string][]int64{}
	for _, ev := range window {
		if !withinWindow(ev, cutoff) || !isAuthFailure(ev) {
			continue
		}
		p := ev.Event.Principal
		if _, ok := touched[p]; !ok {
			continue
		}
		counts[p]++
		ids[p] = appendCapped(ids[p], ev.ID)
	}
	for p := range touched {
		if counts[p] > rule.MaxFailures {
			d.sink.Deliver(alert.Alert{
				Severity:    config.SeverityWarn,
				Rule:        config.RuleAuthFailureBurst,
				Principal:   p,
				DecisionIDs: ids[p],
				TS:          d.now(),
			})
		}
	}
}

// evalBulkPII fires when a principal touches PII across more than max_pii_decisions decisions, or more than
// max_distinct_pii_columns distinct PII columns, in the window.
func (d *Detector) evalBulkPII(fresh, window []store.StoredEvent) {
	rule := d.rules.BulkPII
	if rule.Window <= 0 {
		return
	}
	cutoff := d.now().Add(-rule.Window)

	touched := map[string]struct{}{}
	for _, ev := range fresh {
		if isDecision(ev) && len(ev.Event.PIITouched) > 0 {
			touched[ev.Event.Principal] = struct{}{}
		}
	}
	if len(touched) == 0 {
		return
	}

	counts := map[string]int{}
	columns := map[string]map[string]struct{}{}
	ids := map[string][]int64{}
	for _, ev := range window {
		if !withinWindow(ev, cutoff) || !isDecision(ev) || len(ev.Event.PIITouched) == 0 {
			continue
		}
		p := ev.Event.Principal
		if _, ok := touched[p]; !ok {
			continue
		}
		counts[p]++
		ids[p] = appendCapped(ids[p], ev.ID)
		cols := columns[p]
		if cols == nil {
			cols = map[string]struct{}{}
			columns[p] = cols
		}
		for _, c := range ev.Event.PIITouched {
			cols[c] = struct{}{}
		}
	}
	for p := range touched {
		overDecisions := rule.MaxPIIDecisions > 0 && counts[p] > rule.MaxPIIDecisions
		overColumns := rule.MaxDistinctPIIColumns > 0 && len(columns[p]) > rule.MaxDistinctPIIColumns
		if overDecisions || overColumns {
			d.sink.Deliver(alert.Alert{
				Severity:    config.SeverityWarn,
				Rule:        config.RuleBulkPII,
				Principal:   p,
				DecisionIDs: ids[p],
				TS:          d.now(),
			})
		}
	}
}

// keyPD is a principal+datasource grouping key for mass_export.
type keyPD struct {
	principal  string
	datasource string
}

// massAgg accumulates one (principal, datasource) window's export signal: summed completion volume, or, when
// the window carries no completion event, the count of broad reads for the degraded heuristic.
type massAgg struct {
	rows        int64
	bytes       int64
	completions int
	broadReads  int
	ids         []int64
}

// evalMassExport fires when a principal's result volume for a datasource exceeds that datasource's ceiling in
// the window. Completion events carry the true rows/bytes and are attributed to their decision's
// principal+datasource (joined by decision_id, falling back to the completion's own fields when the decision
// predates the window). When a touched window has no completion event at all — the proxy's post-execution
// completion has not shipped in this deployment — it degrades to counting broad (unbounded) reads against the
// heuristic ceiling and fires at a lower severity, since the statement shape is a weaker signal than volume.
func (d *Detector) evalMassExport(fresh, window []store.StoredEvent) {
	rule := d.rules.MassExport
	if rule.Window <= 0 {
		return
	}
	cutoff := d.now().Add(-rule.Window)

	// Resolve a completion to the principal+datasource of its decision, using the decisions in the window.
	decInfo := map[int64]keyPD{}
	for _, ev := range window {
		if isDecision(ev) {
			decInfo[ev.ID] = keyPD{ev.Event.Principal, ev.Event.Datasource}
		}
	}
	resolve := func(ev store.StoredEvent) keyPD {
		if ev.Event.DecisionID != nil {
			if pd, ok := decInfo[*ev.Event.DecisionID]; ok {
				return pd
			}
		}
		return keyPD{ev.Event.Principal, ev.Event.Datasource}
	}

	// Only keys touched by the fresh batch are worth re-checking: a fresh completion, or a fresh broad read
	// (the heuristic's trigger).
	touched := map[keyPD]struct{}{}
	for _, ev := range fresh {
		switch {
		case isCompletion(ev):
			touched[resolve(ev)] = struct{}{}
		case isDecision(ev) && isBroadRead(ev.Event.Statement):
			touched[keyPD{ev.Event.Principal, ev.Event.Datasource}] = struct{}{}
		}
	}
	if len(touched) == 0 {
		return
	}

	aggs := map[keyPD]*massAgg{}
	agg := func(pd keyPD) *massAgg {
		a := aggs[pd]
		if a == nil {
			a = &massAgg{}
			aggs[pd] = a
		}
		return a
	}
	for _, ev := range window {
		if !withinWindow(ev, cutoff) {
			continue
		}
		switch {
		case isCompletion(ev):
			pd := resolve(ev)
			if _, ok := touched[pd]; !ok {
				continue
			}
			a := agg(pd)
			if ev.Event.RowsReturned != nil {
				a.rows += *ev.Event.RowsReturned
			}
			if ev.Event.BytesReturned != nil {
				a.bytes += *ev.Event.BytesReturned
			}
			a.completions++
			a.ids = appendCapped(a.ids, decisionIDOrSelf(ev))
		case isDecision(ev) && isBroadRead(ev.Event.Statement):
			pd := keyPD{ev.Event.Principal, ev.Event.Datasource}
			if _, ok := touched[pd]; !ok {
				continue
			}
			a := agg(pd)
			a.broadReads++
			a.ids = appendCapped(a.ids, ev.ID)
		}
	}

	for pd := range touched {
		a := aggs[pd]
		if a == nil {
			continue
		}
		if a.completions > 0 {
			th := rule.Threshold(pd.datasource)
			// A resolved threshold of {0,0} means this datasource has no configured ceiling on either
			// dimension: the volume comparison below is vacuously false, so a genuine mass export would pass
			// silently. Fail closed by falling through to the broad-read heuristic instead of returning here.
			if th.Rows > 0 || th.Bytes > 0 {
				if (th.Rows > 0 && a.rows > th.Rows) || (th.Bytes > 0 && a.bytes > th.Bytes) {
					d.sink.Deliver(alert.Alert{
						Severity:    config.SeverityCritical,
						Rule:        config.RuleMassExport,
						Principal:   pd.principal,
						Datasource:  pd.datasource,
						DecisionIDs: a.ids,
						TS:          d.now(),
					})
				}
				continue
			}
		}
		// Degraded heuristic: no completion in the window for this key, or a completion but no ceiling to
		// judge it against (an unprotected datasource).
		if rule.HeuristicMaxBroadReads > 0 && a.broadReads > rule.HeuristicMaxBroadReads {
			d.sink.Deliver(alert.Alert{
				Severity:    config.SeverityWarn,
				Rule:        config.RuleMassExport,
				Principal:   pd.principal,
				Datasource:  pd.datasource,
				DecisionIDs: a.ids,
				TS:          d.now(),
			})
		}
	}
}

func isDecision(ev store.StoredEvent) bool   { return ev.Event.Kind == "decision" }
func isCompletion(ev store.StoredEvent) bool { return ev.Event.Kind == "completion" }
func isAuth(ev store.StoredEvent) bool       { return ev.Event.Kind == "auth" }
func isAdmin(ev store.StoredEvent) bool      { return ev.Event.Kind == "admin" }

// isAuthFailure reports whether an event is a failed authentication (kind "auth" with outcome FAILURE). The
// outcome is a nullable column, so a missing outcome is treated as not-a-failure rather than dereferenced.
func isAuthFailure(ev store.StoredEvent) bool {
	return isAuth(ev) && ev.Event.Outcome != nil && *ev.Event.Outcome == "FAILURE"
}

// isDenyOrError reports whether a decision was denied or errored.
func isDenyOrError(ev store.StoredEvent) bool {
	if !isDecision(ev) {
		return false
	}
	switch ev.Event.Decision {
	case "DENY", "ERROR":
		return true
	default:
		return false
	}
}

// accessKind buckets a decision for off_hours: a write, else a PII read, else "" (uninteresting). A write is
// classified before PII so a PII-touching write is watched under the write kind.
func accessKind(ev store.StoredEvent) string {
	if isWrite(ev.Event.Statement) {
		return "write"
	}
	if len(ev.Event.PIITouched) > 0 {
		return "pii_read"
	}
	return ""
}

// decisionIDOrSelf returns the decision a completion references, or the event's own id when it references
// none — so a mass_export alert points at the actual query rows.
func decisionIDOrSelf(ev store.StoredEvent) int64 {
	if ev.Event.DecisionID != nil {
		return *ev.Event.DecisionID
	}
	return ev.ID
}

// withinWindow reports whether an event's timestamp is at or after cutoff.
func withinWindow(ev store.StoredEvent, cutoff time.Time) bool {
	return ev.Event.TSMicros >= cutoff.UnixMicro()
}

// appendCapped appends id unless the slice is already at the id cap.
func appendCapped(ids []int64, id int64) []int64 {
	if len(ids) >= maxAlertIDs {
		return ids
	}
	return append(ids, id)
}
