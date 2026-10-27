package editor

import "time"

// SetQueryTimeoutForTest overrides the per-statement watchdog timeout so a test can exercise the
// cancellation path without waiting the configured production timeout. Test-only.
func (s *Server) SetQueryTimeoutForTest(d time.Duration) { s.queryTimeout = d }
