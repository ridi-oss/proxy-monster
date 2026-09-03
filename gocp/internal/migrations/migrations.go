// Package migrations embeds the control plane's Flyway migration set.
//
// Area doc: plans/proxy-monster-go-port/01-bootstrap.md §2 ("Db"). The runner that consumes these
// lives in internal/store.
//
// The ten files are copied byte-for-byte from
// control-plane/src/main/resources/db/migration/ (V1__identity .. V10__debug_requester_ip) and MUST
// NOT be edited. Their contents are hashed into flyway_schema_history.checksum by the deployment that
// already ran them, and the Go runner recomputes those checksums and refuses to boot on a mismatch
// (Flyway's validateOnMigrate). Editing one is therefore not a code change — it is a change that
// bricks startup on every existing deployment.
//
// Naming is Flyway's: V<version>__<description>.sql, where the version sorts NUMERICALLY. V10 sorts
// after V9, not between V1 and V2 — a lexicographic sort of these filenames is wrong.
package migrations

import "embed"

// FS holds V1__identity.sql .. V10__debug_requester_ip.sql under the "sql/" prefix.
//
// The glob is sql/V*.sql rather than sql/*: an explicit pattern makes a stray file in the directory a
// non-event, and //go:embed refuses to match names beginning with "." or "_" anyway.
//
//go:embed sql/V*.sql
var FS embed.FS
