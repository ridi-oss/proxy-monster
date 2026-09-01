package mysqlproxy

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

const (
	targetDbHandshakeTimeout = 10 * time.Second
	maxTargetDbAuthPacket    = 64 << 10
)

const (
	targetDbPluginNative      = "mysql_native_password"
	targetDbPluginCachingSHA2 = "caching_sha2_password"
)

// testHookCachingSHA2FullAuth, when non-nil, is invoked whenever the caching_sha2_password full-auth
// exchange runs, with viaPublicKey reporting the plaintext RSA public-key branch (true) versus the TLS
// cleartext branch (false). Production leaves it nil; DB-backed tests set it to prove the full-auth path
// is exercised end-to-end.
var testHookCachingSHA2FullAuth func(viaPublicKey bool)

// dialTargetDbAuth connects to the target and performs the service-account handshake. Both
// mysql_native_password and caching_sha2_password (mysql:8.0 / Aurora MySQL 3 default) are supported,
// each on the direct and auth-switch paths; caching_sha2 additionally runs the full-auth exchange
// (RSA public-key over a plaintext link, cleartext over TLS) when the server's fast-auth cache misses.
// CLIENT_SESSION_TRACK is required so text-protocol database changes arrive as protocol signals instead
// of requiring an interposed SELECT DATABASE() that would corrupt ROW_COUNT/FOUND_ROWS diagnostics.
func dialTargetDbAuth(target spi.TargetDb, mirrorDeprecateEOF bool) (net.Conn, error) {
	conn, _, err := dialTargetDbAuthID(context.Background(), target, mirrorDeprecateEOF)
	return conn, err
}

// dialTargetDbAuthID honors ctx for the whole handshake: DialContext aborts the connect, and while the
// (deadline-bounded) auth exchange runs, an AfterFunc closes the conn on cancel so a blocked read unwinds at
// once. On the run path ctx is the target-DB open context, so a run the control-plane already closed does not
// finish a target-DB handshake nobody is waiting for; the wire path passes a background ctx (never cancelled).
func dialTargetDbAuthID(ctx context.Context, target spi.TargetDb, mirrorDeprecateEOF bool) (net.Conn, uint32, error) {
	dialer := net.Dialer{Timeout: targetDbHandshakeTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
	if err != nil {
		return nil, 0, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = conn.Close()
		}
	}()
	defer context.AfterFunc(ctx, func() { _ = conn.Close() })()
	if err := conn.SetDeadline(time.Now().Add(targetDbHandshakeTimeout)); err != nil {
		return nil, 0, fmt.Errorf("set target-DB auth deadline: %w", err)
	}

	greetingSeq, payload, err := mysqlwire.ReadPacketLimited(conn, maxTargetDbAuthPacket)
	if err != nil {
		return nil, 0, fmt.Errorf("read target-DB greeting: %w", err)
	}
	greeting, err := mysqlwire.ParseHandshakeV10(payload)
	if err != nil {
		return nil, 0, fmt.Errorf("malformed target-DB greeting: %w", err)
	}
	if greeting.Capabilities&mysqlwire.CapSessionTrack == 0 {
		return nil, 0, errors.New("target DB does not support CLIENT_SESSION_TRACK (MySQL 8.0+ required)")
	}

	caps := uint32(mysqlwire.CapLongPassword | mysqlwire.CapProtocol41 | mysqlwire.CapTransactions |
		mysqlwire.CapSecureConn | mysqlwire.CapPluginAuth | mysqlwire.CapConnectWithDB | mysqlwire.CapSessionTrack)
	if mirrorDeprecateEOF {
		caps |= mysqlwire.CapDeprecateEOF
	}

	// The plugin negotiated in the greeting drives the initial HandshakeResponse. scramble is the auth
	// challenge for the CURRENT plugin; it is updated on an auth-switch and is the seed the caching_sha2
	// full-auth path encrypts against.
	plugin, err := canonicalTargetDbPlugin(greeting.AuthPlugin)
	if err != nil {
		return nil, 0, err
	}
	scramble := greeting.Scramble
	authResp, err := targetDbAuthResponse(plugin, target.Password, scramble)
	if err != nil {
		return nil, 0, err
	}
	response := mysqlwire.TargetDbHandshakeResponse(caps, target.User, authResp, target.Db, plugin)
	if err := mysqlwire.WritePacket(conn, greetingSeq+1, response); err != nil {
		return nil, 0, fmt.Errorf("write target-DB handshake response: %w", err)
	}

	for {
		seq, authPayload, err := mysqlwire.ReadPacketLimited(conn, maxTargetDbAuthPacket)
		if err != nil {
			return nil, 0, fmt.Errorf("read target-DB auth response: %w", err)
		}
		if len(authPayload) == 0 {
			return nil, 0, errors.New("unexpected empty target-DB auth packet")
		}
		switch authPayload[0] {
		case 0x00:
			if err := enableSessionTracking(conn); err != nil {
				return nil, 0, err
			}
			if err := conn.SetDeadline(time.Time{}); err != nil {
				return nil, 0, fmt.Errorf("clear target-DB auth deadline: %w", err)
			}
			keep = true
			return conn, greeting.ConnectionID, nil
		case 0xff:
			return nil, 0, fmt.Errorf("target-DB auth failed: %s", mysqlwire.ErrString(authPayload))
		case 0xfe:
			switchPlugin, switchScramble, err := parseAuthSwitch(authPayload)
			if err != nil {
				return nil, 0, err
			}
			plugin = switchPlugin
			scramble = switchScramble
			resp, err := targetDbAuthResponse(plugin, target.Password, scramble)
			if err != nil {
				return nil, 0, err
			}
			if err := mysqlwire.WritePacket(conn, seq+1, resp); err != nil {
				return nil, 0, fmt.Errorf("write target-DB auth switch response: %w", err)
			}
		case mysqlwire.AuthMoreData:
			if plugin != targetDbPluginCachingSHA2 {
				return nil, 0, fmt.Errorf("unexpected AuthMoreData for plugin %s", plugin)
			}
			if err := handleCachingSHA2MoreData(conn, seq, authPayload, target.Password, scramble); err != nil {
				return nil, 0, err
			}
		default:
			return nil, 0, fmt.Errorf("unexpected target-DB auth packet 0x%02x", authPayload[0])
		}
	}
}

// canonicalTargetDbPlugin normalizes the greeting's auth plugin to one the proxy implements, failing
// closed on anything else. An empty plugin name (pre-4.1 greeting without CapPluginAuth) is treated as
// mysql_native_password, matching ParseHandshakeV10's default.
func canonicalTargetDbPlugin(plugin string) (string, error) {
	switch {
	case plugin == "" || strings.EqualFold(plugin, targetDbPluginNative):
		return targetDbPluginNative, nil
	case strings.EqualFold(plugin, targetDbPluginCachingSHA2):
		return targetDbPluginCachingSHA2, nil
	default:
		return "", fmt.Errorf("target DB requested unsupported auth plugin %s", plugin)
	}
}

// targetDbAuthResponse computes the HandshakeResponse (or auth-switch response) auth bytes for plugin.
func targetDbAuthResponse(plugin, password string, scramble []byte) ([]byte, error) {
	switch plugin {
	case targetDbPluginNative:
		return mysqlwire.NativePassword(password, scramble), nil
	case targetDbPluginCachingSHA2:
		return mysqlwire.CachingSHA2Password(password, scramble), nil
	default:
		return nil, fmt.Errorf("target DB requested unsupported auth plugin %s", plugin)
	}
}

// parseAuthSwitch decodes an AuthSwitchRequest (0xfe): plugin name (cstr) then the 20-byte auth data
// (one trailing NUL is stripped). It returns the canonicalized plugin so an unsupported switch fails
// closed here rather than emitting a bad response.
func parseAuthSwitch(payload []byte) (string, []byte, error) {
	r := mysqlwire.NewReader(payload)
	if err := r.Skip(1); err != nil {
		return "", nil, errors.New("unexpected target-DB auth packet")
	}
	plugin, err := r.Cstr()
	if err != nil {
		return "", nil, errors.New("unexpected target-DB auth packet")
	}
	start := 1 + len(plugin) + 1
	if start > len(payload) {
		return "", nil, errors.New("unexpected target-DB auth packet")
	}
	end := len(payload)
	if end > start && payload[end-1] == 0 {
		end--
	}
	if end > start+20 {
		end = start + 20
	}
	canonical, err := canonicalTargetDbPlugin(plugin)
	if err != nil {
		return "", nil, err
	}
	return canonical, payload[start:end], nil
}

// handleCachingSHA2MoreData processes the server's AuthMoreData after a caching_sha2_password response.
// The second byte is the fast-auth outcome: fast-auth SUCCESS just waits for the OK packet, while a
// full-auth demand runs the exchange — over TLS the cleartext password + NUL, otherwise a public-key
// request followed by the RSA-encrypted password. scramble is the current plugin's challenge (the seed
// the encrypted password is XOR-obfuscated against).
func handleCachingSHA2MoreData(conn net.Conn, seq byte, payload []byte, password string, scramble []byte) error {
	if len(payload) < 2 {
		return errors.New("truncated caching_sha2_password AuthMoreData")
	}
	switch payload[1] {
	case mysqlwire.CachingSHA2FastAuthSuccess:
		// The credential was cached server-side; the OK packet follows on the next read.
		return nil
	case mysqlwire.CachingSHA2FullAuth:
		if _, isTLS := conn.(*tls.Conn); isTLS {
			// Over TLS the channel is already confidential: send the cleartext password (NUL-terminated).
			cleartext := append([]byte(password), 0)
			if err := mysqlwire.WritePacket(conn, seq+1, cleartext); err != nil {
				return fmt.Errorf("write caching_sha2 cleartext password: %w", err)
			}
			if testHookCachingSHA2FullAuth != nil {
				testHookCachingSHA2FullAuth(false)
			}
			return nil
		}
		// Plaintext link: request the server's RSA public key, then send the encrypted password.
		if err := mysqlwire.WritePacket(conn, seq+1, []byte{mysqlwire.CachingSHA2RequestPublicKey}); err != nil {
			return fmt.Errorf("request caching_sha2 public key: %w", err)
		}
		keySeq, keyPayload, err := mysqlwire.ReadPacketLimited(conn, maxTargetDbAuthPacket)
		if err != nil {
			return fmt.Errorf("read caching_sha2 public key: %w", err)
		}
		if len(keyPayload) < 2 || keyPayload[0] != mysqlwire.AuthMoreData {
			return errors.New("malformed caching_sha2_password public key packet")
		}
		encrypted, err := mysqlwire.EncryptCachingSHA2Password(password, scramble, keyPayload[1:])
		if err != nil {
			return fmt.Errorf("encrypt caching_sha2 password: %w", err)
		}
		if err := mysqlwire.WritePacket(conn, keySeq+1, encrypted); err != nil {
			return fmt.Errorf("write caching_sha2 encrypted password: %w", err)
		}
		if testHookCachingSHA2FullAuth != nil {
			testHookCachingSHA2FullAuth(true)
		}
		return nil
	default:
		return fmt.Errorf("unexpected caching_sha2_password AuthMoreData marker 0x%02x", payload[1])
	}
}

// enableSessionTracking makes the target DB report enforcement-critical session state in the OK packet of the
// statement that changed it: session_track_schema=ON emits an authoritative SESSION_TRACK_SCHEMA block after
// every text USE, and the SESSION_TRACK_SYSTEM_VARIABLES list surfaces a direct change to schema tracking,
// the tracking list, or the connection charset. This is a fast fail-closed signal for DIRECT tampering; it
// is not sufficient alone (see requiredTrackedSysVars in session.go), so the namespace and charset are also
// re-probed before every statement (see mysqlSessionProbeSQL). MySQL 8.0 advertises the tracking capability
// but the variables are session-configurable, so the proxy sets them explicitly rather than trusting the
// server default.
func enableSessionTracking(conn net.Conn) error {
	if err := execTargetDbSet(conn, "SET SESSION session_track_schema = ON"); err != nil {
		return fmt.Errorf("enable target-DB schema tracking: %w", err)
	}
	if err := execTargetDbSet(conn, "SET SESSION session_track_system_variables = '"+trackedSysVarList()+"'"); err != nil {
		return fmt.Errorf("enable target DB session-variable tracking: %w", err)
	}
	return nil
}

// execTargetDbSet sends one SET on the service-account connection and consumes its single OK packet, failing
// on a target-DB error or a malformed response.
func execTargetDbSet(conn net.Conn, sql string) error {
	if err := mysqlwire.WritePacket(conn, 0, mysqlwire.ComQueryPayload(sql)); err != nil {
		return err
	}
	_, payload, err := mysqlwire.ReadPacketLimited(conn, maxTargetDbAuthPacket)
	if err != nil {
		return err
	}
	if len(payload) == 0 {
		return errors.New("empty response")
	}
	if payload[0] == 0xff {
		return errors.New(mysqlwire.ErrString(payload))
	}
	if payload[0] != 0x00 {
		return fmt.Errorf("unexpected response 0x%02x", payload[0])
	}
	if _, _, _, _, err := normalizeTargetDbOK(payload); err != nil {
		return err
	}
	return nil
}

// mysqlSessionProbeSQL re-reads the connection's current database, its effective client/connection/result
// charsets, AND its session sql_mode in one round trip. The proxy runs it before every client statement
// (probe-always). A client can silently disable session_track_schema or clear session_track_system_variables
// — MySQL reports neither once the tracking list no longer names the variable — so neither the
// SESSION_TRACK_SCHEMA signal nor the sysvar tracker can be trusted as the sole guard. Re-probing observes
// the true current database, charset, and sql_mode regardless of tracker state, so a client cannot silently
// defeat the proxy's namespace/encoding/lexer-mode observation. Reading sql_mode here (not just at connect)
// covers BOTH the connect-time and mid-session vectors: ANSI_QUOTES is OBSERVED and forwarded to the analyzer
// (which parses "…" as the quoted identifier the target DB reads, so a masked column stays masked), while any
// flag that is not parse-safe — a known parse-affecting one the analyzer cannot model or an unrecognized one
// — fails the session closed (see classifyMySQLSqlMode's allowlist; mirrors pgproxy's
// standard_conforming_strings guard). Because the proxy serves one statement at a time and sql_mode changes
// only via a SET statement, the mode this probe observes is exactly the mode the next statement executes
// under — no gap for a mid-session flip to slip a statement past the wrong analyzer mode. The trade-off is
// that interposing this SELECT resets statement-scoped diagnostics such as ROW_COUNT()/FOUND_ROWS() between
// client statements — accepted to close the fail-open.
const mysqlSessionProbeSQL = "SELECT DATABASE(), @@session.character_set_client, @@session.character_set_connection, @@session.character_set_results, @@session.sql_mode"

// interpretSessionProbeRow validates the three charset columns of a mysqlSessionProbeSQL row (failing closed
// if any left UTF-8) and classifies its sql_mode column (failing closed on any lexer-changing flag the
// analyzer cannot model — see classifyMySQLSqlMode). It returns the namespace — the current database, or
// empty when none is selected — and whether the session runs under ANSI_QUOTES (forwarded so the analyzer
// masks a `"`-quoted column).
func interpretSessionProbeRow(values []*string) (namespace []string, ansiQuotes bool, err error) {
	if len(values) != 5 {
		return nil, false, fmt.Errorf("session probe returned %d columns, want 5", len(values))
	}
	for i := 1; i <= 3; i++ {
		if values[i] == nil || !isSafeMySQLCharset(*values[i]) {
			return nil, false, errUnsafeCharset
		}
	}
	if values[4] == nil {
		return nil, false, errUnsafeSqlMode
	}
	ansiQuotes, err = classifyMySQLSqlMode(*values[4])
	if err != nil {
		return nil, false, err
	}
	if values[0] == nil {
		return []string{}, ansiQuotes, nil
	}
	return mysqlNamespace(*values[0]), ansiQuotes, nil
}

// textResultCollector decodes one COM_QUERY text result for probes and run execution.
type textResultCollector struct {
	expected, maxRows, columns int
	masks                      []*pb.ColumnMask
	columnDefs                 []mysqlwire.ColumnDefinition
	result                     *engine.StatementResult
	masker                     *engine.RowMasker
	targetDbErr, affectedErr   error
}

func (c *textResultCollector) hooks() resultHooks {
	return resultHooks{Sink: c.sink, OnColumns: c.onColumns, OnColumnDef: c.onColumnDef, OnRow: c.onRow, OnOK: c.onOK}
}
func (c *textResultCollector) sink(_ byte, payload []byte) error {
	if len(payload) > 0 && payload[0] == 0xff {
		c.targetDbErr = errors.New(mysqlwire.ErrString(payload))
	}
	return c.affectedErr
}
func (c *textResultCollector) onColumns(count int) error {
	c.columns = count
	if c.expected > 0 && count != c.expected {
		return fmt.Errorf("internal query returned %d columns, want %d", count, c.expected)
	}
	if c.result != nil {
		c.result.RowsAffected = -1
		c.columnDefs = make([]mysqlwire.ColumnDefinition, 0, count)
	}
	if len(c.masks) > 0 {
		c.masker = engine.NewRowMasker(c.masks, count)
		if c.masker == nil {
			return engine.ErrMaskUnbound
		}
	}
	return nil
}
func (c *textResultCollector) onColumnDef(payload []byte) error {
	if c.result == nil {
		return nil
	}
	def, err := mysqlwire.ParseColumnDefinition(payload)
	if err != nil {
		return fmt.Errorf("parse column definition: %w", err)
	}
	c.columnDefs = append(c.columnDefs, def)
	c.result.Columns = append(c.result.Columns, def.Name)
	return nil
}
func (c *textResultCollector) onRow(payload []byte) ([]byte, error) {
	values, err := mysqlwire.ParseTextRow(payload, c.columns)
	if err != nil {
		if c.expected > 0 {
			return nil, err
		}
		return nil, fmt.Errorf("decode MySQL text row: %w", err)
	}
	if len(values) != c.columns {
		return nil, fmt.Errorf("MySQL row has %d columns, want %d", len(values), c.columns)
	}
	if c.expected > 0 && len(values) != c.expected {
		return nil, fmt.Errorf("internal query row returned %d columns, want %d", len(values), c.expected)
	}
	if c.masker != nil {
		values = c.masker.Apply(values)
	}
	if c.result != nil && (c.maxRows <= 0 || len(c.result.Rows) < c.maxRows) {
		c.result.Rows = append(c.result.Rows, c.displayValues(values))
	}
	return payload, nil
}
func (c *textResultCollector) onOK(affected uint64) {
	if affected > math.MaxInt32 {
		c.affectedErr = fmt.Errorf("affected rows %d exceeds int32 range", affected)
	} else if c.result != nil {
		c.result.RowsAffected = int(affected)
	}
}

func (c *textResultCollector) displayValues(values []*string) []*string {
	out := append([]*string(nil), values...)
	if len(c.columnDefs) != len(out) {
		return out
	}
	masked := maskedOrdinals(c.masks)
	for i, def := range c.columnDefs {
		if _, ok := masked[i]; ok || out[i] == nil {
			continue
		}
		// A binary/blob column is always rendered as hex. Anything else is left as-is UNLESS its bytes are
		// not valid UTF-8 — BIT and GEOMETRY carry a binary charset but are not named by isBinaryColumn, and
		// RunValue.value is a proto3 string, so a non-UTF-8 cell would fail to marshal and abort the query.
		if !isBinaryColumn(def) && utf8.ValidString(*out[i]) {
			continue
		}
		encoded := "0x" + hex.EncodeToString([]byte(*out[i]))
		out[i] = &encoded
	}
	return out
}

func maskedOrdinals(masks []*pb.ColumnMask) map[int]struct{} {
	if len(masks) == 0 {
		return nil
	}
	out := make(map[int]struct{}, len(masks))
	for _, mask := range masks {
		if mask != nil && mask.Ordinal != nil {
			out[int(mask.GetOrdinal())] = struct{}{}
		}
	}
	return out
}

func isBinaryColumn(def mysqlwire.ColumnDefinition) bool {
	if def.Charset != mysqlwire.CharsetBinary {
		return false
	}
	switch def.Type {
	case mysqlwire.ColumnTypeVarchar,
		mysqlwire.ColumnTypeVarString,
		mysqlwire.ColumnTypeString,
		mysqlwire.ColumnTypeBlob,
		mysqlwire.ColumnTypeTinyBlob,
		mysqlwire.ColumnTypeMedBlob,
		mysqlwire.ColumnTypeLongBlob:
		return true
	case 0x10, 0xff:
		// MYSQL_TYPE_BIT and MYSQL_TYPE_GEOMETRY — binary-charset types mysqlwire does not name. Always
		// rendered as hex like every other binary column, even when a value happens to be valid UTF-8.
		return true
	default:
		return false
	}
}

// runInternalQuery executes one text query on the held target DB and strictly decodes its rows.
func runInternalQuery(targetDb net.Conn, deprecateEOF bool, sql string, expectedColumns int) ([][]*string, error) {
	if expectedColumns <= 0 {
		return nil, fmt.Errorf("internal query expected columns = %d, want positive", expectedColumns)
	}
	if err := mysqlwire.WritePacket(targetDb, 0, mysqlwire.ComQueryPayload(sql)); err != nil {
		return nil, err
	}
	result := engine.StatementResult{Rows: make([][]*string, 0)}
	collect := textResultCollector{expected: expectedColumns, result: &result}
	_, err := relayResultSet(targetDb, deprecateEOF, collect.hooks())
	if err != nil {
		return nil, err
	}
	if collect.targetDbErr != nil {
		return nil, fmt.Errorf("target DB internal query: %w", collect.targetDbErr)
	}
	return result.Rows, collect.affectedErr
}

// probeNamespace runs the pre-statement session probe and returns the connection's namespace plus whether
// its live sql_mode has ANSI_QUOTES active, failing closed on an unsafe charset or a non-modeled
// lexer-changing sql_mode flag.
func probeNamespace(targetDb net.Conn, deprecateEOF bool) (namespace []string, ansiQuotes bool, err error) {
	rows, err := runInternalQuery(targetDb, deprecateEOF, mysqlSessionProbeSQL, 5)
	if err != nil {
		return nil, false, err
	}
	if len(rows) != 1 {
		return nil, false, fmt.Errorf("session probe returned %d rows, want 1", len(rows))
	}
	return interpretSessionProbeRow(rows[0])
}

// probeNamespaceObservation runs the pre-statement session probe and packages its result as the engine's
// NamespaceProbe, so every wire/editor call site shares one probe→engine conversion.
func probeNamespaceObservation(targetDb net.Conn, deprecateEOF bool) (engine.NamespaceProbe, error) {
	namespace, ansiQuotes, err := probeNamespace(targetDb, deprecateEOF)
	if err != nil {
		return engine.NamespaceProbe{}, err
	}
	return engine.NamespaceProbe{Namespace: namespace, MySQLAnsiQuotes: ansiQuotes}, nil
}
