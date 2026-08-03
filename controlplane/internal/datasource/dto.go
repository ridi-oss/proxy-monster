package datasource

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// ---- DTOs — the wire contract for /api/datasources** (05-datasources-catalog.md §1) ----------

// Datasource is the datasource row as served. Port of Datasources.kt:37-69.
//
// host/port/dbName are ADVISORY (admin UI / triage): the proxy is authoritative and overwrites them
// on Register. The control plane holds NO target credential — it never dials a target — so there is
// literally zero target secret at rest here. dbName is advisory but LOAD-BEARING for catalog
// identity (INV-A5-6/INV-A5-12).
//
// 🔒 INV-A5-67 — the chain replaced a leaf-digest pin, and the pin must not come back. There is no
// advertiseCertSha256 field and there must never be one: pinning the leaf by digest required turning
// OFF CA and hostname checks, so a stolen leaf replayed on another host passed the pin
// (V9__datasource_cert_chain.sql, read this session).
type Datasource struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	// Engine marshals through EngineWireSerializer's rules — see Datasource.MarshalJSON.
	Engine   Engine `json:"-"`
	Host     string `json:"host"`
	Port     int32  `json:"port"`
	DBName   string `json:"dbName"`
	Tags     []string `json:"tags"`
	DefaultSchemas []string `json:"defaultSchemas"`
	MysqlLowerCaseTableNames *int32 `json:"mysqlLowerCaseTableNames,omitempty"`
	// CatalogSyncedAt / LastSeenAt are Java Instant.toString() renderings — see javaInstantString.
	CatalogSyncedAt *string `json:"catalogSyncedAt,omitempty"`
	LastSeenAt      *string `json:"lastSeenAt,omitempty"`
	EngineVersion   *string `json:"engineVersion,omitempty"`
	AdvertiseAddr   *string `json:"advertiseAddr,omitempty"`
	// AdvertiseCertChain is PEM, leaf first. PUBLIC material — this is what the proxy already presents
	// to every TLS client.
	//
	// ⚠️ INV-A5-10 is self-contradictory in the Kotlin and the CONTRADICTION is reproduced: the chain
	// IS in the list/get projection (Datasources.kt:59-63 argues for that) while wireCertChain's kdoc
	// says the opposite ("so a certificate body never rides along in the datasource poll every client
	// makes"). The behaviour to port is "the chain rides on the list"; WireCertChain is then a
	// redundant query, and it is kept redundant. §10 Q5.
	AdvertiseCertChain *string `json:"advertiseCertChain,omitempty"`
	// AdvertiseWireTls is a SEPARATE fact from the chain (INV-A5-4 in V9's words): false means
	// plaintext, and a row that predates any registration is treated as plaintext until a proxy says
	// otherwise.
	AdvertiseWireTls bool `json:"advertiseWireTls"`
}

// datasourceWire is Datasource's JSON shape with the engine rendered as its wire string. Declared
// separately so MarshalJSON does not recurse.
type datasourceWire struct {
	ID                       int64           `json:"id"`
	Name                     string          `json:"name"`
	Engine                   json.RawMessage `json:"engine"`
	Host                     string          `json:"host"`
	Port                     int32           `json:"port"`
	DBName                   string          `json:"dbName"`
	Tags                     []string        `json:"tags"`
	DefaultSchemas           []string        `json:"defaultSchemas"`
	MysqlLowerCaseTableNames *int32          `json:"mysqlLowerCaseTableNames,omitempty"`
	CatalogSyncedAt          *string         `json:"catalogSyncedAt,omitempty"`
	LastSeenAt               *string         `json:"lastSeenAt,omitempty"`
	EngineVersion            *string         `json:"engineVersion,omitempty"`
	AdvertiseAddr            *string         `json:"advertiseAddr,omitempty"`
	AdvertiseCertChain       *string         `json:"advertiseCertChain,omitempty"`
	AdvertiseWireTls         bool            `json:"advertiseWireTls"`
}

// MarshalJSON renders the engine through [MarshalEngineJSON] and normalises the two slice fields to
// `[]` rather than `null`, per types/doc.go's D9 rule (a nil slice must never reach the UI as null).
func (d Datasource) MarshalJSON() ([]byte, error) {
	engine, err := MarshalEngineJSON(d.Engine)
	if err != nil {
		return nil, err
	}
	tags := d.Tags
	if tags == nil {
		tags = []string{}
	}
	schemas := d.DefaultSchemas
	if schemas == nil {
		schemas = []string{}
	}
	// types.MarshalWire, NOT json.Marshal — see the note on Classification.MarshalJSON. A datasource
	// name, host or tag carrying '<' '&' '>' would otherwise be escaped into every list/get response.
	return types.MarshalWire(datasourceWire{
		ID: d.ID, Name: d.Name, Engine: engine, Host: d.Host, Port: d.Port, DBName: d.DBName,
		Tags: tags, DefaultSchemas: schemas,
		MysqlLowerCaseTableNames: d.MysqlLowerCaseTableNames,
		CatalogSyncedAt:          d.CatalogSyncedAt,
		LastSeenAt:               d.LastSeenAt,
		EngineVersion:            d.EngineVersion,
		AdvertiseAddr:            d.AdvertiseAddr,
		AdvertiseCertChain:       d.AdvertiseCertChain,
		AdvertiseWireTls:         d.AdvertiseWireTls,
	})
}

// UnmarshalJSON exists only for symmetry with the Kotlin serializer: no route ever deserializes a
// Datasource (verified in §1 — `grep -rn 'receive<Datasource>' control-plane/src` returns nothing).
func (d *Datasource) UnmarshalJSON(b []byte) error {
	var w datasourceWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	engine, err := UnmarshalEngineJSON(w.Engine)
	if err != nil {
		return err
	}
	*d = Datasource{
		ID: w.ID, Name: w.Name, Engine: engine, Host: w.Host, Port: w.Port, DBName: w.DBName,
		Tags: w.Tags, DefaultSchemas: w.DefaultSchemas,
		MysqlLowerCaseTableNames: w.MysqlLowerCaseTableNames,
		CatalogSyncedAt:          w.CatalogSyncedAt,
		LastSeenAt:               w.LastSeenAt,
		EngineVersion:            w.EngineVersion,
		AdvertiseAddr:            w.AdvertiseAddr,
		AdvertiseCertChain:       w.AdvertiseCertChain,
		AdvertiseWireTls:         w.AdvertiseWireTls,
	}
	return nil
}

// DatasourceInput is the admin create/update body. Port of Datasources.kt:76-82.
//
// This is OPTIONAL pre-provisioning only — a way to seed a row (name + advisory connection fields)
// before its proxy first attaches; the proxy's Register is the authoritative path and overwrites
// host/port/db_name. There are NO credential fields, by design. `Engine` is a plain string here (not
// the wire codec) precisely so the route can canonicalize it and render its own error.
//
// ⚠️ The Kotlin defaults are engine="postgres", host="", port=0, dbName="". Go zero values give the
// last three; the engine default has to be applied by the decoder — see [DecodeDatasourceInput].
type DatasourceInput struct {
	Name   string `json:"name"`
	Engine string `json:"engine"`
	Host   string `json:"host"`
	Port   int32  `json:"port"`
	DBName string `json:"dbName"`
}

// DecodeDatasourceInput applies Kotlin's `engine: String = "postgres"` default, which encoding/json
// cannot express. TODO(A1): the admin routes call this, not json.Unmarshal directly.
func DecodeDatasourceInput(b []byte) (DatasourceInput, error) {
	in := DatasourceInput{Engine: "postgres"}
	if err := json.Unmarshal(b, &in); err != nil {
		return DatasourceInput{}, err
	}
	if in.Engine == "" {
		// An explicit `"engine": ""` is NOT the default in Kotlin (the field is present, so the
		// default does not apply) — but an ABSENT field leaves the zero value here. The two are
		// indistinguishable after json.Unmarshal into a plain string, and a blank engine fails
		// engineFromWireOrNull either way, so both end at 400 datasource.invalid_engine.
		in.Engine = "postgres"
	}
	return in, nil
}

// Classification is the column-classification overlay.
//
// TODO(A13): the canonical home is engine/.../probe/TableDetail.kt:7 (a BORROWED shape, §1's "owned
// elsewhere — do not re-derive"). It is declared here because A5 serves it from `catalog()` /
// `classificationsFor()` / `upsertClassification` and internal/engine is not ported. Move it and
// alias when A13 lands; do not fork it.
type Classification struct {
	Schema     string   `json:"schema"`
	Table      string   `json:"table"`
	Column     string   `json:"column"`
	Tags       []string `json:"tags"`
	MaskFnID   *int64   `json:"maskFnId,omitempty"`
	MaskFnName *string  `json:"maskFnName,omitempty"`
}

// MarshalJSON normalises Tags to `[]` rather than `null` (types/doc.go D9).
//
// Encodes through types.MarshalWire, NOT json.Marshal: kotlinx does not HTML-escape, and a column name
// or tag carrying '<' '&' '>' would otherwise reach the console as `<`. RespondJSON's
// non-escaping pass cannot undo an escape already baked in here. Found by the encoding/json/v2
// differential (conformance/wire_jsonv2_oracle_test.go).
func (c Classification) MarshalJSON() ([]byte, error) {
	type alias Classification
	a := alias(c)
	if a.Tags == nil {
		a.Tags = []string{}
	}
	return types.MarshalWire(a)
}

// CatalogColumn is one catalog row as served. Port of Datasources.kt:85-101.
type CatalogColumn struct {
	// Catalog is COMPUTED IN SQL, not stored:
	// `CASE WHEN lower(d.engine)='mysql' THEN 'def' ELSE d.db_name END` (Datasources.kt:539).
	// A port must reproduce this, including the lower().
	Catalog  string `json:"catalog"`
	Schema   string `json:"schema"`
	Table    string `json:"table"`
	Column   string `json:"column"`
	DataType string `json:"dataType"`
	SQLType  string `json:"sqlType"`
	Ordinal  int32  `json:"ordinal"`
	Nullable bool   `json:"nullable"`
	// Classification is non-null IFF a column_classification row exists — a row with empty tags still
	// yields a Classification with tags = [].
	Classification *Classification `json:"classification,omitempty"`
	// IsTemp is true for a per-connection session/temp column overlaid onto the base catalog.
	//
	// 🔒 INV-A5-1 — IsTemp is NEVER set by A5. Both A5 producers (DatasourceStore.catalog and
	// decideConnection's catalog build) leave it false. Only the per-request temp overlay (A6/A10)
	// sets it true, and A6 reads temps UNMASKED without a Cedar grant. A port that defaulted it true
	// — or that let a base-catalog column carry it — turns every column into an ungranted cleartext
	// read.
	IsTemp bool `json:"isTemp"`
}

// ClassificationInput is the PUT {id}/classification body. A nil Schema means "resolve the
// datasource's default schema" (see DatasourceStore.DefaultSchema).
type ClassificationInput struct {
	Schema   *string  `json:"schema,omitempty"`
	Table    string   `json:"table"`
	Column   string   `json:"column"`
	Tags     []string `json:"tags"`
	MaskFnID *int64   `json:"maskFnId,omitempty"`
}

// ClassificationDelete is the DELETE {id}/classification body.
type ClassificationDelete struct {
	Schema *string `json:"schema,omitempty"`
	Table  string  `json:"table"`
	Column string  `json:"column"`
}

// TestResult is the POST {id}/test body.
//
// ⚠️ l10n gap REPRODUCED (candidate finding, analogous to F13, §10 Q8): Message is ENGLISH PROSE on
// the wire, which AGENTS.md says never happens outside SCIM. The field is kept for compatibility;
// the strings are not localizable as written. Do not "fix" this here — §10 Q8 is open.
type TestResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// RefreshResult reports how many attached proxy Events streams took the push. 0 means no proxy
// attached, reported honestly (A12 INV-A12-14's honesty rule surfaced at the REST layer).
type RefreshResult struct {
	Notified int `json:"notified"`
}

// EngineConflictError is the Go form of DatasourceEngineConflictException (Datasources.kt:131-135).
//
// 🔒 INV-A5-9 — engine is immutable, and the reason is a four-way fail-open: silently flipping it
// would repoint every FK keyed off datasource_id (catalog_column, column_classification,
// query_history, access_request) at a schema from a DIFFERENT dialect, and the
// analyzer/system-classification manifest resolution keyed off engine would go stale — ALL
// FAIL-OPEN. Thrown BEFORE any write, so the row/catalog are left untouched.
//
// TODO(A10)/TODO(A1): gRPC Register maps this to FAILED_PRECONDITION; admin PUT maps it to 409
// datasource.engine_immutable.
type EngineConflictError struct {
	Name            string
	ExistingEngine  string
	RequestedEngine string
}

func (e *EngineConflictError) Error() string {
	return fmt.Sprintf(
		"datasource '%s' is registered as %s; refusing re-register as %s — engine is immutable at register (delete and re-create to change it)",
		e.Name, e.ExistingEngine, e.RequestedEngine,
	)
}

// javaInstantString renders a timestamp exactly as Java's `Instant.toString()` (DateTimeFormatter
// .ISO_INSTANT) does, which is what `getTimestamp(...)?.toInstant()?.toString()` produces for
// catalog_synced_at / last_seen_at.
//
// ⚠️ Wire-visible hazard called out in §1 and shared with A2 Q3: ISO_INSTANT OMITS TRAILING ZEROS in
// the fractional second, emitting 0, 3, 6 or 9 digits — never a fixed width. A Go port emitting
// RFC3339Nano differs (RFC3339Nano strips ALL trailing zeros, so .100 becomes .1) and one emitting
// fixed-millis differs too. PostgreSQL timestamptz has microsecond resolution, so in practice this
// yields 0, 3 or 6 digits.
func javaInstantString(t time.Time) string {
	u := t.UTC()
	base := u.Format("2006-01-02T15:04:05")
	nanos := u.Nanosecond()
	switch {
	case nanos == 0:
		return base + "Z"
	case nanos%1_000_000 == 0:
		return fmt.Sprintf("%s.%03dZ", base, nanos/1_000_000)
	case nanos%1_000 == 0:
		return fmt.Sprintf("%s.%06dZ", base, nanos/1_000)
	default:
		return fmt.Sprintf("%s.%09dZ", base, nanos)
	}
}
