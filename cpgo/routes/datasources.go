package routes

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

// datasource is one datasource row; fields in the Kotlin Datasource's order, defaultSchemaSettable last.
type datasource struct {
	ID                       int64           `json:"id"`
	Name                     string          `json:"name"`
	Engine                   string          `json:"engine"`
	Host                     string          `json:"host"`
	Port                     int             `json:"port"`
	DBName                   string          `json:"dbName"`
	Tags                     []string        `json:"tags"`
	DefaultSchemas           []string        `json:"defaultSchemas"`
	MySQLLowerCaseTableNames *int            `json:"mysqlLowerCaseTableNames,omitempty"`
	CatalogSyncedAt          *string         `json:"catalogSyncedAt,omitempty"`
	LastSeenAt               *string         `json:"lastSeenAt,omitempty"`
	EngineVersion            *string         `json:"engineVersion,omitempty"`
	AdvertiseAddr            *string         `json:"advertiseAddr,omitempty"`
	AdvertiseCertChain       *string         `json:"advertiseCertChain,omitempty"`
	AdvertiseWireTLS         bool            `json:"advertiseWireTls"`
	CurrentCatalog           *string         `json:"currentCatalog,omitempty"`
	ConnectionInfo           json.RawMessage `json:"connectionInfo,omitempty"`
	Description              string          `json:"description"`
	DefaultSchemaSettable    bool            `json:"defaultSchemaSettable"`
}

// withoutConnectionMaterial is the row a caller who may not datasource.connect sees.
func (d datasource) withoutConnectionMaterial() datasource {
	d.Host, d.Port, d.DBName = "", 0, ""
	d.AdvertiseAddr, d.AdvertiseCertChain, d.CurrentCatalog, d.ConnectionInfo = nil, nil, nil, nil
	d.Description = ""
	return d
}

func toDatasource(r db.DatasourcesRow) (datasource, error) {
	d := datasource{ID: r.ID, Name: r.Name, Engine: r.Engine, Host: r.Host, Port: r.Port, DBName: r.DbName,
		EngineVersion: r.EngineVersion, AdvertiseAddr: r.AdvertiseAddr, AdvertiseCertChain: r.AdvertiseCertChain,
		AdvertiseWireTLS: r.AdvertiseWireTls, CurrentCatalog: r.CurrentCatalogName, Description: r.Description}
	if r.MysqlLowerCaseTableNames != nil {
		n := int(*r.MysqlLowerCaseTableNames)
		d.MySQLLowerCaseTableNames = &n
	}
	d.Engine = strings.ToLower(d.Engine)
	d.Tags, d.DefaultSchemas = nonNil(r.Tags), nonNil(r.DefaultSchemas)
	d.CatalogSyncedAt, d.LastSeenAt = optInstant(r.CatalogSyncedAt), optInstant(r.LastSeenAt)
	// Athena has no default-schema statement; the wire engines do.
	d.DefaultSchemaSettable = d.Engine == "postgres" || d.Engine == "mysql"
	var err error
	if r.ConnectionInfo != nil {
		d.ConnectionInfo, err = canonicalConnectionInfo(r.ConnectionInfo)
	}
	return d, err
}

// canonicalConnectionInfo re-encodes the stored JSON as {"endpoint", "properties"}, the shape Kotlin's
// ConnectionInfoSerializer writes back, keeping the stored property order.
func canonicalConnectionInfo(stored []byte) (json.RawMessage, error) {
	var in struct {
		Endpoint   string          `json:"endpoint"`
		Properties json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(stored, &in); err != nil {
		return nil, err
	}
	var props bytes.Buffer
	if len(in.Properties) == 0 || string(in.Properties) == "null" {
		props.WriteString("{}")
	} else if err := json.Compact(&props, in.Properties); err != nil {
		return nil, err
	}
	endpoint, _ := json.Marshal(in.Endpoint)
	return json.RawMessage(`{"endpoint":` + string(endpoint) + `,"properties":` + props.String() + `}`), nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type datasources struct {
	pool   *pgxpool.Pool
	authz  api.Authorizer
	kotlin api.Kotlin
}

// list is every live datasource; a row the caller may not connect to loses its connection material, and
// connectable=true drops such rows instead.
func (d datasources) list(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := db.New(d.pool).Datasources(ctx)
	if err != nil {
		fail(w, err)
		return
	}
	all := make([]datasource, len(rows))
	for i, row := range rows {
		if all[i], err = toDatasource(row); err != nil {
			fail(w, err)
			return
		}
	}
	ids := make([]int64, len(all))
	for i, ds := range all {
		ids[i] = ds.ID
	}
	may, err := d.authz.MayConnect(ctx, api.Principal(ctx), ids, api.RequesterIP(ctx))
	if err != nil {
		fail(w, err)
		return
	}
	connectableOnly := strings.EqualFold(r.URL.Query().Get("connectable"), "true")
	out := []datasource{}
	for i, ds := range all {
		switch {
		case may[i]:
			out = append(out, ds)
		case !connectableOnly:
			out = append(out, ds.withoutConnectionMaterial())
		}
	}
	api.WriteJSON(w, http.StatusOK, out)
}

// connectable is the live datasource id names, or the answer already written: 404 for a missing one, 403
// datasource.not_connectable when the caller may not datasource.connect to it.
func (d datasources) connectable(w http.ResponseWriter, r *http.Request, id int64) (*datasource, bool) {
	ctx := r.Context()
	row, err := db.New(d.pool).Datasource(ctx, id)
	var ds datasource
	if err == nil {
		ds, err = toDatasource(db.DatasourcesRow(row))
	}
	if errors.Is(err, pgx.ErrNoRows) {
		api.WriteError(w, http.StatusNotFound, "common.not_found", map[string]string{"resource": "datasource"})
		return nil, false
	}
	var may []bool
	if err == nil {
		may, err = d.authz.MayConnect(ctx, api.Principal(ctx), []int64{id}, api.RequesterIP(ctx))
	}
	if err != nil {
		fail(w, err)
		return nil, false
	}
	if !may[0] {
		api.WriteError(w, http.StatusForbidden, "datasource.not_connectable", nil)
		return nil, false
	}
	return &ds, true
}

// get is one datasource with its connection material, so it takes the same connect gate as wire-cert.
func (d datasources) get(w http.ResponseWriter, r *http.Request, id int64) {
	if ds, ok := d.connectable(w, r, id); ok {
		api.WriteJSON(w, http.StatusOK, ds)
	}
}

// wireCert serves the proxy's advertised wire TLS chain as stored; the client is the one that verifies it.
func (d datasources) wireCert(w http.ResponseWriter, r *http.Request, id int64) {
	ds, ok := d.connectable(w, r, id)
	if !ok {
		return
	}
	if ds.AdvertiseCertChain == nil || strings.TrimSpace(*ds.AdvertiseCertChain) == "" {
		api.WriteError(w, http.StatusNotFound, "datasource.no_wire_cert", nil)
		return
	}
	// The file is named by id: a datasource name could carry a quote or CRLF into the header.
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="datasource-%d-wire-cert.pem"`, ds.ID))
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, *ds.AdvertiseCertChain)
}
