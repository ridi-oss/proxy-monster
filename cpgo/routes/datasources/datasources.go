package datasources

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

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

func Register(mux *http.ServeMux, pool *pgxpool.Pool, gate api.Gate) {
	ds := datasources{pool: pool, authz: gate.Authz, kotlin: gate.Kotlin}
	admin := func(h api.Route) http.HandlerFunc { return gate.RequireAdmin("admin.datasources", api.Serve(h)) }
	mux.HandleFunc("GET /api/datasources", gate.RequireAPIOrBearer(api.Serve(ds.list)))
	mux.HandleFunc("GET /api/datasources/{id}", gate.RequireAPIOrBearer(api.Serve(api.WithID(ds.get))))
	mux.HandleFunc("POST /api/datasources", admin(ds.create))
	mux.HandleFunc("PUT /api/datasources/{id}", admin(api.WithID(ds.update)))
	mux.HandleFunc("DELETE /api/datasources/{id}", admin(api.WithID(ds.delete)))
	mux.HandleFunc("GET /api/datasources/{id}/wire-cert", gate.RequireAPIOrBearer(api.Serve(api.WithID(ds.wireCert))))
}

// datasource is one datasource row; fields in the Kotlin Datasource's order, the engine-derived ones last.
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
	IdentifierQuote          string          `json:"identifierQuote"`
}

// withoutConnectionMaterial is the row a caller who may not datasource.connect sees.
func (d datasource) withoutConnectionMaterial() datasource {
	d.Host, d.Port, d.DBName = "", 0, ""
	d.AdvertiseAddr, d.AdvertiseCertChain, d.CurrentCatalog, d.ConnectionInfo = nil, nil, nil, nil
	d.Description = ""
	return d
}

func toDatasource(r db.DatasourcesRow) (datasource, error) {
	d := datasource{ID: r.ID, Name: r.Name, Engine: r.Engine, Host: r.Host, Port: int(r.Port), DBName: r.DbName,
		EngineVersion: r.EngineVersion, AdvertiseAddr: r.AdvertiseAddr, AdvertiseCertChain: r.AdvertiseCertChain,
		AdvertiseWireTLS: r.AdvertiseWireTls, CurrentCatalog: r.CurrentCatalogName, Description: r.Description}
	if r.MysqlLowerCaseTableNames != nil {
		n := int(*r.MysqlLowerCaseTableNames)
		d.MySQLLowerCaseTableNames = &n
	}
	d.Tags, d.DefaultSchemas = api.NonNil(r.Tags), api.NonNil(r.DefaultSchemas)
	d.CatalogSyncedAt, d.LastSeenAt = api.OptInstant(r.CatalogSyncedAt), api.OptInstant(r.LastSeenAt)
	engine, err := engines.Parse(d.Engine)
	if err != nil {
		return datasource{}, err
	}
	d.DefaultSchemaSettable, d.IdentifierQuote = engine.Traits.DefaultSchemaSettable, engine.Traits.IdentifierQuote
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

type datasources struct {
	pool   *pgxpool.Pool
	authz  api.Authorizer
	kotlin api.Kotlin
}

// list is every live datasource; a row the caller may not connect to loses its connection material, and
// connectable=true drops such rows instead.
func (d datasources) list(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	rows, err := db.New(d.pool).Datasources(ctx)
	if err != nil {
		return err
	}
	all := make([]datasource, len(rows))
	for i, row := range rows {
		if all[i], err = toDatasource(row); err != nil {
			return err
		}
	}
	ids := make([]int64, len(all))
	for i, ds := range all {
		ids[i] = ds.ID
	}
	may, err := d.authz.MayConnect(ctx, api.Principal(ctx), ids, api.RequesterIP(ctx))
	if err != nil {
		return err
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
	return nil
}

// connectable is the live datasource id names, when the caller may datasource.connect to it.
func (d datasources) connectable(r *http.Request, id int64) (datasource, error) {
	ctx := r.Context()
	row, err := db.New(d.pool).Datasource(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return datasource{}, api.NotFound("datasource")
	}
	if err != nil {
		return datasource{}, err
	}
	ds, err := toDatasource(db.DatasourcesRow(row))
	if err != nil {
		return datasource{}, err
	}
	may, err := d.authz.MayConnect(ctx, api.Principal(ctx), []int64{id}, api.RequesterIP(ctx))
	if err != nil {
		return datasource{}, err
	}
	if !may[0] {
		return datasource{}, api.CodeNotConnectable.Err()
	}
	return ds, nil
}

func (d datasources) get(w http.ResponseWriter, r *http.Request, id int64) error {
	ds, err := d.connectable(r, id)
	if err != nil {
		return err
	}
	api.WriteJSON(w, http.StatusOK, ds)
	return nil
}

func (d datasources) wireCert(w http.ResponseWriter, r *http.Request, id int64) error {
	ds, err := d.connectable(r, id)
	if err != nil {
		return err
	}
	if ds.AdvertiseCertChain == nil || strings.TrimSpace(*ds.AdvertiseCertChain) == "" {
		return api.CodeNoWireCert.Err()
	}
	// Named by id: a datasource name could carry a quote or CRLF into the header.
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="datasource-%d-wire-cert.pem"`, ds.ID))
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	_, err = io.WriteString(w, *ds.AdvertiseCertChain)
	return err
}
