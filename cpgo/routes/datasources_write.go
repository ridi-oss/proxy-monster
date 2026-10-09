package routes

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/engine"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

func conflict(code string) error { return &managementError{code: code, status: http.StatusConflict} }

func getDatasource(ctx context.Context, q dbtx, id int64) (*datasource, error) {
	row, err := db.New(q).Datasource(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("datasource")
	}
	var ds datasource
	if err == nil {
		ds, err = toDatasource(db.DatasourcesRow(row))
	}
	return &ds, err
}

type datasourceInput struct {
	Name   *string `json:"name"`
	Engine *string `json:"engine"`
	Host   string  `json:"host"`
	Port   int     `json:"port"`
	DBName string  `json:"dbName"`
}

// decodeDatasource reads the body and canonicalizes its engine, so a stored engine is always a wire name.
func decodeDatasource(r *http.Request) (datasourceInput, error) {
	var in datasourceInput
	if err := decodeBody(r, &in); err != nil || in.Name == nil {
		return in, &managementError{code: "common.invalid_value", params: api.Params{{"field", "body"}}}
	}
	if err := required("name", *in.Name); err != nil {
		return in, err
	}
	raw := "postgres"
	if in.Engine != nil {
		raw = *in.Engine
	}
	def, ok := engine.ByWireName(raw)
	if !ok {
		return in, &managementError{code: "datasource.invalid_engine", params: api.Params{{"engine", raw}}}
	}
	in.Engine = &def.WireName
	return in, nil
}

func datasourceEntity(name string) string { return audit.Entity("Datasource", name) }

func (d datasources) create(w http.ResponseWriter, r *http.Request) {
	in, err := decodeDatasource(r)
	if err != nil {
		writeMutationError(w, err)
		return
	}
	mutate(d.pool, w, r, http.StatusCreated, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		id, err := db.New(tx).CreateDatasource(ctx, db.CreateDatasourceParams{Name: *in.Name, Engine: *in.Engine, Host: in.Host, Port: in.Port, DbName: in.DBName})
		if err != nil {
			return nil, err
		}
		ds, err := getDatasource(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		return ds, audit.Admin(ctx, tx, actor, "admin.datasources", datasourceEntity(ds.Name), "create datasource '"+ds.Name+"'")
	})
}

// update edits the advisory fields. The engine is immutable, so a stored catalog is never read under another
// dialect, and a db_name change drops the catalog, which now describes a different database.
func (d datasources) update(w http.ResponseWriter, r *http.Request, id int64) {
	in, err := decodeDatasource(r)
	if err != nil {
		writeMutationError(w, err)
		return
	}
	mutate(d.pool, w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		before, err := getDatasource(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		q := db.New(tx)
		locked, err := q.LockDatasourceEngine(ctx, id)
		engine, dbName := locked.Engine, locked.DbName
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, notFound("datasource")
		}
		if err != nil {
			return nil, err
		}
		if engine != *in.Engine {
			return nil, conflict("datasource.engine_immutable")
		}
		if err := q.UpdateDatasource(ctx, db.UpdateDatasourceParams{Name: *in.Name, Engine: *in.Engine, Host: in.Host, Port: in.Port, DbName: in.DBName, ID: id}); err != nil {
			return nil, err
		}
		if dbName != in.DBName {
			if err := q.ResetDatasourceCatalog(ctx, id); err != nil {
				return nil, err
			}
		}
		after, err := getDatasource(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		return after, audit.Admin(ctx, tx, actor, "admin.datasources", datasourceEntity(after.Name), updateSummary("datasource", before.Name, after.Name))
	})
}

// delete soft-deletes, refused while a proxy is attached or a request on it is still open: a freed name
// may be reused at once, and live state must not outlive the row it was built for.
func (d datasources) delete(w http.ResponseWriter, r *http.Request, id int64) {
	var deleted string
	mutate(d.pool, w, r, http.StatusNoContent, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		ds, err := getDatasource(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		attached, err := d.kotlin.ProxiesAttached(ctx)
		if err != nil {
			return nil, err
		}
		if slices.Contains(attached, ds.Name) {
			return nil, conflict("datasource.in_use_proxy_attached")
		}
		active, err := db.New(tx).DatasourceHasActiveRequests(ctx, &id)
		if err != nil {
			return nil, err
		}
		if active {
			return nil, conflict("datasource.in_use_active_requests")
		}
		n, err := db.New(tx).DeleteDatasource(ctx, id)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, notFound("datasource")
		}
		deleted = ds.Name
		return nil, audit.Admin(ctx, tx, actor, "admin.datasources", datasourceEntity(ds.Name), "delete datasource '"+ds.Name+"'")
	}, func(ctx context.Context) error { return d.kotlin.DatasourceDeleted(ctx, deleted) })
}
