package datasources

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

// wireEngine is raw as the engine name a proxy registers, if it names one.
func wireEngine(raw string) (string, bool) {
	switch e := strings.ToLower(raw); e {
	case "mysql", "postgres", "athena":
		return e, true
	}
	return "", false
}

type datasourceInput struct {
	Name   *string `json:"name"`
	Engine *string `json:"engine"`
	Host   string  `json:"host"`
	Port   int32   `json:"port"`
	DBName string  `json:"dbName"`
}

// decodeDatasource reads the body and canonicalizes its engine, so a stored engine is always a wire name.
func decodeDatasource(r *http.Request) (datasourceInput, error) {
	var in datasourceInput
	if err := api.DecodeBody(r, &in); err != nil || in.Name == nil {
		// Kotlin answers an unreadable body with 500, not DecodeBody's 400.
		return in, errors.New("datasource body does not decode")
	}
	if err := api.Required("name", *in.Name); err != nil {
		return in, err
	}
	raw := "postgres"
	if in.Engine != nil {
		raw = *in.Engine
	}
	engine, ok := wireEngine(raw)
	if !ok {
		return in, api.CodeInvalidEngine.Err("engine", raw)
	}
	in.Engine = &engine
	return in, nil
}

func getDatasource(ctx context.Context, q db.DBTX, id int64) (datasource, error) {
	row, err := db.New(q).Datasource(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return datasource{}, api.NotFound("datasource")
	}
	if err != nil {
		return datasource{}, err
	}
	return toDatasource(db.DatasourcesRow(row))
}

func recordDatasource(ctx context.Context, tx pgx.Tx, actor audit.Actor, name, summary string) error {
	return audit.Admin(ctx, tx, actor, "admin.datasources", audit.Entity("Datasource", name), summary)
}

func (d datasources) create(w http.ResponseWriter, r *http.Request) error {
	in, err := decodeDatasource(r)
	if err != nil {
		return err
	}
	return api.Mutate(d.pool, w, r, http.StatusCreated, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		id, err := db.New(tx).CreateDatasource(ctx, db.CreateDatasourceParams{Name: *in.Name, Engine: *in.Engine, Host: in.Host, Port: in.Port, DbName: in.DBName})
		if err != nil {
			return nil, err
		}
		ds, err := getDatasource(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		return ds, recordDatasource(ctx, tx, actor, ds.Name, "create datasource '"+ds.Name+"'")
	})
}

// update edits the advisory fields. The engine is immutable, so a stored catalog is never read under another
// dialect, and a db_name change drops the catalog, which now describes a different database.
func (d datasources) update(w http.ResponseWriter, r *http.Request, id int64) error {
	in, err := decodeDatasource(r)
	if err != nil {
		return err
	}
	return api.Mutate(d.pool, w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		before, err := getDatasource(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		q := db.New(tx)
		prior, err := q.LockDatasource(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, api.NotFound("datasource")
		}
		if err != nil {
			return nil, err
		}
		if prior.Engine != *in.Engine {
			return nil, api.CodeEngineImmutable.Err()
		}
		if err := q.UpdateDatasource(ctx, db.UpdateDatasourceParams{Name: *in.Name, Engine: *in.Engine, Host: in.Host, Port: in.Port, DbName: in.DBName, ID: id}); err != nil {
			return nil, err
		}
		if prior.DbName != in.DBName {
			if err := q.ResetDatasourceCatalog(ctx, id); err != nil {
				return nil, err
			}
		}
		after, err := getDatasource(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		return after, recordDatasource(ctx, tx, actor, after.Name, api.UpdateSummary("datasource", before.Name, after.Name))
	})
}

// delete soft-deletes, refused while a proxy is attached or a request on it is still open: a freed name may be
// reused at once, and live state must not outlive the row it was built for.
func (d datasources) delete(w http.ResponseWriter, r *http.Request, id int64) error {
	var deleted string
	return api.Mutate(d.pool, w, r, http.StatusNoContent, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		ds, err := getDatasource(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		attached, err := d.kotlin.ProxiesAttached(ctx)
		if err != nil {
			return nil, err
		}
		if slices.Contains(attached, ds.Name) {
			return nil, api.CodeInUseProxyAttached.Err()
		}
		q := db.New(tx)
		active, err := q.DatasourceHasActiveRequests(ctx, &id)
		if err != nil {
			return nil, err
		}
		if active {
			return nil, api.CodeInUseActiveRequests.Err()
		}
		n, err := q.DeleteDatasource(ctx, id)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, api.NotFound("datasource")
		}
		deleted = ds.Name
		return nil, recordDatasource(ctx, tx, actor, ds.Name, "delete datasource '"+ds.Name+"'")
	}, func(ctx context.Context) error { return d.kotlin.DatasourceDeleted(ctx, deleted) })
}
