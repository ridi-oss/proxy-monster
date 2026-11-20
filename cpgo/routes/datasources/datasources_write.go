package datasources

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

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
