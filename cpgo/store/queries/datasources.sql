-- name: Datasources :many
SELECT id, name, engine, host, port, db_name, tags, default_schemas, mysql_lower_case_table_names,
       catalog_synced_at, last_seen_at, engine_version, advertise_addr, advertise_cert_chain,
       advertise_wire_tls, current_catalog_name, connection_info, description
FROM datasource WHERE deleted_at IS NULL ORDER BY id;

-- name: Datasource :one
SELECT id, name, engine, host, port, db_name, tags, default_schemas, mysql_lower_case_table_names,
       catalog_synced_at, last_seen_at, engine_version, advertise_addr, advertise_cert_chain,
       advertise_wire_tls, current_catalog_name, connection_info, description
FROM datasource WHERE deleted_at IS NULL AND id = $1;

-- name: CreateDatasource :one
INSERT INTO datasource (name, engine, host, port, db_name) VALUES ($1, $2, $3, $4, $5) RETURNING id;

-- name: LockDatasourceEngine :one
SELECT engine, db_name FROM datasource WHERE id = $1 AND deleted_at IS NULL FOR UPDATE;

-- name: UpdateDatasource :exec
UPDATE datasource SET name = $1, engine = $2, host = $3, port = $4, db_name = $5
WHERE id = $6 AND deleted_at IS NULL;

-- name: ResetDatasourceCatalog :exec
UPDATE datasource SET catalog = NULL, current_catalog_name = NULL, catalog_synced_at = NULL,
default_schemas = '[]'::jsonb, mysql_lower_case_table_names = NULL WHERE id = $1;

-- name: DatasourceHasActiveRequests :one
SELECT EXISTS (SELECT 1 FROM access_request WHERE datasource_id = $1 AND (
(kind = 'ROLE' AND status = 'PENDING') OR (kind = 'QUERY' AND status IN ('PENDING', 'EXECUTING'))));

-- name: DeleteDatasource :execrows
UPDATE datasource SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL;
