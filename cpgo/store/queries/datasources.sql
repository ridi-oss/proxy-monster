-- name: Datasources :many
SELECT id, name, engine, db_name, target_info, tags, default_schemas, mysql_lower_case_table_names,
       catalog_synced_at, last_seen_at, engine_version, advertise_addr, advertise_cert_chain,
       advertise_wire_tls, current_catalog_name, connection_info, description
FROM datasource WHERE deleted_at IS NULL ORDER BY id;

-- name: Datasource :one
SELECT id, name, engine, db_name, target_info, tags, default_schemas, mysql_lower_case_table_names,
       catalog_synced_at, last_seen_at, engine_version, advertise_addr, advertise_cert_chain,
       advertise_wire_tls, current_catalog_name, connection_info, description
FROM datasource WHERE id = $1 AND deleted_at IS NULL;

-- name: DatasourceHasActiveRequests :one
SELECT EXISTS (SELECT 1 FROM access_request WHERE datasource_id = $1 AND (
(kind = 'ROLE' AND status = 'PENDING') OR (kind = 'QUERY' AND status IN ('PENDING', 'EXECUTING'))));

-- name: DeleteDatasource :execrows
UPDATE datasource SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL;
