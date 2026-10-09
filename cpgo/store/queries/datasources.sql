-- name: Datasources :many
SELECT id, name, engine, host, port, db_name, tags, default_schemas, mysql_lower_case_table_names,
       catalog_synced_at, last_seen_at, engine_version, advertise_addr, advertise_cert_chain,
       advertise_wire_tls, current_catalog_name, connection_info, description
FROM datasource WHERE deleted_at IS NULL ORDER BY id;
