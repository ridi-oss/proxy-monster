-- name: RequestCaller :one
SELECT principal, kind FROM proxy_token
WHERE token_hash = $1 AND kind IN ('SESSION', 'USER', 'EDITOR', 'APPROVER_EXEC')
  AND revoked_at IS NULL AND expires_at > now();

-- name: RequestDatasource :one
SELECT name, engine, db_name, current_catalog_name, tags FROM datasource WHERE name = $1 AND deleted_at IS NULL;
