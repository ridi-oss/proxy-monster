-- name: SetLocale :exec
UPDATE app_user SET locale = $1 WHERE principal = $2;

-- name: QueryHistory :many
SELECT sql, datasource_id, created_at FROM (
    SELECT DISTINCT ON (sql) sql, datasource_id, created_at
    FROM query_history WHERE principal = $1
    ORDER BY sql, created_at DESC
) q
ORDER BY created_at DESC
LIMIT $2;

-- name: DeleteQueryHistory :exec
DELETE FROM query_history WHERE principal = $1;
