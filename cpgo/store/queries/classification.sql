-- name: SetClassification :exec
INSERT INTO column_classification
(datasource_id, schema_name, table_name, column_name, tags, mask_fn_id, updated_at, catalog_name)
VALUES (@datasource_id, @schema_name, @table_name, @column_name, @tags::jsonb, @mask_fn_id, now(), @catalog_name)
ON CONFLICT (datasource_id, catalog_name, schema_name, table_name, column_name)
DO UPDATE SET tags = EXCLUDED.tags, mask_fn_id = EXCLUDED.mask_fn_id, updated_at = now();

-- name: LiveMaskFnName :one
SELECT name FROM mask_fn WHERE id = $1 AND deleted_at IS NULL;

-- name: ClearClassification :execrows
DELETE FROM column_classification WHERE datasource_id = $1 AND schema_name = $2
AND table_name = $3 AND column_name = $4 AND catalog_name = $5;
