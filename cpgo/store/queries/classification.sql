-- name: SetClassification :exec
INSERT INTO column_classification
(datasource_id, schema_name, table_name, column_name, tags, mask_fn_id, updated_at, catalog_name)
VALUES (@datasource_id, @schema_name, @table_name, @column_name, @tags::jsonb, @mask_fn_id, now(), @catalog_name)
ON CONFLICT (datasource_id, catalog_name, schema_name, table_name, column_name)
DO UPDATE SET tags = EXCLUDED.tags, mask_fn_id = EXCLUDED.mask_fn_id, updated_at = now();

-- name: LiveMaskFnName :one
SELECT name FROM mask_fn WHERE id = $1 AND deleted_at IS NULL;

-- name: ClearClassification :execrows
DELETE FROM column_classification WHERE datasource_id = @datasource_id AND catalog_name = @catalog_name
AND schema_name = @schema_name AND table_name = @table_name AND column_name = @column_name;
