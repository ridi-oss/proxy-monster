-- Soft delete for roles and mask functions, mirroring datasource (V13). A delete stamps `deleted_at`
-- instead of removing the row, so the access_request / access_grant / column_classification history that
-- references it survives (and the referencing foreign keys a hard delete could not satisfy are never
-- touched). A soft-deleted row is excluded from every live read and, critically, from role resolution and
-- mask selection, so a deleted role grants nothing and a deleted mask function falls back to FIXED masking.
-- The name is freed for reuse via a partial unique index scoped to live rows.

ALTER TABLE app_role ADD COLUMN deleted_at TIMESTAMPTZ;
ALTER TABLE app_role DROP CONSTRAINT app_role_name_key;
CREATE UNIQUE INDEX app_role_name_live_key ON app_role (name) WHERE deleted_at IS NULL;

ALTER TABLE mask_fn ADD COLUMN deleted_at TIMESTAMPTZ;
ALTER TABLE mask_fn DROP CONSTRAINT mask_fn_name_key;
CREATE UNIQUE INDEX mask_fn_name_live_key ON mask_fn (name) WHERE deleted_at IS NULL;
