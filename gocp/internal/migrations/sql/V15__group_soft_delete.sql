-- Soft delete for groups, mirroring datasource (V13) and role/mask_fn (V14). A delete stamps `deleted_at`
-- instead of removing the row, so the group_member / group_role history survives and the referencing
-- foreign keys a hard delete could not need to cascade are left intact. A soft-deleted group is excluded
-- from every live read AND from role resolution — its group_role links grant nothing. Its name and SCIM
-- external_id are freed for reuse by scoping both uniqueness indexes to live rows.
ALTER TABLE app_group ADD COLUMN deleted_at TIMESTAMPTZ;

ALTER TABLE app_group DROP CONSTRAINT app_group_name_key;
CREATE UNIQUE INDEX app_group_name_live_key ON app_group (name) WHERE deleted_at IS NULL;

DROP INDEX idx_app_group_external_id_unique;
CREATE UNIQUE INDEX idx_app_group_external_id_unique
    ON app_group (external_id) WHERE external_id IS NOT NULL AND deleted_at IS NULL;
