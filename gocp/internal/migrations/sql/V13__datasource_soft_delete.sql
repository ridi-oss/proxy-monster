-- Datasource delete is a soft delete. An operator's delete flips `deleted_at` instead of removing
-- the row, so the access_request / query_result / audit_event history that references the datasource
-- survives -- audit_event is the authoritative security record and must not be lost to a delete, and
-- access_request holds a foreign key to datasource that a hard delete could not satisfy anyway.
--
-- A soft-deleted row is excluded from every live read (store.list / get / getByName), so policies and
-- proxy resolution behave exactly as if the datasource were gone. Its name is freed for reuse by
-- scoping the name-uniqueness index to live rows: two live datasources still cannot share a name, but
-- a new one may take the name of a soft-deleted predecessor.
ALTER TABLE datasource ADD COLUMN deleted_at TIMESTAMPTZ;

ALTER TABLE datasource DROP CONSTRAINT datasource_name_key;
CREATE UNIQUE INDEX datasource_name_live_key ON datasource (name) WHERE deleted_at IS NULL;
