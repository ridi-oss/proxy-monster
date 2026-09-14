ALTER TABLE datasource ADD COLUMN current_catalog_name TEXT;
ALTER TABLE datasource ADD COLUMN connection_info JSONB;
UPDATE datasource SET current_catalog_name = CASE WHEN engine = 'mysql' THEN 'def' ELSE db_name END;

ALTER TABLE column_classification ADD COLUMN catalog_name TEXT;
UPDATE column_classification c SET catalog_name = d.current_catalog_name FROM datasource d WHERE d.id = c.datasource_id;
ALTER TABLE column_classification ALTER COLUMN catalog_name SET NOT NULL;

DO $$
DECLARE key RECORD;
BEGIN
    FOR key IN SELECT conrelid::regclass AS relation, conname FROM pg_constraint
        WHERE conrelid = 'column_classification'::regclass AND contype = 'u'
    LOOP
        EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', key.relation, key.conname);
    END LOOP;
END $$;

ALTER TABLE column_classification ADD CONSTRAINT column_classification_identity_key
    UNIQUE (datasource_id, catalog_name, schema_name, table_name, column_name);
