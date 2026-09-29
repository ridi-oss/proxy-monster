-- Datasources and the catalog the analyzer resolves against.
--
-- The proxy is the source of truth: it self-registers over gRPC (Register) and pushes its own
-- introspected catalog (PushCatalog). The control plane never dials a target, so it holds no
-- credential to one -- there is literally zero target-datasource secret at rest here.

CREATE TABLE datasource (
    id                BIGSERIAL PRIMARY KEY,
    name              TEXT NOT NULL UNIQUE,
    engine            TEXT NOT NULL DEFAULT 'postgres',   -- postgres | mysql
    host              TEXT NOT NULL,                      -- advisory upstream db, for display
    port              INT  NOT NULL,
    db_name           TEXT NOT NULL,
    -- Posture and free-form tags. Authz marshals these onto the Datasource Cedar entity, so every
    -- Table/Column/Function under it is transitively `in Tag::"<tag>"`. Only the two recognized
    -- posture tags (system:development / system:production) govern the shipped preset policies; any
    -- other tag is carried but inert. Same JSONB-array shape as column_classification.tags.
    tags              JSONB NOT NULL DEFAULT '[]',
    -- Static namespace metadata captured from the same fresh target connection as each catalog
    -- snapshot: the ordered default schemas (PG search_path / the MySQL database) bare names resolve
    -- against. Empty until a proxy introspects -- guessing would make bare-name resolution unsafe.
    default_schemas   JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- MySQL's @@lower_case_table_names, which decides identifier-case behavior. NULL until read.
    mysql_lower_case_table_names INT,
    -- The target's live server version, pushed over PushCatalog. system classification resolves its
    -- immutable manifest by major engine version + Aurora-ness, keyed off this. NULL until a push.
    engine_version    TEXT,
    -- The client-facing address a wire client (pmon) dials to reach THIS datasource's proxy, set at
    -- Register (RegisterRequest.advertise_addr). Distinct from host/port. NULL until a proxy
    -- advertises one.
    advertise_addr    TEXT,
    -- Hex SHA-256 of the proxy's LEAF wire cert (self-signed is fine; no chain), set at Register.
    -- GET /api/datasources surfaces it so pmon pins the proxy against exactly this cert per
    -- connection -- no CA, no system trust store. The CHECK backstops the register RPC's boundary
    -- validation: a malformed value can never silently break every pinned handshake for a datasource.
    advertise_cert_sha256 TEXT,
    -- Liveness, driven by the Events stream's open/closed state. NULL for a datasource that has never
    -- had a proxy attach (pre-provisioned through the admin UI).
    last_seen_at      TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    catalog_synced_at TIMESTAMPTZ,
    CONSTRAINT datasource_tags_array CHECK (jsonb_typeof(tags) = 'array'),
    CONSTRAINT datasource_default_schemas_array CHECK (jsonb_typeof(default_schemas) = 'array'),
    CONSTRAINT datasource_mysql_lower_case_table_names_range
        CHECK (mysql_lower_case_table_names IS NULL OR mysql_lower_case_table_names BETWEEN 0 AND 2),
    CONSTRAINT datasource_advertise_cert_sha256_check
        CHECK (advertise_cert_sha256 IS NULL OR advertise_cert_sha256 ~ '^[0-9a-f]{64}$')
);

-- The introspected catalog: one row per column, keyed by the REAL schema name (a MySQL database is a
-- schema), so classifications and lineage join on the same identifier the backend resolves.
CREATE TABLE catalog_column (
    id            BIGSERIAL PRIMARY KEY,
    datasource_id BIGINT NOT NULL REFERENCES datasource(id) ON DELETE CASCADE,
    schema_name   TEXT NOT NULL DEFAULT 'public',
    table_name    TEXT NOT NULL,
    column_name   TEXT NOT NULL,
    data_type     TEXT NOT NULL,   -- the raw db type (e.g. "character varying")
    sql_type      TEXT NOT NULL,   -- the normalized type name the analyzer binds against
    ordinal       INT  NOT NULL,
    nullable      BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (datasource_id, schema_name, table_name, column_name)
);
CREATE INDEX idx_catalog_column_ds ON catalog_column (datasource_id, table_name);

-- Mask functions a classification may point at. Masking selects the transform by `kind` alone.
CREATE TABLE mask_fn (
    id   BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL          -- FIXED | LAST_N | FORMAT_PRESERVING | NULL
);

-- Column classification, overlaid on the catalog: the `tags` a column carries (e.g. "pii") plus an
-- optional mask function. This is catalog DATA, not authorization -- Authz.authorizeColumns marshals
-- it fresh into Cedar entities per request (Column/Table/Tag in resources/authz/schema.cedarschema),
-- and WHO may read or mask a column is Cedar policy text in `policy`. A touched column with no
-- matching grant is denied, never returned cleartext.
CREATE TABLE column_classification (
    id            BIGSERIAL PRIMARY KEY,
    datasource_id BIGINT NOT NULL REFERENCES datasource(id) ON DELETE CASCADE,
    schema_name   TEXT NOT NULL DEFAULT 'public',
    table_name    TEXT NOT NULL,
    column_name   TEXT NOT NULL,
    tags          JSONB NOT NULL DEFAULT '[]',
    mask_fn_id    BIGINT REFERENCES mask_fn(id),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (datasource_id, schema_name, table_name, column_name)
);
