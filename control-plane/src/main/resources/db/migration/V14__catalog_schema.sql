-- The per-schema version behind the stored catalog.
--
-- catalog_column holds a datasource's columns; this holds, per schema, the reading those columns came
-- from: the content hash the backend computed, the backend's own clock at that instant, and which
-- backend it was. A schema's columns are replaced only by a reading that is newer in the backend's own
-- clock, so a slow whole-server scan cannot overwrite a newer per-connection measurement that arrived
-- first.
--
-- A row exists only for a schema whose reading could be believed. A schema whose hash measurement
-- failed keeps its columns and carries no version, which reads as "no ordering evidence" rather than as
-- an ordering claim.

CREATE TABLE catalog_schema (
    id              BIGSERIAL PRIMARY KEY,
    datasource_id   BIGINT NOT NULL REFERENCES datasource(id) ON DELETE CASCADE,
    schema_name     TEXT NOT NULL,
    -- The backend-computed content hash of this schema's columns, as raw bytes.
    hash            BYTEA NOT NULL,
    -- The backend's own clock, in microseconds, read in the same statement as the hash. 0 = the backend
    -- could not supply a clock that a session variable cannot move, so the reading carries no version.
    db_clock_micros BIGINT NOT NULL DEFAULT 0,
    -- The server the reading came from (MySQL @@server_uuid / PostgreSQL system_identifier). Empty when
    -- unreadable under the service account; clocks are only ever compared within one non-empty identity.
    backend_id      TEXT NOT NULL DEFAULT '',
    observed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (datasource_id, schema_name)
);
