-- Shared column classification: a named set of rules several datasources attach to.
--
-- `column_classification` is keyed by datasource, so N datasources over the same schema need N copies
-- of every rule and they drift independently. A profile holds the rules once; an attachment points a
-- datasource at it.
--
-- Resolution is ADDITIVE, and that is a security property rather than a convenience. A column's tags
-- are the UNION of every attached profile's rule and the datasource's own row, so a per-datasource
-- override can add a tag but can never drop one a profile applied -- an override that omitted `pii`
-- would silently return a masked column as cleartext. Dropping an inherited tag requires detaching
-- the profile, which is explicit and visible. The mask function is the one value resolved by
-- precedence rather than union (a column masks one way): the datasource's own row wins, then the
-- lowest `precedence` attachment, so a datasource can sharpen a profile's mask without touching tags.
--
-- The union itself is resolved in Kotlin (DatasourceStore.classificationsFor), not in a view here:
-- aggregating the tag arrays in SQL costs ~35x the unordered scan on a realistic catalog, and this
-- read sits on the per-statement decision path.

CREATE TABLE classification_profile (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One rule per column, the same shape as a column_classification row minus the datasource.
-- schema_name has no default: a profile belongs to no one datasource when it is written, so there is
-- no introspected default schema to resolve a NULL against the way a column_classification write can.
CREATE TABLE classification_profile_rule (
    id          BIGSERIAL PRIMARY KEY,
    profile_id  BIGINT NOT NULL REFERENCES classification_profile(id) ON DELETE CASCADE,
    schema_name TEXT NOT NULL,
    table_name  TEXT NOT NULL,
    column_name TEXT NOT NULL,
    tags        JSONB NOT NULL DEFAULT '[]',
    mask_fn_id  BIGINT REFERENCES mask_fn(id),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (profile_id, schema_name, table_name, column_name),
    CONSTRAINT classification_profile_rule_tags_array CHECK (jsonb_typeof(tags) = 'array')
);
CREATE INDEX idx_classification_profile_rule_profile ON classification_profile_rule (profile_id);

-- Which profiles a datasource inherits. `precedence` orders only the mask-function tiebreak; tags
-- union regardless of it, so no ordering can subtract a tag.
--
-- RESTRICT on profile_id, not CASCADE: cascading would let a profile delete silently drop the
-- attachments that carry its tags, unclassifying every column it alone covered. The application also
-- refuses that delete, but the constraint is what makes it impossible rather than merely checked --
-- an app-level check alone races with a concurrent attach. Detaching first is the only path.
-- datasource_id stays CASCADE: deleting the datasource takes its columns with it, so there is no
-- classification left to lose.
CREATE TABLE datasource_classification_profile (
    datasource_id BIGINT NOT NULL REFERENCES datasource(id) ON DELETE CASCADE,
    profile_id    BIGINT NOT NULL REFERENCES classification_profile(id) ON DELETE RESTRICT,
    -- The datasource's own classification sits at -1 in resolution and must outrank every profile.
    precedence    INT NOT NULL DEFAULT 0,
    attached_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (datasource_id, profile_id),
    CONSTRAINT datasource_classification_profile_precedence_non_negative CHECK (precedence >= 0)
);
CREATE INDEX idx_datasource_classification_profile_profile
    ON datasource_classification_profile (profile_id);
