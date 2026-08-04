-- Identity: users, groups, roles, and the two maps that turn an authenticated principal into a set
-- of effective roles.
--
-- The IdP never mints a role. Its group claim provisions local `app_group` membership on first login
-- (UserGroupStore.provisionFromOidc); `group_role` maps a local group to a proxy-monster role. A
-- principal string is the identity key everything else joins on -- `app_user.principal` parallels the
-- free-text principal in `principal_role` and `access_grant` without being an FK target for them, so a
-- local assignment stays independent of whether a user row exists yet.

CREATE TABLE app_role (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE app_user (
    id           BIGSERIAL PRIMARY KEY,
    principal    TEXT NOT NULL UNIQUE,
    display_name TEXT,
    email        TEXT,
    source       TEXT NOT NULL DEFAULT 'LOCAL',   -- LOCAL | SCIM
    external_id  TEXT,                            -- SCIM externalId; NULL for LOCAL
    active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE app_group (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    source      TEXT NOT NULL DEFAULT 'LOCAL',   -- LOCAL | SCIM
    external_id TEXT
);

-- external_id is an identity key for the SCIM lookups (findUserIdByExternalId /
-- findGroupIdByExternalId). Without uniqueness two rows could share one, and a later `active=false`
-- push would deactivate whichever row Postgres returned first while the real one stayed credentialed.
-- Partial (NULL excluded) because external_id is NULL for LOCAL rows and for the synthetic tombstone
-- rows deactivatePrincipalTombstone writes -- multiple NULLs must keep coexisting.
CREATE UNIQUE INDEX idx_app_user_external_id_unique ON app_user (external_id) WHERE external_id IS NOT NULL;
CREATE UNIQUE INDEX idx_app_group_external_id_unique ON app_group (external_id) WHERE external_id IS NOT NULL;

CREATE TABLE group_member (
    group_id BIGINT NOT NULL REFERENCES app_group(id) ON DELETE CASCADE,
    user_id  BIGINT NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX idx_group_member_user ON group_member (user_id);  -- the resolver walks user -> groups

CREATE TABLE group_role (
    group_id BIGINT NOT NULL REFERENCES app_group(id) ON DELETE CASCADE,
    role_id  BIGINT NOT NULL REFERENCES app_role(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, role_id)
);
CREATE INDEX idx_group_role_role ON group_role (role_id);

-- Direct principal -> role assignment, independent of group membership.
CREATE TABLE principal_role (
    id        BIGSERIAL PRIMARY KEY,
    principal TEXT NOT NULL,
    role_id   BIGINT NOT NULL REFERENCES app_role(id) ON DELETE CASCADE,
    UNIQUE (principal, role_id)
);
