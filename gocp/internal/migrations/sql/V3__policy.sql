-- The Cedar policy store.
--
-- Each row is one Cedar-source policy statement. `enabled` rows are loaded into the PolicySet
-- CedarEngine evaluates. Rows are validated against resources/authz/schema.cedarschema on write
-- (CedarPolicyStore.create/update) and again on load (CedarEngine's startup fail-fast), so a policy
-- that no longer type-checks aborts boot rather than silently going inert.
--
-- Shipped policies and operator-authored policies share this table but have different owners.
-- Migrations own shipped source and name identity; an administrator may only toggle `enabled`.
-- Three disjoint representations encode that, and the constraints enforce all three together so no
-- application or manual write can create an ambiguous row:
--
--   * origin      SYSTEM (migration-owned) or USER (operator-owned).
--   * id          SYSTEM rows take reserved NEGATIVE ids, disjoint from the positive BIGSERIAL
--                 sequence USER rows draw from.
--   * name        SYSTEM rows are `system:`-prefixed; USER rows may not be.
--   * system_key  a write-once stable key on SYSTEM rows, the handle a later migration updates a
--                 shipped policy by. NULL on USER rows, unique where present.
--
-- The reserved id blocks are -1..-99 bootstrap and task lifecycle, -100..-199 the system-object
-- floor, -200..-299 preset policies, -300..-399 context guardrails. V8 seeds them.

CREATE TABLE policy (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    cedar_src  TEXT NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    origin     TEXT NOT NULL DEFAULT 'USER',
    system_key TEXT,
    updated_by TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT policy_origin_check CHECK (origin IN ('SYSTEM', 'USER')),
    CONSTRAINT policy_id_origin_check CHECK (
        (origin = 'SYSTEM' AND id < 0 AND system_key IS NOT NULL) OR
        (origin = 'USER'   AND id > 0 AND system_key IS NULL)
    ),
    CONSTRAINT policy_name_origin_check CHECK (
        (origin = 'SYSTEM' AND name LIKE 'system:%') OR
        (origin = 'USER'   AND name NOT LIKE 'system:%')
    ),
    CONSTRAINT policy_system_key_unique UNIQUE (system_key)
);

-- Vetted query fingerprints: the operator escape hatch for a statement the analyzer cannot prove
-- safe. role_id NULL means the entry applies to any role.
CREATE TABLE allowlist (
    id          BIGSERIAL PRIMARY KEY,
    role_id     BIGINT REFERENCES app_role(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    note        TEXT,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
