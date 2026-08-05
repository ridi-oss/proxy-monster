-- Migrate the bootstrap presets AND any operator policy from the five sql.<verb> datasource actions to the
-- statement-category gate (stmt.cat.<category>), matching the control-plane's per-statement classification.
-- Each category is an action group over the granular stmt.kind.* actions, so a category preset covers both
-- the category action (the resolved read/write/ddl path) and every kind under it. read/write/ddl decisions
-- are unchanged — same roles, same tag scope; only the action name moves. The per-grant AND (INSERT ... ON
-- DUPLICATE KEY UPDATE needs write.insert AND write.update) and REPLACE's deny are preserved by the
-- control-plane, not here.
--
-- The rewrite: the exact-match scope form `action == Action::"sql.select"` becomes
-- `action in [Action::"stmt.cat.read"]` — a category must be matched with `in` so its kinds resolve, whereas
-- `==` matches only the bare category; any other reference is a plain action-name swap. Whitespace around
-- `==`/`::` is tolerated and the output is canonical; sql.unanalyzable / sql.unmaskable are left alone. A verb
-- named in a Cedar escape spelling (sql.\u{73}elect) is not rewritten and, if enabled, fails startup schema
-- validation after upgrade — rewrite it to stmt.cat.* (fail-closed, never a silent match).

-- Pass 1: the exact-match scope form → the in-list form.
UPDATE policy SET
    cedar_src = regexp_replace(regexp_replace(regexp_replace(regexp_replace(regexp_replace(
        cedar_src,
        'action[[:space:]]*==[[:space:]]*Action[[:space:]]*::[[:space:]]*"sql\.select"', 'action in [Action::"stmt.cat.read"]',        'g'),
        'action[[:space:]]*==[[:space:]]*Action[[:space:]]*::[[:space:]]*"sql\.insert"', 'action in [Action::"stmt.cat.write.insert"]', 'g'),
        'action[[:space:]]*==[[:space:]]*Action[[:space:]]*::[[:space:]]*"sql\.update"', 'action in [Action::"stmt.cat.write.update"]', 'g'),
        'action[[:space:]]*==[[:space:]]*Action[[:space:]]*::[[:space:]]*"sql\.delete"', 'action in [Action::"stmt.cat.write.delete"]', 'g'),
        'action[[:space:]]*==[[:space:]]*Action[[:space:]]*::[[:space:]]*"sql\.ddl"',    'action in [Action::"stmt.cat.ddl"]',          'g'),
    updated_by = 'migration:V17',
    updated_at = now()
WHERE cedar_src ~ 'action[[:space:]]*==[[:space:]]*Action[[:space:]]*::[[:space:]]*"sql\.(select|insert|update|delete|ddl)"';

-- Pass 2: any remaining reference (in-list, condition) → the category action name.
UPDATE policy SET
    cedar_src = regexp_replace(regexp_replace(regexp_replace(regexp_replace(regexp_replace(
        cedar_src,
        'Action[[:space:]]*::[[:space:]]*"sql\.select"', 'Action::"stmt.cat.read"',         'g'),
        'Action[[:space:]]*::[[:space:]]*"sql\.insert"', 'Action::"stmt.cat.write.insert"', 'g'),
        'Action[[:space:]]*::[[:space:]]*"sql\.update"', 'Action::"stmt.cat.write.update"', 'g'),
        'Action[[:space:]]*::[[:space:]]*"sql\.delete"', 'Action::"stmt.cat.write.delete"', 'g'),
        'Action[[:space:]]*::[[:space:]]*"sql\.ddl"',    'Action::"stmt.cat.ddl"',          'g'),
    updated_by = 'migration:V17',
    updated_at = now()
WHERE cedar_src ~ 'Action[[:space:]]*::[[:space:]]*"sql\.(select|insert|update|delete|ddl)"';

-- Seed the new category presets — metadata/session/admin have no verb equivalent to convert above.
-- development (ENABLED): benign passthrough + the permissive admin relay a dev datasource already had.
INSERT INTO policy (id, system_key, name, cedar_src, enabled, origin, updated_by, updated_at) VALUES
    (-236, 'preset.development-metadata', 'system:development-metadata',
     $$permit (
  principal,
  action in [Action::"stmt.cat.metadata"],
  resource
)
when { resource in Tag::"system:development" };
$$,
     TRUE, 'SYSTEM', 'migration:V17', now()),
    (-237, 'preset.development-session', 'system:development-session',
     $$permit (
  principal,
  action in [Action::"stmt.cat.session"],
  resource
)
when { resource in Tag::"system:development" };
$$,
     TRUE, 'SYSTEM', 'migration:V17', now()),
    (-238, 'preset.development-admin', 'system:development-admin',
     $$permit (
  principal,
  action in [Action::"stmt.cat.admin"],
  resource
)
when { resource in Tag::"system:development" };
$$,
     TRUE, 'SYSTEM', 'migration:V17', now()),
-- production (DISABLED): benign passthrough only. No admin, so the connect-only gaps fail closed.
    (-260, 'preset.production-metadata', 'system:production-metadata',
     $$permit (
  principal,
  action in [Action::"stmt.cat.metadata"],
  resource
)
when { resource in Tag::"system:production" };
$$,
     FALSE, 'SYSTEM', 'migration:V17', now()),
    (-261, 'preset.production-session', 'system:production-session',
     $$permit (
  principal,
  action in [Action::"stmt.cat.session"],
  resource
)
when { resource in Tag::"system:production" };
$$,
     FALSE, 'SYSTEM', 'migration:V17', now());
