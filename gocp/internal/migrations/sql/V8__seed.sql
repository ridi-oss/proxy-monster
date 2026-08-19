-- The shipped starter package: predefined roles, protected groups, and the SYSTEM Cedar policies.
--
-- proxy-monster is deny-by-default, so without a seed a clean install has no usable admin and no
-- ordinary role can run a statement until someone hand-authors every datasource.connect / sql.* /
-- result.read.* grant. This file ships a concrete least-privilege package instead.
--
-- Everything system-owned is `system:`-prefixed: the classification tags
-- (system:critical / activity / data-leak / catalog), the datasource posture tags
-- (system:development / system:production), the predefined roles, the protected groups, and the
-- policy names. Every row here is SYSTEM-owned -- a negative id from the reserved blocks, a write-once
-- system_key, origin='SYSTEM' -- so an administrator may toggle `enabled` but never edit the source.
--
-- Central design fact: a system:development datasource holds NO real PII -- that is what makes it
-- dev. So development reads everything CLEARTEXT (masking fake data buys nothing), and PII masking,
-- the pii-accessor trusted-network unmask, and the disabled-by-default posture are PRODUCTION
-- concerns. The one surface dev never opens is system:critical, because server credentials are
-- dangerous on any server.
--
-- WHO becomes an admin is decided at login from the IdP group claim (PM_OIDC_GROUP_MAP, see
-- UserGroupStore.provisionFromOidc). No human principal is invented here.

-- -------------------------------------------------------------------------------------------------
-- 1. Predefined roles: one per environment and capability, plus admin and auditor. Dev holds no PII,
--    so the dev viewer and pii-accessor read the same (cleartext); the dev pii-accessor exists for
--    symmetry with production, where the distinction is load-bearing.

INSERT INTO app_role (name, description) VALUES
    ('system:admin', 'proxy-monster policy, identity, and datasource administration'),
    ('system:development-viewer', 'Development datasource SELECT (dev holds no PII, so results are cleartext)'),
    ('system:development-pii-accessor', 'Development datasource SELECT (mirrors system:production-pii-accessor; dev has no PII)'),
    ('system:development-updater', 'Development datasource INSERT and UPDATE'),
    ('system:development-deleter', 'Development datasource DELETE'),
    ('system:development-architect', 'Development datasource DDL'),
    ('system:production-viewer', 'Production datasource SELECT with non-PII cleartext and PII masking'),
    ('system:production-pii-accessor', 'Production datasource SELECT; PII cleartext only on trusted-network'),
    ('system:production-updater', 'Production datasource INSERT and UPDATE'),
    ('system:production-deleter', 'Production datasource DELETE'),
    ('system:production-architect', 'Production datasource DDL'),
    ('system:auditor', 'May assume a task execution role to inspect saved results.');

-- -------------------------------------------------------------------------------------------------
-- 2. Protected identity groups (source=SYSTEM, no external_id -- immutable through the API and SCIM,
--    guarded in UserGroupStore). An explicit PM_OIDC_GROUP_MAP entry is the only path from an IdP
--    group into the reserved system:* namespace. system:developer aggregates the five development
--    roles; each production role gets its own 1:1 group so an IdP group can map to a single
--    production capability. Membership is always assigned at login from the IdP claim, never seeded.

INSERT INTO app_group (name, description, source, external_id) VALUES
    ('query-approvers', 'Default approvers for query-approval requests', 'LOCAL', NULL),
    ('system:admin',
     'Administrators. System-managed group; membership is assigned from the IdP group claim (PM_OIDC_GROUP_MAP), not edited here.',
     'SYSTEM', NULL),
    ('system:developer', 'Default development team: viewer + PII accessor + updater + deleter + architect.', 'SYSTEM', NULL),
    ('system:production-viewer', 'Production viewers. Explicit assignment only.', 'SYSTEM', NULL),
    ('system:production-pii-accessor', 'Production PII accessors. Explicit assignment only.', 'SYSTEM', NULL),
    ('system:production-updater', 'Production insert/update operators. Explicit assignment only.', 'SYSTEM', NULL),
    ('system:production-deleter', 'Production delete operators. Explicit assignment only.', 'SYSTEM', NULL),
    ('system:production-architect', 'Production DDL operators. Explicit assignment only.', 'SYSTEM', NULL);

-- Being in system:admin confers the admin role and only that -- system:admin is administrative, not a
-- data reader, so it grants no result.read.*.
INSERT INTO group_role (group_id, role_id)
SELECT g.id, r.id
FROM app_group g
JOIN app_role r ON
    (g.name = 'system:admin' AND r.name = 'system:admin') OR
    (g.name = 'system:developer' AND r.name IN (
        'system:development-viewer', 'system:development-pii-accessor', 'system:development-updater',
        'system:development-deleter', 'system:development-architect')) OR
    (g.name = 'system:production-viewer' AND r.name = 'system:production-viewer') OR
    (g.name = 'system:production-pii-accessor' AND r.name = 'system:production-pii-accessor') OR
    (g.name = 'system:production-updater' AND r.name = 'system:production-updater') OR
    (g.name = 'system:production-deleter' AND r.name = 'system:production-deleter') OR
    (g.name = 'system:production-architect' AND r.name = 'system:production-architect');

-- -------------------------------------------------------------------------------------------------
-- 3. Administration and audit reads (-1, -3, -4, -5). -4 lets any principal read their OWN audit
--    records; -5 grants the whole log to system:admin.

INSERT INTO policy (id, system_key, name, cedar_src, enabled, origin, updated_by, updated_at) VALUES
    (-1, 'bootstrap.pm-admin', 'system:admin',
     'permit(principal in Role::"system:admin", action in [Action::"admin.datasources",Action::"admin.policies",Action::"admin.identity"], resource);',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    (-4, 'audit.read-own', 'system:audit-read-own',
     'permit(principal, action == Action::"audit.read", resource) when { resource is AuditRecord && resource.principal == principal };',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    (-5, 'audit.read-admin', 'system:audit-read-admin',
     'permit(principal in Role::"system:admin", action == Action::"audit.read", resource);',
     TRUE, 'SYSTEM', 'migration:V8', now());

-- -------------------------------------------------------------------------------------------------
-- 4. Task lifecycle (-2, -3, -14..-25). Self-approval is forbidden outright for a human approval, and
--    exempted only on the two server-attested machine channels: the web editor and the native wire
--    both record each submit as a born-APPROVED task self-approved by its own requester. Because
--    `context.channel` is set by the server and never client-asserted, an ordinary human approval --
--    which runs on no channel or a workflow channel -- still cannot self-approve.

INSERT INTO policy (id, system_key, name, cedar_src, enabled, origin, updated_by, updated_at) VALUES
    (-2, 'workflow.no-self-approval', 'system:no-self-approval',
     'forbid(principal, action == Action::"task.approve", resource) when { principal == resource.requester } unless { context has channel && (context.channel == "editor" || context.channel == "wire") };',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    -- Admin authority over the whole task lifecycle, in one policy rather than several admin rules.
    (-3, 'workflow.pm-admin-approve', 'system:admin-approver',
     'permit(principal in Role::"system:admin", action in [Action::"task.approve", Action::"task.read", Action::"grant.revoke", Action::"task.request", Action::"task.cancel", Action::"task.delete"], resource);',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    -- Self-service: a requester reads their OWN task's metadata. The stored RESULT is deliberately not
    -- granted here; -21 governs who may assume a task and see its rows. task.read also applies to an
    -- AccessGrant, so the `is Request` guard narrows the type before touching `.requester`.
    (-14, 'workflow.self-request', 'system:workflow-self-request',
     'permit(principal, action == Action::"task.read", resource) when { resource is Request && resource.requester == principal };',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    -- Self-service: a grantee reads and revokes their OWN grant, to give elevation back early.
    (-15, 'workflow.self-grant', 'system:workflow-self-grant',
     'permit(principal, action in [Action::"task.read", Action::"grant.revoke"], resource) when { resource is AccessGrant && resource.owner == principal };',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    -- Any authenticated principal may open a task. Tighten by replacing this with per-datasource
    -- task.request policies (resource == Datasource::"...") where no approval path should exist.
    (-16, 'workflow.request-default', 'system:workflow-request-default',
     'permit(principal, action == Action::"task.request", resource);',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    -- Self-service tokens: a principal mints and manages their OWN wire tokens. token.* apply only to
    -- a Token, which always carries `owner`, so no type guard is needed. Tighten per deployment, e.g.
    -- a forbid on resource.kind == "USER" for a restricted role to bar long-lived tokens.
    (-18, 'token.self', 'system:token-self',
     'permit(principal, action in [Action::"token.mint", Action::"token.list", Action::"token.revoke"], resource) when { resource.owner == principal };',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    -- Token oversight: an admin lists and revokes ANY principal's tokens (deprovisioning, incident).
    (-19, 'token.admin', 'system:token-admin',
     'permit(principal in Role::"system:admin", action in [Action::"token.list", Action::"token.revoke"], resource);',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    -- Owner-locked mint: a HARD forbid so a token is NEVER minted AS another principal. Minting is the
    -- only way to obtain a token's secret (returned once at mint, hashed after), so this also confines
    -- secret exposure to your own tokens. A Cedar forbid overrides any permit, so it holds even
    -- against a future broad grant or an admin. Listing metadata and revoking stay cross-user, for
    -- that admin oversight.
    (-20, 'token.no-cross-mint', 'system:token-no-cross-mint',
     'forbid(principal, action == Action::"token.mint", resource) when { resource.owner != principal };',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    -- Assuming a task: its two parties (requester, approver) may inspect its saved result.
    (-21, 'task.assume-parties', 'system:task-assume-parties',
     'permit(principal, action == Action::"task.assume", resource) when { resource is Request && (resource.requester == principal || (resource has approver && resource.approver == principal)) };',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    -- An auditor may assume any task. Audit completeness beats confidentiality from auditors.
    (-22, 'task.assume-auditor', 'system:task-assume-auditor',
     'permit(principal in Role::"system:auditor", action == Action::"task.assume", resource) when { resource is Request };',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    -- The editor-channel and wire-channel self-approve permits the -2 exemption above pairs with. Both
    -- are base capabilities, enabled by default, not production-widening toggles.
    (-23, 'task.editor-self-approve', 'system:task-editor-self-approve',
     'permit(principal, action == Action::"task.approve", resource) when { resource is Request && principal == resource.requester && context has channel && context.channel == "editor" };',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    (-24, 'task.wire-self-approve', 'system:task-wire-self-approve',
     'permit(principal, action == Action::"task.approve", resource) when { resource is Request && principal == resource.requester && context has channel && context.channel == "wire" };',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    -- Either party may cancel a task.
    (-25, 'task.cancel-parties', 'system:task-cancel-parties',
     'permit(principal, action == Action::"task.cancel", resource) when { resource is Request && (resource.requester == principal || (resource has approver && resource.approver == principal)) };',
     TRUE, 'SYSTEM', 'migration:V8', now());

-- -------------------------------------------------------------------------------------------------
-- 5. The system-object floor (-100..-130). Catalog structure is browsable everywhere; the dangerous
--    tags are forbidden on the production floor and relaxed only where a datasource opts in by
--    carrying the system:development posture tag. A forbid overrides even a broad datasource read
--    grant, so this is defense in depth against an overly-broad operator permit, not just
--    deny-by-default. system:critical is never relaxed -- it is the one authoritative floor, biting
--    on dev too, so no permit anywhere can open a credential surface.

INSERT INTO policy (id, system_key, name, cedar_src, enabled, origin, updated_by, updated_at) VALUES
    (-100, 'system.catalog-read', 'system:catalog-read',
     'permit(principal, action == Action::"result.read.unmasked", resource) when { resource in Tag::"system:catalog" };',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    (-110, 'system.activity-guard', 'system:activity-guard',
     'forbid(principal, action in [Action::"result.read.unmasked", Action::"result.read.masked"], resource) when { resource in Tag::"system:activity" } unless { resource in Tag::"system:development" };',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    (-120, 'system.data-leak-guard', 'system:data-leak-guard',
     'forbid(principal, action in [Action::"result.read.unmasked", Action::"result.read.masked"], resource) when { resource in Tag::"system:data-leak" } unless { resource in Tag::"system:development" };',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    (-130, 'system.critical-guard', 'system:critical-guard',
     'forbid(principal, action in [Action::"result.read.unmasked", Action::"result.read.masked"], resource) when { resource in Tag::"system:critical" };',
     TRUE, 'SYSTEM', 'migration:V8', now());

-- -------------------------------------------------------------------------------------------------
-- 6. The development preset (-200..-235). Every row is ENABLED: a dev datasource holds no PII, so
--    -200 reads every column cleartext for any principal that reached it, and since -110/-120 are
--    relaxed on dev that role-agnostic permit is also what makes the diagnostic surfaces readable
--    there. Only system:critical stays excluded, and -130 forbids it regardless.
--
--    -200 is safe because the system:development posture tag is type-scoped to a Datasource --
--    Authz.datasourceEntity honors it only there and strips it from any Column, Table, or Function --
--    so it cannot be forged onto a production PII column. The -230..-235 rows gate WHO may connect
--    and which statement kinds they may run.

INSERT INTO policy (id, system_key, name, cedar_src, enabled, origin, updated_by, updated_at) VALUES
    (-200, 'preset.development-unmasked', 'system:development-unmasked',
     'permit(principal, action == Action::"result.read.unmasked", resource) when { resource in Tag::"system:development" } unless { resource in Tag::"system:critical" };',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    -- The two fail-closed gates a permissive dev datasource may relay: a statement the analyzer cannot
    -- prove safe, and one whose masked columns it cannot pin. On production
    -- neither is permitted, so the deny stands.
    (-201, 'preset.development-unanalyzable', 'system:development-unanalyzable',
     'permit(principal, action == Action::"sql.unanalyzable", resource) when { resource in Tag::"system:development" };',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    (-202, 'preset.development-unmaskable', 'system:development-unmaskable',
     'permit(principal, action == Action::"sql.unmaskable", resource) when { resource in Tag::"system:development" };',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    (-230, 'preset.development-connect', 'system:development-connect',
     'permit(principal, action == Action::"datasource.connect", resource) when { resource in Tag::"system:development" && (principal in Role::"system:development-viewer" || principal in Role::"system:development-pii-accessor" || principal in Role::"system:development-updater" || principal in Role::"system:development-deleter" || principal in Role::"system:development-architect") };',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    (-231, 'preset.development-select', 'system:development-select',
     'permit(principal, action == Action::"sql.select", resource) when { resource in Tag::"system:development" && (principal in Role::"system:development-viewer" || principal in Role::"system:development-pii-accessor") };',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    (-232, 'preset.development-insert', 'system:development-insert',
     'permit(principal in Role::"system:development-updater", action == Action::"sql.insert", resource) when { resource in Tag::"system:development" };',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    (-233, 'preset.development-update', 'system:development-update',
     'permit(principal in Role::"system:development-updater", action == Action::"sql.update", resource) when { resource in Tag::"system:development" };',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    (-234, 'preset.development-delete', 'system:development-delete',
     'permit(principal in Role::"system:development-deleter", action == Action::"sql.delete", resource) when { resource in Tag::"system:development" };',
     TRUE, 'SYSTEM', 'migration:V8', now()),
    (-235, 'preset.development-ddl', 'system:development-ddl',
     'permit(principal in Role::"system:development-architect", action == Action::"sql.ddl", resource) when { resource in Tag::"system:development" };',
     TRUE, 'SYSTEM', 'migration:V8', now());

-- -------------------------------------------------------------------------------------------------
-- 7. The production preset (-250..-259) plus the trusted-network context producer (-300). The same
--    connect and sql.* package as development, PLUS PII-aware result visibility: masked by default,
--    cleartext only for a pii-accessor whose request earns the widening.
--
--    EVERY row here ships DISABLED. Enabling production access is an explicit, audited policy toggle,
--    and there is no aggregate group to hand it out by accident.
--
--    Two triggers unmask production PII for a pii-accessor, and only for that role:
--      -258  the request came from the trusted network (the -300 producer earns the tag).
--      -259  the request is an approved task's execution (context.channel == "workflow-executor"), so
--            an approved run stores the maximal result R is entitled to even off the trusted network.
--            A viewer runs on "workflow-viewer", which -259 does NOT match, so a saved result re-masks
--            at view time unless the viewer is themselves on the trusted network.
--    Both carry the same activity / data-leak / critical carve-outs; only the trigger differs.

INSERT INTO policy (id, system_key, name, cedar_src, enabled, origin, updated_by, updated_at) VALUES
    (-250, 'preset.production-connect', 'system:production-connect',
     'permit(principal, action == Action::"datasource.connect", resource) when { resource in Tag::"system:production" && (principal in Role::"system:production-viewer" || principal in Role::"system:production-pii-accessor" || principal in Role::"system:production-updater" || principal in Role::"system:production-deleter" || principal in Role::"system:production-architect") };',
     FALSE, 'SYSTEM', 'migration:V8', now()),
    (-251, 'preset.production-select', 'system:production-select',
     'permit(principal, action == Action::"sql.select", resource) when { resource in Tag::"system:production" && (principal in Role::"system:production-viewer" || principal in Role::"system:production-pii-accessor") };',
     FALSE, 'SYSTEM', 'migration:V8', now()),
    (-252, 'preset.production-insert', 'system:production-insert',
     'permit(principal in Role::"system:production-updater", action == Action::"sql.insert", resource) when { resource in Tag::"system:production" };',
     FALSE, 'SYSTEM', 'migration:V8', now()),
    (-253, 'preset.production-update', 'system:production-update',
     'permit(principal in Role::"system:production-updater", action == Action::"sql.update", resource) when { resource in Tag::"system:production" };',
     FALSE, 'SYSTEM', 'migration:V8', now()),
    (-254, 'preset.production-delete', 'system:production-delete',
     'permit(principal in Role::"system:production-deleter", action == Action::"sql.delete", resource) when { resource in Tag::"system:production" };',
     FALSE, 'SYSTEM', 'migration:V8', now()),
    (-255, 'preset.production-ddl', 'system:production-ddl',
     'permit(principal in Role::"system:production-architect", action == Action::"sql.ddl", resource) when { resource in Tag::"system:production" };',
     FALSE, 'SYSTEM', 'migration:V8', now()),
    (-256, 'preset.production-non-pii-read', 'system:production-non-pii-read',
     'permit(principal, action == Action::"result.read.unmasked", resource) when { resource in Tag::"system:production" && (principal in Role::"system:production-viewer" || principal in Role::"system:production-pii-accessor" || principal in Role::"system:production-updater" || principal in Role::"system:production-deleter" || principal in Role::"system:production-architect") } unless { resource in Tag::"pii" || resource in Tag::"system:catalog" || resource in Tag::"system:activity" || resource in Tag::"system:data-leak" || resource in Tag::"system:critical" };',
     FALSE, 'SYSTEM', 'migration:V8', now()),
    (-257, 'preset.production-pii-masked', 'system:production-pii-masked',
     'permit(principal, action == Action::"result.read.masked", resource) when { resource in Tag::"system:production" && resource in Tag::"pii" && (principal in Role::"system:production-viewer" || principal in Role::"system:production-pii-accessor" || principal in Role::"system:production-updater" || principal in Role::"system:production-deleter" || principal in Role::"system:production-architect") } unless { resource in Tag::"system:activity" || resource in Tag::"system:data-leak" || resource in Tag::"system:critical" };',
     FALSE, 'SYSTEM', 'migration:V8', now()),
    (-258, 'preset.production-pii-unmasked', 'system:production-pii-unmasked-trusted-network',
     'permit(principal in Role::"system:production-pii-accessor", action == Action::"result.read.unmasked", resource) when { resource in Tag::"system:production" && resource in Tag::"pii" && context has tags && context.tags.contains("trusted-network") } unless { resource in Tag::"system:activity" || resource in Tag::"system:data-leak" || resource in Tag::"system:critical" };',
     FALSE, 'SYSTEM', 'migration:V8', now()),
    (-259, 'preset.production-pii-unmasked-workflow', 'system:production-pii-unmasked-workflow-executor',
     'permit(principal in Role::"system:production-pii-accessor", action == Action::"result.read.unmasked", resource) when { resource in Tag::"system:production" && resource in Tag::"pii" && context has channel && context.channel == "workflow-executor" } unless { resource in Tag::"system:activity" || resource in Tag::"system:data-leak" || resource in Tag::"system:critical" };',
     FALSE, 'SYSTEM', 'migration:V8', now()),
    -- The example trusted-network tag producer. Pass 1 runs this as an
    -- ordinary Cedar rule: a request whose observed requester_ip falls in the range earns the
    -- "trusted-network" context tag, which -258 consumes in pass 2. Since dev holds no PII,
    -- trusted-network is a production concept, so this ships disabled and is enabled with the rest of
    -- the production package -- enabling the producer alone would trip the readiness dangling-tag lint
    -- (a producer with no enabled consumer) and buy nothing. 100.100.0.0/16 is an EXAMPLE allocation
    -- inside the CGNAT range 100.64.0.0/10; replace it with your own, or author a USER rule for a
    -- tighter posture.
    (-300, 'context.trusted-network-tailscale', 'system:trusted-network-tailscale-example',
     'permit(principal, action == Action::"context.tag::trusted-network", resource) when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };',
     FALSE, 'SYSTEM', 'migration:V8', now());
