# Policy store — system policies and clean-DB bootstrap

proxy-monster keeps one `policy` table holding both user-authored Cedar policies
and the shipped system policies. This doc owns the schema convention that
separates the two id spaces, the Flyway delivery of the system set, and the
clean-database bootstrap that makes a fresh install governed and deny-by-default
before the server opens its port. The Cedar entities and actions these policies
reference live in [authz-model.md](./authz-model.md) and
[facts-emission.md](./facts-emission.md); which engine objects carry `system:`
tags lives in [system-classification.md](./system-classification.md); migration
mechanics follow [migrations.md](./migrations.md).

## Decision

One `policy` table, with an explicit `origin` (`SYSTEM` or `USER`) and a stable
`system_key`. System policies use negative ids and the reserved `system:`
policy-name prefix; user policies keep the positive `BIGSERIAL` sequence and
cannot use that prefix. Negative ids are permanently reserved, so a Flyway
migration can UPSERT a shipped row by id without advancing, resetting, or
colliding with the user sequence.

System rows are immutable through the API except for `enabled`:

- the migration owns `name`, `cedar_src`, `origin`, and `system_key`;
- an admin may enable/disable the row;
- an upgrade UPSERT updates the shipped source but deliberately preserves the
  row's current `enabled` value;
- user rows remain full CRUD; and
- the backend enforces the distinction. The console is a matching read-only
  presentation, not the security boundary.

A clean database runs the whole migration chain and therefore starts with the
full validated, deny-by-default set. No migration invents a human principal or
hidden admin bypass: assigning the first principal or group to `system:admin` is
an explicit identity-plane deployment step.

## Scope

This doc owns the `policy` schema and reserved-id convention, the shipped
system-policy inventory and stable ids, forward migration of the seed, clean-DB
admin-role bootstrap, system-policy load/update/toggle semantics, and
API/console behavior. It consumes Cedar entities/actions from
[authz-model.md](./authz-model.md) and [facts-emission.md](./facts-emission.md),
`system:` resource facts from
[system-classification.md](./system-classification.md), and
datasource/column/function tags from the catalog/identity planes. It does not
own which engine object receives which `system:` tag, first-principal identity
proofing or OIDC provisioning, data-plane capability for COPY/fast-path, or
user-authored policy semantics beyond validation and storage.

## Why negative ids plus an origin column

`BIGSERIAL` allocates positive ids from a sequence. Negative ids are disjoint by
construction and need no sequence surgery: a system migration inserts an
explicit negative id, user creation omits `id` and receives the next positive
sequence value, and neither side can reach the other by normal operation. A high
positive reserved block would be practically but not structurally disjoint; a
low positive block would require guarding the sequence; a separate system table
would duplicate the loader, validation, toggle, diagnostics, and console paths.

The id range is not the authorization signal — `origin` is. Store/API code
branches on `origin`, while the range and name constraints catch corrupt or
hand-written rows. `system_key` is a stable machine name for migrations,
diagnostics, and tests. The `system:` prefix on a policy name reserves migration
ownership; it is a different namespace from Cedar resource tags such as
`Tag::"system:activity"`.

## Target schema

```sql
ALTER TABLE policy
    ADD COLUMN origin TEXT,
    ADD COLUMN system_key TEXT;

-- Existing non-seed rows are user-authored.
UPDATE policy SET origin = 'USER' WHERE origin IS NULL;

-- The migration then converts/upserts the known seed rows and inserts the new system set.

ALTER TABLE policy
    ALTER COLUMN origin SET NOT NULL,
    ALTER COLUMN origin SET DEFAULT 'USER',
    ADD CONSTRAINT policy_origin_check CHECK (origin IN ('SYSTEM', 'USER')),
    ADD CONSTRAINT policy_id_origin_check CHECK (
        (origin = 'SYSTEM' AND id < 0 AND system_key IS NOT NULL) OR
        (origin = 'USER'   AND id > 0 AND system_key IS NULL)
    ),
    ADD CONSTRAINT policy_name_origin_check CHECK (
        (origin = 'SYSTEM' AND name LIKE 'system:%') OR
        (origin = 'USER'   AND name NOT LIKE 'system:%')
    ),
    ADD CONSTRAINT policy_system_key_unique UNIQUE (system_key);
```

Target row:

```text
policy(
  id BIGINT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  cedar_src TEXT NOT NULL,
  enabled BOOLEAN NOT NULL,
  origin TEXT NOT NULL,          -- SYSTEM | USER
  system_key TEXT UNIQUE NULL,   -- required only for SYSTEM
  updated_by TEXT NULL,
  updated_at TIMESTAMPTZ NOT NULL
)
```

### Reserved blocks

Ranges keep review diffs legible while all negative ids stay reserved:

<!-- prettier-ignore -->
| range | purpose |
| --- | --- |
| `-1 .. -99` | bootstrap/admin/workflow/audit policies |
| `-100 .. -199` | `system:` classification policies |
| `-200 .. -299` | datasource/column/function preset policies |
| `-300 .. -399` | shipped workflow/context guardrails |
| all other negative ids | reserved for future system migrations; never user-created |

Ids are never recycled. Removing a shipped policy tombstones its allocation; a
later unrelated policy does not take its id.

## Migration and UPSERT semantics

### Convert the existing seed

The forward migration recognizes the names the original seed created and moves
them into the reserved namespace:

<!-- prettier-ignore -->
| id | `system_key` | legacy name | system name |
| --- | --- | --- | --- |
| `-1` | `bootstrap.pm-admin` | `pm-admin` | `system:admin` |
| `-2` | `workflow.no-self-approval` | `no-self-approval` | `system:no-self-approval` |
| `-3` | `workflow.pm-admin-approve` | `approver` | `system:admin-approver` |

For each legacy name the migration compares the row's source with the exact
original source:

- unchanged source → move it to the negative id/system name, preserving its
  current `enabled`;
- user-modified source → leave that positive row byte-identical as a USER policy
  and insert the new system row disabled, so the migration never silently widens
  the current posture; and
- missing/deleted row → insert the system row with its shipped default.

The migration spells this out in SQL rather than in application code (one row
shown; the others use their exact source constants):

```sql
DO $$
DECLARE
    legacy policy%ROWTYPE;
    original_src CONSTANT TEXT := '<exact original pm-admin cedar_src>';
BEGIN
    SELECT * INTO legacy FROM policy WHERE name = 'pm-admin' FOR UPDATE;
    IF FOUND AND legacy.cedar_src = original_src THEN
        INSERT INTO policy (id, system_key, name, cedar_src, enabled, origin, updated_by, updated_at)
        VALUES (-1, 'bootstrap.pm-admin', 'system:admin', original_src, legacy.enabled, 'SYSTEM', 'migration:<version>', now());
        DELETE FROM policy WHERE id = legacy.id;
    ELSIF FOUND THEN
        INSERT INTO policy (id, system_key, name, cedar_src, enabled, origin, updated_by, updated_at)
        VALUES (-1, 'bootstrap.pm-admin', 'system:admin', original_src, FALSE, 'SYSTEM', 'migration:<version>', now());
    ELSE
        INSERT INTO policy (id, system_key, name, cedar_src, enabled, origin, updated_by, updated_at)
        VALUES (-1, 'bootstrap.pm-admin', 'system:admin', original_src, TRUE, 'SYSTEM', 'migration:<version>', now());
    END IF;
END $$;
```

The negative-id insert precedes deleting the unchanged positive row, so any
unexpected negative-id conflict aborts without losing the legacy row. Before
adding the name constraint, the migration also fails with a diagnostic if any
unrelated USER policy already uses `system:%` — an admin must rename that row
explicitly rather than have the migration silently rewrite it. Conversion
happens before adding the id/origin/name constraints.

### Every system-policy migration

A system row is written as an id-preconditioned UPSERT that never touches
`enabled`:

```sql
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM policy WHERE id = -110 AND system_key IS DISTINCT FROM 'system.activity-guard') THEN
        RAISE EXCEPTION 'policy id -110 belongs to a different system_key';
    END IF;
END $$;

INSERT INTO policy (id, system_key, name, cedar_src, enabled, origin, updated_by, updated_at)
VALUES (-110, 'system.activity-guard', 'system:activity-guard', '...', TRUE, 'SYSTEM', 'migration:<version>', now())
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name, cedar_src = EXCLUDED.cedar_src, origin = 'SYSTEM',
    updated_by = EXCLUDED.updated_by, updated_at = now()
WHERE policy.cedar_src IS DISTINCT FROM EXCLUDED.cedar_src OR policy.name IS DISTINCT FROM EXCLUDED.name;
```

`enabled` is absent from the UPDATE list, so a clean insert starts with the
shipped default; an admin-disabled policy stays disabled across upgrades; a
source/security fix still updates the disabled row, ready for re-enable; and a
manual deletion is recreated with the default by the next carrying migration.
`system_key` is write-once — absent from the UPDATE list, and the precondition
raises if the fixed id already belongs to another key; the unique constraint
catches the inverse collision. Either disagreement fails the transaction, Flyway
rolls back the whole migration, and the control-plane never serves.

### User inserts

The API always inserts a USER row and never accepts `id`, `origin`, or
`system_key` from the request, rejecting a name beginning `system:`:

```sql
INSERT INTO policy (name, cedar_src, enabled, origin) VALUES (?, ?, ?, 'USER') RETURNING id;
```

The sequence supplies a positive id; the check constraints protect both reserved
namespaces even from future code paths.

## Bootstrap system-policy inventory

Each row holds one independently toggleable Cedar policy statement. The exact
source is validated against the shipped Cedar schema at migration time and again
at runtime load; the tables below are the stable semantic registry. A dependent
row co-lands in the same migration as the Cedar entity/action it references, so
no new fact becomes enforceable without its floor.

### Bootstrap / workflow / audit

<!-- prettier-ignore -->
| id | `system_key` | effect | default |
| --- | --- | --- | --- |
| `-1` | `bootstrap.pm-admin` | `Role::"system:admin"` may use `admin.datasources`, `admin.policies`, `admin.identity` | enabled |
| `-2` | `workflow.no-self-approval` | authoritative forbid when requester == approver | enabled |
| `-3` | `workflow.pm-admin-approve` | `system:admin` may approve/read/revoke/request the task lifecycle | enabled |
| `-4` | `audit.read-own` | any principal may `audit.read` their own `AuditRecord` | enabled |
| `-5` | `audit.read-admin` | `Role::"system:admin"` may `audit.read` any record or the log | enabled |

The admin role is `system:admin` (write-once system_keys `bootstrap.pm-admin` /
`workflow.pm-admin-approve` are stable machine names, not the display name). It
is an administrative role, not an implicit data-reader: no `datasource.connect`,
`sql.*`, or `result.read.*` grant. `-5` grants it the audit log by default, so
admins review decisions out of the box. There is no predefined `auditor` role —
a deployment wanting a dedicated read-only auditor authors a USER role and
policy. The task-approval and wire-token lifecycle policies
(self-request/self-grant, owner-locked `token.mint` with a cross-user forbid)
live in this block under the same UPSERT/immutability contract; their Cedar
actions are defined in [authz-model.md](./authz-model.md).

### System-object floor

<!-- prettier-ignore -->
| id | `system_key` | effect | default |
| --- | --- | --- | --- |
| `-100` | `system.catalog-read` | permit `result.read.unmasked` on `system:catalog` everywhere | enabled |
| `-110` | `system.activity-guard` | forbid result read on `system:activity` unless `system:development` | enabled |
| `-120` | `system.data-leak-guard` | forbid result read on `system:data-leak` unless `system:development` | enabled |
| `-130` | `system.critical-guard` | forbid result read on `system:critical` — never relaxed | enabled |

These are forbids, not deny-by-default: a Cedar `forbid` overrides `permit`, so
the guard blocks a dangerous surface even against an over-broad user grant (e.g.
`permit(role, action, resource in Datasource::"prod")`), which deny-by-default
alone would not. `-110`/`-120` relax only where the resource is under a
`system:development` datasource (through its Datasource parent); on that dev
datasource the `-200` cleartext read then permits it. `-130` (credentials +
privileged ops) is never relaxed, not even on development. To grant a critical
surface an admin must deliberately disable/replace `system.critical-guard`; a
user permit alone cannot bypass it, and the console presents that consequence
before toggling.

### Presets — roles and result visibility

Each preset ships a concrete, least-privilege role package. Posture tags are
`system:development` / `system:production`; datasource tags are otherwise a
free-form bag, and the marshaller carries every one of them onto the Datasource
entity, so a policy may match an operator's own tag exactly as it matches a
posture one. There is no exact-one-posture constraint. Reservation is a NAMING
rule and nothing more: the six `system:` names the product defines are writable
on any resource, and an invented `system:whatever` is refused at the write. No
tag is filtered by resource type.

The seed migration's own comment on `-200` says the development posture is
type-scoped to a datasource and stripped from a column. That is no longer how
marshalling works, and the comment cannot be corrected in place — an applied
migration is immutable, since Flyway checksums the whole file.

A datasource tag is inherited by every Table, Column, and Function under it, and
it matches the same `Tag::` entity a column classification does. So naming one
after a classification policy keys on applies it datasource-wide, and `pii` cuts
both ways:

- the shipped presets **close** — `production-non-pii-read` stops granting
  cleartext and `production-pii-masked` masks every column, whatever each
  column's own classification says;
- a permit keyed on `resource in Tag::"pii"` **opens** — the `pii-reader` grant
  in [authz-model.md](./authz-model.md) hands that role cleartext on every
  column under the datasource, including columns nobody classified as PII.

Classify columns to decide columns; a datasource tag decides the datasource.

Roles: ten predefined roles in the `system:` namespace — five
`system:development-{viewer, pii-accessor, updater, deleter, architect}` and
five `system:production-{…same five…}` — plus the admin role `system:admin`. The
protected group `system:developer` aggregates the five development roles (map an
IdP group to it with `PM_OIDC_GROUP_MAP`); each production role has its own 1:1
`system:production-*` group so an IdP group can be mapped to a single production
capability.

A `system:development` datasource holds no real PII — that is the definition of
dev. So development reads are cleartext and there is no dev masking; PII
masking, the pii-accessor trusted-network unmask, and the `-300` producer are
production concerns.

Development preset (all enabled):

<!-- prettier-ignore -->
| id | `system_key` | effect |
| --- | --- | --- |
| `-200` | `preset.development-unmasked` | permit `result.read.unmasked` on any `system:development` resource unless `system:critical` — role-agnostic (dev is cleartext) |
| `-201` | `preset.development-unanalyzable` | permit `sql.unanalyzable` verbatim relay on `system:development` |
| `-202` | `preset.development-unmaskable` | permit `sql.unmaskable` relay on `system:development` (data-plane capability still required) |
| `-230` | `preset.development-connect` | any `system:development-*` role → `datasource.connect` |
| `-231` | `preset.development-select` | `system:development-viewer` / `-pii-accessor` → `stmt.cat.read` |
| `-232` | `preset.development-insert` | `system:development-updater` → `stmt.cat.write.insert` |
| `-233` | `preset.development-update` | `system:development-updater` → `stmt.cat.write.update` |
| `-234` | `preset.development-delete` | `system:development-deleter` → `stmt.cat.write.delete` |
| `-235` | `preset.development-ddl` | `system:development-architect` → `stmt.cat.ddl` |
| `-236` | `preset.development-metadata` | any principal → `stmt.cat.metadata` on `system:development` |
| `-237` | `preset.development-session` | any principal → `stmt.cat.session` on `system:development` |
| `-238` | `preset.development-admin` | any principal → `stmt.cat.admin` on `system:development` |

Production preset (all disabled by default — enabling production access is an
explicit, audited toggle; ships through `-261`):

<!-- prettier-ignore -->
| id | `system_key` | effect |
| --- | --- | --- |
| `-250` | `preset.production-connect` | any `system:production-*` role → `datasource.connect` |
| `-251` | `preset.production-select` | `system:production-viewer` / `-pii-accessor` → `stmt.cat.read` |
| `-252` | `preset.production-insert` | `system:production-updater` → `stmt.cat.write.insert` |
| `-253` | `preset.production-update` | `system:production-updater` → `stmt.cat.write.update` |
| `-254` | `preset.production-delete` | `system:production-deleter` → `stmt.cat.write.delete` |
| `-255` | `preset.production-ddl` | `system:production-architect` → `stmt.cat.ddl` |
| `-256` | `preset.production-non-pii-read` | `system:production-*` roles → `result.read.unmasked` unless `pii`/`system:*` |
| `-257` | `preset.production-pii-masked` | `system:production-*` roles → `result.read.masked` on `pii` unless `system:*` |
| `-258` | `preset.production-pii-unmasked` | `system:production-pii-accessor` → `result.read.unmasked` on `pii` when `context.tags` has `trusted-network` unless `system:*` |
| `-259` | `preset.production-pii-unmasked-workflow` | `system:production-pii-accessor` → `result.read.unmasked` on `pii` when `context.channel == "workflow-executor"` unless `system:*` |
| `-260` | `preset.production-metadata` | any principal → `stmt.cat.metadata` on `system:production` |
| `-261` | `preset.production-session` | any principal → `stmt.cat.session` on `system:production` |

Context tag producer:

<!-- prettier-ignore -->
| id | `system_key` | effect | default |
| --- | --- | --- | --- |
| `-300` | `context.trusted-network-tailscale` | earns `trusted-network` when `context.requester_ip.isInRange(100.100.0.0/16)` — an example Tailscale range | disabled (enable alongside production) |

`-300` ships disabled because, with no PII in dev, `trusted-network` has only a
production consumer (`-258`, also disabled): enabling the producer alone would
trip the readiness dangling-tag lint (a producer with no enabled consumer) and
buy nothing. Enable it with the production package, or replace the CIDR / author
a USER rule for a tighter posture. Production PII visibility keys off the
ordinary `pii` column-classification tag, not a reserved posture tag.

### Trust boundary — posture is a cleartext lever

The posture tag is a cleartext lever on production. A `system:development` tag
makes reads cleartext and relaxes the `-110`/`-120` forbids, so whoever can set
a datasource's posture can unmask its columns. Datasource tags are free-form (no
posture validation), so this is purely about who may assert
`system:development`: posture is self-asserted through the proxy
self-registration gRPC path (`ControlPlaneGrpcService.register` passes the tag
list into the `Datasources.register` upsert; a non-empty list overwrites an
existing row's posture), gated only by the nullable shared `PM_SECRET_TOKEN`.
Before the dev preset is relied on in production, that registration/token path
(owned by [datasource-registration.md](./datasource-registration.md)) must close
the boundary — any of: fail boot if the secret is unset in prod; gate
posture-tag mutation behind admin authz rather than proxy self-assertion; or
forbid `Register` from overwriting an existing datasource's posture. This doc's
side is fail-closed given a trustworthy posture; that trust is asserted here,
not enforced.

## Interpretation — what a query gets, by preset × resource

A query clears gates in order: `datasource.connect` → `sql.<kind>` → per-column
result read (cleartext / masked / deny), with the function/command gate and the
`sql.unanalyzable`/`sql.unmaskable` relay layered on. Deny-by-default
throughout; the `system:*` guards are forbids that override even a broad grant.

Development datasource (`system:development`) — connect via any dev role;
`sql.*` per the role split above:

<!-- prettier-ignore -->
| resource the query touches | result |
| --- | --- |
| user table, non-PII column (`users.id`) | cleartext (`-200`) |
| user table, PII column (`users.rrn`) | cleartext — dev holds no PII, nothing is masked (`-200`) |
| system table — catalog (`pg_class`, `information_schema`) | readable (`-100`) |
| system table — activity (`pg_stat_activity`, `SHOW PROCESSLIST`) | readable (`-110` relaxed on dev, `-200` permits) |
| system table — data-leak (`pg_stats`, `SHOW BINLOG EVENTS`) | readable (`-120` relaxed on dev) |
| system — critical (`pg_authid`, `SET GLOBAL`, `SHOW GRANTS`, `SET PASSWORD`) | DENIED even on dev (`-130`) |
| dangerous function — file/remote read (`pg_read_file`, `dblink`, `get_raw_page`) | allowed (data-leak, relaxed on dev) |
| dangerous function — critical (`dblink_exec`, `pg_terminate_backend`, `lo_export`) | DENIED even on dev (`-130`) |
| un-analyzable statement / binary-result relay | relayed (`-201`/`-202`); a hidden critical function is still denied first |

Production datasource (`system:production`) — nothing below applies until an
admin enables `-250..-259` (and `-300` for the trusted-network path). Once
enabled, with the `system:production-*` roles:

<!-- prettier-ignore -->
| resource the query touches | result |
| --- | --- |
| user table, non-PII column | cleartext (`-256`) |
| user table, PII column — ordinary role | masked (`-257`) |
| user table, PII column — `system:production-pii-accessor` on `trusted-network` | cleartext (`-258`) |
| user table, PII column — `system:production-pii-accessor` on `workflow-executor` channel | cleartext (`-259`) |
| user table, PII column — viewer, even on `trusted-network` | masked (not a pii-accessor) |
| system table — catalog | readable (`-100`, environment-agnostic) |
| system table — activity / data-leak | DENIED (`-110`/`-120` forbid — overrides even a broad grant) |
| system — critical | DENIED (`-130`) |
| dangerous function (activity / data-leak / critical) | DENIED (forbid overrides a broad grant, incl. file-read/dblink) |
| un-analyzable / unmaskable relay | DENIED (no production permit) |

Two invariants hold on both presets: `system:critical` is forbidden everywhere
and no grant can open it; `system:activity`/`system:data-leak` are forbidden on
production and relaxed only on development. `system:admin` stays an
administrative role with no implicit data access — the presets change posture
and role capability, not who is an admin.

## Cedar shape

The exact syntax is compiled in tests; the intent follows this shape:

```cedar
permit(principal, action == Action::"result.read.unmasked", resource)
  when { resource in Tag::"system:catalog" };

forbid(principal, action in [Action::"result.read.unmasked", Action::"result.read.masked"], resource)
  when { resource in Tag::"system:activity" } unless { resource in Tag::"system:development" };

forbid(principal, action in [Action::"result.read.unmasked", Action::"result.read.masked"], resource)
  when { resource in Tag::"system:data-leak" } unless { resource in Tag::"system:development" };

forbid(principal, action in [Action::"result.read.unmasked", Action::"result.read.masked"], resource)
  when { resource in Tag::"system:critical" };

// development cleartext read (dev holds no PII) — role-agnostic, everything but critical
permit(principal, action == Action::"result.read.unmasked", resource)
  when   { resource in Tag::"system:development" }
  unless { resource in Tag::"system:critical" };

// production PII: masked for every production role; cleartext only for a pii-accessor on
// trusted-network (-258) or the workflow-executor channel (-259)
permit(principal, action == Action::"result.read.masked", resource)
  when { resource in Tag::"system:production" && resource in Tag::"pii"
         && (principal in Role::"system:production-viewer"
             || principal in Role::"system:production-pii-accessor"
             || principal in Role::"system:production-updater"
             || principal in Role::"system:production-deleter"
             || principal in Role::"system:production-architect") }
  unless { resource in Tag::"system:activity" || resource in Tag::"system:data-leak"
           || resource in Tag::"system:critical" };
permit(principal in Role::"system:production-pii-accessor",
       action == Action::"result.read.unmasked", resource)
  when { resource in Tag::"system:production" && resource in Tag::"pii"
         && context has tags && context.tags.contains("trusted-network") }
  unless { resource in Tag::"system:activity" || resource in Tag::"system:data-leak"
           || resource in Tag::"system:critical" };
```

## First admin role on a clean database

The migration upserts the admin role:

```sql
INSERT INTO app_role (name, description)
VALUES ('pm-admin', 'proxy-monster policy, identity, and datasource administration')
ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description;
```

A later migration renames this role to `system:admin` while keeping the
write-once `bootstrap.pm-admin` system_key. It does not create a fake principal,
default password, or auth-debug bypass, and it does not guess an IdP group name.
`RoleResolver` stays fail-closed: a principal without an explicit
direct/group/JIT assignment resolves no `system:admin` role (`RoleResolver.kt`).

The deployment's identity bootstrap assigns the first real principal or IdP
group to `system:admin` through the existing `principal_role` / `group_role`
model. Before that assignment: migrations and policy validation succeed; all
system policies are active; admin APIs return DENY; and a readiness diagnostic
reports `system:admin role has no active assignee`. That is a governed but
administratively unopened install, not an insecure bootstrap account. The
install runbook (alongside [auth-model.md](./auth-model.md)) completes one of
two explicit procedures before handover:

```sql
-- break-glass first-principal assignment, run with control-plane DB owner access
INSERT INTO principal_role (principal, role_id)
SELECT '<verified OIDC principal>', id FROM app_role WHERE name = 'system:admin'
ON CONFLICT (principal, role_id) DO NOTHING;
```

or pre-provision the verified IdP group and its `group_role` mapping in
deployment SQL. The same DB-owner procedure is the documented lockout recovery;
there is no hidden application bypass. `PM_AUTH_DEBUG` stays a dev-only server
bypass governed by its production-startup refusal and is not part of production
bootstrap.

## Runtime loading and validation

`CedarEngine` loads only `enabled=true` rows in stable id order
(`CedarPolicyStore.enabledSources()`). Origin does not alter Cedar evaluation;
it alters who may mutate source. Safety rules:

1. create/update of a user policy validates `cedar_src` before commit;
2. enabling any row revalidates stored source;
3. every enabled row is validated/compiled when the engine rebuilds — an invalid
   enabled row yields a fail-closed engine error, never a partial PolicySet;
4. migration-seeded system source is validated in CI against the exact schema
   and through a real migrated Postgres test; and
5. Flyway runs before the server, so migration UPSERTs are visible when the
   first engine cache is built.

Migration SQL bypasses the store's in-process `stateVersion`, which is correct
at boot: the new process begins with an empty cache and reads the migrated rows.
Runtime API toggles still increment `stateVersion` so the next authorization
rebuilds promptly.

## Store and API contract

DTO:

```text
CedarPolicy(id, systemKey?, origin /* SYSTEM | USER */, name, cedarSrc, enabled, updatedBy, updatedAt)
```

Backend invariants:

- `POST /api/policies` creates USER only and rejects a `system:`-prefixed name
  with a 400;
- `PUT`/`DELETE /api/policies/{id}` on a SYSTEM row rejects with a
  system-policy-immutable error (409);
- enable/disable works for both origins and validates on enable;
- requests cannot change origin/systemKey/id; and
- store methods enforce the guard even when called outside the current routes.

A system policy's source stays readable to policy admins for review/debugging —
read-only does not mean hidden. A toggle writes only `enabled`, `updated_by`,
and `updated_at`; the audit identity is the authenticated principal. Disabling a
system guard is a security-sensitive admin event and enters the admin audit
stream with `policy_id`, `system_key`, old/new enabled values, and principal.

## Console behavior

The policy list shows one surface, grouped or filterable by origin
(`web/src/components/policies/cedar-policies-tab.tsx`):

- System rows: badge, stable key, shipped description, read-only source viewer,
  enable switch. Edit and Delete are absent/disabled; the editor opens read-only
  for copy/review; the enable switch stays available to `admin.policies`;
  disabling shows the concrete consequence (for example, "Disabling the critical
  guard allows a later permit to expose credentials or privileged mutation");
  and the UI handles backend immutability errors rather than assuming its own
  controls suffice.
- User rows: normal Edit/Delete/enable controls.

A migration may change a system row's name/source/description while it is
disabled; the console displays the updated source and preserves the disabled
state.

## Worked lifecycle

Clean install: Flyway creates the schema, converts/inserts the stable negative
system rows, and creates the admin role; every enabled system row validates and
compiles before serving; no principal has admin until deployment explicitly
assigns one; untagged datasources are deny-by-default.

An admin disables the activity guard: toggling `-110` off updates only
`enabled=false`, `updated_by`, `updated_at` → CedarEngine rebuilds without that
forbid → existing user permits may now authorize activity resources (no source
is rewritten). A later migration may update `-110.cedar_src` but leaves it
disabled; re-enabling validates the updated source and restores the guard.

Product ships a data-leak policy fix: a new migration UPSERTs `-120` with the
same `system_key`, updating `cedar_src` and display name transactionally,
preserving the existing enabled/disabled choice; any id/key/name conflict aborts
migration and startup.

## Data model

New / changed: `policy.origin` and `policy.system_key`; negative reserved system
ids, reserved `system:` policy names, and the check constraints; forward
conversion of the original seed rows; migration-seeded access-model
system/preset policies; the migration-seeded admin role; DTO/API/console origin
awareness; and admin audit/readiness diagnostics for system toggles and an
unassigned bootstrap role.

Kept: one `policy` table and the `enabledSources()` load path; Cedar source
validation on write/enable/load; positive `BIGSERIAL` user ids; `app_role`,
`principal_role`, `app_group`, `group_role`, and `RoleResolver`; and Flyway
migrate-before-serve, per-migration transaction, forward-only.

## Failure modes

1. Migration conflict or invalid constraint: transaction rolls back; startup
   aborts.
2. Invalid enabled Cedar source: engine load/decision fails closed; no partial
   policy set.
3. System row update/delete through the API: rejected by the store, regardless
   of UI.
4. System row disabled: a deliberate security posture change, audited and
   preserved across upgrade.
5. Negative USER or positive SYSTEM row inserted manually: the database
   constraint rejects it.
6. Duplicate id/system_key/name in a migration: the migration fails instead of
   silently retargeting a policy.
7. No first admin assignment: admin stays inaccessible; no fallback principal is
   invented.
8. Admin role deleted or last assignment removed: administrative access is lost
   and recovered through the same trusted identity/database bootstrap. The
   identity admin surface warns/blocks the last-admin operation; role lifecycle
   protection belongs to the identity layer, not policy loading.
9. System policy absent after manual DB deletion: runtime loses that rule, which
   is why direct DB write access is trusted/break-glass; the next carrying
   migration recreates it, and health diagnostics report a missing expected
   system-key set.
10. Cedar schema and seed deployed out of order: one release migration owns
    both; boot validation prevents serving an incompatible set.
11. Admin permit conflicts with a system forbid: the forbid wins. The guard must
    be explicitly toggled/replaced, so a hidden user policy cannot override the
    shipped safety floor.
