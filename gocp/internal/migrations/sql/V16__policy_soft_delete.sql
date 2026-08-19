-- Soft delete for Cedar policies, mirroring the sibling entities (V13–V15). A delete stamps `deleted_at`
-- instead of removing the row. The one runtime effect of deleting a policy is that it leaves the evaluated
-- Cedar policy set: `CedarPolicyStore.enabledSources()` — the engine's only policy load — filters
-- `deleted_at IS NULL`, and the existing per-mutation version bump rebuilds the cached PolicySet, so a
-- soft-deleted policy (permit OR forbid) stops applying immediately. The name is freed for reuse via a
-- partial unique index scoped to live rows. SYSTEM policies (negative id, `origin='SYSTEM'`) are already
-- undeletable, so soft-delete only ever applies to USER policies.
ALTER TABLE policy ADD COLUMN deleted_at TIMESTAMPTZ;

ALTER TABLE policy DROP CONSTRAINT policy_name_key;
CREATE UNIQUE INDEX policy_name_live_key ON policy (name) WHERE deleted_at IS NULL;
