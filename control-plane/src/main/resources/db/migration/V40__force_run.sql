-- Set by an admin to run a GitHub request past its scope's freshness and one-PR-at-a-time checks.
ALTER TABLE access_request ADD COLUMN force_run BOOLEAN NOT NULL DEFAULT FALSE;
-- The admin who forced it, for the PR comment and the Slack announcement.
ALTER TABLE access_request ADD COLUMN force_run_by TEXT;

UPDATE policy SET cedar_src = $$permit (
  principal in Role::"system:admin",
  action in
    [Action::"task.approve",
     Action::"task.read",
     Action::"grant.revoke",
     Action::"task.request",
     Action::"task.cancel",
     Action::"task.delete",
     Action::"task.force_run"],
  resource
);
$$ WHERE id = -3 AND origin = 'SYSTEM';
