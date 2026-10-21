-- task.run gates running an approved query request: any approver, or the requester.
UPDATE policy SET cedar_src = $$permit (
  principal in Role::"system:admin",
  action in
    [Action::"task.approve",
     Action::"task.run",
     Action::"task.read",
     Action::"grant.revoke",
     Action::"task.request",
     Action::"task.cancel",
     Action::"task.delete",
     Action::"task.force_run"],
  resource
);
$$ WHERE id = -3 AND origin = 'SYSTEM';

INSERT INTO policy (id, system_key, name, cedar_src, enabled, origin, updated_by, updated_at) VALUES
    (-26, 'task.run-requester', 'system:task-run-requester',
     $$permit (
  principal,
  action == Action::"task.run",
  resource
)
when { resource is Request && resource.requester == principal };
$$, TRUE, 'SYSTEM', 'migration:V43', now());

-- Whoever ran a request sees its result, as the requester and the approver do.
UPDATE policy SET cedar_src = $$permit (
  principal,
  action == Action::"task.assume",
  resource
)
when
{
  resource is Request &&
  (resource.requester == principal ||
   (resource has approver && resource.approver == principal) ||
   (resource has executedBy && resource.executedBy == principal))
};
$$ WHERE id = -21 AND origin = 'SYSTEM';
