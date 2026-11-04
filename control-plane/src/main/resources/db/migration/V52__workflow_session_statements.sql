UPDATE policy SET
    cedar_src = $$forbid (
  principal,
  action in [Action::"stmt.cat.session"],
  resource
)
unless
{
  context has channel &&
  (context.channel == "editor" ||
   context.channel == "wire" ||
   ((context.channel == "workflow-executor" ||
     context.channel == "workflow-viewer") &&
    action == Action::"stmt.kind.set_session_var"))
};
$$,
    updated_by = 'migration:V52',
    updated_at = now()
WHERE id = -280 AND origin = 'SYSTEM';
