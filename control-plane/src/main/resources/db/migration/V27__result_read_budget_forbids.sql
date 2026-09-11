-- The shipped per-principal result-volume budgets: once a principal's completion events over a rolling
-- window reach the threshold, every further read is denied until the window rolls off. The 1h
-- and 24h windows are summed by the control plane and passed as context attributes, so a deployment that
-- wants other numbers disables these rows and writes its own. An ALLOW on result.read.unbounded leaves the
-- attributes absent, which is what lets an approved dump run past them.
-- cedar_src is stored in canonical `cedar format` output.

INSERT INTO policy (id, system_key, name, cedar_src, enabled, origin, updated_by, updated_at) VALUES
    (-301, 'guardrail.budget-rows-1h', 'system:budget-rows-1h',
     'forbid (
  principal,
  action in [Action::"result.read.unmasked", Action::"result.read.masked"],
  resource
)
when { context has budget_rows_1h && context.budget_rows_1h >= 10000 };',
     TRUE, 'SYSTEM', 'migration:V27', now()),
    (-302, 'guardrail.budget-bytes-1h', 'system:budget-bytes-1h',
     'forbid (
  principal,
  action in [Action::"result.read.unmasked", Action::"result.read.masked"],
  resource
)
when { context has budget_bytes_1h && context.budget_bytes_1h >= 100000000 };',
     TRUE, 'SYSTEM', 'migration:V27', now()),
    (-303, 'guardrail.budget-rows-24h', 'system:budget-rows-24h',
     'forbid (
  principal,
  action in [Action::"result.read.unmasked", Action::"result.read.masked"],
  resource
)
when { context has budget_rows_24h && context.budget_rows_24h >= 50000 };',
     TRUE, 'SYSTEM', 'migration:V27', now()),
    (-304, 'guardrail.budget-bytes-24h', 'system:budget-bytes-24h',
     'forbid (
  principal,
  action in [Action::"result.read.unmasked", Action::"result.read.masked"],
  resource
)
when { context has budget_bytes_24h && context.budget_bytes_24h >= 500000000 };',
     TRUE, 'SYSTEM', 'migration:V27', now());
