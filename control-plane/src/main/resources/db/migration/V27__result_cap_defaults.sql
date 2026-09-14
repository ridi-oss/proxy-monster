-- The shipped result limits. Action `result.cap` is never consulted for access, so a permit on it
-- grants nothing: the control plane asks it per returned resource and per datasource and folds the @cap
-- entries of the permits that answered — an entry <amount> caps one result, an entry <amount>/<window> is a
-- rate over a rolling window, and a forbid on the action clears every limit for whoever it names. A
-- deployment that wants other numbers disables a row and writes its own; with every permit off the
-- control plane still caps at 5,000 rows / 50 MB.
-- cedar_src is stored in canonical `cedar format` output.

INSERT INTO policy (id, system_key, name, cedar_src, enabled, origin, updated_by, updated_at) VALUES
    (-305, 'guardrail.result-cap-default', 'system:result-cap-default',
     '@cap("5000, 50MB, 10000/1h, 50000/1d, 100MB/1h, 500MB/1d")
permit (
  principal,
  action == Action::"result.cap",
  resource
);',
     TRUE, 'SYSTEM', 'migration:V27', now()),
    (-306, 'guardrail.result-cap-clear', 'system:result-cap-clear',
     '@cap("500, 5MB")
permit (
  principal,
  action == Action::"result.cap",
  resource
)
when
{
  resource is Column && resource.tagged && context has masked && !context.masked
};',
     TRUE, 'SYSTEM', 'migration:V27', now());

-- The one shipped way past the limits: system:production-exporter. It reads production exactly like
-- system:production-pii-accessor (it joins -250/-251/-256/-257/-258/-259 below) and its forbid on
-- result.cap clears every cap and rate on top. A workflow executes under ONE role, so the lift has to
-- ride a role that can also read: request this role for a full PII export. Meant to be held for a window
-- through a JIT grant, or by a workflow executing as it, never assigned permanently and never earned by
-- network.
INSERT INTO app_role (name, description) VALUES
    ('system:production-exporter', 'Production SELECT with PII cleartext and no result cap or rate. Grant for a window, not permanently.');
INSERT INTO app_group (name, description, source, external_id) VALUES
    ('system:production-exporter', 'Production uncapped exporters. Explicit assignment only.', 'SYSTEM', NULL);
INSERT INTO group_role (group_id, role_id)
SELECT g.id, r.id FROM app_group g JOIN app_role r
  ON g.name = 'system:production-exporter' AND r.name = 'system:production-exporter';

INSERT INTO policy (id, system_key, name, cedar_src, enabled, origin, updated_by, updated_at) VALUES
    (-307, 'guardrail.result-cap-exporter', 'system:result-cap-exporter',
     'forbid (
  principal in Role::"system:production-exporter",
  action == Action::"result.cap",
  resource
);',
     TRUE, 'SYSTEM', 'migration:V27', now());

-- The exporter joins every production read preset the pii-accessor is in. Same bodies as V12/V18,
-- with the one extra role; enabled flags are untouched (the production package still ships off).
UPDATE policy SET cedar_src = $$permit (
  principal,
  action == Action::"datasource.connect",
  resource
)
when
{
  resource in Tag::"system:production" &&
  (principal in Role::"system:production-viewer" ||
   principal in Role::"system:production-pii-accessor" ||
   principal in Role::"system:production-exporter" ||
   principal in Role::"system:production-updater" ||
   principal in Role::"system:production-deleter" ||
   principal in Role::"system:production-architect")
};
$$ WHERE id = -250 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal,
  action in [Action::"stmt.cat.read"],
  resource
)
when
{
  resource in Tag::"system:production" &&
  (principal in Role::"system:production-viewer" ||
   principal in Role::"system:production-pii-accessor" ||
   principal in Role::"system:production-exporter")
};
$$ WHERE id = -251 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal,
  action == Action::"result.read.unmasked",
  resource
)
when
{
  resource in Tag::"system:production" &&
  (principal in Role::"system:production-viewer" ||
   principal in Role::"system:production-pii-accessor" ||
   principal in Role::"system:production-exporter" ||
   principal in Role::"system:production-updater" ||
   principal in Role::"system:production-deleter" ||
   principal in Role::"system:production-architect")
}
unless
{
  resource in Tag::"pii" ||
  resource in Tag::"system:catalog" ||
  resource in Tag::"system:activity" ||
  resource in Tag::"system:data-leak" ||
  resource in Tag::"system:critical"
};
$$ WHERE id = -256 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal,
  action == Action::"result.read.masked",
  resource
)
when
{
  resource in Tag::"system:production" &&
  resource in Tag::"pii" &&
  (principal in Role::"system:production-viewer" ||
   principal in Role::"system:production-pii-accessor" ||
   principal in Role::"system:production-exporter" ||
   principal in Role::"system:production-updater" ||
   principal in Role::"system:production-deleter" ||
   principal in Role::"system:production-architect")
}
unless
{
  resource in Tag::"system:activity" ||
  resource in Tag::"system:data-leak" ||
  resource in Tag::"system:critical"
};
$$ WHERE id = -257 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal,
  action == Action::"result.read.unmasked",
  resource
)
when
{
  resource in Tag::"system:production" &&
  resource in Tag::"pii" &&
  (principal in Role::"system:production-pii-accessor" ||
   principal in Role::"system:production-exporter") &&
  context has tags &&
  context.tags.contains("trusted-network")
}
unless
{
  resource in Tag::"system:activity" ||
  resource in Tag::"system:data-leak" ||
  resource in Tag::"system:critical"
};
$$ WHERE id = -258 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal,
  action == Action::"result.read.unmasked",
  resource
)
when
{
  resource in Tag::"system:production" &&
  resource in Tag::"pii" &&
  (principal in Role::"system:production-pii-accessor" ||
   principal in Role::"system:production-exporter") &&
  context has channel &&
  context.channel == "workflow-executor"
}
unless
{
  resource in Tag::"system:activity" ||
  resource in Tag::"system:data-leak" ||
  resource in Tag::"system:critical"
};
$$ WHERE id = -259 AND origin = 'SYSTEM';
