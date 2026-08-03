-- Reprint the seeded policy source with the Cedar formatter's line breaks and indentation. The
-- inserts in V8 write each policy as one long line, which the console renders verbatim — the policy
-- IS its source there, so it reads as an unbroken wall of text.
--
-- Only whitespace changes; every policy means exactly what it did. Scoped to the migration-authored
-- SYSTEM rows: a user's policy is stored as typed and is not this migration's to reshape.

UPDATE policy SET cedar_src = $$permit (
  principal,
  action == Action::"context.tag::trusted-network",
  resource
)
when
{
  context has requester_ip &&
  context.requester_ip.isInRange(ip("100.100.0.0/16"))
};
$$ WHERE id = -300 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal in Role::"system:production-pii-accessor",
  action == Action::"result.read.unmasked",
  resource
)
when
{
  resource in Tag::"system:production" &&
  resource in Tag::"pii" &&
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
UPDATE policy SET cedar_src = $$permit (
  principal in Role::"system:production-pii-accessor",
  action == Action::"result.read.unmasked",
  resource
)
when
{
  resource in Tag::"system:production" &&
  resource in Tag::"pii" &&
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
  action == Action::"result.read.masked",
  resource
)
when
{
  resource in Tag::"system:production" &&
  resource in Tag::"pii" &&
  (principal in Role::"system:production-viewer" ||
   principal in Role::"system:production-pii-accessor" ||
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
  (principal in Role::"system:production-viewer" ||
   principal in Role::"system:production-pii-accessor" ||
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
  principal in Role::"system:production-architect",
  action == Action::"sql.ddl",
  resource
)
when { resource in Tag::"system:production" };
$$ WHERE id = -255 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal in Role::"system:production-deleter",
  action == Action::"sql.delete",
  resource
)
when { resource in Tag::"system:production" };
$$ WHERE id = -254 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal in Role::"system:production-updater",
  action == Action::"sql.update",
  resource
)
when { resource in Tag::"system:production" };
$$ WHERE id = -253 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal in Role::"system:production-updater",
  action == Action::"sql.insert",
  resource
)
when { resource in Tag::"system:production" };
$$ WHERE id = -252 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal,
  action == Action::"sql.select",
  resource
)
when
{
  resource in Tag::"system:production" &&
  (principal in Role::"system:production-viewer" ||
   principal in Role::"system:production-pii-accessor")
};
$$ WHERE id = -251 AND origin = 'SYSTEM';
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
   principal in Role::"system:production-updater" ||
   principal in Role::"system:production-deleter" ||
   principal in Role::"system:production-architect")
};
$$ WHERE id = -250 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal in Role::"system:development-architect",
  action == Action::"sql.ddl",
  resource
)
when { resource in Tag::"system:development" };
$$ WHERE id = -235 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal in Role::"system:development-deleter",
  action == Action::"sql.delete",
  resource
)
when { resource in Tag::"system:development" };
$$ WHERE id = -234 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal in Role::"system:development-updater",
  action == Action::"sql.update",
  resource
)
when { resource in Tag::"system:development" };
$$ WHERE id = -233 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal in Role::"system:development-updater",
  action == Action::"sql.insert",
  resource
)
when { resource in Tag::"system:development" };
$$ WHERE id = -232 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal,
  action == Action::"sql.select",
  resource
)
when
{
  resource in Tag::"system:development" &&
  (principal in Role::"system:development-viewer" ||
   principal in Role::"system:development-pii-accessor")
};
$$ WHERE id = -231 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal,
  action == Action::"datasource.connect",
  resource
)
when
{
  resource in Tag::"system:development" &&
  (principal in Role::"system:development-viewer" ||
   principal in Role::"system:development-pii-accessor" ||
   principal in Role::"system:development-updater" ||
   principal in Role::"system:development-deleter" ||
   principal in Role::"system:development-architect")
};
$$ WHERE id = -230 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal,
  action == Action::"sql.unmaskable",
  resource
)
when { resource in Tag::"system:development" };
$$ WHERE id = -202 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal,
  action == Action::"sql.unanalyzable",
  resource
)
when { resource in Tag::"system:development" };
$$ WHERE id = -201 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal,
  action == Action::"result.read.unmasked",
  resource
)
when { resource in Tag::"system:development" }
unless { resource in Tag::"system:critical" };
$$ WHERE id = -200 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$forbid (
  principal,
  action in [Action::"result.read.unmasked", Action::"result.read.masked"],
  resource
)
when { resource in Tag::"system:critical" };
$$ WHERE id = -130 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$forbid (
  principal,
  action in [Action::"result.read.unmasked", Action::"result.read.masked"],
  resource
)
when { resource in Tag::"system:data-leak" }
unless { resource in Tag::"system:development" };
$$ WHERE id = -120 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$forbid (
  principal,
  action in [Action::"result.read.unmasked", Action::"result.read.masked"],
  resource
)
when { resource in Tag::"system:activity" }
unless { resource in Tag::"system:development" };
$$ WHERE id = -110 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal,
  action == Action::"result.read.unmasked",
  resource
)
when { resource in Tag::"system:catalog" };
$$ WHERE id = -100 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal,
  action == Action::"task.cancel",
  resource
)
when
{
  resource is Request &&
  (resource.requester == principal ||
   (resource has approver && resource.approver == principal))
};
$$ WHERE id = -25 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal,
  action == Action::"task.approve",
  resource
)
when
{
  resource is Request &&
  principal == resource.requester &&
  context has channel &&
  context.channel == "wire"
};
$$ WHERE id = -24 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal,
  action == Action::"task.approve",
  resource
)
when
{
  resource is Request &&
  principal == resource.requester &&
  context has channel &&
  context.channel == "editor"
};
$$ WHERE id = -23 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal in Role::"system:auditor",
  action == Action::"task.assume",
  resource
)
when { resource is Request };
$$ WHERE id = -22 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal,
  action == Action::"task.assume",
  resource
)
when
{
  resource is Request &&
  (resource.requester == principal ||
   (resource has approver && resource.approver == principal))
};
$$ WHERE id = -21 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$forbid (
  principal,
  action == Action::"token.mint",
  resource
)
when { resource.owner != principal };
$$ WHERE id = -20 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal in Role::"system:admin",
  action in [Action::"token.list", Action::"token.revoke"],
  resource
);
$$ WHERE id = -19 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal,
  action in
    [Action::"token.mint", Action::"token.list", Action::"token.revoke"],
  resource
)
when { resource.owner == principal };
$$ WHERE id = -18 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal,
  action == Action::"task.request",
  resource
);
$$ WHERE id = -16 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal,
  action in [Action::"task.read", Action::"grant.revoke"],
  resource
)
when { resource is AccessGrant && resource.owner == principal };
$$ WHERE id = -15 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal,
  action == Action::"task.read",
  resource
)
when { resource is Request && resource.requester == principal };
$$ WHERE id = -14 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal in Role::"system:admin",
  action == Action::"audit.read",
  resource
);
$$ WHERE id = -5 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal,
  action == Action::"audit.read",
  resource
)
when { resource is AuditRecord && resource.principal == principal };
$$ WHERE id = -4 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal in Role::"system:admin",
  action in
    [Action::"task.approve",
     Action::"task.read",
     Action::"grant.revoke",
     Action::"task.request",
     Action::"task.cancel",
     Action::"task.delete"],
  resource
);
$$ WHERE id = -3 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$forbid (
  principal,
  action == Action::"task.approve",
  resource
)
when { principal == resource.requester }
unless
{
  context has channel &&
  (context.channel == "editor" || context.channel == "wire")
};
$$ WHERE id = -2 AND origin = 'SYSTEM';
UPDATE policy SET cedar_src = $$permit (
  principal in Role::"system:admin",
  action in
    [Action::"admin.datasources",
     Action::"admin.policies",
     Action::"admin.identity"],
  resource
);
$$ WHERE id = -1 AND origin = 'SYSTEM';
