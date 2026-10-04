-- The production plan-only-EXPLAIN preset (-262), shipped DISABLED like the rest of the production
-- package. A plan-only EXPLAIN returns the query plan, not rows, so a masked column in a predicate is
-- denied by default -- its selectivity would leak (a bare EXPLAIN's cost estimate, and the EXACT actual
-- row counts an EXPLAIN ANALYZE of a read reports, which reconstruct a value bit by bit). Enabling this
-- lets a production pii-accessor EXPLAIN ANY query: PII resolves unmasked ONLY under
-- context.stmt_kind == "explain", which the analyzer sets for a plan-only EXPLAIN of a read and never for
-- a row-returning SELECT or an EXPLAIN of a write (that keeps the write's own kind). The same
-- activity / data-leak / critical carve-outs still bite.
--
-- Scoped to system:production-pii-accessor only, matching -258/-259: that EXPLAIN-selectivity channel
-- reaches a role already trusted to read PII cleartext (on the trusted network, -258), not a plain viewer.
-- cedar_src is stored in canonical `cedar format` output (PolicyOriginDbTest enforces it).

INSERT INTO policy (id, system_key, name, cedar_src, enabled, origin, updated_by, updated_at) VALUES
    (-262, 'preset.production-explain-unmasked', 'system:production-explain-unmasked',
     'permit (
  principal in Role::"system:production-pii-accessor",
  action == Action::"result.read.unmasked",
  resource
)
when
{
  resource in Tag::"system:production" &&
  resource in Tag::"pii" &&
  context has stmt_kind &&
  context.stmt_kind == "explain"
}
unless
{
  resource in Tag::"system:activity" ||
  resource in Tag::"system:data-leak" ||
  resource in Tag::"system:critical"
};',
     FALSE, 'SYSTEM', 'migration:V21', now());
