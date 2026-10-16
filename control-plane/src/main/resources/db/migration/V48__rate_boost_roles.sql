-- A spent rate is raised by holding a boost role for a while (a ROLE request, or a JIT grant), not by a
-- reset marker. @boost("N") on a result.cap permit multiplies every rate the statement's permits carry.
INSERT INTO app_role (name, description) VALUES
    ('system:rate-boost-2x', 'Doubles every result rate. Grant for a window, not permanently.'),
    ('system:rate-boost-5x', 'Multiplies every result rate by five. Grant for a window, not permanently.');

INSERT INTO policy (id, system_key, name, cedar_src, enabled, origin, updated_by, updated_at) VALUES
    (-308, 'guardrail.rate-boost-2x', 'system:rate-boost-2x',
     '@boost("2")
permit (
  principal in Role::"system:rate-boost-2x",
  action == Action::"result.cap",
  resource
);',
     TRUE, 'SYSTEM', 'migration:V48', now()),
    (-309, 'guardrail.rate-boost-5x', 'system:rate-boost-5x',
     '@boost("5")
permit (
  principal in Role::"system:rate-boost-5x",
  action == Action::"result.cap",
  resource
);',
     TRUE, 'SYSTEM', 'migration:V48', now());
