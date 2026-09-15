-- A rate reset marker. A @cap rate is computed from the audit trail, which is append-only, so a reset
-- is a row, not a deletion: the relayed-volume scan counts no completion before the principal's latest
-- reset_at, whatever the window. Written by an admin directly or by approving a RATE_RESET request; both
-- paths also record a management-audit event.
CREATE TABLE result_rate_reset (
    id        BIGSERIAL PRIMARY KEY,
    principal TEXT NOT NULL,
    reset_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    reset_by  TEXT NOT NULL,
    reason    TEXT NOT NULL
);
CREATE INDEX result_rate_reset_principal_at ON result_rate_reset (principal, reset_at DESC);

-- A RATE_RESET request needs no role and no datasource; it is decided PENDING -> APPROVED | REJECTED like
-- a ROLE request.
ALTER TABLE access_request DROP CONSTRAINT access_request_kind_shape;
ALTER TABLE access_request ADD CONSTRAINT access_request_kind_shape CHECK (
    (kind = 'ROLE'  AND role_id IS NOT NULL)
 OR (kind = 'QUERY' AND datasource_id IS NOT NULL)
 OR (kind = 'RATE_RESET')
);
ALTER TABLE access_request DROP CONSTRAINT access_request_status_shape;
ALTER TABLE access_request ADD CONSTRAINT access_request_status_shape CHECK (
    (kind IN ('ROLE', 'RATE_RESET') AND status IN ('PENDING', 'APPROVED', 'REJECTED'))
 OR (kind = 'QUERY' AND status IN ('DRAFT', 'PENDING', 'APPROVED', 'REJECTED', 'EXECUTING',
                                   'EXECUTED', 'FAILED', 'CANCELLED', 'DELETED'))
);
