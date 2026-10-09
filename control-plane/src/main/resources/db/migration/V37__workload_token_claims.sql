-- The CI OIDC token's allow-listed string claims, marshalled as the Workload principal's Cedar attributes.
ALTER TABLE proxy_token ADD COLUMN claims JSONB;
ALTER TABLE proxy_token ADD CONSTRAINT proxy_token_workload_claims_ck CHECK ((kind = 'WORKLOAD') = (claims IS NOT NULL));
