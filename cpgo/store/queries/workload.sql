-- name: MintWorkloadToken :one
INSERT INTO proxy_token (token_hash, kind, principal, roles, name, expires_at, claims)
VALUES (sqlc.arg(token_hash), 'WORKLOAD', sqlc.arg(principal), '[]'::jsonb, NULL, now() + (sqlc.arg(ttl)::bigint * interval '1 second'), sqlc.arg(claims)::jsonb)
RETURNING id, expires_at;
