-- name: LiveWebSession :one
SELECT id, principal, created_at, absolute_expires_at, idle_expires_at, device_id,
       coalesce(debug_requester_ip, '')::text AS debug_requester_ip, clock_timestamp()::timestamptz AS db_now
FROM principal_session
WHERE id = $1 AND kind = 'WEB' AND ended_at IS NULL
  AND absolute_expires_at > clock_timestamp()
  AND idle_expires_at > clock_timestamp();

-- name: WirePrincipal :one
SELECT t.principal FROM proxy_token t
WHERE t.token_hash = $1 AND t.kind IN ('SESSION', 'USER') AND t.revoked_at IS NULL
  AND t.retired_at IS NULL AND t.expires_at > now()
  AND NOT EXISTS (SELECT 1 FROM app_user u WHERE u.principal = t.principal AND NOT u.active);

-- name: WebSessionIDByKey :one
SELECT id FROM principal_session WHERE session_key = $1 AND kind = 'WEB';

-- name: WebSessionEndedReason :one
SELECT ended_reason FROM principal_session WHERE id = $1 AND kind = 'WEB';

-- name: MintWebSession :one
WITH t AS (SELECT clock_timestamp() AS ts)
INSERT INTO principal_session (kind, principal, device_id, refresh_token_enc, created_at, absolute_expires_at,
                               idle_expires_at, liveness_status, debug_requester_ip)
SELECT 'WEB', sqlc.arg(principal), sqlc.arg(device_id), sqlc.arg(refresh_token_enc), t.ts, t.ts + make_interval(secs => sqlc.arg(absolute_seconds)), t.ts + make_interval(secs => sqlc.arg(idle_seconds)), 'ACTIVE', sqlc.arg(debug_requester_ip)
FROM t RETURNING id;

-- name: DisplaceWebSessions :execrows
UPDATE principal_session SET ended_at = clock_timestamp(), ended_reason = 'DISPLACED',
liveness_status = 'INACTIVE' WHERE principal = $1 AND kind = 'WEB' AND ended_at IS NULL AND id <> $2;

-- name: UnlinkSessionKey :exec
UPDATE principal_session SET session_key = NULL WHERE session_key = $1 AND kind = 'WEB' AND id <> $2;

-- name: LinkSessionKey :exec
UPDATE principal_session SET session_key = $1 WHERE id = $2 AND kind = 'WEB';

-- name: EndWebSession :one
UPDATE principal_session SET ended_at = now(), ended_reason = $1, liveness_status = 'INACTIVE'
WHERE id = $2 AND kind = 'WEB' AND ended_at IS NULL RETURNING principal;

-- name: WebSessionOwner :one
SELECT principal FROM principal_session WHERE id = $1 AND kind = 'WEB';

-- name: TouchWebSession :exec
UPDATE principal_session SET idle_expires_at = now() + make_interval(secs => sqlc.arg(idle_seconds)), last_seen_at = now()
WHERE id = sqlc.arg(id) AND kind = 'WEB' AND ended_at IS NULL
  AND absolute_expires_at > clock_timestamp() AND idle_expires_at > clock_timestamp()
  AND device_id = sqlc.arg(device_id)
  AND (last_seen_at IS NULL OR last_seen_at < now() - make_interval(secs => sqlc.arg(slide_seconds)));
