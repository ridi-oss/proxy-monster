-- name: LiveWebSession :one
SELECT id, principal, created_at, absolute_expires_at, idle_expires_at, device_id,
       coalesce(debug_requester_ip, '')::text AS debug_requester_ip, clock_timestamp()::timestamptz AS db_now
FROM principal_session
WHERE session_key = $1 AND kind = 'WEB' AND ended_at IS NULL
  AND absolute_expires_at > clock_timestamp()
  AND idle_expires_at > clock_timestamp();

-- name: WirePrincipal :one
SELECT t.principal FROM proxy_token t
WHERE t.token_hash = $1 AND t.kind IN ('SESSION', 'USER') AND t.revoked_at IS NULL
  AND t.retired_at IS NULL AND t.expires_at > now()
  AND NOT EXISTS (SELECT 1 FROM app_user u WHERE u.principal = t.principal AND NOT u.active);
