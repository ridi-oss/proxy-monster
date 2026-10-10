-- name: LiveWebSession :one
SELECT id, principal, created_at, absolute_expires_at, idle_expires_at, device_id,
       coalesce(debug_requester_ip, '')::text AS debug_requester_ip, clock_timestamp()::timestamptz AS db_now
FROM principal_session
WHERE session_key = $1 AND kind = 'WEB' AND ended_at IS NULL
  AND absolute_expires_at > clock_timestamp()
  AND idle_expires_at > clock_timestamp();
