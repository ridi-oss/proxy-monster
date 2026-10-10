-- name: StaleSessions :many
SELECT id, kind, principal, refresh_token_enc FROM principal_session
WHERE (last_idp_check_at IS NULL OR last_idp_check_at < now() - make_interval(secs => $1))
  AND ((kind = 'DAEMON' AND absolute_expires_at > now())
    OR (kind = 'WEB' AND ended_at IS NULL AND absolute_expires_at > now() AND idle_expires_at > now()));

-- name: RotateRefreshToken :exec
UPDATE principal_session SET refresh_token_enc = $1 WHERE id = $2;

-- name: MarkIdpChecked :exec
UPDATE principal_session SET last_idp_check_at = now(),
liveness_status = CASE WHEN ended_at IS NULL THEN 'ACTIVE' ELSE liveness_status END WHERE id = $1;

-- name: CloseDaemonRenewal :execrows
UPDATE principal_session SET liveness_status = 'INACTIVE', absolute_expires_at = now()
WHERE id = $1 AND kind = 'DAEMON' AND absolute_expires_at > now();

-- name: EndGroupRevokedSessions :execrows
UPDATE principal_session SET ended_at = now(), ended_reason = 'GROUP_REVOKED', liveness_status = 'INACTIVE'
WHERE principal = $1 AND kind = 'WEB' AND ended_at IS NULL;
