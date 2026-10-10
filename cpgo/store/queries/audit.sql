-- name: AuditLog :many
SELECT * FROM audit_event ORDER BY ts DESC LIMIT $1;

-- name: AuditLogOf :many
SELECT * FROM audit_event WHERE principal = $1 ORDER BY ts DESC LIMIT $2;

-- name: AuditEvent :one
SELECT * FROM audit_event WHERE id = $1;
