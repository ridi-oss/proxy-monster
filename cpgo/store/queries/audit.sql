-- name: AuditLog :many
SELECT * FROM audit_event ORDER BY ts DESC LIMIT $1;

-- name: AuditLogOf :many
SELECT * FROM audit_event WHERE principal = $1 ORDER BY ts DESC LIMIT $2;

-- name: AuditEvent :one
SELECT * FROM audit_event WHERE id = $1;

-- name: LockAuditChainHead :one
SELECT last_id, head_hash FROM audit_chain_head WHERE id = 1 FOR UPDATE;

-- name: InsertAuditEvent :exec
INSERT INTO audit_event
    (id, ts, principal, roles, datasource, client_addr, statement, decision,
     failed_stage, masked_columns, pii_touched, latency_ms, detail, effective_namespace,
     channel, context_tags, action, resource, outcome, kind, rows_returned, bytes_returned,
     decision_id, chain_version, prev_hash, row_hash)
VALUES (@id, @ts, @principal, @roles::jsonb, @datasource, @client_addr, @statement, @decision, @failed_stage,
        @masked_columns::jsonb, @pii_touched::jsonb, @latency_ms, @detail, @effective_namespace::jsonb,
        @channel, @context_tags::jsonb, @action, @resource, @outcome, @kind, @rows_returned, @bytes_returned,
        @decision_id, @chain_version, @prev_hash, @row_hash);

-- name: AdvanceAuditChainHead :exec
UPDATE audit_chain_head SET last_id = $1, head_hash = $2 WHERE id = 1;
