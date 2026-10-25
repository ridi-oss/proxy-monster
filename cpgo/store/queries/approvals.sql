-- name: PendingQueryRequests :many
SELECT ar.id, ar.principal, ar.role_id, r.name AS role_name, ar.datasource_id, d.name AS datasource_name,
       ar.reason, ar.requested_duration_sec, ar.status, ar.decided_by,
       (SELECT qr.executed_by FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.ordinal LIMIT 1) AS executed_by,
       ar.decided_at, ar.rejection_reason, ar.created_at, ar.kind,
       (SELECT string_agg(qr.sql, E';\n' ORDER BY qr.ordinal) FROM query_result qr WHERE qr.task_id = ar.id) AS sql,
       (SELECT qr.sql_hash FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.ordinal LIMIT 1) AS sql_hash,
       (SELECT count(*) FROM query_result qr WHERE qr.task_id = ar.id) AS statement_count,
       ar.deny_reason, ar.source_decision_id, ar.title, ar.evaluated_decision,
       ar.approved_at, ar.executing_at, ar.executed_at, ar.execute_as, ar.creator_kind,
       ar.statement_carries_protected_literal, ar.source, ar.scope, ar.change_key, ar.merged_at,
       ar.revision, ar.revised_at, ar.content_hash,
       ar.file_key, ar.path, ar.pr_url, ar.repository, ar.pr, ar.default_schema, ar.pr_auto_merge,
       ar.head_sha, ar.merge_sha, ar.approved_review_id, ar.filed_head, ar.key_order, ar.force_run, ar.force_run_by,
       (SELECT coalesce(array_agg(p.principal ORDER BY p.principal), '{}') FROM request_participant p
        WHERE p.request_id = ar.id AND p.kind = 'cc')::text[] AS ccs
FROM access_request ar LEFT JOIN app_role r ON r.id = ar.role_id
LEFT JOIN datasource d ON d.id = ar.datasource_id
WHERE ar.kind = 'QUERY' AND ar.creator_kind = 'WORKFLOW' AND ar.status = 'PENDING' ORDER BY ar.created_at DESC;

-- name: DecideQueryRequest :execrows
UPDATE access_request
SET status = @status::text, decided_by = @decided_by, decided_at = now(),
    approved_at = CASE WHEN @status::text = 'APPROVED' THEN now() END,
    rejection_reason = @rejection_reason, approved_review_id = NULL
WHERE id = @id AND kind = 'QUERY' AND revision = @revision
  AND (status = 'PENDING' OR (status = 'APPROVED' AND @status::text = 'REJECTED'));

-- name: ActiveResult :one
SELECT r.task_id, r.ordinal, r.sql, r.executed_by, r.executed_at, r.row_count, r.expires_at, r.status, r.error_code,
       r.deny_reason, r.decision_id, r.columns
FROM query_result r WHERE r.task_id = @task_id AND r.ordinal = COALESCE((SELECT MAX(q.ordinal) FROM query_result q
    WHERE q.task_id = @task_id AND q.status IS NOT NULL AND q.status <> 'SKIPPED'), 0);

-- name: ResultStatements :many
SELECT task_id, ordinal, sql, executed_by, executed_at, row_count, expires_at, status, error_code, deny_reason,
       decision_id, columns
FROM query_result WHERE task_id = $1 ORDER BY ordinal;

-- name: ReopenQueryRequest :execrows
UPDATE access_request SET status = 'PENDING', decided_by = NULL, decided_at = NULL, approved_at = NULL,
    approved_review_id = NULL
WHERE id = $1 AND kind = 'QUERY' AND status = 'APPROVED';
