-- name: DecisionEvent :one
SELECT principal, datasource, statement, decision, channel FROM audit_event WHERE id = $1;

-- name: WireTaskOfDecision :one
SELECT id FROM access_request WHERE kind = 'QUERY' AND creator_kind = 'WIRE' AND source_decision_id = $1;

-- name: ClaimWireTask :execrows
UPDATE access_request SET status = 'EXECUTING', executing_at = $1
WHERE id = $2 AND kind = 'QUERY' AND status = 'APPROVED';

-- name: SettleWireTaskExecuted :execrows
UPDATE access_request SET status = 'EXECUTED', executed_at = $1
WHERE id = $2 AND kind = 'QUERY' AND status = 'EXECUTING';

-- name: SettleWireTaskFailed :execrows
UPDATE access_request SET status = 'FAILED' WHERE id = $1 AND kind = 'QUERY' AND status = 'EXECUTING';
