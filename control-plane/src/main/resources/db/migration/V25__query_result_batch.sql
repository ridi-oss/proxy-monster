-- One query_result child per statement of a batch, addressed by position rather than by
-- `ORDER BY id DESC LIMIT 1` (correct only while a task holds one child).
ALTER TABLE query_result ADD COLUMN ordinal INT NOT NULL DEFAULT 0;

-- Numbered by insert order, not a constant 0: query_result is 1:N in schema, so a task that does hold
-- two rows would collide on the index below and abort the migration.
UPDATE query_result qr
   SET ordinal = ranked.position
  FROM (
        SELECT id, row_number() OVER (PARTITION BY task_id ORDER BY id) - 1 AS position
          FROM query_result
       ) AS ranked
 WHERE qr.id = ranked.id;

-- A duplicate would make "the statement at position k" ambiguous — run one twice, or skip one.
CREATE UNIQUE INDEX uq_query_result_task_ordinal ON query_result (task_id, ordinal);

-- The batch runs one statement at a time. Two RUNNING children would let completeRun store a result
-- against the wrong statement's SQL, so the database refuses the second rather than trusting callers.
CREATE UNIQUE INDEX uq_query_result_one_running ON query_result (task_id) WHERE status = 'RUNNING';

-- SKIPPED: never reached, because an earlier statement stopped the batch. Distinct from the NULL status
-- that means "not started yet".
ALTER TABLE query_result DROP CONSTRAINT query_result_status_check;
ALTER TABLE query_result ADD CONSTRAINT query_result_status_check
    CHECK (status IN ('RUNNING', 'DONE', 'FAILED', 'CANCELLED', 'SKIPPED'));

COMMENT ON COLUMN query_result.ordinal IS
    'The statement''s 0-based position in its task''s batch. Dense, fixed at creation, unique per task.';
