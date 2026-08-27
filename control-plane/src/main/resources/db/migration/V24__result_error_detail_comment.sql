-- The column's own DB comment (V23's file comment predates the per-viewer re-gate and is immutable once applied).
COMMENT ON COLUMN query_result.error_detail IS
    'Encrypted protobuf RunError — a failed run''s target-DB error in both forms (raw + value-free redacted), released per viewer at view time. NULL unless a target-DB statement failed.';
