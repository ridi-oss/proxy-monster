-- The ResultRequirements (controlplane.proto) a DONE or FAILED result's view is decided from: names only, so not encrypted.
ALTER TABLE query_result ADD COLUMN requirements BYTEA;
