-- A result-cap rate counts one principal's relayed volume on one datasource.
DROP INDEX IF EXISTS audit_event_completion_principal_ts;
CREATE INDEX audit_event_completion_principal_datasource_ts ON audit_event (principal, datasource, ts) WHERE kind = 'completion';
