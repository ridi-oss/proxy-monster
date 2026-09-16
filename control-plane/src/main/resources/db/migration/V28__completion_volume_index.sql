CREATE INDEX audit_event_completion_principal_ts ON audit_event (principal, ts) WHERE kind = 'completion';
