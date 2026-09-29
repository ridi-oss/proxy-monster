-- Why a saved query result failed, beyond its error code.
--
-- A statement the policy refuses is not an error: it is a decision, and the console's response to it is to
-- offer an approval request built from that decision. Making that offer needs two facts the error code
-- alone cannot carry -- the human-readable reason the decision recorded, and the audit decision it was
-- recorded under, which is the identifier an approval request is opened against.
--
-- Both already exist on the decision the proxy round trip wrote; these columns carry them onto the result
-- child so the polling client that only ever sees this row can present the denial as a decision rather
-- than as a generic failure. NULL for every non-denial outcome.
ALTER TABLE query_result ADD COLUMN deny_reason TEXT;
ALTER TABLE query_result ADD COLUMN decision_id BIGINT REFERENCES audit_event(id) ON DELETE SET NULL;
