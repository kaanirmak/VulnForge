CREATE TABLE connection_intents (
 state_hash TEXT PRIMARY KEY REFERENCES auth_states(state_hash) ON DELETE CASCADE,
 session_hash TEXT NOT NULL REFERENCES user_sessions(token_hash) ON DELETE CASCADE,
 organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 repo TEXT NOT NULL, expected_connection_id TEXT, consent_version TEXT NOT NULL,
 created_at DOUBLE PRECISION NOT NULL
);
ALTER TABLE connection_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE connection_intents FORCE ROW LEVEL SECURITY;
CREATE POLICY vf_internal ON connection_intents FOR ALL USING (vf_security.is_internal()) WITH CHECK (vf_security.is_internal());
REVOKE ALL ON connection_intents FROM PUBLIC;
