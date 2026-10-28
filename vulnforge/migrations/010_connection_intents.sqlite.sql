CREATE TABLE connection_intents (
 state_hash TEXT PRIMARY KEY REFERENCES auth_states(state_hash) ON DELETE CASCADE,
 session_hash TEXT NOT NULL REFERENCES user_sessions(token_hash) ON DELETE CASCADE,
 organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 repo TEXT NOT NULL, expected_connection_id TEXT, consent_version TEXT NOT NULL,
 created_at REAL NOT NULL
);
