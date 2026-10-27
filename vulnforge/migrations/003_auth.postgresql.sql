CREATE TABLE IF NOT EXISTS auth_states (
 state_hash TEXT PRIMARY KEY, browser_hash TEXT NOT NULL, expires_at DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_states_expiry_idx ON auth_states(expires_at);
CREATE TABLE IF NOT EXISTS user_sessions (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 csrf_hash TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL, expires_at DOUBLE PRECISION NOT NULL,
 last_seen_at DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON user_sessions(expires_at);
