CREATE TABLE invitations (
 id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
 organization_id TEXT NOT NULL REFERENCES organizations(id), github_id INTEGER NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('org_admin','maintainer','analyst','viewer','auditor')),
 invited_by TEXT NOT NULL REFERENCES users(id), created_at REAL NOT NULL, expires_at REAL NOT NULL,
 accepted_at REAL, revoked_at REAL
);
CREATE INDEX invitations_org_idx ON invitations(organization_id,github_id);
