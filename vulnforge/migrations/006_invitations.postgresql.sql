CREATE TABLE invitations (
 id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
 organization_id TEXT NOT NULL REFERENCES organizations(id), github_id BIGINT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('org_admin','maintainer','analyst','viewer','auditor')),
 invited_by TEXT NOT NULL REFERENCES users(id), created_at DOUBLE PRECISION NOT NULL,
 expires_at DOUBLE PRECISION NOT NULL, accepted_at DOUBLE PRECISION, revoked_at DOUBLE PRECISION
);
CREATE INDEX invitations_org_idx ON invitations(organization_id,github_id);
ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations FORCE ROW LEVEL SECURITY;
CREATE POLICY vf_internal ON invitations FOR ALL USING (vf_security.is_internal()) WITH CHECK (vf_security.is_internal());
REVOKE ALL ON invitations FROM PUBLIC;
