CREATE TABLE remediation_policies (
 repo TEXT PRIMARY KEY REFERENCES repositories(full_name) ON DELETE CASCADE,
 connection_id TEXT NOT NULL, organization_id TEXT NOT NULL REFERENCES organizations(id),
 approved_by TEXT NOT NULL REFERENCES users(id), enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
 allowed_packages TEXT NOT NULL, allowed_files TEXT NOT NULL, updated_at DOUBLE PRECISION NOT NULL
);
ALTER TABLE remediation_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY vf_internal ON remediation_policies FOR ALL USING (vf_security.is_internal()) WITH CHECK (vf_security.is_internal());
REVOKE ALL ON remediation_policies FROM PUBLIC;
