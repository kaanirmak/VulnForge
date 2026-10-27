CREATE TABLE remediation_policies (
 repo TEXT PRIMARY KEY REFERENCES repositories(full_name) ON DELETE CASCADE,
 connection_id TEXT NOT NULL, organization_id TEXT NOT NULL REFERENCES organizations(id),
 approved_by TEXT NOT NULL REFERENCES users(id), enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
 allowed_packages TEXT NOT NULL, allowed_files TEXT NOT NULL, updated_at REAL NOT NULL
);
