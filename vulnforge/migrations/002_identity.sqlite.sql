CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, github_id INTEGER NOT NULL UNIQUE, login TEXT NOT NULL,
 created_at REAL NOT NULL, updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS organizations (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, created_by TEXT NOT NULL REFERENCES users(id),
 created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS memberships (
 organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id),
 role TEXT NOT NULL CHECK(role IN ('org_admin','maintainer','analyst','viewer','auditor')),
 created_at REAL NOT NULL, updated_at REAL NOT NULL,
 PRIMARY KEY(organization_id,user_id)
);
CREATE INDEX IF NOT EXISTS memberships_user_idx ON memberships(user_id,organization_id);
CREATE TABLE IF NOT EXISTS repository_ownership (
 repo TEXT PRIMARY KEY REFERENCES repositories(full_name) ON DELETE CASCADE,
 organization_id TEXT NOT NULL REFERENCES organizations(id),
 granted_by TEXT NOT NULL REFERENCES users(id), verification_reference TEXT NOT NULL,
 created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ownership_org_idx ON repository_ownership(organization_id,repo);
