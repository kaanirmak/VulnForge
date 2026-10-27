CREATE TABLE runner_policies (
 repo TEXT PRIMARY KEY REFERENCES repositories(full_name) ON DELETE CASCADE,
 connection_id TEXT NOT NULL, organization_id TEXT NOT NULL REFERENCES organizations(id),
 repository_id INTEGER NOT NULL UNIQUE, owner_id INTEGER NOT NULL,
 workflow_ref TEXT NOT NULL, ref TEXT NOT NULL, approved_by TEXT NOT NULL REFERENCES users(id),
 verified_at REAL NOT NULL, enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1))
);
CREATE TABLE runner_receipts (
 id TEXT PRIMARY KEY, repo TEXT NOT NULL REFERENCES repositories(full_name) ON DELETE CASCADE,
 connection_id TEXT NOT NULL, organization_id TEXT NOT NULL REFERENCES organizations(id),
 policy_digest TEXT NOT NULL, body_digest TEXT NOT NULL,
 commit_sha TEXT NOT NULL, scan_kind TEXT NOT NULL, report TEXT NOT NULL,
 workflow_ref TEXT NOT NULL, caller_workflow_ref TEXT NOT NULL, run_id TEXT NOT NULL,
 run_attempt TEXT NOT NULL, event_name TEXT NOT NULL, runner_environment TEXT NOT NULL,
 trust_state TEXT NOT NULL DEFAULT 'identity_verified_quarantined', received_at REAL NOT NULL,
 UNIQUE(connection_id,run_id,run_attempt,scan_kind)
);
CREATE INDEX runner_receipts_org_idx ON runner_receipts(organization_id,received_at);
CREATE TABLE runner_token_uses (
 jti_hash TEXT PRIMARY KEY, receipt_id TEXT NOT NULL REFERENCES runner_receipts(id) ON DELETE CASCADE,
 expires_at REAL NOT NULL
);
