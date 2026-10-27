CREATE TABLE IF NOT EXISTS runner_reports (
 id TEXT PRIMARY KEY, repo TEXT NOT NULL, commit_sha TEXT NOT NULL,
 report TEXT NOT NULL, trust_state TEXT NOT NULL DEFAULT 'quarantined', received_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS advisories (
 id TEXT PRIMARY KEY, aliases TEXT NOT NULL, summary TEXT NOT NULL,
 source TEXT NOT NULL, data TEXT NOT NULL, source_sha256 TEXT NOT NULL,
 withdrawn BIGINT NOT NULL DEFAULT 0, first_seen_at DOUBLE PRECISION NOT NULL, updated_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS advisory_aliases (
 alias TEXT NOT NULL, advisory_id TEXT NOT NULL, PRIMARY KEY(alias, advisory_id)
);
CREATE TABLE IF NOT EXISTS advisory_impacts (
 id BIGSERIAL PRIMARY KEY, repo TEXT NOT NULL, advisory_id TEXT NOT NULL,
 state TEXT NOT NULL, scan_id TEXT, evidence TEXT NOT NULL, recommendations TEXT NOT NULL,
 updated_at DOUBLE PRECISION NOT NULL, UNIQUE(repo, advisory_id)
);
CREATE INDEX IF NOT EXISTS impacts_lookup_idx ON advisory_impacts(advisory_id, state, repo);
CREATE TABLE IF NOT EXISTS scans (
 id TEXT PRIMARY KEY, repo TEXT NOT NULL, kind TEXT NOT NULL, commit_sha TEXT,
 state TEXT NOT NULL, coverage TEXT NOT NULL DEFAULT '{}', dependencies TEXT NOT NULL DEFAULT '[]',
 started_at DOUBLE PRECISION NOT NULL, finished_at DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS scans_repo_idx ON scans(repo, started_at DESC);
CREATE TABLE IF NOT EXISTS scan_findings (
 scan_id TEXT NOT NULL, finding_key TEXT NOT NULL, data TEXT NOT NULL,
 PRIMARY KEY(scan_id, finding_key)
);
CREATE TABLE IF NOT EXISTS audit_events (
 id BIGSERIAL PRIMARY KEY, repo TEXT NOT NULL, finding_id BIGINT,
 actor TEXT NOT NULL, action TEXT NOT NULL, details TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_repo_idx ON audit_events(repo, id DESC);
CREATE TABLE IF NOT EXISTS suppressions (
 finding_id BIGINT PRIMARY KEY, reason TEXT NOT NULL, expires_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS repositories (
 full_name TEXT PRIMARY KEY, installation_id BIGINT NOT NULL,
 default_branch TEXT NOT NULL, last_sha TEXT, next_scan_at DOUBLE PRECISION NOT NULL DEFAULT 0,
 updated_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS deliveries (
 delivery_id TEXT PRIMARY KEY, received_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
 id BIGSERIAL PRIMARY KEY, unique_key TEXT NOT NULL UNIQUE,
 kind TEXT NOT NULL, repo TEXT NOT NULL, payload TEXT NOT NULL,
 state TEXT NOT NULL DEFAULT 'pending', attempts BIGINT NOT NULL DEFAULT 0,
 available_at DOUBLE PRECISION NOT NULL, lease_until DOUBLE PRECISION,
 last_error TEXT, created_at DOUBLE PRECISION NOT NULL, finished_at DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS jobs_queue_idx ON jobs(state, available_at);
CREATE TABLE IF NOT EXISTS findings (
 id BIGSERIAL PRIMARY KEY, repo TEXT NOT NULL,
 key TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL,
 title TEXT NOT NULL, file_path TEXT, commit_sha TEXT,
 details TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', detected_at DOUBLE PRECISION NOT NULL,
 UNIQUE(repo, key)
);
CREATE INDEX IF NOT EXISTS finding_repo_idx ON findings(repo, detected_at DESC);
CREATE TABLE IF NOT EXISTS dependency_inventory (
 repo TEXT NOT NULL, file_path TEXT NOT NULL, ecosystem TEXT NOT NULL,
 normalized_name TEXT NOT NULL, package_name TEXT NOT NULL,
 version TEXT NOT NULL, scanned_at DOUBLE PRECISION NOT NULL,
 PRIMARY KEY(repo,file_path,ecosystem,normalized_name,version)
);
CREATE INDEX IF NOT EXISTS dependency_lookup_idx ON dependency_inventory(ecosystem,normalized_name);

CREATE TABLE IF NOT EXISTS remediations (
 id BIGSERIAL PRIMARY KEY, repo TEXT NOT NULL,
 key TEXT NOT NULL, url TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL,
 UNIQUE(repo, key)
);
