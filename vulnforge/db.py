"""SQLite-backed durable queue, repo inventory and findings store."""
import json
import sqlite3
import time
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS repositories (
 full_name TEXT PRIMARY KEY, installation_id INTEGER NOT NULL,
 default_branch TEXT NOT NULL, last_sha TEXT, next_scan_at REAL NOT NULL DEFAULT 0,
 updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS deliveries (
 delivery_id TEXT PRIMARY KEY, received_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, unique_key TEXT NOT NULL UNIQUE,
 kind TEXT NOT NULL, repo TEXT NOT NULL, payload TEXT NOT NULL,
 state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
 available_at REAL NOT NULL, lease_until REAL,
 last_error TEXT, created_at REAL NOT NULL, finished_at REAL
);
CREATE INDEX IF NOT EXISTS jobs_queue_idx ON jobs(state, available_at);
CREATE TABLE IF NOT EXISTS findings (
 id INTEGER PRIMARY KEY AUTOINCREMENT, repo TEXT NOT NULL,
 key TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL,
 title TEXT NOT NULL, file_path TEXT, commit_sha TEXT,
 details TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', detected_at REAL NOT NULL,
 UNIQUE(repo, key)
);
CREATE INDEX IF NOT EXISTS finding_repo_idx ON findings(repo, detected_at DESC);
CREATE TABLE IF NOT EXISTS dependency_inventory (
 repo TEXT NOT NULL, file_path TEXT NOT NULL, ecosystem TEXT NOT NULL,
 normalized_name TEXT NOT NULL, package_name TEXT NOT NULL,
 version TEXT NOT NULL, scanned_at REAL NOT NULL,
 PRIMARY KEY(repo,file_path,ecosystem,normalized_name,version)
);
CREATE INDEX IF NOT EXISTS dependency_lookup_idx ON dependency_inventory(ecosystem,normalized_name);

CREATE TABLE IF NOT EXISTS remediations (
 id INTEGER PRIMARY KEY AUTOINCREMENT, repo TEXT NOT NULL,
 key TEXT NOT NULL, url TEXT NOT NULL, created_at REAL NOT NULL,
 UNIQUE(repo, key)
);
"""


class Store:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.conn() as c:
            c.executescript(SCHEMA)

    def conn(self):
        c = sqlite3.connect(self.path, timeout=20, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA busy_timeout=20000")
        c.execute("PRAGMA journal_mode=WAL")
        return c

    def upsert_repo(self, name: str, installation_id: int, default_branch: str):
        now = time.time()
        with self.conn() as c:
            c.execute("""INSERT INTO repositories(full_name,installation_id,default_branch,updated_at)
                VALUES(?,?,?,?) ON CONFLICT(full_name) DO UPDATE SET
                installation_id=excluded.installation_id,
                default_branch=excluded.default_branch,updated_at=excluded.updated_at""",
                      (name, installation_id, default_branch, now))

    def remove_repo(self, name: str):
        # Clean security metadata when a GitHub App is uninstalled from a repo.
        with self.conn() as c:
            c.execute('BEGIN IMMEDIATE')
            for table in ('repositories','dependency_inventory'):
                c.execute(f"DELETE FROM {table} WHERE {'full_name' if table=='repositories' else 'repo'}=?",(name,))
            for table in ('jobs','findings','remediations'):
                c.execute(f"DELETE FROM {table} WHERE repo=?",(name,))
            c.execute('COMMIT')

    def add_delivery(self, delivery_id: str) -> bool:
        with self.conn() as c:
            result = c.execute("INSERT OR IGNORE INTO deliveries VALUES(?,?)", (delivery_id, time.time()))
            return result.rowcount == 1

    def enqueue(self, kind: str, repo: str, payload: dict, key: str, delay: float = 0) -> bool:
        now = time.time()
        with self.conn() as c:
            result = c.execute("""INSERT OR IGNORE INTO jobs
            (unique_key,kind,repo,payload,available_at,created_at) VALUES(?,?,?,?,?,?)""",
            (key,kind,repo,json.dumps(payload),now+delay,now))
            return result.rowcount == 1

    def claim(self):
        now = time.time()
        with self.conn() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("""SELECT * FROM jobs WHERE
                (state='pending' AND available_at<=?) OR
                (state='running' AND lease_until<?)
                ORDER BY id LIMIT 1""", (now, now)).fetchone()
            if row:
                c.execute("UPDATE jobs SET state='running', lease_until=?, attempts=attempts+1 WHERE id=?",
                          (now+300, row['id']))
            c.execute("COMMIT")
            return dict(row) if row else None

    def finish(self, job_id: int, error: str | None = None):
        with self.conn() as c:
            if error:
                attempts = c.execute("SELECT attempts FROM jobs WHERE id=?", (job_id,)).fetchone()[0]
                state = "failed" if attempts >= 4 else "pending"
                c.execute("UPDATE jobs SET state=?, last_error=?, available_at=?, lease_until=NULL WHERE id=?",
                          (state, error[:400], time.time()+min(300, 15*(2**attempts)), job_id))
            else:
                c.execute("UPDATE jobs SET state='done',finished_at=?,lease_until=NULL WHERE id=?",
                          (time.time(),job_id))

    def save_finding(self, repo: str, key: str, category: str, severity: str,
                     title: str, file_path: str | None, commit_sha: str | None, details: dict):
        with self.conn() as c:
            c.execute("""INSERT INTO findings(repo,key,category,severity,title,file_path,commit_sha,details,detected_at)
            VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(repo,key) DO UPDATE SET
            severity=excluded.severity,title=excluded.title,details=excluded.details,status='open',
            commit_sha=excluded.commit_sha,detected_at=excluded.detected_at""",
            (repo,key,category,severity,title,file_path,commit_sha,json.dumps(details),time.time()))

    def resolve_missing_dependencies(self, repo: str, seen_keys: set[str]):
        """Close findings no longer present after a *successful* complete audit."""
        with self.conn() as c:
            rows = c.execute("SELECT key FROM findings WHERE repo=? AND category='dependency' AND status='open'",
                             (repo,)).fetchall()
            for row in rows:
                if row['key'] not in seen_keys:
                    c.execute("UPDATE findings SET status='resolved' WHERE repo=? AND key=?",
                              (repo, row['key']))

    @staticmethod
    def normalize_package(name: str, eco: str) -> str:
        import re
        return re.sub(r'[-_.]+', '-', name).lower() if eco == 'PyPI' else name.lower()

    def replace_inventory(self, repo: str, dependencies):
        now = time.time()
        with self.conn() as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute("DELETE FROM dependency_inventory WHERE repo=?", (repo,))
            for dep in set(dependencies):
                c.execute("""INSERT OR IGNORE INTO dependency_inventory
                    (repo,file_path,ecosystem,normalized_name,package_name,version,scanned_at)
                    VALUES(?,?,?,?,?,?,?)""",
                    (repo,dep.file_path,dep.ecosystem,self.normalize_package(dep.name,dep.ecosystem),
                     dep.name,dep.version,now))
            c.execute("COMMIT")

    def repos_using_packages(self, packages: list[tuple[str, str]]) -> set[str]:
        """Match advisory package names to known dependency inventory, not vulnerable ranges."""
        matching = set()
        with self.conn() as c:
            for eco,name in packages[:150]:
                normalized=self.normalize_package(name,eco)
                rows=c.execute("""SELECT DISTINCT repo FROM dependency_inventory
                    WHERE ecosystem=? AND normalized_name=?""", (eco,normalized)).fetchall()
                matching.update(r['repo'] for r in rows)
        return matching

    def save_remediation(self, repo: str, key: str, url: str):
        with self.conn() as c:
            c.execute("INSERT OR IGNORE INTO remediations(repo,key,url,created_at) VALUES(?,?,?,?)",
                      (repo,key,url,time.time()))

    def has_remediation(self, repo: str, key: str) -> bool:
        with self.conn() as c:
            return c.execute("SELECT 1 FROM remediations WHERE repo=? AND key=?", (repo,key)).fetchone() is not None

    def list_rows(self, table: str, limit: int = 100, repo: str | None = None):
        if table not in ("repositories", "jobs", "findings", "remediations", "dependency_inventory"):
            raise ValueError("Invalid table")
        limit = max(1, min(200, limit))
        with self.conn() as c:
            if repo and table != "repositories":
                rows = c.execute(f"SELECT * FROM {table} WHERE repo=? ORDER BY 1 DESC LIMIT ?", (repo,limit))
            else:
                rows = c.execute(f"SELECT * FROM {table} ORDER BY 1 DESC LIMIT ?", (limit,))
            return [dict(r) for r in rows]

    def schedule_due(self, interval: int):
        now=time.time()
        with self.conn() as c:
            c.execute("BEGIN IMMEDIATE")
            rows = c.execute("SELECT * FROM repositories WHERE next_scan_at<=? LIMIT 100", (now,)).fetchall()
            for r in rows:
                c.execute("UPDATE repositories SET next_scan_at=? WHERE full_name=?", (now+interval, r['full_name']))
            c.execute("COMMIT")
        for r in rows:
            self.enqueue("dependency_audit", r['full_name'], {},
                         f"audit:{r['full_name']}:{int(now//interval)}")
        return len(rows)
