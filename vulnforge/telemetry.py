"""End-to-end lifecycle trace correlation and operational telemetry metrics for VulnForge."""
from __future__ import annotations

import json
import statistics
import time
from typing import Any, Dict, List, Optional


class CorrelationTracer:
    """Tracks end-to-end correlation across Delivery -> Job -> Scan -> Finding -> PR."""

    def __init__(self, store: Any):
        self.store = store
        self._ensure_table()

    def _ensure_table(self) -> None:
        if getattr(self.store, "backend", "sqlite") == "sqlite":
            with self.store.conn() as c:
                c.execute("""
                CREATE TABLE IF NOT EXISTS correlation_traces (
                    correlation_id TEXT PRIMARY KEY,
                    delivery_id TEXT,
                    event_type TEXT NOT NULL,
                    repo TEXT NOT NULL,
                    job_id INTEGER,
                    scan_id TEXT,
                    finding_ids TEXT,
                    remediation_id INTEGER,
                    pr_number INTEGER,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    metadata TEXT NOT NULL
                )
                """)
                c.execute("CREATE INDEX IF NOT EXISTS idx_corr_repo ON correlation_traces(repo, updated_at DESC)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_corr_job ON correlation_traces(job_id)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_corr_delivery ON correlation_traces(delivery_id)")

    def start_trace(
        self,
        correlation_id: str,
        event_type: str,
        repo: str,
        *,
        delivery_id: Optional[str] = None,
        job_id: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Start a new lifecycle trace for an incoming event or scheduled task."""
        now = time.time()
        meta = json.dumps(metadata or {})
        try:
            with self.store.conn() as c:
                c.execute(
                    """
                    INSERT INTO correlation_traces (
                        correlation_id, delivery_id, event_type, repo, job_id,
                        finding_ids, status, created_at, updated_at, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (correlation_id, delivery_id, event_type, repo, job_id, "[]", "queued", now, now, meta),
                )
        except Exception:
            pass  # Table might be managed externally or restricted in certain RLS modes
        return self.get_trace(correlation_id) or {
            "correlation_id": correlation_id,
            "delivery_id": delivery_id,
            "event_type": event_type,
            "repo": repo,
            "job_id": job_id,
            "status": "queued",
            "created_at": now,
        }

    def update_trace(
        self,
        correlation_id: str,
        *,
        job_id: Optional[int] = None,
        scan_id: Optional[str] = None,
        finding_ids: Optional[List[int]] = None,
        remediation_id: Optional[int] = None,
        pr_number: Optional[int] = None,
        status: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Update correlation steps as the lifecycle progresses."""
        now = time.time()
        try:
            with self.store.conn() as c:
                existing = c.execute(
                    "SELECT metadata, finding_ids FROM correlation_traces WHERE correlation_id=?",
                    (correlation_id,),
                ).fetchone()
                if not existing:
                    return None

                old_meta = json.loads(existing[0]) if existing[0] else {}
                if metadata:
                    old_meta.update(metadata)

                old_findings = json.loads(existing[1]) if existing[1] else []
                if finding_ids:
                    combined_findings = list(set(old_findings + finding_ids))
                else:
                    combined_findings = old_findings

                query = "UPDATE correlation_traces SET updated_at=?"
                params: List[Any] = [now]

                if job_id is not None:
                    query += ", job_id=?"
                    params.append(job_id)
                if scan_id is not None:
                    query += ", scan_id=?"
                    params.append(scan_id)
                if combined_findings:
                    query += ", finding_ids=?"
                    params.append(json.dumps(combined_findings))
                if remediation_id is not None:
                    query += ", remediation_id=?"
                    params.append(remediation_id)
                if pr_number is not None:
                    query += ", pr_number=?"
                    params.append(pr_number)
                if status is not None:
                    query += ", status=?"
                    params.append(status)

                query += ", metadata=? WHERE correlation_id=?"
                params.extend([json.dumps(old_meta), correlation_id])

                c.execute(query, tuple(params))
        except Exception:
            pass

        return self.get_trace(correlation_id)

    def get_trace(self, correlation_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve the complete end-to-end trace by correlation ID."""
        try:
            with self.store.conn() as c:
                row = c.execute(
                    "SELECT * FROM correlation_traces WHERE correlation_id=?",
                    (correlation_id,),
                ).fetchone()
                if not row:
                    return None
                data = dict(row)
                data["finding_ids"] = json.loads(data["finding_ids"]) if data.get("finding_ids") else []
                data["metadata"] = json.loads(data["metadata"]) if data.get("metadata") else {}
                return data
        except Exception:
            return None


def collect_operational_metrics(store: Any) -> Dict[str, Any]:
    """Collect queue age, scan durations, resource errors, and data freshness metrics."""
    now = time.time()
    metrics: Dict[str, Any] = {
        "timestamp": now,
        "queue": {},
        "scans": {},
        "errors": {},
        "freshness": {},
    }

    with store.conn() as c:
        # 1. Queue Metrics
        jobs = c.execute("SELECT id, state, available_at, lease_until, last_error FROM jobs").fetchall()
        pending_jobs = [j for j in jobs if j["state"] == "pending"]
        running_jobs = [j for j in jobs if j["state"] == "running"]
        failed_jobs = [j for j in jobs if j["state"] == "failed"]

        queue_ages = [max(0.0, now - j["available_at"]) for j in pending_jobs if j["available_at"]]
        metrics["queue"] = {
            "pending_count": len(pending_jobs),
            "running_count": len(running_jobs),
            "failed_count": len(failed_jobs),
            "max_queue_age_seconds": round(max(queue_ages), 2) if queue_ages else 0.0,
            "avg_queue_age_seconds": round(statistics.mean(queue_ages), 2) if queue_ages else 0.0,
        }

        # 2. Scan Duration Metrics
        recent_scans = c.execute(
            "SELECT id, started_at, finished_at, state, coverage FROM scans WHERE started_at IS NOT NULL ORDER BY started_at DESC LIMIT 100"
        ).fetchall()
        completed_durations = [
            s["finished_at"] - s["started_at"]
            for s in recent_scans
            if s["finished_at"] and s["started_at"] and s["finished_at"] >= s["started_at"]
        ]
        metrics["scans"] = {
            "total_sampled": len(recent_scans),
            "completed_count": len(completed_durations),
            "avg_scan_duration_seconds": round(statistics.mean(completed_durations), 2) if completed_durations else 0.0,
            "p95_scan_duration_seconds": round(statistics.quantiles(completed_durations, n=20)[-1], 2) if len(completed_durations) >= 20 else (round(max(completed_durations), 2) if completed_durations else 0.0),
        }

        # 3. Resource & Scanner Errors (across both scans coverage and failed jobs)
        scan_errors = []
        for s in recent_scans:
            if s["state"] == "failed":
                cov = s["coverage"]
                err_text = ""
                if cov:
                    try:
                        parsed_cov = json.loads(cov) if isinstance(cov, str) else cov
                        err_text = str(parsed_cov.get("error") or parsed_cov.get("issues") or "")
                    except Exception:
                        err_text = str(cov)
                scan_errors.append(err_text)

        failed_job_errors = [str(j["last_error"] or "") for j in failed_jobs]
        all_errors = scan_errors + failed_job_errors

        timeout_errors = sum(1 for e in all_errors if any(k in e.lower() for k in ("timeout", "timed out", "time out")))
        resource_errors = sum(1 for e in all_errors if any(k in e.lower() for k in ("memory", "killed", "oom", "disk")))
        metrics["errors"] = {
            "total_failed_scans": len(scan_errors),
            "total_failed_jobs": len(failed_jobs),
            "timeout_errors": timeout_errors,
            "resource_exhaustion_errors": resource_errors,
        }

        # 4. Freshness Metrics
        repos = c.execute("SELECT full_name, default_branch, updated_at FROM repositories").fetchall()
        fresh_repos = 0
        stale_repos = 0
        for r in repos:
            latest_scan = c.execute(
                "SELECT finished_at FROM scans WHERE repo=? AND state='complete' ORDER BY finished_at DESC LIMIT 1",
                (r["full_name"],),
            ).fetchone()
            if latest_scan and latest_scan[0] and (now - latest_scan[0] < 86400):
                fresh_repos += 1
            else:
                stale_repos += 1

        # Ingestion freshness
        ingest_row = None
        try:
            ingest_row = c.execute("SELECT updated_at FROM advisory_ingestion_state ORDER BY updated_at DESC LIMIT 1").fetchone()
        except Exception:
            pass

        advisory_freshness_age = round(now - ingest_row[0], 2) if ingest_row and ingest_row[0] else None

        metrics["freshness"] = {
            "total_repositories": len(repos),
            "fresh_repositories_count": fresh_repos,
            "stale_repositories_count": stale_repos,
            "advisory_freshness_age_seconds": advisory_freshness_age,
        }

    return metrics
