import time
from fastapi.testclient import TestClient
import pytest

from vulnforge.api import create_app
from vulnforge.auth import AuthSessions
from vulnforge.config import Config
from vulnforge.db import Store
from vulnforge.identity import Identities
from vulnforge.telemetry import CorrelationTracer, collect_operational_metrics

ORIGIN = "http://127.0.0.1:8000"


def test_correlation_tracer_end_to_end_lifecycle(tmp_path):
    store = Store(str(tmp_path / "test.db"))
    tracer = CorrelationTracer(store)

    correlation_id = "trace-cycle-12345"

    # 1. Webhook delivery starts trace
    trace = tracer.start_trace(
        correlation_id=correlation_id,
        event_type="push",
        repo="acme/web",
        delivery_id="deliv-987",
        job_id=42,
        metadata={"branch": "main", "sender": "alice"},
    )
    assert trace["correlation_id"] == correlation_id
    assert trace["delivery_id"] == "deliv-987"
    assert trace["event_type"] == "push"
    assert trace["repo"] == "acme/web"
    assert trace["job_id"] == 42
    assert trace["status"] == "queued"

    # 2. Worker executes job and starts scan
    tracer.update_trace(
        correlation_id=correlation_id,
        scan_id="scan-xyz-001",
        status="scanning",
    )

    # 3. Scan completes and produces findings
    tracer.update_trace(
        correlation_id=correlation_id,
        finding_ids=[101, 102],
        status="findings_detected",
    )

    # 4. Remediation creates a Draft PR
    updated = tracer.update_trace(
        correlation_id=correlation_id,
        remediation_id=55,
        pr_number=314,
        status="remediation_pr_published",
        metadata={"pr_url": "https://github.com/acme/web/pull/314"},
    )

    assert updated is not None
    assert updated["scan_id"] == "scan-xyz-001"
    assert set(updated["finding_ids"]) == {101, 102}
    assert updated["remediation_id"] == 55
    assert updated["pr_number"] == 314
    assert updated["status"] == "remediation_pr_published"
    assert updated["metadata"]["pr_url"] == "https://github.com/acme/web/pull/314"

    # Query back
    fetched = tracer.get_trace(correlation_id)
    assert fetched == updated


def test_collect_operational_metrics(tmp_path):
    store = Store(str(tmp_path / "test.db"))
    repo = "acme/backend"
    store.upsert_repo(repo, 1, "main")

    now = time.time()
    # 1. Enqueue jobs with past available_at to test queue age
    with store.conn() as c:
        c.execute(
            "INSERT INTO jobs (unique_key, repo, kind, payload, state, attempts, available_at, lease_until, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("key-pend-1", repo, "scan", "{}", "pending", 0, now - 120, None, now - 120),
        )
        c.execute(
            "INSERT INTO jobs (unique_key, repo, kind, payload, state, attempts, available_at, lease_until, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("key-run-1", repo, "scan", "{}", "running", 1, now - 60, now + 240, now - 60),
        )

        # 2. Add scan records to test durations and resource errors
        c.execute(
            "INSERT INTO scans (id, repo, kind, commit_sha, state, started_at, finished_at, coverage) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("s1", repo, "dependencies", "a" * 40, "complete", now - 50, now - 10, "{}"),
        )
        c.execute(
            "INSERT INTO scans (id, repo, kind, commit_sha, state, started_at, finished_at, coverage) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("s2", repo, "dependencies", "b" * 40, "failed", now - 30, now - 5, '{"error": "Memory limit exceeded (OOM killed)"}'),
        )
        c.execute(
            "INSERT INTO scans (id, repo, kind, commit_sha, state, started_at, finished_at, coverage) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("s3", repo, "dependencies", "c" * 40, "failed", now - 20, now - 2, '{"error": "Command timed out after 300s"}'),
        )

        # 3. Add ingestion state
        c.execute(
            "CREATE TABLE IF NOT EXISTS advisory_ingestion_state (source TEXT PRIMARY KEY, cursor TEXT, updated_at REAL, error TEXT)"
        )
        c.execute(
            "INSERT INTO advisory_ingestion_state (source, cursor, updated_at) VALUES (?, ?, ?)",
            ("ghsa", "cursor-1", now - 450),
        )

    metrics = collect_operational_metrics(store)

    assert metrics["queue"]["pending_count"] >= 1
    assert metrics["queue"]["running_count"] >= 1
    assert metrics["queue"]["max_queue_age_seconds"] >= 115

    assert metrics["scans"]["completed_count"] >= 1
    assert metrics["scans"]["avg_scan_duration_seconds"] > 0

    assert metrics["errors"]["total_failed_scans"] == 2
    assert metrics["errors"]["timeout_errors"] == 1
    assert metrics["errors"]["resource_exhaustion_errors"] == 1

    assert metrics["freshness"]["total_repositories"] >= 1
    assert metrics["freshness"]["fresh_repositories_count"] >= 1
    assert metrics["freshness"]["advisory_freshness_age_seconds"] >= 400


def test_telemetry_api_endpoints(tmp_path):
    db_path = str(tmp_path / "test.db")
    cfg = Config(
        database_path=db_path,
        admin_token="test-admin-token-1234567890123456",
        customer_api_preview=True,
        allow_insecure_local_auth=True,
        public_origin=ORIGIN,
        github_oauth_client_id="test-client-id",
        github_oauth_client_secret="test-client-secret",
    )
    store = Store(db_path)
    app = create_app(cfg=cfg, store=store)

    identity = Identities(store)
    owner = identity.record_github_user(401, "telemetry-owner")
    org = identity.create_organization(owner["id"], "Telemetry Org")
    org_id = org["id"]

    sessions = AuthSessions(store, cfg)
    token, csrf = sessions.create(owner["id"])

    client = TestClient(app, base_url=ORIGIN)
    client.cookies.set(sessions.cookie_prefix + "session", token)
    client.cookies.set(sessions.cookie_prefix + "csrf", csrf)

    # Start a trace
    tracer = CorrelationTracer(store)
    tracer.start_trace(
        correlation_id="trace-api-test-99",
        event_type="workflow_run",
        repo="telemetry-org/service",
        job_id=88,
    )

    # 1. Query Metrics API
    r_metrics = client.get(f"/api/v1/organizations/{org_id}/telemetry/metrics")
    assert r_metrics.status_code == 200
    m_data = r_metrics.json()
    assert "queue" in m_data
    assert "scans" in m_data
    assert "errors" in m_data
    assert "freshness" in m_data

    # 2. Query Trace API
    r_trace = client.get(f"/api/v1/organizations/{org_id}/telemetry/traces/trace-api-test-99")
    assert r_trace.status_code == 200
    t_data = r_trace.json()
    assert t_data["correlation_id"] == "trace-api-test-99"
    assert t_data["event_type"] == "workflow_run"
    assert t_data["job_id"] == 88

    # 3. Non-existent trace returns 404
    r_not_found = client.get(f"/api/v1/organizations/{org_id}/telemetry/traces/nonexistent")
    assert r_not_found.status_code == 404
