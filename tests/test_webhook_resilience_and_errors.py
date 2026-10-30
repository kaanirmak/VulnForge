import hashlib
import hmac
import json
import time
import uuid
from fastapi.testclient import TestClient
import pytest

from support import managed_config as Config
from vulnforge.api import create_app
from vulnforge.db import StaleJob, Store
from vulnforge.network import IngressRateLimiter, SecurityHeadersMiddleware


def make_signed_headers(event: str, body: bytes, secret: str = "test-resilience-secret", delivery: str | None = None):
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return {
        "X-GitHub-Event": event,
        "X-GitHub-Delivery": delivery or str(uuid.uuid4()),
        "X-Hub-Signature-256": sig,
        "Content-Type": "application/json",
    }


def test_webhook_redelivery_deduplication(tmp_path):
    """Verify that webhook redeliveries do not result in duplicate processing or jobs."""
    db_path = str(tmp_path / "redeliv.db")
    secret = "test-resilience-secret"
    cfg = Config(webhook_secret=secret, admin_token="test-admin", database_path=db_path)
    store = Store(db_path)
    client = TestClient(create_app(cfg, store))

    delivery_id = "deliv-guid-12345"
    payload = {
        "repository": {"full_name": "org/repo-resilience", "default_branch": "main"},
        "installation": {"id": 100},
        "ref": "refs/heads/main",
        "before": "0" * 40,
        "after": "1" * 40,
        "commits": [{"id": "1" * 40}],
    }
    body = json.dumps(payload).encode()
    headers = make_signed_headers("push", body, secret=secret, delivery=delivery_id)

    # First delivery
    res1 = client.post("/github/webhook", content=body, headers=headers)
    assert res1.status_code == 202
    assert res1.json().get("accepted") is True
    assert res1.json().get("duplicate") is None

    with store.conn() as c:
        assert c.execute("SELECT COUNT(*) FROM jobs WHERE repo='org/repo-resilience'").fetchone()[0] == 1

    # Second delivery (exact redelivery)
    res2 = client.post("/github/webhook", content=body, headers=headers)
    assert res2.status_code == 202
    assert res2.json().get("accepted") is True
    assert res2.json().get("duplicate") is True

    # No additional job should have been created
    with store.conn() as c:
        assert c.execute("SELECT COUNT(*) FROM jobs WHERE repo='org/repo-resilience'").fetchone()[0] == 1


def test_webhook_force_push_handling(tmp_path):
    """Verify that force-push events correctly record forced flag and audit trail."""
    db_path = str(tmp_path / "force_push.db")
    secret = "test-resilience-secret"
    cfg = Config(webhook_secret=secret, admin_token="test-admin", database_path=db_path)
    store = Store(db_path)
    client = TestClient(create_app(cfg, store))

    payload = {
        "repository": {"full_name": "org/force-repo", "default_branch": "main"},
        "installation": {"id": 101},
        "ref": "refs/heads/main",
        "before": "a" * 40,
        "after": "b" * 40,
        "commits": [{"id": "b" * 40}],
        "forced": True,
    }
    body = json.dumps(payload).encode()
    headers = make_signed_headers("push", body, secret=secret)

    res = client.post("/github/webhook", content=body, headers=headers)
    assert res.status_code == 202
    assert res.json().get("accepted") is True

    with store.conn() as c:
        job = c.execute("SELECT * FROM jobs WHERE repo='org/force-repo'").fetchone()
        assert job is not None
        job_payload = json.loads(job["payload"])
        assert job_payload.get("forced") is True

        audit = c.execute(
            "SELECT * FROM audit_events WHERE repo='org/force-repo' AND action='default_branch_push_observed'"
        ).fetchone()
        assert audit is not None
        meta = json.loads(audit["details"])
        assert meta.get("forced") is True


def test_webhook_branch_deletion_skips_scans(tmp_path):
    """Verify that branch deletion does not schedule scan jobs and logs audit event."""
    db_path = str(tmp_path / "branch_del.db")
    secret = "test-resilience-secret"
    cfg = Config(webhook_secret=secret, admin_token="test-admin", database_path=db_path)
    store = Store(db_path)
    client = TestClient(create_app(cfg, store))

    # 1. Feature branch deletion
    payload_feature = {
        "repository": {"full_name": "org/branch-repo", "default_branch": "main"},
        "installation": {"id": 102},
        "ref": "refs/heads/feature-x",
        "before": "c" * 40,
        "after": "0" * 40,
        "deleted": True,
        "commits": [],
    }
    body_feat = json.dumps(payload_feature).encode()
    headers_feat = make_signed_headers("push", body_feat, secret=secret)
    res_feat = client.post("/github/webhook", content=body_feat, headers=headers_feat)
    assert res_feat.status_code == 202

    # 2. Default branch deletion
    payload_main = {
        "repository": {"full_name": "org/branch-repo", "default_branch": "main"},
        "installation": {"id": 102},
        "ref": "refs/heads/main",
        "before": "d" * 40,
        "after": "0" * 40,
        "deleted": True,
        "commits": [],
    }
    body_main = json.dumps(payload_main).encode()
    headers_main = make_signed_headers("push", body_main, secret=secret)
    res_main = client.post("/github/webhook", content=body_main, headers=headers_main)
    assert res_main.status_code == 202

    with store.conn() as c:
        # Zero jobs queued because deleted branches do not trigger push scans
        assert c.execute("SELECT COUNT(*) FROM jobs WHERE repo='org/branch-repo'").fetchone()[0] == 0

        # Audit events recorded for both
        feat_audit = c.execute(
            "SELECT * FROM audit_events WHERE repo='org/branch-repo' AND action='branch_deleted_observed'"
        ).fetchone()
        assert feat_audit is not None

        main_audit = c.execute(
            "SELECT * FROM audit_events WHERE repo='org/branch-repo' AND action='default_branch_deleted_observed'"
        ).fetchone()
        assert main_audit is not None


def test_ingress_rate_limiting_and_retry_after(tmp_path):
    """Verify rate limiter blocks burst traffic with HTTP 429 and Retry-After header."""
    db_path = str(tmp_path / "rate_limit.db")
    cfg = Config(admin_token="test-admin", database_path=db_path)
    store = Store(db_path)
    app = create_app(cfg, store)

    # Use a small limit for test
    limiter = IngressRateLimiter(limit=3, window_seconds=10.0)
    app.add_middleware(SecurityHeadersMiddleware, cfg=cfg, rate_limiter=limiter)
    client = TestClient(app)

    # 3 allowed requests
    for _ in range(3):
        r = client.get("/health")
        assert r.status_code == 200

    # 4th request must be rate limited
    blocked_r = client.get("/health")
    assert blocked_r.status_code == 429
    assert blocked_r.headers.get("Retry-After") is not None
    assert blocked_r.headers.get("X-RateLimit-Remaining") == "0"
    data = blocked_r.json()
    assert data.get("error_code") == "RATE_LIMIT_EXCEEDED"


def test_job_crash_stale_lease_recovery_and_dead_letter(tmp_path):
    """Verify worker crash recovery via lease expiration, retry backoff, and dead-letter routing."""
    db_path = str(tmp_path / "jobs.db")
    store = Store(db_path)
    repo = "org/crash-repo"
    store.upsert_repo(repo, 200, "main")

    # Enqueue a job
    job_id = store.enqueue("push", repo, {"test": "data"}, "unique-key-crash-1")
    assert job_id > 0

    # Worker 1 claims the job
    worker1_job = store.claim()
    assert worker1_job is not None
    assert worker1_job["id"] == job_id
    assert worker1_job["attempts"] == 1

    # Simulate worker 1 crashing and lease expiring
    with store.conn() as c:
        c.execute("UPDATE jobs SET lease_until=? WHERE id=?", (time.time() - 10, job_id))

    # Worker 2 claims the expired job
    worker2_job = store.claim()
    assert worker2_job is not None
    assert worker2_job["id"] == job_id
    assert worker2_job["attempts"] == 2

    # Fail job repeatedly until max attempts (4)
    store.finish(worker2_job, error="Crash simulation attempt 2")

    # Advance time for backoff
    with store.conn() as c:
        c.execute("UPDATE jobs SET available_at=? WHERE id=?", (time.time() - 1, job_id))

    worker3_job = store.claim()
    assert worker3_job["attempts"] == 3
    store.finish(worker3_job, error="Crash simulation attempt 3")

    with store.conn() as c:
        c.execute("UPDATE jobs SET available_at=? WHERE id=?", (time.time() - 1, job_id))

    worker4_job = store.claim()
    assert worker4_job["attempts"] == 4
    # On 4th failed attempt, store marks it as 'failed' (dead letter)
    store.finish(worker4_job, error="Crash simulation final failure")

    with store.conn() as c:
        job_state = c.execute("SELECT state FROM jobs WHERE id=?", (job_id,)).fetchone()[0]
        assert job_state == "failed"

    # Verify dead letter listing
    dead = store.dead_letters()
    assert any(d["id"] == job_id for d in dead)

    # Operator retries dead letter
    res = store.retry_dead_letter(job_id)
    assert res is not None
    assert res["retried_job_id"] == job_id

    # Retried job can be claimed again
    new_claim = store.claim()
    assert new_claim is not None
    assert new_claim["repo"] == repo


def test_job_discard_and_cancellation(tmp_path):
    """Verify that discarded or cancelled jobs cannot be updated by stale workers."""
    db_path = str(tmp_path / "cancel.db")
    store = Store(db_path)
    repo = "org/cancel-repo"
    store.upsert_repo(repo, 300, "main")

    job_id = store.enqueue("push", repo, {"test": "data"}, "unique-key-cancel-1")
    job = store.claim()
    assert job is not None

    # Discard / cancel job
    store.discard_job(job)

    with store.conn() as c:
        row = c.execute("SELECT state, last_error FROM jobs WHERE id=?", (job_id,)).fetchone()
        assert row["state"] == "cancelled"
        assert "expired" in row["last_error"]

    # Trying to renew the discarded job must raise StaleJob
    with pytest.raises(StaleJob):
        store.renew_job(job)
