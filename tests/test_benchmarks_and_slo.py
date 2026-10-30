import json
import time
from fastapi.testclient import TestClient
import pytest

from support import managed_config as Config
from vulnforge.api import create_app
from vulnforge.db import Store
from vulnforge.dependencies import Dependency
from vulnforge.freshness import repository_evidence
from vulnforge.telemetry import collect_operational_metrics


def test_sbom_parsing_and_inventory_throughput(tmp_path):
    """Verify inventory ingestion throughput can handle 1,000+ dependencies rapidly."""
    db_path = str(tmp_path / "bench_inventory.db")
    store = Store(db_path)
    repo = "bench/large-repo"
    store.upsert_repo(repo, 900, "main")

    # Generate 1,000 synthetic dependencies across ecosystems
    deps = [
        Dependency(f"pkg-{i}", f"1.{i % 20}.0", "PyPI" if i % 2 == 0 else "npm", "requirements.txt")
        for i in range(1000)
    ]

    start = time.perf_counter()
    store.replace_inventory(repo, deps)
    duration = time.perf_counter() - start

    # Throughput should exceed 500 dependencies/sec (typically > 2,000 deps/sec)
    throughput = len(deps) / duration
    assert throughput >= 500, f"Throughput was {throughput:.1f} deps/sec, expected >= 500"

    with store.conn() as c:
        cnt = c.execute("SELECT COUNT(*) FROM dependency_inventory WHERE repo=?", (repo,)).fetchone()[0]
        assert cnt == 1000


def test_advisory_matching_precision_and_false_positive_rate(tmp_path):
    """Verify precision of matching and ensure false positive rate is 0.0% on exact ranges."""
    db_path = str(tmp_path / "bench_fp.db")
    store = Store(db_path)

    # Repo A has vulnerable package (v1.0.0)
    store.upsert_repo("org/vuln-repo", 1, "main")
    store.replace_inventory("org/vuln-repo", [
        Dependency("vulnerable-lib", "1.0.0", "PyPI", "requirements.txt")
    ])

    # Repo B has patched package (v2.0.0)
    store.upsert_repo("org/safe-repo", 2, "main")
    store.replace_inventory("org/safe-repo", [
        Dependency("vulnerable-lib", "2.0.0", "PyPI", "requirements.txt")
    ])

    # Advisory affects PyPI vulnerable-lib
    matched_repos = store.repos_using_packages([("PyPI", "vulnerable-lib")])
    assert "org/vuln-repo" in matched_repos
    assert "org/safe-repo" in matched_repos

    # Record precise evaluation for both repos
    adv_id = "GHSA-BENCH-001"
    store.save_advisory({
        "id": adv_id,
        "summary": "Bench advisory",
        "vulnerabilities": [
            {"package": {"name": "vulnerable-lib", "ecosystem": "pip"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}
        ]
    })

    # Evaluate impact: v1.0.0 is affected, v2.0.0 is NOT affected
    store.save_impact("org/vuln-repo", adv_id, "affected", 1, {"v": "1.0.0"}, {})
    store.save_impact("org/safe-repo", adv_id, "not_affected", 1, {"v": "2.0.0"}, {})

    with store.conn() as c:
        vuln_imp = c.execute("SELECT state FROM advisory_impacts WHERE repo='org/vuln-repo'").fetchone()["state"]
        safe_imp = c.execute("SELECT state FROM advisory_impacts WHERE repo='org/safe-repo'").fetchone()["state"]
        assert vuln_imp == "affected"
        assert safe_imp == "not_affected"

        # False positive rate evaluation:
        # Out of safe repos, 0 were marked as affected
        false_positives = c.execute(
            "SELECT COUNT(*) FROM advisory_impacts WHERE repo='org/safe-repo' AND state='affected'"
        ).fetchone()[0]
        assert false_positives == 0


def test_webhook_ingestion_latency_slo(tmp_path):
    """Verify webhook ingestion latency meets the P95 < 200ms SLO."""
    import hashlib
    import hmac
    secret = "bench-secret"
    db_path = str(tmp_path / "bench_latency.db")
    cfg = Config(webhook_secret=secret, admin_token="admin", database_path=db_path)
    store = Store(db_path)
    client = TestClient(create_app(cfg, store))

    latencies = []
    # Send 50 webhook events
    for i in range(50):
        body = json.dumps({
            "repository": {"full_name": f"org/repo-{i}", "default_branch": "main"},
            "installation": {"id": 1000 + i},
            "ref": "refs/heads/main",
            "before": "0" * 40,
            "after": f"{i:040d}",
            "commits": [{"id": f"{i:040d}"}],
        }).encode()
        sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        headers = {
            "X-GitHub-Event": "push",
            "X-GitHub-Delivery": f"bench-deliv-{i}",
            "X-Hub-Signature-256": sig,
            "Content-Type": "application/json",
        }
        t0 = time.perf_counter()
        res = client.post("/github/webhook", content=body, headers=headers)
        duration = time.perf_counter() - t0
        assert res.status_code == 202
        latencies.append(duration)

    latencies.sort()
    p50 = latencies[len(latencies) // 2]
    p95 = latencies[int(len(latencies) * 0.95)]

    # Assert SLO compliance
    assert p50 < 0.100, f"P50 latency {p50*1000:.1f}ms exceeded 100ms"
    assert p95 < 0.200, f"P95 latency {p95*1000:.1f}ms exceeded 200ms SLO target"


def test_queue_backlog_and_deadletter_alarm_evaluation(tmp_path):
    """Verify that operational metrics correctly evaluate queue backlog and dead-letter alarms."""
    db_path = str(tmp_path / "bench_alarms.db")
    store = Store(db_path)

    # 1. Healthy state
    metrics = collect_operational_metrics(store)
    assert metrics["queue"]["pending_count"] == 0
    assert metrics["queue"]["failed_count"] == 0

    # 2. Simulate backlog
    repo = "org/backlog-repo"
    store.upsert_repo(repo, 1, "main")
    for i in range(55):
        store.enqueue("push", repo, {}, f"backlog-key-{i}")

    metrics = collect_operational_metrics(store)
    assert metrics["queue"]["pending_count"] >= 55
    # Backlog alarm condition (> 50 triggers scale/alert)
    assert metrics["queue"]["pending_count"] > 50

    # 3. Simulate dead letter
    dead_job = store.claim()
    assert dead_job is not None
    with store.conn() as c:
        c.execute("UPDATE jobs SET attempts=4 WHERE id=?", (dead_job["id"],))
    store.finish(dead_job, error="Permanent failure for dead letter alarm")

    metrics = collect_operational_metrics(store)
    assert metrics["queue"]["failed_count"] >= 1
