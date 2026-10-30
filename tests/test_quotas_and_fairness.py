import time
from fastapi.testclient import TestClient
import pytest

from vulnforge.api import create_app
from vulnforge.auth import AuthSessions
from vulnforge.config import Config
from vulnforge.db import Store
from vulnforge.identity import Identities
from vulnforge.quotas import (
    TenantQuotaManager,
    QuotaExceededError,
    AbuseBlockedError,
)

ORIGIN = "http://127.0.0.1:8000"


def test_tenant_concurrency_and_fair_dispatch(tmp_path):
    store = Store(str(tmp_path / "test.db"))

    # Seed repos for Org A and Org B
    store.upsert_repo("org-a/repo1", 101, "main")
    store.upsert_repo("org-b/repo2", 102, "main")

    identities = Identities(store)
    u_a = identities.record_github_user(1, "user-a")
    u_b = identities.record_github_user(2, "user-b")

    org_a = identities.create_organization(u_a["id"], "Org A")["id"]
    org_b = identities.create_organization(u_b["id"], "Org B")["id"]

    identities.record_repository_ownership(org_a, "org-a/repo1", u_a["id"], "ev-a")
    identities.record_repository_ownership(org_b, "org-b/repo2", u_b["id"], "ev-b")

    # Enqueue 3 jobs for Org A, and 1 job for Org B
    j_a1 = store.enqueue("scan", "org-a/repo1", {"target": "1"}, "key-a1")
    j_a2 = store.enqueue("scan", "org-a/repo1", {"target": "2"}, "key-a2")
    j_a3 = store.enqueue("scan", "org-a/repo1", {"target": "3"}, "key-a3")
    j_b1 = store.enqueue("scan", "org-b/repo2", {"target": "1"}, "key-b1")

    # Claim with max_concurrency_per_org = 2
    claim_1 = store.claim(max_concurrency_per_org=2)
    assert claim_1 is not None
    assert claim_1["organization_id"] == org_a

    claim_2 = store.claim(max_concurrency_per_org=2)
    assert claim_2 is not None
    assert claim_2["organization_id"] == org_a

    # Org A now has 2 running jobs. Next claim MUST NOT be j_a3. It MUST be j_b1!
    claim_3 = store.claim(max_concurrency_per_org=2)
    assert claim_3 is not None
    assert claim_3["organization_id"] == org_b
    assert claim_3["repo"] == "org-b/repo2"

    # Now Org A is at 2, Org B is at 1 (let's say limit is 2).
    # Since only Org A has pending job j_a3, but Org A is at capacity (2), claim() returns None!
    claim_4 = store.claim(max_concurrency_per_org=2)
    assert claim_4 is None

    # Once one of Org A's jobs finishes:
    store.finish(claim_1)

    # Now Org A capacity is available again, so j_a3 can be claimed!
    claim_5 = store.claim(max_concurrency_per_org=2)
    assert claim_5 is not None
    assert claim_5["organization_id"] == org_a
    import json
    assert json.loads(claim_5["payload"]) == {"target": "3"}


def test_tenant_api_and_scan_quotas():
    qm = TenantQuotaManager(default_daily_scans=2, default_hourly_api=3)

    # Consume API quota
    qm.check_and_consume_api_quota("tenant_xyz")
    qm.check_and_consume_api_quota("tenant_xyz")
    qm.check_and_consume_api_quota("tenant_xyz")

    with pytest.raises(QuotaExceededError, match="Hourly API quota of 3 requests exceeded"):
        qm.check_and_consume_api_quota("tenant_xyz")

    # Consume Scan quota
    qm.check_and_consume_scan_quota("tenant_xyz")
    qm.check_and_consume_scan_quota("tenant_xyz")

    with pytest.raises(QuotaExceededError, match="Daily scan quota of 2 scans exceeded"):
        qm.check_and_consume_scan_quota("tenant_xyz")


def test_abuse_protection_and_rate_limiting(tmp_path):
    qm = TenantQuotaManager(abuse_threshold=3, abuse_block_duration=60)
    identifier = "abusive-actor"

    qm.record_abuse_violation(identifier)
    assert qm.is_abuse_blocked(identifier)[0] is False

    qm.record_abuse_violation(identifier)
    assert qm.is_abuse_blocked(identifier)[0] is False

    qm.record_abuse_violation(identifier)
    # Threshold reached -> blocked
    is_blocked, remaining = qm.is_abuse_blocked(identifier)
    assert is_blocked is True
    assert remaining > 0

    with pytest.raises(AbuseBlockedError, match="Tenant is temporarily blocked due to abusive traffic"):
        qm.check_and_consume_api_quota(identifier)


def test_api_quota_integration_endpoint(tmp_path):
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

    # Configure a tiny quota manager on app.state
    qm = TenantQuotaManager(default_hourly_api=2)
    app.state.quota_manager = qm

    identity = Identities(store)
    owner = identity.record_github_user(301, "quota-owner")
    org = identity.create_organization(owner["id"], "Quota Org")
    org_id = org["id"]

    sessions = AuthSessions(store, cfg)
    token, csrf = sessions.create(owner["id"])

    client = TestClient(app, base_url=ORIGIN)
    client.cookies.set(sessions.cookie_prefix + "session", token)
    client.cookies.set(sessions.cookie_prefix + "csrf", csrf)

    # Request 1: OK
    r1 = client.get(f"/api/v1/organizations/{org_id}/repositories")
    assert r1.status_code == 200

    # Request 2: OK
    r2 = client.get(f"/api/v1/organizations/{org_id}/repositories")
    assert r2.status_code == 200

    # Request 3: 429 Too Many Requests
    r3 = client.get(f"/api/v1/organizations/{org_id}/repositories")
    assert r3.status_code == 429
    assert "Retry-After" in r3.headers
    assert r3.json()["error_code"] == "TOO_MANY_REQUESTS"
