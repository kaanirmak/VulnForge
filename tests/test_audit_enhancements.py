from pathlib import Path
from fastapi.testclient import TestClient
import pytest

from vulnforge.api import create_app
from vulnforge.auth import AuthSessions
from vulnforge.config import Config
from vulnforge.db import Store
from vulnforge.identity import Identities
from vulnforge.audit import (
    audit_operator_access,
    mask_sensitive_audit_data,
    query_audit_events,
)

ORIGIN = "http://127.0.0.1:8000"


def test_mask_sensitive_audit_data():
    payload = {
        "user": "alice",
        "api_key": "secret123",
        "github_token": "ghp_1234567890abcdef1234567890",
        "nested": {
            "password": "supersecretpassword",
            "session_id": "sess_abcdef123456",
            "header": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "safe_field": "production-environment",
        },
        "raw_string": "Token is ghp_9876543210fedcba9876543210 and key is AKIA1234567890ABCDEF",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
    }

    masked = mask_sensitive_audit_data(payload)

    assert masked["user"] == "alice"
    assert masked["api_key"] == "***REDACTED***"
    assert masked["github_token"] == "***REDACTED***"
    assert masked["nested"]["password"] == "***REDACTED***"
    assert masked["nested"]["session_id"] == "***REDACTED***"
    assert masked["nested"]["safe_field"] == "production-environment"
    assert "Bearer ***REDACTED***" in masked["nested"]["header"]
    assert "gh_***REDACTED***" in masked["raw_string"]
    assert "AKIA***REDACTED***" in masked["raw_string"]
    assert masked["private_key"] == "***REDACTED***"


def test_audit_event_enrichment_and_redaction(tmp_path):
    store = Store(str(tmp_path / "test.db"))

    # Store.audit_event should automatically mask sensitive contents and enrich details
    store.audit_event(
        repo="octocat/Hello-World",
        finding_id=None,
        actor="dev-user",
        action="config_change",
        details={
            "token": "ghp_verysecrettoken123456789",
            "setting": "strict_mode",
        },
        organization_id="org_test_1",
        job_id="job_999",
        correlation_id="corr_abc_123",
        client_ip="192.168.1.100",
    )

    events = query_audit_events(store, organization_id="org_test_1", repo="octocat/Hello-World")
    assert len(events) >= 1
    ev = events[0]
    assert ev["actor"] == "dev-user"
    assert ev["action"] == "config_change"
    details = ev["details"]
    assert details["token"] == "***REDACTED***"
    assert details["setting"] == "strict_mode"
    assert details["organization_id"] == "org_test_1"
    assert details["job_id"] == "job_999"
    assert details["correlation_id"] == "corr_abc_123"
    assert details["client_ip"] == "192.168.1.100"


def test_operator_access_oversight(tmp_path):
    store = Store(str(tmp_path / "test.db"))

    # Operator access without justification MUST raise ValueError
    with pytest.raises(ValueError, match="Operator access requires a non-empty audit justification"):
        audit_operator_access(
            store=store,
            operator_actor="support_agent_01",
            organization_id="org_client_42",
            action="inspect_customer_findings",
            justification="",
        )

    # Operator access with ticket justification
    audit_operator_access(
        store=store,
        operator_actor="support_agent_01",
        organization_id="org_client_42",
        action="inspect_customer_findings",
        justification="INCIDENT-5012: Customer reported missed advisory",
        repo="octocat/private-repo",
        correlation_id="trace_op_987",
    )

    events = query_audit_events(store, organization_id="org_client_42")
    assert len(events) >= 1
    op_ev = events[0]
    assert op_ev["actor"] == "operator:support_agent_01"
    assert op_ev["action"] == "operator_access:inspect_customer_findings"
    assert op_ev["details"]["operator_justification"] == "INCIDENT-5012: Customer reported missed advisory"
    assert op_ev["details"]["operator_access"] is True
    assert op_ev["details"]["correlation_id"] == "trace_op_987"


def test_audit_api_filtering(tmp_path):
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
    owner = identity.record_github_user(201, "auditor-user")
    org = identity.create_organization(owner["id"], "Audit Co")
    org_id = org["id"]
    repo = "audit-co/core-repo"
    store.upsert_repo(repo, 101, "main")
    identity.record_repository_ownership(org_id, repo, owner["id"], "verified-fixture")

    sessions = AuthSessions(store, cfg)
    token, csrf = sessions.create(owner["id"])

    client = TestClient(app, base_url=ORIGIN)
    client.cookies.set(sessions.cookie_prefix + "session", token)
    client.cookies.set(sessions.cookie_prefix + "csrf", csrf)

    # Record some specific events
    store.audit_event(
        repo=repo,
        finding_id=None,
        actor=owner["id"],
        action="security_policy_updated",
        details={"mode": "enforcing"},
        organization_id=org_id,
        job_id="job_scan_44",
    )
    store.audit_event(
        repo=repo,
        finding_id=None,
        actor="system",
        action="background_sync",
        details={"status": "ok"},
        organization_id=org_id,
        job_id="job_sync_55",
    )

    # Query via API
    res = client.get(
        f"/api/v1/organizations/{org_id}/audit/events?actor={owner['id']}",
        headers={"x-csrf-token": csrf, "origin": ORIGIN},
    )
    assert res.status_code == 200
    data = res.json()
    assert any(item["action"] == "security_policy_updated" for item in data["items"])

    # Query with job_id filter
    res_job = client.get(
        f"/api/v1/organizations/{org_id}/audit/events?job_id=job_scan_44",
        headers={"x-csrf-token": csrf, "origin": ORIGIN},
    )
    assert res_job.status_code == 200
    job_items = res_job.json()["items"]
    assert len(job_items) == 1
    assert job_items[0]["details"]["job_id"] == "job_scan_44"
