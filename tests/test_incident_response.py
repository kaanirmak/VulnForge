import time
import pytest

from vulnforge.auth import AuthSessions
from vulnforge.config import Config
from vulnforge.db import Store
from vulnforge.identity import Identities
from vulnforge.incident import IncidentManager
from vulnforge.vault import SecretVault

ORIGIN = "http://127.0.0.1:8000"


def test_killswitch_lifecycle(tmp_path):
    store = Store(str(tmp_path / "test.db"))
    im = IncidentManager()

    assert im.is_killswitch_active("auto_pr") is False

    # 1. Trigger killswitch
    rec = im.trigger_emergency_killswitch(
        store=store,
        component="auto_pr",
        reason="Security anomaly in auto-pr patch generation",
        operator_actor="secops_lead",
    )
    assert rec["component"] == "auto_pr"
    assert im.is_killswitch_active("auto_pr") is True

    # Check audit log
    with store.conn() as c:
        row = c.execute("SELECT * FROM audit_events WHERE action='emergency_killswitch_triggered'").fetchone()
        assert row is not None
        assert row["actor"] == "operator:secops_lead"
        assert row["repo"] == "system:auto_pr"

    # 2. Release killswitch
    released = im.release_killswitch(store, "auto_pr", "secops_lead")
    assert released is True
    assert im.is_killswitch_active("auto_pr") is False

    with store.conn() as c:
        rel_row = c.execute("SELECT * FROM audit_events WHERE action='emergency_killswitch_released'").fetchone()
        assert rel_row is not None


def test_revoke_compromised_sessions(tmp_path):
    store = Store(str(tmp_path / "test.db"))
    cfg = Config(
        database_path=str(tmp_path / "test.db"),
        admin_token="test-admin-token-1234567890123456",
        customer_api_preview=True,
        allow_insecure_local_auth=True,
        public_origin=ORIGIN,
        github_oauth_client_id="test-client-id",
        github_oauth_client_secret="test-client-secret",
    )
    identities = Identities(store)
    user = identities.record_github_user(777, "compromised-user")
    user_id = user["id"]

    sessions = AuthSessions(store, cfg)
    # Create 3 active sessions for this user
    sessions.create(user_id)
    sessions.create(user_id)
    sessions.create(user_id)

    with store.conn() as c:
        cnt = c.execute("SELECT COUNT(*) FROM user_sessions WHERE user_id=?", (user_id,)).fetchone()[0]
        assert cnt == 3

    # Revoke sessions via IncidentManager
    im = IncidentManager()
    revoked = im.revoke_compromised_sessions(
        store=store,
        user_id=user_id,
        reason="Suspected credential leak on public paste site",
        operator_actor="incident_commander",
    )
    assert revoked == 3

    # Verify database state
    with store.conn() as c:
        cnt_after = c.execute("SELECT COUNT(*) FROM user_sessions WHERE user_id=?", (user_id,)).fetchone()[0]
        assert cnt_after == 0

        audit_row = c.execute("SELECT * FROM audit_events WHERE action='compromised_sessions_revoked'").fetchone()
        assert audit_row is not None
        assert audit_row["actor"] == "operator:incident_commander"


def test_rotate_compromised_credential(tmp_path):
    store = Store(str(tmp_path / "test.db"))
    vault = SecretVault()
    vault.set_secret("WEBHOOK_SECRET", "old-secret-key-1234567890123456")

    im = IncidentManager()
    record = im.rotate_compromised_credential(
        vault=vault,
        store=store,
        secret_name="WEBHOOK_SECRET",
        new_value="new-rotated-super-secret-9876543210123456",
        operator_actor="secops_oncall",
    )
    assert record["secret_name"] == "WEBHOOK_SECRET"
    assert record["rotated_by"] == "secops_oncall"

    # Current secret in vault is new secret
    assert vault.get_secret("WEBHOOK_SECRET") == "new-rotated-super-secret-9876543210123456"

    # Audit event recorded
    with store.conn() as c:
        row = c.execute("SELECT * FROM audit_events WHERE action='compromised_credential_rotated'").fetchone()
        assert row is not None
        assert row["actor"] == "operator:secops_oncall"


def test_evaluate_incident_signals():
    im = IncidentManager()

    # Scenario 1: Clean state
    alerts_clean = im.evaluate_incident_signals(
        metrics={
            "freshness": {"advisory_freshness_age_seconds": 1200},
            "errors": {"resource_exhaustion_errors": 0, "timeout_errors": 0},
        },
        recent_prs_count=2,
        abuse_violations_count=1,
    )
    assert len(alerts_clean) == 0

    # Scenario 2: Intelligence feed outage + PR flood anomaly + Abuse violation
    alerts = im.evaluate_incident_signals(
        metrics={
            "freshness": {"advisory_freshness_age_seconds": 90000},  # > 24h
            "errors": {"resource_exhaustion_errors": 8, "timeout_errors": 12},
        },
        recent_prs_count=25,
        abuse_violations_count=20,
    )

    categories = {a.category for a in alerts}
    assert "feed_outage" in categories
    assert "pr_spam" in categories
    assert "resource_exhaustion" in categories
    assert "unauthorized_access" in categories
    assert any(a.severity == "SEV-1" for a in alerts)
