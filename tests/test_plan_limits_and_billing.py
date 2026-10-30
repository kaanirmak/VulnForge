"""Tests for plan limits, usage tracking, budget visibility, and billing lifecycle."""
import pytest
import time
from vulnforge.billing import (
    BillingManager,
    BillingPastDueError,
    PlanLimitExceededError,
    PlanTier,
    SubscriptionStatus,
)


def test_free_tier_limits_and_defaults():
    mgr = BillingManager()
    org_id = "org_free_test"

    sub = mgr.get_or_create_subscription(org_id)
    assert sub.tier == PlanTier.FREE
    assert sub.status == SubscriptionStatus.ACTIVE

    # Check defaults: 3 repos, 100 scans, 2 members
    mgr.check_repo_limit(org_id, 2)  # OK
    with pytest.raises(PlanLimitExceededError) as exc:
        mgr.check_repo_limit(org_id, 3)
    assert exc.value.resource == "repositories"

    mgr.check_member_limit(org_id, 1)  # OK
    with pytest.raises(PlanLimitExceededError) as exc:
        mgr.check_member_limit(org_id, 2)
    assert exc.value.resource == "members"

    for _ in range(99):
        mgr.record_scan_event(org_id, compute_seconds=10.0)
    mgr.check_scan_limit(org_id)  # OK: 99 < 100

    mgr.record_scan_event(org_id, compute_seconds=10.0)  # Now 100
    with pytest.raises(PlanLimitExceededError) as exc:
        mgr.check_scan_limit(org_id)
    assert exc.value.resource == "monthly_scans"


def test_upgrade_to_team_and_enterprise():
    mgr = BillingManager()
    org_id = "org_upgrade_test"

    # Initially Free
    sub = mgr.upgrade_plan(org_id, PlanTier.TEAM, customer_id="cus_123", subscription_id="sub_123")
    assert sub.tier == PlanTier.TEAM
    assert sub.customer_id == "cus_123"

    # Team allows up to 25 repos and 2500 scans
    mgr.check_repo_limit(org_id, 20)  # OK
    with pytest.raises(PlanLimitExceededError):
        mgr.check_repo_limit(org_id, 25)

    # Upgrade to Enterprise
    sub_ent = mgr.upgrade_plan(org_id, PlanTier.ENTERPRISE)
    assert sub_ent.tier == PlanTier.ENTERPRISE
    # Enterprise allows 10000 repos
    mgr.check_repo_limit(org_id, 500)  # OK


def test_budget_visibility_and_alerts():
    mgr = BillingManager()
    org_id = "org_budget_test"

    mgr.upgrade_plan(org_id, PlanTier.TEAM)
    mgr.sync_entity_counts(org_id, repos_count=20, members_count=10)

    # 1800 scans out of 2500 is 72%
    for _ in range(1800):
        mgr.record_scan_event(org_id, compute_seconds=6.0)

    summary = mgr.get_budget_summary(org_id)
    assert summary["tier"] == "team"
    assert summary["base_monthly_cost_usd"] == 199.0
    assert summary["usage"]["repos"]["current"] == 20
    assert summary["usage"]["monthly_scans"]["current"] == 1800
    assert summary["usage"]["compute_minutes"] == 180.0
    assert len(summary["alerts"]) == 0

    # Cross 75% threshold (1900 / 2500 = 76%)
    for _ in range(100):
        mgr.record_scan_event(org_id, compute_seconds=6.0)

    summary_warn = mgr.get_budget_summary(org_id)
    assert any("Warning: Scans at" in a for a in summary_warn["alerts"])

    # Cross 90% threshold (2300 / 2500 = 92%)
    for _ in range(400):
        mgr.record_scan_event(org_id, compute_seconds=6.0)

    summary_crit = mgr.get_budget_summary(org_id)
    assert any("Critical: Scans at" in a for a in summary_crit["alerts"])


def test_payment_failure_grace_period_and_recovery():
    mgr = BillingManager(grace_period_seconds=86400)  # 1 day grace period for test
    org_id = "org_grace_test"

    mgr.upgrade_plan(org_id, PlanTier.TEAM)
    now = time.time()

    # Payment fails
    mgr.handle_payment_failure(org_id, timestamp=now)
    sub = mgr.get_or_create_subscription(org_id)
    assert sub.status == SubscriptionStatus.PAST_DUE
    assert sub.payment_method_valid is False

    # Within grace period (+12 hours): should still allow operations
    mgr.check_subscription_health(org_id, now=now + 43200)

    # Past grace period (+25 hours): raises BillingPastDueError
    with pytest.raises(BillingPastDueError):
        mgr.check_subscription_health(org_id, now=now + 90000)

    with pytest.raises(BillingPastDueError):
        mgr.check_repo_limit(org_id, current_repos=1, now=now + 90000)

    # Payment succeeds (user updated card)
    mgr.handle_payment_success(org_id)
    sub_restored = mgr.get_or_create_subscription(org_id)
    assert sub_restored.status == SubscriptionStatus.ACTIVE
    assert sub_restored.payment_method_valid is True

    # Now operations are healthy again
    mgr.check_subscription_health(org_id, now=now + 90000)
