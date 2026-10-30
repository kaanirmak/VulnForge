"""Usage limits, plan tiers, budget visibility, and subscription billing for VulnForge."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class PlanTier(str, Enum):
    FREE = "free"
    TEAM = "team"
    ENTERPRISE = "enterprise"


class SubscriptionStatus(str, Enum):
    ACTIVE = "active"
    TRIALING = "trialing"
    PAST_DUE = "past_due"
    CANCELED = "canceled"


@dataclass(frozen=True)
class PlanDefinition:
    tier: PlanTier
    name: str
    price_cents_monthly: int
    max_repos: int
    max_monthly_scans: int
    max_members: int
    max_concurrency: int
    included_features: list[str]


PLAN_DEFINITIONS: dict[PlanTier, PlanDefinition] = {
    PlanTier.FREE: PlanDefinition(
        tier=PlanTier.FREE,
        name="Free Tier",
        price_cents_monthly=0,
        max_repos=3,
        max_monthly_scans=100,
        max_members=2,
        max_concurrency=1,
        included_features=["scans", "patch_plans", "basic_reporting"],
    ),
    PlanTier.TEAM: PlanDefinition(
        tier=PlanTier.TEAM,
        name="Team Tier",
        price_cents_monthly=19900,  # $199/month
        max_repos=25,
        max_monthly_scans=2500,
        max_members=15,
        max_concurrency=4,
        included_features=["scans", "patch_plans", "slack_notifications", "reachability", "automerge_pilot"],
    ),
    PlanTier.ENTERPRISE: PlanDefinition(
        tier=PlanTier.ENTERPRISE,
        name="Enterprise Tier",
        price_cents_monthly=99900,  # $999/month
        max_repos=10000,
        max_monthly_scans=100000,
        max_members=10000,
        max_concurrency=16,
        included_features=[
            "scans", "patch_plans", "slack_notifications", "reachability",
            "automerge_pilot", "enterprise_sso", "airgapped_onprem", "data_residency", "dedicated_audit"
        ],
    ),
}


class PlanLimitExceededError(Exception):
    """Raised when an organization exceeds its plan limits."""
    def __init__(self, resource: str, current: int, limit: int, message: str | None = None):
        msg = message or f"Plan limit reached for {resource}: current={current}, limit={limit}"
        super().__init__(msg)
        self.resource = resource
        self.current = current
        self.limit = limit


class BillingPastDueError(Exception):
    """Raised when an organization's subscription is past due and grace period has expired."""
    def __init__(self, org_id: str, message: str | None = None):
        msg = message or f"Organization {org_id} subscription is past due and grace period expired."
        super().__init__(msg)
        self.org_id = org_id


@dataclass
class OrganizationSubscription:
    org_id: str
    tier: PlanTier = PlanTier.FREE
    status: SubscriptionStatus = SubscriptionStatus.ACTIVE
    current_period_start: float = field(default_factory=time.time)
    current_period_end: float = field(default_factory=lambda: time.time() + 30 * 86400)
    customer_id: Optional[str] = None
    subscription_id: Optional[str] = None
    payment_method_valid: bool = True
    past_due_since: Optional[float] = None
    budget_limit_usd: Optional[float] = None
    hard_budget_cap: bool = False


@dataclass
class UsageMetrics:
    repos_count: int = 0
    scans_this_period: int = 0
    members_count: int = 0
    compute_minutes: float = 0.0
    llm_triage_calls: int = 0


class BillingManager:
    """Manages organization subscriptions, usage meters, budget visibility, and limit enforcement."""

    def __init__(self, grace_period_seconds: int = 7 * 86400):
        self._subscriptions: dict[str, OrganizationSubscription] = {}
        self._usage: dict[str, UsageMetrics] = {}
        self.grace_period_seconds = grace_period_seconds

    def get_or_create_subscription(self, org_id: str) -> OrganizationSubscription:
        if org_id not in self._subscriptions:
            self._subscriptions[org_id] = OrganizationSubscription(org_id=org_id)
        return self._subscriptions[org_id]

    def get_or_create_usage(self, org_id: str) -> UsageMetrics:
        if org_id not in self._usage:
            self._usage[org_id] = UsageMetrics()
        return self._usage[org_id]

    def upgrade_plan(
        self,
        org_id: str,
        target_tier: PlanTier,
        customer_id: str | None = None,
        subscription_id: str | None = None,
    ) -> OrganizationSubscription:
        sub = self.get_or_create_subscription(org_id)
        sub.tier = target_tier
        sub.status = SubscriptionStatus.ACTIVE
        sub.past_due_since = None
        sub.payment_method_valid = True
        if customer_id:
            sub.customer_id = customer_id
        if subscription_id:
            sub.subscription_id = subscription_id
        return sub

    def record_scan_event(self, org_id: str, compute_seconds: float = 12.0) -> None:
        usage = self.get_or_create_usage(org_id)
        usage.scans_this_period += 1
        usage.compute_minutes += compute_seconds / 60.0

    def record_llm_call(self, org_id: str) -> None:
        usage = self.get_or_create_usage(org_id)
        usage.llm_triage_calls += 1

    def sync_entity_counts(self, org_id: str, repos_count: int, members_count: int) -> None:
        usage = self.get_or_create_usage(org_id)
        usage.repos_count = repos_count
        usage.members_count = members_count

    def handle_payment_failure(self, org_id: str, timestamp: float | None = None) -> None:
        sub = self.get_or_create_subscription(org_id)
        sub.status = SubscriptionStatus.PAST_DUE
        sub.payment_method_valid = False
        sub.past_due_since = timestamp or time.time()

    def handle_payment_success(self, org_id: str) -> None:
        sub = self.get_or_create_subscription(org_id)
        sub.status = SubscriptionStatus.ACTIVE
        sub.payment_method_valid = True
        sub.past_due_since = None

    def check_subscription_health(self, org_id: str, now: float | None = None) -> None:
        sub = self.get_or_create_subscription(org_id)
        if sub.tier == PlanTier.FREE:
            return

        current_time = now or time.time()
        if sub.status == SubscriptionStatus.PAST_DUE:
            if sub.past_due_since and (current_time - sub.past_due_since) > self.grace_period_seconds:
                raise BillingPastDueError(org_id, f"Subscription past due for more than {self.grace_period_seconds // 86400} days grace period.")

        if sub.status == SubscriptionStatus.CANCELED:
            raise BillingPastDueError(org_id, "Subscription has been canceled.")

    def check_repo_limit(self, org_id: str, current_repos: int, now: float | None = None) -> None:
        self.check_subscription_health(org_id, now=now)
        sub = self.get_or_create_subscription(org_id)
        plan = PLAN_DEFINITIONS[sub.tier]
        if current_repos >= plan.max_repos:
            raise PlanLimitExceededError(
                resource="repositories",
                current=current_repos,
                limit=plan.max_repos,
                message=f"Repository limit reached ({current_repos}/{plan.max_repos}) on {plan.name}. Upgrade to add more repos.",
            )

    def check_scan_limit(self, org_id: str, now: float | None = None) -> None:
        self.check_subscription_health(org_id, now=now)
        sub = self.get_or_create_subscription(org_id)
        plan = PLAN_DEFINITIONS[sub.tier]
        usage = self.get_or_create_usage(org_id)
        if usage.scans_this_period >= plan.max_monthly_scans:
            raise PlanLimitExceededError(
                resource="monthly_scans",
                current=usage.scans_this_period,
                limit=plan.max_monthly_scans,
                message=f"Monthly scan limit reached ({usage.scans_this_period}/{plan.max_monthly_scans}) on {plan.name}.",
            )

    def check_member_limit(self, org_id: str, current_members: int, now: float | None = None) -> None:
        self.check_subscription_health(org_id, now=now)
        sub = self.get_or_create_subscription(org_id)
        plan = PLAN_DEFINITIONS[sub.tier]
        if current_members >= plan.max_members:
            raise PlanLimitExceededError(
                resource="members",
                current=current_members,
                limit=plan.max_members,
                message=f"Member seats limit reached ({current_members}/{plan.max_members}) on {plan.name}. Upgrade to invite more members.",
            )

    def get_budget_summary(self, org_id: str) -> dict[str, Any]:
        """Provides visibility into plan limits, usage, budget alerts, and estimated costs."""
        sub = self.get_or_create_subscription(org_id)
        plan = PLAN_DEFINITIONS[sub.tier]
        usage = self.get_or_create_usage(org_id)

        base_cost_usd = plan.price_cents_monthly / 100.0
        # Compute overage estimate if applicable
        scan_usage_pct = (usage.scans_this_period / plan.max_monthly_scans * 100.0) if plan.max_monthly_scans > 0 else 0.0
        repo_usage_pct = (usage.repos_count / plan.max_repos * 100.0) if plan.max_repos > 0 else 0.0

        alerts: list[str] = []
        if scan_usage_pct >= 90.0:
            alerts.append(f"Critical: Scans at {scan_usage_pct:.1f}% of monthly limit.")
        elif scan_usage_pct >= 75.0:
            alerts.append(f"Warning: Scans at {scan_usage_pct:.1f}% of monthly limit.")

        if repo_usage_pct >= 100.0:
            alerts.append("Repository limit reached.")

        if sub.status == SubscriptionStatus.PAST_DUE:
            alerts.append("Payment past due; please update billing method.")

        return {
            "org_id": org_id,
            "tier": sub.tier.value,
            "tier_name": plan.name,
            "status": sub.status.value,
            "base_monthly_cost_usd": base_cost_usd,
            "budget_limit_usd": sub.budget_limit_usd,
            "hard_budget_cap": sub.hard_budget_cap,
            "usage": {
                "repos": {"current": usage.repos_count, "limit": plan.max_repos, "pct": round(repo_usage_pct, 1)},
                "monthly_scans": {"current": usage.scans_this_period, "limit": plan.max_monthly_scans, "pct": round(scan_usage_pct, 1)},
                "members": {"current": usage.members_count, "limit": plan.max_members},
                "compute_minutes": round(usage.compute_minutes, 2),
                "llm_triage_calls": usage.llm_triage_calls,
            },
            "features": plan.included_features,
            "alerts": alerts,
        }
