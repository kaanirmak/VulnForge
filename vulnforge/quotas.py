"""Tenant quotas, concurrency limits, fair scheduling, and abuse protection for VulnForge."""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Any, Dict, Optional, Tuple


class QuotaExceededError(Exception):
    """Raised when an organization exceeds its API or scan quota."""
    def __init__(self, message: str, retry_after: int = 60):
        super().__init__(message)
        self.retry_after = retry_after


class AbuseBlockedError(Exception):
    """Raised when an actor or organization is temporarily blocked due to abusive patterns."""
    def __init__(self, message: str, unblock_in: int = 300):
        super().__init__(message)
        self.unblock_in = unblock_in


class TenantQuotaManager:
    """Manages tenant rate/volume quotas, concurrent execution limits, and abuse controls."""

    def __init__(
        self,
        default_max_concurrency: int = 2,
        default_daily_scans: int = 100,
        default_hourly_api: int = 1000,
        abuse_threshold: int = 15,
        abuse_block_duration: int = 300,
    ):
        self.default_max_concurrency = default_max_concurrency
        self.default_daily_scans = default_daily_scans
        self.default_hourly_api = default_hourly_api
        self.abuse_threshold = abuse_threshold
        self.abuse_block_duration = abuse_block_duration

        # In-memory windows: org_id -> [(timestamp, count)]
        self._scan_usage: Dict[str, list[float]] = defaultdict(list)
        self._api_usage: Dict[str, list[float]] = defaultdict(list)
        self._abuse_violations: Dict[str, list[float]] = defaultdict(list)
        self._abuse_blocked_until: Dict[str, float] = {}

    def is_abuse_blocked(self, identifier: str) -> Tuple[bool, int]:
        """Check if an identifier (org_id or IP) is currently blocked for abuse."""
        now = time.time()
        blocked_until = self._abuse_blocked_until.get(identifier, 0)
        if blocked_until > now:
            return True, int(blocked_until - now)
        return False, 0

    def record_abuse_violation(self, identifier: str) -> None:
        """Record an abuse event (e.g. repeated 401/403, bad payloads, signature failures)."""
        now = time.time()
        cutoff = now - 300  # 5 min rolling window
        recent = [t for t in self._abuse_violations[identifier] if t > cutoff]
        recent.append(now)
        self._abuse_violations[identifier] = recent

        if len(recent) >= self.abuse_threshold:
            self._abuse_blocked_until[identifier] = now + self.abuse_block_duration

    def check_and_consume_api_quota(self, org_id: str, limit: Optional[int] = None) -> None:
        """Check and consume one API request against hourly tenant quota."""
        is_blocked, remaining = self.is_abuse_blocked(org_id)
        if is_blocked:
            raise AbuseBlockedError(f"Tenant is temporarily blocked due to abusive traffic. Retry in {remaining}s", remaining)

        max_allowed = limit or self.default_hourly_api
        now = time.time()
        cutoff = now - 3600  # 1 hour window
        recent = [t for t in self._api_usage[org_id] if t > cutoff]
        if len(recent) >= max_allowed:
            retry_after = int(3600 - (now - recent[0]))
            raise QuotaExceededError(f"Hourly API quota of {max_allowed} requests exceeded. Retry in {retry_after}s", retry_after=max(1, retry_after))

        recent.append(now)
        self._api_usage[org_id] = recent

    def check_and_consume_scan_quota(self, org_id: str, limit: Optional[int] = None) -> None:
        """Check and consume one scan job against daily tenant quota."""
        is_blocked, remaining = self.is_abuse_blocked(org_id)
        if is_blocked:
            raise AbuseBlockedError(f"Tenant is temporarily blocked due to abusive traffic. Retry in {remaining}s", remaining)

        max_allowed = limit or self.default_daily_scans
        now = time.time()
        cutoff = now - 86400  # 24 hours window
        recent = [t for t in self._scan_usage[org_id] if t > cutoff]
        if len(recent) >= max_allowed:
            retry_after = int(86400 - (now - recent[0]))
            raise QuotaExceededError(f"Daily scan quota of {max_allowed} scans exceeded. Retry in {retry_after}s", retry_after=max(1, retry_after))

        recent.append(now)
        self._scan_usage[org_id] = recent

    def get_active_concurrency(self, store: Any, org_id: str) -> int:
        """Get the count of currently running jobs for the organization."""
        now = time.time()
        with store.conn() as c:
            row = c.execute(
                "SELECT COUNT(*) FROM jobs WHERE organization_id = ? AND state = 'running' AND lease_until > ?",
                (org_id, now),
            ).fetchone()
            return int(row[0]) if row else 0

    def can_dispatch_job(self, store: Any, org_id: Optional[str], max_concurrency: Optional[int] = None) -> bool:
        """Determine if an organization has concurrency capacity available."""
        if not org_id:
            return True
        limit = max_concurrency or self.default_max_concurrency
        return self.get_active_concurrency(store, org_id) < limit

