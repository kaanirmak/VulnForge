"""Incident response management, emergency killswitches, and automated security alerting."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional

from vulnforge.db import Store


@dataclass(frozen=True)
class IncidentAlert:
    alert_id: str
    severity: Literal["SEV-0", "SEV-1", "SEV-2"]
    category: Literal["secret_leak", "unauthorized_access", "feed_outage", "pr_spam", "resource_exhaustion"]
    title: str
    description: str
    recommended_action: str
    timestamp: float


class IncidentManager:
    """Orchestrates security incident response, emergency killswitches, and automated triage."""

    def __init__(self):
        self._killswitches: Dict[str, Dict[str, Any]] = {}

    def is_killswitch_active(self, component: str) -> bool:
        """Check if an emergency killswitch is active for a system component or tenant."""
        return component in self._killswitches

    def trigger_emergency_killswitch(
        self,
        store: Store,
        component: str,
        reason: str,
        operator_actor: str,
    ) -> Dict[str, Any]:
        """Trigger an emergency killswitch halting automated actions (e.g. auto_pr, runner_dispatch)."""
        now = time.time()
        record = {
            "component": component,
            "reason": reason,
            "operator_actor": operator_actor,
            "triggered_at": now,
        }
        self._killswitches[component] = record

        store.audit_event(
            repo=f"system:{component}",
            finding_id=None,
            actor=f"operator:{operator_actor}",
            action="emergency_killswitch_triggered",
            details=record,
        )
        return record

    def release_killswitch(
        self,
        store: Store,
        component: str,
        operator_actor: str,
    ) -> bool:
        """Release an active emergency killswitch after resolution."""
        if component not in self._killswitches:
            return False

        old = self._killswitches.pop(component)
        store.audit_event(
            repo=f"system:{component}",
            finding_id=None,
            actor=f"operator:{operator_actor}",
            action="emergency_killswitch_released",
            details={"component": component, "previous_reason": old.get("reason")},
        )
        return True

    def revoke_compromised_sessions(
        self,
        store: Store,
        user_id: str,
        reason: str,
        operator_actor: str,
    ) -> int:
        """Revoke all active user sessions upon suspected credential compromise."""
        with store.conn() as c:
            row = c.execute("DELETE FROM user_sessions WHERE user_id=?", (user_id,))
            revoked_count = getattr(row, "rowcount", 0)

        store.audit_event(
            repo=f"user:{user_id}",
            finding_id=None,
            actor=f"operator:{operator_actor}",
            action="compromised_sessions_revoked",
            details={"user_id": user_id, "reason": reason, "revoked_count": revoked_count},
        )
        return revoked_count

    def rotate_compromised_credential(
        self,
        vault: Any,
        store: Store,
        secret_name: str,
        new_value: str,
        operator_actor: str,
    ) -> Dict[str, Any]:
        """Rotate a compromised credential with dual-key grace period and audit logging."""
        vault.rotate_secret(secret_name, new_value)
        record = {
            "secret_name": secret_name,
            "rotated_by": operator_actor,
            "rotated_at": time.time(),
        }
        store.audit_event(
            repo=f"vault:{secret_name}",
            finding_id=None,
            actor=f"operator:{operator_actor}",
            action="compromised_credential_rotated",
            details=record,
        )
        return record

    def evaluate_incident_signals(
        self,
        metrics: Dict[str, Any],
        *,
        recent_prs_count: int = 0,
        abuse_violations_count: int = 0,
    ) -> List[IncidentAlert]:
        """Analyze operational telemetry and metrics to detect active incident patterns."""
        alerts: List[IncidentAlert] = []
        now = time.time()

        # 1. Threat Feed Outage
        freshness = metrics.get("freshness", {})
        advisory_age = freshness.get("advisory_freshness_age_seconds")
        if advisory_age is not None and advisory_age > 86400:  # > 24 hours
            alerts.append(
                IncidentAlert(
                    alert_id=f"alert-{uuid.uuid4().hex[:8]}",
                    severity="SEV-2",
                    category="feed_outage",
                    title="Intelligence Feed Outage Detected",
                    description=f"Advisory intelligence feed has not updated in {int(advisory_age // 3600)} hours.",
                    recommended_action="Inspect advisory ingestion runners and failover to secondary OSV/GHSA mirror.",
                    timestamp=now,
                )
            )

        # 2. PR Spam / Flood Attack
        if recent_prs_count > 20:
            alerts.append(
                IncidentAlert(
                    alert_id=f"alert-{uuid.uuid4().hex[:8]}",
                    severity="SEV-1",
                    category="pr_spam",
                    title="Automated PR Flood Anomaly",
                    description=f"Unusually high automated PR creation volume ({recent_prs_count} PRs in short window).",
                    recommended_action="Trigger emergency killswitch on 'auto_pr' and inspect recent remediation triggers.",
                    timestamp=now,
                )
            )

        # 3. Excessive Resource Exhaustion
        errors = metrics.get("errors", {})
        resource_errors = errors.get("resource_exhaustion_errors", 0)
        timeout_errors = errors.get("timeout_errors", 0)
        if resource_errors >= 5 or timeout_errors >= 10:
            alerts.append(
                IncidentAlert(
                    alert_id=f"alert-{uuid.uuid4().hex[:8]}",
                    severity="SEV-1",
                    category="resource_exhaustion",
                    title="Scanner Resource Exhaustion / Denial of Service",
                    description=f"High rate of scanner failures ({resource_errors} resource/OOM, {timeout_errors} timeouts).",
                    recommended_action="Verify customer runner resource boundaries and isolate malicious payload repos.",
                    timestamp=now,
                )
            )

        # 4. Unauthorized Access / Brute-force Abuse
        if abuse_violations_count >= 15:
            alerts.append(
                IncidentAlert(
                    alert_id=f"alert-{uuid.uuid4().hex[:8]}",
                    severity="SEV-1",
                    category="unauthorized_access",
                    title="Potential Brute Force or Ingress Abuse",
                    description=f"High threshold of abusive request patterns recorded ({abuse_violations_count} violations).",
                    recommended_action="Engage edge WAF rate-limiting and verify tenant auth tokens.",
                    timestamp=now,
                )
            )

        return alerts
