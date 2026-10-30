"""Conditional, least-privilege automerge pilot evaluation engine with strict policy gates."""
from dataclasses import dataclass, field
import time
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class AutomergePolicy:
    enabled: bool = False  # Strict default: Disabled
    allowed_upgrade_types: Tuple[str, ...] = ("patch", "minor")
    require_all_ci_passing: bool = True
    require_up_to_date_sha: bool = True
    max_critical_vulnerabilities: int = 0
    require_approval: bool = True


@dataclass
class AutomergeDecision:
    eligible: bool
    reasons: List[str]
    head_sha: str
    base_sha: str
    decision_timestamp: float = field(default_factory=time.time)


def evaluate_automerge_readiness(
    policy: AutomergePolicy,
    pr_details: Dict[str, Any],
    ci_statuses: List[Dict[str, Any]],
    current_base_sha: str,
    scan_findings: Optional[List[Dict[str, Any]]] = None,
) -> AutomergeDecision:
    """Evaluate whether a security patch PR satisfies all gates for conditional automerge."""
    reasons: List[str] = []
    findings = scan_findings or []

    head_sha = pr_details.get("head_sha", "")
    pr_base_sha = pr_details.get("base_sha", "")
    upgrade_type = pr_details.get("upgrade_type", "unknown")
    is_approved = pr_details.get("is_approved", False)

    # 1. Policy Gate
    if not policy.enabled:
        reasons.append("Automerge policy is disabled for this repository.")

    # 2. Upgrade Scope Gate (Dar kapsam: only patch or minor)
    if upgrade_type not in policy.allowed_upgrade_types:
        reasons.append(
            f"Upgrade type '{upgrade_type}' is outside allowed automerge scope: {policy.allowed_upgrade_types}"
        )

    # 3. Base SHA Freshness / Drift Gate
    if policy.require_up_to_date_sha:
        if pr_base_sha != current_base_sha:
            reasons.append(
                f"PR base SHA ({pr_base_sha[:8]}) has drifted from latest target branch HEAD ({current_base_sha[:8]})."
            )

    # 4. CI Status Gate
    if policy.require_all_ci_passing:
        if not ci_statuses:
            reasons.append("No CI check runs reported for PR head commit.")
        else:
            failing_checks = [
                c.get("context") or c.get("name", "unnamed")
                for c in ci_statuses
                if c.get("state") not in ("success", "passed")
            ]
            if failing_checks:
                reasons.append(f"CI check(s) did not pass: {', '.join(failing_checks)}")

    # 5. Security Findings Gate
    critical_findings = [f for f in findings if f.get("severity") in ("critical", "high")]
    if len(critical_findings) > policy.max_critical_vulnerabilities:
        reasons.append(
            f"PR contains {len(critical_findings)} high/critical security findings, exceeding policy threshold (0)."
        )

    # 6. Approval Gate
    if policy.require_approval and not is_approved:
        reasons.append("PR requires at least one authorized maintainer approval before merging.")

    eligible = len(reasons) == 0
    if eligible:
        reasons.append("All CI, policy, SHA freshness, and security gates passed successfully.")

    return AutomergeDecision(
        eligible=eligible,
        reasons=reasons,
        head_sha=head_sha,
        base_sha=current_base_sha,
    )
