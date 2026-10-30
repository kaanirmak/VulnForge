import pytest
from vulnforge.automerge import AutomergePolicy, evaluate_automerge_readiness


def test_automerge_blocked_when_policy_disabled():
    policy = AutomergePolicy(enabled=False)
    pr = {
        "head_sha": "a" * 40,
        "base_sha": "b" * 40,
        "upgrade_type": "patch",
        "is_approved": True,
    }
    decision = evaluate_automerge_readiness(
        policy=policy,
        pr_details=pr,
        ci_statuses=[{"context": "unit-tests", "state": "success"}],
        current_base_sha="b" * 40,
    )
    assert decision.eligible is False
    assert any("Automerge policy is disabled" in r for r in decision.reasons)


def test_automerge_blocked_when_ci_failing():
    policy = AutomergePolicy(enabled=True)
    pr = {
        "head_sha": "a" * 40,
        "base_sha": "b" * 40,
        "upgrade_type": "patch",
        "is_approved": True,
    }
    ci = [
        {"context": "lint", "state": "success"},
        {"context": "security-tests", "state": "failure"},
    ]
    decision = evaluate_automerge_readiness(
        policy=policy,
        pr_details=pr,
        ci_statuses=ci,
        current_base_sha="b" * 40,
    )
    assert decision.eligible is False
    assert any("CI check(s) did not pass: security-tests" in r for r in decision.reasons)


def test_automerge_blocked_when_sha_drifted():
    policy = AutomergePolicy(enabled=True)
    pr = {
        "head_sha": "a" * 40,
        "base_sha": "old_base_" + "0" * 31,
        "upgrade_type": "patch",
        "is_approved": True,
    }
    ci = [{"context": "all-tests", "state": "success"}]
    # Main branch has moved forward to new_base_
    decision = evaluate_automerge_readiness(
        policy=policy,
        pr_details=pr,
        ci_statuses=ci,
        current_base_sha="new_base_" + "1" * 31,
    )
    assert decision.eligible is False
    assert any("drifted" in r for r in decision.reasons)


def test_automerge_blocked_on_major_upgrade():
    policy = AutomergePolicy(enabled=True, allowed_upgrade_types=("patch", "minor"))
    pr = {
        "head_sha": "a" * 40,
        "base_sha": "b" * 40,
        "upgrade_type": "major",
        "is_approved": True,
    }
    decision = evaluate_automerge_readiness(
        policy=policy,
        pr_details=pr,
        ci_statuses=[{"context": "tests", "state": "success"}],
        current_base_sha="b" * 40,
    )
    assert decision.eligible is False
    assert any("outside allowed automerge scope" in r for r in decision.reasons)


def test_automerge_approved_when_all_gates_pass():
    policy = AutomergePolicy(
        enabled=True,
        allowed_upgrade_types=("patch", "minor"),
        require_all_ci_passing=True,
        require_up_to_date_sha=True,
        require_approval=True,
    )
    pr = {
        "head_sha": "a" * 40,
        "base_sha": "b" * 40,
        "upgrade_type": "patch",
        "is_approved": True,
    }
    ci = [
        {"context": "build", "state": "success"},
        {"context": "tests", "state": "success"},
    ]
    scan_findings = [
        {"package": "requests", "severity": "low"}
    ]
    decision = evaluate_automerge_readiness(
        policy=policy,
        pr_details=pr,
        ci_statuses=ci,
        current_base_sha="b" * 40,
        scan_findings=scan_findings,
    )
    assert decision.eligible is True
    assert any("All CI, policy, SHA freshness" in r for r in decision.reasons)

