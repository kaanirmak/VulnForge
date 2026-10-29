import pytest
from vulnforge.remediation import evaluate_publication_gate


def test_gate_halts_when_validation_missing():
    plan = {
        'plan_id': 'p1',
        'baseline_sha': 'a' * 40,
        'upgrade_class': 'minor',
        'allowed_files': ['requirements.txt'],
    }
    gate = evaluate_publication_gate(plan, validation_evidence=None)
    assert gate['publication_allowed'] is False
    assert gate['gate_status'] == 'halted'
    assert 'validation_failed_or_missing' in gate['blockers']


def test_gate_halts_when_validation_evidence_failed():
    plan = {
        'plan_id': 'p1',
        'baseline_sha': 'a' * 40,
        'upgrade_class': 'minor',
        'allowed_files': ['requirements.txt'],
    }
    evidence = {
        'plan_id': 'p1',
        'baseline_sha': 'a' * 40,
        'all_checks_passed': False,
    }
    gate = evaluate_publication_gate(plan, validation_evidence=evidence)
    assert gate['publication_allowed'] is False
    assert 'validation_failed_or_missing' in gate['blockers']


def test_gate_halts_on_head_drift():
    plan = {
        'plan_id': 'p1',
        'baseline_sha': 'a' * 40,
        'upgrade_class': 'minor',
        'allowed_files': ['requirements.txt'],
    }
    evidence = {
        'plan_id': 'p1',
        'baseline_sha': 'a' * 40,
        'all_checks_passed': True,
    }
    # Current HEAD on branch has moved to 'b'*40!
    gate = evaluate_publication_gate(
        plan,
        validation_evidence=evidence,
        current_head_sha='b' * 40
    )
    assert gate['publication_allowed'] is False
    assert 'baseline_head_drift_detected' in gate['blockers']


def test_gate_halts_on_major_upgrade():
    plan = {
        'plan_id': 'p1',
        'baseline_sha': 'a' * 40,
        'upgrade_class': 'major',
        'allowed_files': ['requirements.txt'],
    }
    evidence = {
        'plan_id': 'p1',
        'baseline_sha': 'a' * 40,
        'all_checks_passed': True,
    }
    gate = evaluate_publication_gate(
        plan,
        validation_evidence=evidence,
        current_head_sha='a' * 40
    )
    assert gate['publication_allowed'] is False
    assert 'major_upgrade_requires_explicit_review' in gate['blockers']


def test_gate_halts_on_risky_file_or_unauthorized_file():
    plan = {
        'plan_id': 'p1',
        'baseline_sha': 'a' * 40,
        'upgrade_class': 'patch',
        'allowed_files': ['requirements.txt'],
    }
    evidence = {
        'plan_id': 'p1',
        'baseline_sha': 'a' * 40,
        'all_checks_passed': True,
    }
    gate = evaluate_publication_gate(
        plan,
        validation_evidence=evidence,
        current_head_sha='a' * 40,
        touched_files=['requirements.txt', '.github/workflows/ci.yml'],
        policy={'allowed_files': ['requirements.txt']}
    )
    assert gate['publication_allowed'] is False
    assert any('risky_file_modified' in b for b in gate['blockers'])
    assert any('unauthorized_file_modified' in b for b in gate['blockers'])


def test_gate_passes_when_all_conditions_satisfied():
    plan = {
        'plan_id': 'p1',
        'baseline_sha': 'a' * 40,
        'upgrade_class': 'patch',
        'allowed_files': ['requirements.txt'],
    }
    evidence = {
        'plan_id': 'p1',
        'baseline_sha': 'a' * 40,
        'all_checks_passed': True,
    }
    approval = {
        'plan_id': 'p1',
        'user_id': 100,
        'baseline_sha': 'a' * 40,
        'diff_sha256': 'diff-hash-xyz',
        'status': 'approved'
    }
    gate = evaluate_publication_gate(
        plan,
        validation_evidence=evidence,
        approval=approval,
        current_head_sha='a' * 40,
        current_diff_sha256='diff-hash-xyz',
        touched_files=['requirements.txt'],
        policy={'allowed_files': ['requirements.txt']}
    )
    assert gate['publication_allowed'] is True
    assert gate['gate_status'] == 'passed'
    assert gate['approval_status'] == 'approved'
    assert len(gate['blockers']) == 0


def test_gate_halts_when_human_approval_missing():
    plan = {
        'plan_id': 'p1',
        'baseline_sha': 'a' * 40,
        'upgrade_class': 'patch',
        'allowed_files': ['requirements.txt'],
    }
    evidence = {
        'plan_id': 'p1',
        'baseline_sha': 'a' * 40,
        'all_checks_passed': True,
    }
    gate = evaluate_publication_gate(
        plan,
        validation_evidence=evidence,
        approval=None,
        current_head_sha='a' * 40,
        touched_files=['requirements.txt'],
        policy={'allowed_files': ['requirements.txt']}
    )
    assert gate['publication_allowed'] is False
    assert 'bound_human_approval_required' in gate['blockers']


def test_gate_halts_when_approval_diff_mismatch():
    plan = {
        'plan_id': 'p1',
        'baseline_sha': 'a' * 40,
        'upgrade_class': 'patch',
        'allowed_files': ['requirements.txt'],
    }
    evidence = {
        'plan_id': 'p1',
        'baseline_sha': 'a' * 40,
        'all_checks_passed': True,
    }
    approval = {
        'plan_id': 'p1',
        'user_id': 100,
        'baseline_sha': 'a' * 40,
        'diff_sha256': 'old-diff-hash',
        'status': 'approved'
    }
    gate = evaluate_publication_gate(
        plan,
        validation_evidence=evidence,
        approval=approval,
        current_head_sha='a' * 40,
        current_diff_sha256='new-modified-diff-hash',
        touched_files=['requirements.txt'],
        policy={'allowed_files': ['requirements.txt']}
    )
    assert gate['publication_allowed'] is False
    assert 'approval_diff_mismatch' in gate['blockers']


def test_store_approval_binding_and_invalidation(tmp_path):
    from vulnforge.db import Store
    store = Store(str(tmp_path / "test.db"))
    repo = "my/repo"
    plan_id = "plan-123"
    base_sha = "a" * 40
    diff_hash = "diff-1"

    # Record approval
    store.record_patch_approval(repo, plan_id, user_id=42, baseline_sha=base_sha, diff_sha256=diff_hash)
    appr = store.get_patch_approval(repo, plan_id)
    assert appr['status'] == 'approved'
    assert appr['user_id'] == 42

    # Verify matching approval succeeds
    ok, err = store.verify_patch_approval(repo, plan_id, base_sha, diff_hash)
    assert ok is True
    assert err is None

    # Verify baseline mismatch invalidates approval
    ok, err = store.verify_patch_approval(repo, plan_id, "b" * 40, diff_hash)
    assert ok is False
    assert err == 'baseline_sha_mismatch'
    appr = store.get_patch_approval(repo, plan_id)
    assert appr['status'] == 'invalidated'
    assert appr['invalidation_reason'] == 'baseline_sha_mismatch'

    # Re-approve and test diff modification invalidates approval
    store.record_patch_approval(repo, plan_id, user_id=42, baseline_sha=base_sha, diff_sha256=diff_hash)
    ok, err = store.verify_patch_approval(repo, plan_id, base_sha, "diff-modified")
    assert ok is False
    assert err == 'diff_content_changed'
    appr = store.get_patch_approval(repo, plan_id)
    assert appr['status'] == 'invalidated'

