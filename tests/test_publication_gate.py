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
    gate = evaluate_publication_gate(
        plan,
        validation_evidence=evidence,
        current_head_sha='a' * 40,
        touched_files=['requirements.txt'],
        policy={'allowed_files': ['requirements.txt']}
    )
    assert gate['publication_allowed'] is True
    assert gate['gate_status'] == 'passed'
    assert len(gate['blockers']) == 0
