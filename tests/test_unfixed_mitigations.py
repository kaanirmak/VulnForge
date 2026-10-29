import time
import pytest
from vulnforge.db import Store
from vulnforge.remediation import build_unfixed_mitigation_plan, evaluate_sla_status
from vulnforge.dependencies import Dependency


def test_build_unfixed_mitigation_plan():
    dep = Dependency(name='vulnerable-lib', version='1.0.0', ecosystem='pypi', file_path='requirements.txt')
    advisory = {'id': 'GHSA-xxxx-yyyy-zzzz', 'summary': 'Unfixed RCE'}
    plan = build_unfixed_mitigation_plan(
        'octocat/hello-world',
        dep,
        advisory,
        recommendation={'status': 'no_fix'},
        owner='security-team',
        priority='P1',
        recheck_interval_hours=12
    )

    assert plan['repo'] == 'octocat/hello-world'
    assert plan['advisory_id'] == 'GHSA-xxxx-yyyy-zzzz'
    assert plan['package'] == 'vulnerable-lib'
    assert plan['priority'] == 'P1'
    assert plan['sla_hours'] == 72
    assert plan['recheck_interval_hours'] == 12
    assert 'No published fix currently exists' in plan['mitigation_guidance']


def test_evaluate_sla_status():
    created = 1000.0
    deadline = 2000.0  # window is 1000s, 20% risk window starts at 1800s
    record = {
        'status': 'active',
        'created_at': created,
        'sla_deadline': deadline
    }

    # Within SLA
    assert evaluate_sla_status(record, now=1500.0) == 'within_sla'
    # At risk
    assert evaluate_sla_status(record, now=1850.0) == 'at_risk'
    # Breached
    assert evaluate_sla_status(record, now=2050.0) == 'breached'
    # Resolved
    record['status'] = 'mitigated'
    assert evaluate_sla_status(record, now=2050.0) == 'mitigated'


def test_store_unfixed_mitigations_lifecycle(tmp_path):
    store = Store(str(tmp_path / "test.db"))
    repo = "org/repo"
    adv_id = "GHSA-unfixed-1"

    # Save mitigation
    store.save_unfixed_mitigation(
        repo=repo,
        advisory_id=adv_id,
        package="logger-pkg",
        ecosystem="npm",
        current_version="0.5.0",
        mitigation_guidance="Apply input sanitization filter",
        owner="team-lead",
        priority="P0",
        sla_hours=24,
        recheck_interval_hours=6
    )

    items = store.get_unfixed_mitigations(repo)
    assert len(items) == 1
    m = items[0]
    assert m['package'] == "logger-pkg"
    assert m['owner'] == "team-lead"
    assert m['priority'] == "P0"
    assert m['sla_status'] in ('within_sla', 'at_risk')
    assert len(m['history']) == 1

    # Extend SLA
    store.extend_mitigation_sla(
        repo, adv_id, additional_hours=48, reason="Upstream patch in progress", actor="dev-lead"
    )

    items = store.get_unfixed_mitigations(repo)
    assert len(items[0]['history']) == 2
    assert items[0]['history'][1]['action'] == 'sla_extended'
    assert items[0]['history'][1]['reason'] == 'Upstream patch in progress'

    # Recheck
    store.record_mitigation_recheck(repo, adv_id, status='mitigated', result_summary='WAF rule verified')
    items = store.get_unfixed_mitigations(repo)
    assert items[0]['status'] == 'mitigated'
    assert items[0]['sla_status'] == 'mitigated'
    assert len(items[0]['history']) == 3
