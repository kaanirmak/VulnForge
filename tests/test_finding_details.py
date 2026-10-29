"""Unit and integration tests for VF-073: Finding detail with evidence, advisory, package graph, SHA, history, and update alternatives."""
import json
import time
from fastapi.testclient import TestClient
import pytest

from vulnforge.api import create_app
from vulnforge.auth import AuthSessions, digest
from vulnforge.config import Config
from vulnforge.db import Store
from vulnforge.dependencies import Dependency
from vulnforge.identity import Identities
from vulnforge.organization import OrganizationData, ResourceNotFound

ORIGIN = 'http://127.0.0.1:8000'
ROOT = '/api/v1/organizations'


def seed_finding_environment(store):
    identity = Identities(store)
    owner = identity.record_github_user(101, 'alpha-owner')
    org = identity.create_organization(owner['id'], 'alpha organization')
    org_id = org['id']

    analyst = identity.record_github_user(102, 'alpha-analyst')
    identity.set_membership(org_id, analyst['id'], 'analyst', owner['id'])

    viewer = identity.record_github_user(103, 'alpha-viewer')
    identity.set_membership(org_id, viewer['id'], 'viewer', owner['id'])

    # Foreign org
    foreign_owner = identity.record_github_user(201, 'bravo-owner')
    foreign_org = identity.create_organization(foreign_owner['id'], 'bravo organization')
    foreign_repo = 'bravo/foreign-repo'
    store.upsert_repo(foreign_repo, 99, 'main')
    identity.record_repository_ownership(foreign_org['id'], foreign_repo, foreign_owner['id'], 'ref-foreign')
    store.save_finding(foreign_repo, 'foreign-key', 'sast', 'high', 'Foreign bug', 'main.py', 'f' * 40, {})
    with store.conn() as c:
        foreign_finding_id = c.execute("SELECT id FROM findings WHERE repo=?", (foreign_repo,)).fetchone()[0]

    repo = 'alpha/test-project'
    store.upsert_repo(repo, 42, 'main')
    with store.conn() as c:
        c.execute("UPDATE repositories SET last_sha=? WHERE full_name=?", ('b' * 40, repo))
    identity.record_repository_ownership(org_id, repo, owner['id'], 'ref-alpha')

    # Advisory & metrics
    adv = store.save_advisory({
        'id': 'GHSA-TEST-1234',
        'summary': 'Critical remote code execution in demo-pkg',
        'details': 'Full explanation of vulnerable sink',
        'aliases': ['CVE-2023-1111'],
        'source': 'osv'
    })
    from vulnforge.kev import VulnerabilityMetrics
    store.save_vulnerability_metrics(VulnerabilityMetrics(
        cve_id='CVE-2023-1111',
        cvss_score=9.8,
        cvss_severity='CRITICAL',
        cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        epss_score=0.85,
        epss_percentile=0.95,
        kev_date_added='2023-01-15',
        kev_ransomware=True,
        evidence={'test': 'fixture'}
    ))

    # Dependency inventory with parent graph edge
    store.replace_inventory(repo, [
        Dependency(
            'demo-pkg', '1.0.0', 'PyPI', 'requirements.txt',
            direct=False, scope='runtime',
            dependency_edges=['parent-app->demo-pkg'],
            digest='sha256:' + 'd' * 64
        )
    ])

    # Finding details with evidence, advisory link, and update recommendation
    details = {
        'advisory_id': 'GHSA-TEST-1234',
        'package_name': 'demo-pkg',
        'ecosystem': 'PyPI',
        'direct': False,
        'dependency_edges': ['parent-app->demo-pkg'],
        'digest': 'sha256:' + 'd' * 64,
        'line': 42,
        'snippet': 'demo_pkg.vulnerable_call(user_input)',
        'sink': 'vulnerable_call',
        'source': 'user_input',
        'rule_id': 'vulnforge/rce-injection',
        'fingerprint': 'fp-1234567890',
        'update_recommendation': {
            'package': 'demo-pkg',
            'current_version': '1.0.0',
            'recommended_version': '1.2.0',
            'breaking_risk': False,
            'verified_at': time.time()
        }
    }
    store.save_finding(repo, 'demo-key', 'dependency', 'critical', 'Critical RCE in demo-pkg', 'requirements.txt', 'a' * 40, details)
    with store.conn() as c:
        finding_id = c.execute("SELECT id FROM findings WHERE repo=?", (repo,)).fetchone()[0]

    # Audit events / history
    store.audit_event(repo, finding_id, 'user-101', 'finding_triaged', {'status': 'open', 'reason': 'Initial review'})
    store.audit_event(repo, finding_id, 'user-102', 'finding_annotated', {'note': 'Confirmed exploitable in staging'})

    # Remediation PR plan
    plan_json = json.dumps({'findings': [str(finding_id)], 'packages': ['demo-pkg']})
    store.save_remediation(repo, plan_json, 'https://github.com/alpha/test-project/pull/10')

    return owner, analyst, viewer, org_id, repo, finding_id, foreign_finding_id


def make_config(store):
    return Config(
        database_path=store.path,
        admin_token='operator-only',
        operator_report_token='separate-report-operator',
        customer_api_preview=True,
        github_oauth_client_id='test-client-id',
        github_oauth_client_secret='test-client-secret',
        public_origin=ORIGIN,
        allow_insecure_local_auth=True
    )


def make_client(store, user):
    cfg = make_config(store)
    app = create_app(cfg, store)
    sessions = AuthSessions(store, cfg)
    token, _ = sessions.create(user['id'])
    client = TestClient(app, base_url=ORIGIN)
    client.cookies.set(sessions.cookie_prefix + 'session', token)
    return client, cfg, token


def test_finding_detail_data_method(tmp_path):
    store = Store(str(tmp_path / 'db'))
    owner, analyst, viewer, org_id, repo, finding_id, foreign_finding_id = seed_finding_environment(store)
    cfg = make_config(store)
    sessions = AuthSessions(store, cfg)
    token, _ = sessions.create(owner['id'])

    org_data = OrganizationData(store, org_id, owner['id'], digest(token))
    result = org_data.finding(finding_id)

    assert result['id'] == finding_id
    assert result['repo'] == repo
    assert result['severity'] == 'critical'
    assert result['title'] == 'Critical RCE in demo-pkg'

    # SHA & Drift check
    sha_info = result['sha_info']
    assert sha_info['commit_sha'] == 'a' * 40
    assert sha_info['head_sha'] == 'b' * 40
    assert sha_info['head_drifted'] is True
    assert sha_info['default_branch'] == 'main'

    # Evidence
    ev = result['evidence']
    assert ev['file_path'] == 'requirements.txt'
    assert ev['line'] == 42
    assert ev['snippet'] == 'demo_pkg.vulnerable_call(user_input)'
    assert ev['sink'] == 'vulnerable_call'
    assert ev['rule_id'] == 'vulnforge/rce-injection'
    assert ev['fingerprint'] == 'fp-1234567890'

    # Advisory & Metrics
    adv = result['advisory']
    assert adv is not None
    assert adv['id'] == 'GHSA-TEST-1234'
    assert 'CVE-2023-1111' in adv['aliases']
    assert adv['metrics']['cvss_score'] == 9.8
    assert adv['metrics']['cisa_kev'] is True
    assert adv['metrics']['epss_score'] == 0.85

    # Package graph
    graph = result['package_graph']
    assert graph is not None
    assert graph['package'] == 'demo-pkg'
    assert graph['version'] == '1.0.0'
    assert graph['ecosystem'] == 'PyPI'
    assert graph['direct'] is False
    assert graph['dependency_edges'] == ['parent-app->demo-pkg']
    assert graph['digest'] == 'sha256:' + 'd' * 64

    # History
    hist = result['history']
    assert len(hist) == 3
    assert [h['action'] for h in hist] == ['finding_observed', 'finding_triaged', 'finding_annotated']

    # Recommendations
    recs = result['recommendations']
    assert len(recs) >= 1
    assert recs[0]['package'] == 'demo-pkg'
    assert recs[0].get('recommended_version') == '1.2.0' or recs[0].get('previous_recommended_version') == '1.2.0'
    assert recs[0]['freshness'] in ('fresh_snapshot', 'needs_reverification')

    # Remediation plan
    plan = result['remediation_plan']
    assert plan is not None
    assert plan['pr_url'] == 'https://github.com/alpha/test-project/pull/10'

    # Foreign finding access raises ResourceNotFound
    with pytest.raises(ResourceNotFound):
        org_data.finding(foreign_finding_id)

    with pytest.raises(ResourceNotFound):
        org_data.finding(999999)


def test_finding_detail_api_endpoint(tmp_path):
    store = Store(str(tmp_path / 'db'))
    owner, analyst, viewer, org_id, repo, finding_id, foreign_finding_id = seed_finding_environment(store)
    client, cfg, _ = make_client(store, viewer)

    # 1. Successful fetch by viewer role
    resp = client.get(f'{ROOT}/{org_id}/findings/{finding_id}')
    assert resp.status_code == 200
    data = resp.json()
    assert data['id'] == finding_id
    assert data['severity'] == 'critical'
    assert data['sha_info']['head_drifted'] is True
    assert data['advisory']['metrics']['cvss_score'] == 9.8
    assert data['package_graph']['direct'] is False
    assert len(data['history']) == 3
    assert data['remediation_plan']['pr_url'] == 'https://github.com/alpha/test-project/pull/10'

    # 2. Foreign finding ID returns 404 (tenant isolation)
    resp_foreign = client.get(f'{ROOT}/{org_id}/findings/{foreign_finding_id}')
    assert resp_foreign.status_code == 404

    # 3. Nonexistent finding ID returns 404
    resp_missing = client.get(f'{ROOT}/{org_id}/findings/999999')
    assert resp_missing.status_code == 404
