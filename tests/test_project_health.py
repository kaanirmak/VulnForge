"""Unit and integration tests for VF-072: Project health, risk summary, latest scan, coverage, intelligence freshness, and connection health."""
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


def seed_test_org(store):
    identity = Identities(store)
    owner = identity.record_github_user(101, 'alpha-owner')
    org = identity.create_organization(owner['id'], 'alpha organization')
    org_id = org['id']

    analyst = identity.record_github_user(102, 'alpha-analyst')
    identity.set_membership(org_id, analyst['id'], 'analyst', owner['id'])

    # Foreign org
    foreign_owner = identity.record_github_user(201, 'bravo-owner')
    foreign_org = identity.create_organization(foreign_owner['id'], 'bravo organization')
    foreign_repo = 'bravo/foreign-repo'
    store.upsert_repo(foreign_repo, 99, 'main')
    identity.record_repository_ownership(foreign_org['id'], foreign_repo, foreign_owner['id'], 'ref-foreign')

    repo = 'alpha/test-project'
    store.upsert_repo(repo, 42, 'main')
    with store.conn() as c:
        c.execute("UPDATE repositories SET last_sha=? WHERE full_name=?", ('a' * 40, repo))
    identity.record_repository_ownership(org_id, repo, owner['id'], 'ref-123')

    # Add findings: 1 critical, 2 high, 1 low (open), 1 resolved
    store.save_finding(repo, 'crit-1', 'sast', 'critical', 'Command injection', 'app.py', 'a' * 40, {})
    store.save_finding(repo, 'high-1', 'dependency', 'high', 'Vulnerable dep 1', 'req.txt', 'a' * 40, {})
    store.save_finding(repo, 'high-2', 'dependency', 'high', 'Vulnerable dep 2', 'req.txt', 'a' * 40, {})
    store.save_finding(repo, 'low-1', 'sast', 'low', 'Information disclosure', 'app.py', 'a' * 40, {})
    store.save_finding(repo, 'res-1', 'sast', 'medium', 'Resolved issue', 'app.py', 'a' * 40, {})
    with store.conn() as c:
        c.execute("UPDATE findings SET status='resolved' WHERE key='res-1'")

    # Add dependencies: PyPI and npm
    store.replace_inventory(repo, [
        Dependency('flask', '2.0.1', 'PyPI', 'requirements.txt'),
        Dependency('requests', '2.25.1', 'PyPI', 'requirements.txt'),
        Dependency('lodash', '4.17.20', 'npm', 'package.json')
    ])

    # Add scan
    now = time.time()
    scan_id = store.start_scan(repo, 'dependencies', 'a' * 40)
    finding = {'key': 'high-1', 'title': 'Vulnerable dep 1', 'severity': 'high', 'category': 'dependency', 'file_path': 'req.txt', 'details': {}}
    store.record_scan_finding(scan_id, finding)
    store.finish_scan(
        scan_id,
        'complete',
        {
            'files_total': 10,
            'files_scanned': 9,
            'files_skipped': 1,
            'manifests': ['requirements.txt', 'package.json'],
            'scope': 'dependency_manifests',
            'intelligence_source': 'public_osv',
            'intelligence_checked_at': now - 60,
            'default_branch': 'main'
        },
        [
            {'name': 'flask', 'version': '2.0.1', 'ecosystem': 'PyPI', 'file_path': 'requirements.txt'},
            {'name': 'lodash', 'version': '4.17.20', 'ecosystem': 'npm', 'file_path': 'package.json'}
        ]
    )

    # Advisory impact
    adv = store.save_advisory({'id': 'GHSA-TEST-001', 'summary': 'Test advisory', 'aliases': ['CVE-2023-9999']})
    store.save_impact(repo, adv, 'affected', scan_id, {}, [{'package': 'lodash'}])

    return owner, analyst, org_id, repo, foreign_repo


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


def test_project_health_data_method(tmp_path):
    store = Store(str(tmp_path / 'db'))
    owner, analyst, org_id, repo, foreign_repo = seed_test_org(store)
    cfg = make_config(store)
    sessions = AuthSessions(store, cfg)
    token, _ = sessions.create(owner['id'])

    org_data = OrganizationData(store, org_id, owner['id'], digest(token))
    health = org_data.project_health(repo)

    assert health['repo'] == repo

    # Risk summary
    risk = health['risk_summary']
    assert risk['open_findings'] == 4
    assert risk['total_findings'] == 5
    assert risk['severities']['critical'] == 1
    assert risk['severities']['high'] == 2
    assert risk['severities']['low'] == 1
    assert risk['status_counts']['resolved'] == 1
    assert risk['risk_score'] == 1 * 10 + 2 * 5 + 1 * 1  # 21
    assert risk['posture'] == 'critical'

    # Latest scan
    scan = health['latest_scan']
    assert scan is not None
    assert scan['kind'] == 'dependencies'
    assert scan['state'] == 'complete'
    assert scan['commit_sha'] == 'a' * 40
    assert 'evidence_status' in scan

    # Coverage
    cov = health['coverage']
    assert cov['files_total'] == 10
    assert cov['files_scanned'] == 9
    assert cov['files_skipped'] == 1
    assert cov['coverage_percent'] == 90.0
    assert cov['manifests'] == ['requirements.txt', 'package.json']
    assert cov['dependency_count'] == 3
    assert set(cov['ecosystems']) == {'PyPI', 'npm'}

    # Intelligence freshness
    freshness = health['intelligence_freshness']
    assert 'status' in freshness
    assert freshness['advisory_impacts']['affected'] == 1
    assert freshness['advisory_impacts']['not_affected'] == 0

    # Connection health
    conn = health['connection_health']
    assert conn['repo'] == repo
    assert conn['status'] == 'connected'
    assert conn['installation_id'] == 42
    assert conn['default_branch'] == 'main'
    assert conn['last_sha'] == 'a' * 40

    # Foreign repo raises ResourceNotFound
    with pytest.raises(ResourceNotFound):
        org_data.project_health(foreign_repo)

    with pytest.raises(ResourceNotFound):
        org_data.project_health('nonexistent/repo')


def test_project_health_api_endpoints(tmp_path):
    store = Store(str(tmp_path / 'db'))
    owner, analyst, org_id, repo, foreign_repo = seed_test_org(store)
    client, cfg, _ = make_client(store, analyst)

    # Test GET /repositories/{repo}/health
    resp = client.get(f'{ROOT}/{org_id}/repositories/{repo}/health')
    assert resp.status_code == 200
    data = resp.json()
    assert data['repo'] == repo
    assert data['risk_summary']['open_findings'] == 4
    assert data['coverage']['dependency_count'] == 3
    assert data['connection_health']['status'] == 'connected'

    # Test GET /projects/{repo}/health alias
    resp_proj = client.get(f'{ROOT}/{org_id}/projects/{repo}/health')
    assert resp_proj.status_code == 200
    assert resp_proj.json() == data

    # Foreign repo returns 404 (tenant isolation)
    resp_foreign = client.get(f'{ROOT}/{org_id}/repositories/{foreign_repo}/health')
    assert resp_foreign.status_code == 404

    # Nonexistent repo returns 404
    resp_missing = client.get(f'{ROOT}/{org_id}/repositories/random/missing/health')
    assert resp_missing.status_code == 404


def test_project_health_without_scans(tmp_path):
    store = Store(str(tmp_path / 'db'))
    identity = Identities(store)
    owner = identity.record_github_user(105, 'owner-noscan')
    org = identity.create_organization(owner['id'], 'noscan-org')
    repo = 'noscan/repo'
    store.upsert_repo(repo, 10, 'develop')
    identity.record_repository_ownership(org['id'], repo, owner['id'], 'ref-noscan')

    cfg = make_config(store)
    sessions = AuthSessions(store, cfg)
    token, _ = sessions.create(owner['id'])
    org_data = OrganizationData(store, org['id'], owner['id'], digest(token))

    health = org_data.project_health(repo)
    assert health['repo'] == repo
    assert health['risk_summary']['risk_score'] == 0
    assert health['risk_summary']['posture'] == 'healthy'
    assert health['latest_scan'] is None
    assert health['coverage']['dependency_count'] == 0
    assert health['coverage']['coverage_percent'] == 0.0
    assert health['connection_health']['status'] == 'connected'
