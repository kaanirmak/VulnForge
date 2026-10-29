"""Unit and integration tests for VF-076: Separately show pending approval, validated, blocked, and published remediations."""
import json
import time
from fastapi.testclient import TestClient
import pytest

from vulnforge.api import create_app
from vulnforge.auth import AuthSessions, digest
from vulnforge.config import Config
from vulnforge.db import Store
from vulnforge.identity import Identities
from vulnforge.organization import OrganizationData, ResourceNotFound, RoleDenied

ORIGIN = 'http://127.0.0.1:8000'
ROOT = '/api/v1/organizations'


def seed_remediation_environment(store):
    identity = Identities(store)
    owner = identity.record_github_user(101, 'alpha-owner')
    org = identity.create_organization(owner['id'], 'alpha organization')
    org_id = org['id']

    analyst = identity.record_github_user(102, 'alpha-analyst')
    identity.set_membership(org_id, analyst['id'], 'analyst', owner['id'])

    viewer = identity.record_github_user(103, 'alpha-viewer')
    identity.set_membership(org_id, viewer['id'], 'viewer', owner['id'])

    repo = 'alpha/test-project'
    store.upsert_repo(repo, 42, 'main')
    with store.conn() as c:
        c.execute("UPDATE repositories SET last_sha=? WHERE full_name=?", ('a' * 40, repo))
    identity.record_repository_ownership(org_id, repo, owner['id'], 'ref-alpha')

    # Foreign org & repo
    foreign_owner = identity.record_github_user(201, 'bravo-owner')
    foreign_org = identity.create_organization(foreign_owner['id'], 'bravo organization')
    foreign_repo = 'bravo/foreign-repo'
    store.upsert_repo(foreign_repo, 99, 'main')
    identity.record_repository_ownership(foreign_org['id'], foreign_repo, foreign_owner['id'], 'ref-foreign')
    store.save_remediation(foreign_repo, 'plan-foreign-pub', 'https://github.com/bravo/foreign-repo/pull/1')

    # 1. Published remediation
    store.save_remediation(repo, 'plan-pub-1', 'https://github.com/alpha/test-project/pull/101')

    # 2. Validated plan (checks passed + approved)
    store.save_patch_validation(repo, 'plan-val-1', {
        'all_checks_passed': True,
        'baseline_sha': 'a' * 40,
        'blockers': []
    })
    store.record_patch_approval(repo, 'plan-val-1', analyst['id'], 'a' * 40, 'd' * 64)

    # 3. Pending approval plan (checks passed + NO approval yet)
    store.save_patch_validation(repo, 'plan-pend-1', {
        'all_checks_passed': True,
        'baseline_sha': 'a' * 40,
        'blockers': []
    })

    # 4. Blocked plan (checks failed or risky file blocker)
    store.save_patch_validation(repo, 'plan-block-1', {
        'all_checks_passed': False,
        'baseline_sha': 'a' * 40,
        'blockers': ['validation_failed_or_missing', 'risky_file_modified:.github/ci.yml']
    })

    return owner, analyst, viewer, org_id, repo, foreign_repo


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
    token, csrf_token = sessions.create(user['id'])
    client = TestClient(app, base_url=ORIGIN)
    client.cookies.set(sessions.cookie_prefix + 'session', token)
    client.cookies.set(sessions.cookie_prefix + 'csrf', csrf_token)
    return client, cfg, token, csrf_token


def test_remediation_plans_categorization(tmp_path):
    store = Store(str(tmp_path / 'db'))
    owner, analyst, viewer, org_id, repo, foreign_repo = seed_remediation_environment(store)
    cfg = make_config(store)
    sessions = AuthSessions(store, cfg)
    token, _ = sessions.create(owner['id'])

    org_data = OrganizationData(store, org_id, owner['id'], digest(token))
    res = org_data.remediation_plans()

    summary = res['summary']
    assert summary['published'] == 1
    assert summary['validated'] == 1
    assert summary['pending_approval'] == 1
    assert summary['blocked'] == 1
    assert summary['total'] == 4

    categorized = res['categorized']
    assert len(categorized['published']) == 1
    assert categorized['published'][0]['url'] == 'https://github.com/alpha/test-project/pull/101'

    assert len(categorized['validated']) == 1
    assert categorized['validated'][0]['plan_id'] == 'plan-val-1'
    assert categorized['validated'][0]['approval']['status'] == 'approved'

    assert len(categorized['pending_approval']) == 1
    assert categorized['pending_approval'][0]['plan_id'] == 'plan-pend-1'
    assert categorized['pending_approval'][0]['approval'] is None

    assert len(categorized['blocked']) == 1
    assert categorized['blocked'][0]['plan_id'] == 'plan-block-1'
    assert 'risky_file_modified:.github/ci.yml' in categorized['blocked'][0]['blockers']

    # Filter by specific status
    pending_only = org_data.remediation_plans(status='pending_approval')
    assert len(pending_only['items']) == 1
    assert pending_only['items'][0]['plan_id'] == 'plan-pend-1'

    validated_only = org_data.remediation_plans(status='validated')
    assert len(validated_only['items']) == 1
    assert validated_only['items'][0]['plan_id'] == 'plan-val-1'

    blocked_only = org_data.remediation_plans(status='blocked')
    assert len(blocked_only['items']) == 1
    assert blocked_only['items'][0]['plan_id'] == 'plan-block-1'

    published_only = org_data.remediation_plans(status='published')
    assert len(published_only['items']) == 1
    assert published_only['items'][0]['url'] == 'https://github.com/alpha/test-project/pull/101'


def test_approve_patch_workflow(tmp_path):
    store = Store(str(tmp_path / 'db'))
    owner, analyst, viewer, org_id, repo, foreign_repo = seed_remediation_environment(store)
    cfg = make_config(store)
    sessions = AuthSessions(store, cfg)
    token, _ = sessions.create(analyst['id'])

    org_data = OrganizationData(store, org_id, analyst['id'], digest(token))

    # Before approval, plan-pend-1 is in pending_approval
    before = org_data.remediation_plans(status='pending_approval')['items']
    assert any(p['plan_id'] == 'plan-pend-1' for p in before)

    # Analyst approves plan-pend-1
    approved = org_data.approve_patch(repo, 'plan-pend-1', 'a' * 40, 'e' * 64)
    assert approved['status'] == 'approved'
    assert approved['approved_by'] == analyst['id']

    # Now plan-pend-1 moves to validated
    after_pending = org_data.remediation_plans(status='pending_approval')['items']
    assert not any(p['plan_id'] == 'plan-pend-1' for p in after_pending)

    after_validated = org_data.remediation_plans(status='validated')['items']
    assert any(p['plan_id'] == 'plan-pend-1' for p in after_validated)

    # Viewer role cannot approve (RoleDenied)
    v_token, _ = sessions.create(viewer['id'])
    v_data = OrganizationData(store, org_id, viewer['id'], digest(v_token))
    with pytest.raises(RoleDenied):
        v_data.approve_patch(repo, 'plan-pend-1', 'a' * 40, 'e' * 64)


def test_remediation_api_routes(tmp_path):
    store = Store(str(tmp_path / 'db'))
    owner, analyst, viewer, org_id, repo, foreign_repo = seed_remediation_environment(store)
    client, cfg, _, csrf = make_client(store, analyst)

    headers = {'x-csrf-token': csrf, 'origin': ORIGIN}

    # 1. GET /remediations returns categorized summary
    resp = client.get(f'{ROOT}/{org_id}/remediations')
    assert resp.status_code == 200
    data = resp.json()
    assert data['summary']['pending_approval'] == 1
    assert data['summary']['validated'] == 1
    assert data['summary']['blocked'] == 1
    assert data['summary']['published'] == 1

    # 2. GET /remediations?status=blocked
    resp_blocked = client.get(f'{ROOT}/{org_id}/remediations', params={'status': 'blocked'})
    assert resp_blocked.status_code == 200
    assert len(resp_blocked.json()['items']) == 1
    assert resp_blocked.json()['items'][0]['plan_id'] == 'plan-block-1'

    # 3. POST /remediations/{plan_id}/approve
    resp_approve = client.post(
        f'{ROOT}/{org_id}/remediations/plan-pend-1/approve?repo={repo}',
        json={'baseline_sha': 'a' * 40, 'diff_sha256': 'f' * 64},
        headers=headers
    )
    assert resp_approve.status_code == 200
    assert resp_approve.json()['status'] == 'approved'

    # 4. Foreign repo / unowned approval returns 404
    resp_foreign = client.post(
        f'{ROOT}/{org_id}/remediations/plan-foreign-pub/approve?repo={foreign_repo}',
        json={'baseline_sha': 'a' * 40, 'diff_sha256': 'f' * 64},
        headers=headers
    )
    assert resp_foreign.status_code == 404
