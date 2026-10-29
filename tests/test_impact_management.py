"""Unit and integration tests for VF-074: Owner assignment, batch filtering, and historical comparison for affected projects."""
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


def seed_impact_env(store):
    identity = Identities(store)
    owner = identity.record_github_user(101, 'alpha-owner')
    org = identity.create_organization(owner['id'], 'alpha organization')
    org_id = org['id']

    analyst = identity.record_github_user(102, 'alpha-analyst')
    identity.set_membership(org_id, analyst['id'], 'analyst', owner['id'])

    viewer = identity.record_github_user(103, 'alpha-viewer')
    identity.set_membership(org_id, viewer['id'], 'viewer', owner['id'])

    # Non-member user
    stranger = identity.record_github_user(999, 'stranger')

    # Foreign org & repo
    foreign_owner = identity.record_github_user(201, 'bravo-owner')
    foreign_org = identity.create_organization(foreign_owner['id'], 'bravo organization')
    foreign_repo = 'bravo/foreign-repo'
    store.upsert_repo(foreign_repo, 99, 'main')
    identity.record_repository_ownership(foreign_org['id'], foreign_repo, foreign_owner['id'], 'ref-foreign')
    adv_foreign = store.save_advisory({'id': 'GHSA-FOREIGN-1', 'summary': 'Foreign issue'})
    store.save_impact(foreign_repo, adv_foreign, 'affected', 'scan-foreign', {}, [{'package': 'foreign-pkg'}])
    with store.conn() as c:
        foreign_impact_id = c.execute("SELECT id FROM advisory_impacts WHERE repo=?", (foreign_repo,)).fetchone()[0]

    repo = 'alpha/test-project'
    store.upsert_repo(repo, 42, 'main')
    identity.record_repository_ownership(org_id, repo, owner['id'], 'ref-alpha')

    adv1 = store.save_advisory({'id': 'GHSA-PYPI-001', 'summary': 'Flask vulnerability'})
    store.save_impact(
        repo, adv1, 'affected', 'scan-1',
        {'ecosystem': 'PyPI', 'package': 'flask'},
        [{'package': 'flask', 'current_version': '1.0.0', 'recommended_version': '2.0.0'}]
    )

    adv2 = store.save_advisory({'id': 'GHSA-NPM-002', 'summary': 'Lodash prototype pollution'})
    store.save_impact(
        repo, adv2, 'affected', 'scan-1',
        {'ecosystem': 'npm', 'package': 'lodash'},
        [{'package': 'lodash', 'current_version': '4.17.15', 'recommended_version': '4.17.21'}]
    )

    adv3 = store.save_advisory({'id': 'GHSA-CARGO-003', 'summary': 'Rust tokio issue'})
    store.save_impact(
        repo, adv3, 'not_affected', 'scan-1',
        {'ecosystem': 'cargo', 'package': 'tokio'},
        [{'package': 'tokio', 'current_version': '1.0.0', 'recommended_version': None}]
    )

    with store.conn() as c:
        impact1_id = c.execute("SELECT id FROM advisory_impacts WHERE advisory_id='GHSA-PYPI-001'").fetchone()[0]
        impact2_id = c.execute("SELECT id FROM advisory_impacts WHERE advisory_id='GHSA-NPM-002'").fetchone()[0]
        impact3_id = c.execute("SELECT id FROM advisory_impacts WHERE advisory_id='GHSA-CARGO-003'").fetchone()[0]

    return owner, analyst, viewer, stranger, org_id, repo, impact1_id, impact2_id, impact3_id, foreign_impact_id


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


def test_assign_impact_lifecycle(tmp_path):
    store = Store(str(tmp_path / 'db'))
    owner, analyst, viewer, stranger, org_id, repo, i1, i2, i3, foreign_id = seed_impact_env(store)
    cfg = make_config(store)
    sessions = AuthSessions(store, cfg)
    token, _ = sessions.create(owner['id'])

    org_data = OrganizationData(store, org_id, owner['id'], digest(token))

    # 1. Assign impact to analyst
    res = org_data.assign_impact(i1, analyst['id'])
    assert res['id'] == i1
    assert res['assigned_to'] == analyst['id']
    assert res['previous_assigned_to'] is None

    # Check assignment is reflected in list
    items = org_data.impacts(repo=repo)['items']
    assigned_item = next(x for x in items if x['id'] == i1)
    assert assigned_item['assigned_to'] == analyst['id']

    # 2. Reassign to owner
    res2 = org_data.assign_impact(i1, owner['id'])
    assert res2['assigned_to'] == owner['id']
    assert res2['previous_assigned_to'] == analyst['id']

    # 3. Unassign
    res3 = org_data.assign_impact(i1, None)
    assert res3['assigned_to'] is None
    assert res3['previous_assigned_to'] == owner['id']

    # 4. Assigning to a non-member raises ResourceNotFound
    with pytest.raises(ResourceNotFound):
        org_data.assign_impact(i1, stranger['id'])

    # 5. Assigning non-existent or foreign impact raises ResourceNotFound
    with pytest.raises(ResourceNotFound):
        org_data.assign_impact(foreign_id, analyst['id'])

    with pytest.raises(ResourceNotFound):
        org_data.assign_impact(999999, analyst['id'])

    # 6. Viewer cannot assign (RoleDenied)
    viewer_token, _ = sessions.create(viewer['id'])
    viewer_data = OrganizationData(store, org_id, viewer['id'], digest(viewer_token))
    with pytest.raises(RoleDenied):
        viewer_data.assign_impact(i1, analyst['id'])


def test_batch_filtering_impacts(tmp_path):
    store = Store(str(tmp_path / 'db'))
    owner, analyst, viewer, stranger, org_id, repo, i1, i2, i3, foreign_id = seed_impact_env(store)
    cfg = make_config(store)
    sessions = AuthSessions(store, cfg)
    token, _ = sessions.create(owner['id'])
    org_data = OrganizationData(store, org_id, owner['id'], digest(token))

    # Assign i1 to analyst
    org_data.assign_impact(i1, analyst['id'])

    # Filter by state
    affected = org_data.impacts(state='affected')['items']
    assert len(affected) == 2
    assert all(x['state'] == 'affected' for x in affected)

    not_affected = org_data.impacts(state='not_affected')['items']
    assert len(not_affected) == 1
    assert not_affected[0]['id'] == i3

    # Filter by package
    flask_items = org_data.impacts(package='flask')['items']
    assert len(flask_items) == 1
    assert flask_items[0]['id'] == i1

    # Filter by ecosystem
    npm_items = org_data.impacts(ecosystem='npm')['items']
    assert len(npm_items) == 1
    assert npm_items[0]['id'] == i2

    # Filter by assigned_to
    analyst_items = org_data.impacts(assigned_to=analyst['id'])['items']
    assert len(analyst_items) == 1
    assert analyst_items[0]['id'] == i1

    unassigned_items = org_data.impacts(assigned_to='unassigned')['items']
    assert len(unassigned_items) == 2
    assert set(x['id'] for x in unassigned_items) == {i2, i3}


def test_impact_historical_comparison(tmp_path):
    store = Store(str(tmp_path / 'db'))
    owner, analyst, viewer, stranger, org_id, repo, i1, i2, i3, foreign_id = seed_impact_env(store)
    cfg = make_config(store)
    sessions = AuthSessions(store, cfg)
    token, _ = sessions.create(owner['id'])
    org_data = OrganizationData(store, org_id, owner['id'], digest(token))

    # Perform updates to create revision history
    # 1. Update impact state from affected to not_affected
    store.save_impact(
        repo, 'GHSA-PYPI-001', 'not_affected', 'scan-2',
        {'ecosystem': 'PyPI', 'package': 'flask'},
        [{'package': 'flask', 'current_version': '2.0.0', 'recommended_version': None}]
    )

    # 2. Assign impact to analyst
    org_data.assign_impact(i1, analyst['id'])

    # 3. Retrieve history and compare
    hist = org_data.impact_history(i1)
    assert hist['id'] == i1
    assert hist['repo'] == repo
    assert hist['advisory_id'] == 'GHSA-PYPI-001'
    assert hist['total_revisions'] >= 3

    timeline = hist['timeline']
    assert len(timeline) >= 3

    # Verify initial revision
    assert timeline[0]['diff'].get('initial_state') == 'affected'

    # Verify state transition in revision 2
    state_diff = timeline[1]['diff'].get('state_changed')
    assert state_diff == {'from': 'affected', 'to': 'not_affected'}

    # Verify assignment transition in revision 3
    assign_diff = timeline[2]['diff'].get('assignment_changed')
    assert assign_diff == {'from': None, 'to': analyst['id']}

    # Foreign impact history returns 404
    with pytest.raises(ResourceNotFound):
        org_data.impact_history(foreign_id)


def test_impact_routes_api(tmp_path):
    store = Store(str(tmp_path / 'db'))
    owner, analyst, viewer, stranger, org_id, repo, i1, i2, i3, foreign_id = seed_impact_env(store)
    client, cfg, _, csrf = make_client(store, analyst)

    headers = {'x-csrf-token': csrf, 'origin': ORIGIN}

    # 1. PATCH assign endpoint
    resp = client.patch(
        f'{ROOT}/{org_id}/impacts/{i1}/assign',
        json={'assigned_to': analyst['id']},
        headers=headers
    )
    assert resp.status_code == 200
    assert resp.json()['assigned_to'] == analyst['id']

    # 2. GET history endpoint
    resp_hist = client.get(f'{ROOT}/{org_id}/impacts/{i1}/history')
    assert resp_hist.status_code == 200
    data = resp_hist.json()
    assert data['id'] == i1
    assert data['current_assigned_to'] == analyst['id']
    assert len(data['timeline']) >= 2

    # 3. GET impacts with filters
    resp_filtered = client.get(
        f'{ROOT}/{org_id}/impacts',
        params={'ecosystem': 'PyPI', 'assigned_to': analyst['id']}
    )
    assert resp_filtered.status_code == 200
    items = resp_filtered.json()['items']
    assert len(items) == 1
    assert items[0]['id'] == i1

    # 4. Foreign impact assign returns 404
    resp_foreign = client.patch(
        f'{ROOT}/{org_id}/impacts/{foreign_id}/assign',
        json={'assigned_to': analyst['id']},
        headers=headers
    )
    assert resp_foreign.status_code == 404
