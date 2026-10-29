import pytest
from test_organization import organizations, actor


def test_onboarding_endpoint(organizations):
    client, headers, org_path = actor(organizations, label='alpha', role='org_admin')
    res = client.get(f"{org_path}/onboarding")
    assert res.status_code == 200
    data = res.json()
    assert data['installation_status'] in ('installed', 'pending_setup')
    assert data['steps_completed'] >= 1
    assert data['total_steps'] == 4
    assert any(s['step'] == 'create_organization' and s['completed'] is True for s in data['steps'])


def test_onboarding_unauthorized(organizations):
    client, headers, _ = actor(organizations, label='alpha', role='org_admin')
    # Try accessing bravo organization with alpha admin
    store, fixtures, cfg, app = organizations
    bravo_org = fixtures[1]['bravo']
    res = client.get(f"/api/v1/organizations/{bravo_org}/onboarding")
    assert res.status_code == 404
