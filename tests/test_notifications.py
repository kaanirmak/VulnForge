"""Unit and integration tests for VF-077: User-configurable email, Slack, and Microsoft Teams notifications."""
import json
import time
from fastapi.testclient import TestClient
import httpx
import pytest

from vulnforge.api import create_app
from vulnforge.auth import AuthSessions, digest
from vulnforge.config import Config
from vulnforge.db import Store
from vulnforge.identity import Identities
from vulnforge.notifications import (
    format_email_notification,
    format_slack_notification,
    format_teams_notification,
    validate_channel_target,
    NotificationDispatcher
)
from vulnforge.organization import OrganizationData, ResourceNotFound, RoleDenied

ORIGIN = 'http://127.0.0.1:8000'
ROOT = '/api/v1/organizations'


def test_notification_formatters():
    details = {
        'repo': 'org/repo',
        'severity': 'critical',
        'message': 'CVE-2023-9999 remote code execution detected in dependencies.',
        'url': 'https://app.vulnforge.com/findings/123',
        'timestamp': 1700000000
    }

    # 1. Email formatting
    email = format_email_notification('critical_finding', 'Critical Vulnerability in org/repo', details)
    assert '[VulnForge Alert]' in email['subject']
    assert 'CVE-2023-9999' in email['body']
    assert '<h3>Critical Vulnerability in org/repo</h3>' in email['html']

    # 2. Slack formatting
    slack = format_slack_notification('critical_finding', 'Critical Vulnerability in org/repo', details)
    assert 'blocks' in slack
    assert any('CRITICAL' in json.dumps(b) for b in slack['blocks'])
    assert any('org/repo' in json.dumps(b) for b in slack['blocks'])
    assert any('https://app.vulnforge.com/findings/123' in json.dumps(b) for b in slack['blocks'])

    # 3. Teams formatting
    teams = format_teams_notification('critical_finding', 'Critical Vulnerability in org/repo', details)
    assert teams['@type'] == 'MessageCard'
    assert teams['themeColor'] == 'E81123'  # Red for critical
    assert any(f['value'] == 'CRITICAL' for f in teams['sections'][0]['facts'])
    assert teams['potentialAction'][0]['targets'][0]['uri'] == 'https://app.vulnforge.com/findings/123'


def test_target_validation():
    # Valid targets
    validate_channel_target('email', 'alerts@example.com')
    validate_channel_target('slack', 'https://hooks.slack.com/services/T00/B00/X00')
    validate_channel_target('teams', 'https://outlook.office.com/webhook/1234')

    # Invalid email
    with pytest.raises(ValueError):
        validate_channel_target('email', 'not-an-email')

    # Invalid URL (http or malformed)
    with pytest.raises(ValueError):
        validate_channel_target('slack', 'http://insecure.webhook.com')

    with pytest.raises(ValueError):
        validate_channel_target('teams', 'not-a-url')

    # Invalid kind
    with pytest.raises(ValueError):
        validate_channel_target('discord', 'https://discord.com/webhook')


@pytest.mark.anyio
async def test_notification_dispatcher_mock():
    # 1. Email dispatcher
    disp = NotificationDispatcher()
    res_email = await disp.dispatch(
        {'id': 'chan_email', 'kind': 'email', 'target': 'dev@example.com'},
        'test_ping', 'Test Subject', {'message': 'Hello'}
    )
    assert res_email['delivered'] is True
    assert res_email['kind'] == 'email'

    # 2. Slack dispatcher with mock transport
    def handler(request: httpx.Request) -> httpx.Response:
        data = json.loads(request.content)
        assert 'blocks' in data
        return httpx.Response(200, json={'ok': True})

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    disp_slack = NotificationDispatcher(http_client=mock_client)
    res_slack = await disp_slack.dispatch(
        {'id': 'chan_slack', 'kind': 'slack', 'target': 'https://hooks.slack.com/test'},
        'scan_completed', 'Scan Finished', {'repo': 'org/repo', 'message': 'All clean'}
    )
    assert res_slack['delivered'] is True
    assert res_slack['status_code'] == 200

    # 3. Teams dispatcher with mock transport
    def teams_handler(request: httpx.Request) -> httpx.Response:
        data = json.loads(request.content)
        assert data['@type'] == 'MessageCard'
        return httpx.Response(200, text='1')

    mock_teams_client = httpx.AsyncClient(transport=httpx.MockTransport(teams_handler))
    disp_teams = NotificationDispatcher(http_client=mock_teams_client)
    res_teams = await disp_teams.dispatch(
        {'id': 'chan_teams', 'kind': 'teams', 'target': 'https://outlook.office.com/test'},
        'critical_finding', 'Alert', {'severity': 'critical', 'message': 'Immediate action'}
    )
    assert res_teams['delivered'] is True
    assert res_teams['status_code'] == 200


def seed_notif_env(store):
    identity = Identities(store)
    owner = identity.record_github_user(101, 'alpha-owner')
    org = identity.create_organization(owner['id'], 'alpha organization')
    org_id = org['id']

    analyst = identity.record_github_user(102, 'alpha-analyst')
    identity.set_membership(org_id, analyst['id'], 'analyst', owner['id'])

    viewer = identity.record_github_user(103, 'alpha-viewer')
    identity.set_membership(org_id, viewer['id'], 'viewer', owner['id'])

    foreign_owner = identity.record_github_user(201, 'bravo-owner')
    foreign_org = identity.create_organization(foreign_owner['id'], 'bravo organization')

    return owner, analyst, viewer, org_id, foreign_org['id']


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


def test_notification_channels_crud_lifecycle(tmp_path):
    store = Store(str(tmp_path / 'db'))
    owner, analyst, viewer, org_id, foreign_org_id = seed_notif_env(store)
    cfg = make_config(store)
    sessions = AuthSessions(store, cfg)
    token, _ = sessions.create(analyst['id'])
    org_data = OrganizationData(store, org_id, analyst['id'], digest(token))

    # 1. Create channels
    c1 = org_data.create_notification_channel('SecOps Slack', 'slack', 'https://hooks.slack.com/services/abc', ['critical_finding'])
    assert c1['name'] == 'SecOps Slack'
    assert c1['kind'] == 'slack'
    assert c1['enabled'] is True

    c2 = org_data.create_notification_channel('Dev Team Email', 'email', 'devs@example.com', ['scan_completed'])
    assert c2['kind'] == 'email'

    c3 = org_data.create_notification_channel('Operations Teams', 'teams', 'https://outlook.office.com/webhook/test', ['remediation_ready'])
    assert c3['kind'] == 'teams'

    # 2. List channels
    channels = org_data.list_notification_channels()
    assert len(channels) == 3
    assert [c['name'] for c in channels] == ['SecOps Slack', 'Dev Team Email', 'Operations Teams']

    # 3. Update channel
    updated = org_data.update_notification_channel(c1['id'], 'Security Slack V2', 'https://hooks.slack.com/services/v2', ['scan_completed', 'critical_finding'], False)
    assert updated['name'] == 'Security Slack V2'
    assert updated['enabled'] is False
    assert updated['target'] == 'https://hooks.slack.com/services/v2'

    # 4. Delete channel
    org_data.delete_notification_channel(c2['id'])
    remaining = org_data.list_notification_channels()
    assert len(remaining) == 2
    assert not any(c['id'] == c2['id'] for c in remaining)

    # 5. Viewer role cannot mutate
    v_token, _ = sessions.create(viewer['id'])
    v_data = OrganizationData(store, org_id, viewer['id'], digest(v_token))
    with pytest.raises(RoleDenied):
        v_data.create_notification_channel('Forbidden', 'email', 'f@example.com', [])


def test_notification_api_endpoints(tmp_path):
    store = Store(str(tmp_path / 'db'))
    owner, analyst, viewer, org_id, foreign_org_id = seed_notif_env(store)
    client, cfg, _, csrf = make_client(store, analyst)

    headers = {'x-csrf-token': csrf, 'origin': ORIGIN}

    # 1. POST /notifications/channels
    resp_create = client.post(
        f'{ROOT}/{org_id}/notifications/channels',
        json={
            'name': 'API Alert Email',
            'kind': 'email',
            'target': 'api-alerts@example.com',
            'events': ['critical_finding'],
            'enabled': True
        },
        headers=headers
    )
    assert resp_create.status_code == 201
    channel_id = resp_create.json()['id']

    # 2. GET /notifications/channels
    resp_list = client.get(f'{ROOT}/{org_id}/notifications/channels')
    assert resp_list.status_code == 200
    items = resp_list.json()['items']
    assert len(items) == 1
    assert items[0]['id'] == channel_id

    # 3. POST /notifications/channels/{channel_id}/test
    resp_test = client.post(
        f'{ROOT}/{org_id}/notifications/channels/{channel_id}/test',
        headers=headers
    )
    assert resp_test.status_code == 200
    assert resp_test.json()['delivered'] is True

    # 4. PUT /notifications/channels/{channel_id}
    resp_update = client.put(
        f'{ROOT}/{org_id}/notifications/channels/{channel_id}',
        json={
            'name': 'API Alert Email Updated',
            'target': 'updated-alerts@example.com',
            'events': ['scan_completed'],
            'enabled': False
        },
        headers=headers
    )
    assert resp_update.status_code == 200
    assert resp_update.json()['name'] == 'API Alert Email Updated'
    assert resp_update.json()['enabled'] is False

    # 5. DELETE /notifications/channels/{channel_id}
    resp_delete = client.delete(
        f'{ROOT}/{org_id}/notifications/channels/{channel_id}',
        headers=headers
    )
    assert resp_delete.status_code == 204

    # 6. Foreign org cannot access
    resp_foreign = client.get(f'{ROOT}/{foreign_org_id}/notifications/channels')
    assert resp_foreign.status_code == 404
