import time
from fastapi.testclient import TestClient
import pytest
from vulnforge.api import create_app
from vulnforge.auth import AuthSessions
from vulnforge.config import Config
from vulnforge.db import Store
from vulnforge.identity import Identities

ORIGIN = 'http://127.0.0.1:8000'


@pytest.fixture
def api_client(tmp_path):
    db_path = str(tmp_path / 'vulnforge.db')
    store = Store(db_path)
    identity = Identities(store)
    owner = identity.record_github_user(101, 'alpha-owner')
    org = identity.create_organization(owner['id'], 'SecOps Corp')
    org_id = org['id']

    repo = 'my-org/core-api'
    store.upsert_repo(repo, 101, 'main')
    identity.record_repository_ownership(org_id, repo, owner['id'], 'verified-server-fixture')

    cfg = Config(
        database_path=store.path,
        admin_token='operator-only',
        customer_api_preview=True,
        allow_insecure_local_auth=True,
        github_oauth_client_id='mock_id',
        github_oauth_client_secret='mock_secret',
        public_origin=ORIGIN
    )
    app = create_app(cfg, store)
    client = TestClient(app, base_url=ORIGIN)

    sessions = AuthSessions(store, cfg)
    token, csrf_token = sessions.create(owner['id'])

    client.cookies.set(sessions.cookie_prefix + 'session', token)
    client.cookies.set(sessions.cookie_prefix + 'csrf', csrf_token)

    return {
        'client': client,
        'csrf_token': csrf_token,
        'org_id': org_id,
        'repo': repo,
        'store': store
    }


def test_request_id_generation_and_propagation(api_client):
    client = api_client['client']
    org_id = api_client['org_id']

    # 1. Automatic generation when no header provided
    res = client.get(f'/api/v1/organizations/{org_id}/overview')
    assert res.status_code == 200
    req_id = res.headers.get('X-Request-ID')
    assert req_id is not None
    assert req_id.startswith('req-')

    # 2. Propagation when header is provided
    custom_id = 'trace-id-abc12345'
    res = client.get(
        f'/api/v1/organizations/{org_id}/overview',
        headers={'x-request-id': custom_id}
    )
    assert res.status_code == 200
    assert res.headers.get('X-Request-ID') == custom_id


def test_consistent_v1_error_schema(api_client):
    client = api_client['client']
    org_id = api_client['org_id']
    csrf = api_client['csrf_token']

    # 1. 404 Not Found with v1 header
    res = client.get(
        f'/api/v1/organizations/{org_id}/findings/9999999',
        headers={'x-request-id': 'custom-404-req'}
    )
    assert res.status_code == 404
    body = res.json()
    assert body['error_code'] == 'RESOURCE_NOT_FOUND'
    assert 'Resource not found' in body['message']
    assert 'request_id' in body
    assert res.headers.get('X-Request-ID') == body['request_id']

    # 1b. 404 without explicit v1 header returns detail and header metadata
    res_raw = client.get(f'/api/v1/organizations/{org_id}/findings/9999999')
    assert res_raw.status_code == 404
    assert res_raw.json() == {'detail': 'Resource not found'}
    assert res_raw.headers.get('X-Error-Code') == 'RESOURCE_NOT_FOUND'
    assert res_raw.headers.get('X-Request-ID') is not None

    # 2. 422 Validation Error
    headers = {
        'x-csrf-token': csrf,
        'origin': ORIGIN,
        'x-request-id': 'custom-validation-req'
    }
    # Send empty body to a route expecting fields
    res = client.post(f'/api/v1/organizations/{org_id}/notifications/channels', json={}, headers=headers)
    assert res.status_code == 422
    body = res.json()
    assert body['error_code'] == 'VALIDATION_FAILED'
    assert 'request_id' in body
    assert body['request_id'] == 'custom-validation-req'

    # 3. 403 CSRF Failure
    bad_headers = {
        'x-csrf-token': 'bad-token-value',
        'origin': ORIGIN,
        'x-request-id': 'csrf-fail-req'
    }
    res = client.post(
        f'/api/v1/organizations/{org_id}/notifications/channels',
        json={'name': 'test', 'kind': 'email', 'target': 'a@b.com'},
        headers=bad_headers
    )
    assert res.status_code == 403
    body = res.json()
    assert body['error_code'] == 'FORBIDDEN'
    assert 'request_id' in body
    assert body['request_id'] == 'csrf-fail-req'


def test_mutation_idempotency(api_client):
    client = api_client['client']
    org_id = api_client['org_id']
    csrf = api_client['csrf_token']

    idemp_key = 'idemp-channel-creation-001'
    headers = {
        'x-csrf-token': csrf,
        'origin': ORIGIN,
        'idempotency-key': idemp_key
    }
    channel_payload = {
        'name': 'Primary Slack Alerts',
        'kind': 'slack',
        'target': 'https://hooks.slack.com/services/T1/B1/K1',
        'events': ['scan_completed', 'critical_finding'],
        'enabled': True
    }

    # 1. First execution creates resource (201 Created)
    res1 = client.post(
        f'/api/v1/organizations/{org_id}/notifications/channels',
        json=channel_payload,
        headers=headers
    )
    assert res1.status_code == 201
    created_channel = res1.json()
    assert created_channel['name'] == 'Primary Slack Alerts'
    channel_id = created_channel['id']

    # 2. Replay with identical idempotency key returns exact cached response
    res2 = client.post(
        f'/api/v1/organizations/{org_id}/notifications/channels',
        json=channel_payload,
        headers=headers
    )
    assert res2.status_code == 201
    assert res2.headers.get('X-Idempotent-Replayed') == 'true'
    replayed_channel = res2.json()
    assert replayed_channel['id'] == channel_id

    # Verify no duplicate channel was created in database
    list_res = client.get(f'/api/v1/organizations/{org_id}/notifications/channels')
    items = list_res.json()['items']
    matching = [ch for ch in items if ch['id'] == channel_id]
    assert len(matching) == 1

    # 3. New mutation with different idempotency key succeeds
    headers2 = {**headers, 'idempotency-key': 'idemp-channel-creation-002'}
    channel_payload2 = {**channel_payload, 'name': 'Second Channel'}
    res3 = client.post(
        f'/api/v1/organizations/{org_id}/notifications/channels',
        json=channel_payload2,
        headers=headers2
    )
    assert res3.status_code == 201
    assert res3.headers.get('X-Idempotent-Replayed') is None
    assert res3.json()['id'] != channel_id


def test_cursor_pagination_consistency(api_client):
    client = api_client['client']
    org_id = api_client['org_id']
    csrf = api_client['csrf_token']

    # Create several notification channels
    headers = {'x-csrf-token': csrf, 'origin': ORIGIN}
    for i in range(5):
        client.post(
            f'/api/v1/organizations/{org_id}/notifications/channels',
            json={
                'name': f"Channel {i}",
                'kind': 'email',
                'target': f"alerts{i}@example.com",
                'events': ['scan_completed'],
                'enabled': True
            },
            headers=headers
        )

    # 1. Fetch page 1 with limit=2, cursor=0
    res = client.get(f'/api/v1/organizations/{org_id}/notifications/channels?limit=2&cursor=0')
    assert res.status_code == 200
    page1 = res.json()
    assert len(page1['items']) == 2
    assert page1['total'] >= 5
    assert page1['cursor'] == 0
    assert page1['next_cursor'] == 2
    assert page1['has_more'] is True

    # 2. Fetch page 2 with cursor=2
    res2 = client.get(f'/api/v1/organizations/{org_id}/notifications/channels?limit=2&cursor=2')
    assert res2.status_code == 200
    page2 = res2.json()
    assert len(page2['items']) == 2
    assert page2['cursor'] == 2
    assert page2['next_cursor'] == 4
    assert page2['has_more'] is True
